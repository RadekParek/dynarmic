// SPDX-FileCopyrightText: Copyright (c) 2022 merryhime <https://mary.rs>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <new>

#if defined(_WIN32)
#    define NOMINMAX
#    include <windows.h>
#elif defined(__APPLE__)
#    include <TargetConditionals.h>
#    include <libkern/OSCacheControl.h>
#    include <pthread.h>
#    include <sys/mman.h>
#    include <unistd.h>
#else
#    if defined(__ANDROID__) && !defined(_GNU_SOURCE)
#        define _GNU_SOURCE
#    endif
#    include <sys/mman.h>
#    if defined(__ANDROID__)
#        include <sys/types.h>
#        include <unistd.h>
#        include <sys/syscall.h>
#        ifndef __NR_memfd_create
#            define __NR_memfd_create 279
#        endif
#    endif
#endif

namespace oaknut {

class CodeBlock {
public:
    explicit CodeBlock(std::size_t size)
        : m_size(size)
    {
#if defined(_WIN32)
        m_memory = (std::uint32_t*)VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#elif defined(__APPLE__)
#    if TARGET_OS_IPHONE
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
#    else
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
#    endif
#elif defined(__NetBSD__)
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_MPROTECT(PROT_READ | PROT_WRITE | PROT_EXEC), MAP_ANON | MAP_PRIVATE, -1, 0);
#elif defined(__OpenBSD__)
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
#else
#    if defined(__ANDROID__)
        fd = static_cast<int>(syscall(__NR_memfd_create, "oaknut_code_block", 0));
        if (fd < 0 || ftruncate(fd, size) != 0)
            throw std::bad_alloc{};
        m_write_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
#    else
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
        m_write_memory = m_memory;
#    endif
#endif

#if !defined(__ANDROID__)
        m_write_memory = m_memory;
#endif

        if (m_memory == nullptr || m_memory == MAP_FAILED || m_write_memory == nullptr || m_write_memory == MAP_FAILED)
            throw std::bad_alloc{};
    }

    ~CodeBlock()
    {
        if (m_memory == nullptr)
            return;

#if defined(_WIN32)
        VirtualFree((void*)m_memory, 0, MEM_RELEASE);
#else
        munmap(m_memory, m_size);
#    if defined(__ANDROID__)
        munmap(m_write_memory, m_size);
        close(fd);
#    endif
#endif
    }

    CodeBlock(const CodeBlock&) = delete;
    CodeBlock& operator=(const CodeBlock&) = delete;
    CodeBlock(CodeBlock&&) = delete;
    CodeBlock& operator=(CodeBlock&&) = delete;

    std::uint32_t* ptr() const
    {
        return m_write_memory;
    }

    template<typename T>
    T xptr() const
    {
        static_assert(std::is_pointer_v<T> || std::is_same_v<T, std::uintptr_t> || std::is_same_v<T, std::intptr_t>);
        return reinterpret_cast<T>(m_memory);
    }

    void protect()
    {
#if defined(__APPLE__) && !TARGET_OS_IPHONE
        pthread_jit_write_protect_np(1);
#elif defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
        mprotect(m_memory, m_size, PROT_READ | PROT_EXEC);
#endif
    }

    void unprotect()
    {
#if defined(__APPLE__) && !TARGET_OS_IPHONE
        pthread_jit_write_protect_np(0);
#elif defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
        mprotect(m_memory, m_size, PROT_READ | PROT_WRITE);
#endif
    }

    void invalidate(std::uint32_t* executable_memory, std::size_t size)
    {
#if defined(__APPLE__)
        sys_icache_invalidate(executable_memory, size);
#elif defined(_WIN32)
        FlushInstructionCache(GetCurrentProcess(), executable_memory, size);
#else
        const auto executable_address = reinterpret_cast<std::uintptr_t>(executable_memory);
        const auto code_address = reinterpret_cast<std::uintptr_t>(m_memory);
        const auto write_address = reinterpret_cast<std::uintptr_t>(m_write_memory) + (executable_address - code_address);
        invalidate_impl(reinterpret_cast<void*>(write_address), executable_memory, size);
#endif
    }

    void invalidate_all()
    {
        invalidate(m_memory, m_size);
    }

private:
#if !defined(__APPLE__) && !defined(_WIN32)
    static void invalidate_impl(void* writable_memory, void* executable_memory, std::size_t size)
    {
        static std::size_t icache_line_size = 0x10000, dcache_line_size = 0x10000;

        std::uint64_t ctr;
        __asm__ volatile("mrs %0, ctr_el0"
                         : "=r"(ctr));

        const std::size_t isize = icache_line_size = std::min<std::size_t>(icache_line_size, 4 << ((ctr >> 0) & 0xf));
        const std::size_t dsize = dcache_line_size = std::min<std::size_t>(dcache_line_size, 4 << ((ctr >> 16) & 0xf));
        const std::uintptr_t writable_start = reinterpret_cast<std::uintptr_t>(writable_memory);
        const std::uintptr_t executable_start = reinterpret_cast<std::uintptr_t>(executable_memory);
        const std::uintptr_t writable_end = writable_start + size;
        const std::uintptr_t executable_end = executable_start + size;

        for (std::uintptr_t addr = writable_start & ~(dsize - 1); addr < writable_end; addr += dsize) {
            __asm__ volatile("dc cvau, %0"
                             :
                             : "r"(addr)
                             : "memory");
        }
        __asm__ volatile("dsb ish\n"
                         :
                         :
                         : "memory");

        for (std::uintptr_t addr = executable_start & ~(isize - 1); addr < executable_end; addr += isize) {
            __asm__ volatile("ic ivau, %0"
                             :
                             : "r"(addr)
                             : "memory");
        }
        __asm__ volatile("dsb ish\nisb\n"
                         :
                         :
                         : "memory");
    }
#endif

protected:
#if defined(__ANDROID__)
    int fd = -1;
#endif
    std::uint32_t* m_memory;
    std::uint32_t* m_write_memory = nullptr;
    std::size_t m_size = 0;
};

}  // namespace oaknut
