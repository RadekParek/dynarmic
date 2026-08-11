#include <array>
#include <atomic>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <thread>
#include <unistd.h>

#include <dynarmic/interface/A64/a64.h>
#include <dynarmic/interface/exclusive_monitor.h>

namespace {

constexpr std::uint64_t code_address = 0x100007dd8;
constexpr std::uint64_t code_page = 0x100007000;
constexpr std::uint64_t stack_address = 0x7ffffffeff10;
constexpr std::uint64_t stack_page = 0x7ffffffef000;
constexpr std::size_t page_size = 0x1000;
constexpr std::uint64_t x21_value = 0x2121212121212121;
constexpr std::uint64_t x22_value = 0x2222222222222222;
constexpr std::uint32_t stp_x22_x21 = 0xa9bd57f6;
constexpr std::uint32_t add_x0_x0_one = 0x91000400;

std::atomic<bool> returned{false};
pthread_t execution_thread{};
std::uint64_t watchdog_pc = 0;
std::uint64_t watchdog_sp = 0;
std::uint64_t watchdog_host = 0;

void print_watchdog_signal(int signal_number, siginfo_t*, void* raw_context) {
    auto* context = static_cast<ucontext_t*>(raw_context);
    std::uint64_t pc = 0;
    std::uint64_t sp = 0;
    std::uint64_t lr = 0;
#if defined(__aarch64__)
    pc = context->uc_mcontext.pc;
    sp = context->uc_mcontext.sp;
    lr = context->uc_mcontext.regs[30];
#elif defined(__x86_64__)
    pc = context->uc_mcontext.gregs[REG_RIP];
    sp = context->uc_mcontext.gregs[REG_RSP];
    lr = context->uc_mcontext.gregs[REG_RBP];
#endif
    const auto thread_id = static_cast<unsigned long long>(syscall(SYS_gettid));
    dprintf(STDERR_FILENO, "WATCHDOG signal=%d thread_id=%llu native_pc=%#" PRIx64 " native_sp=%#" PRIx64 " native_lr=%#" PRIx64 " guest_pc=%#" PRIx64 " guest_sp=%#" PRIx64 " host_block=%#" PRIx64 "\n", signal_number, thread_id, pc, sp, lr, watchdog_pc, watchdog_sp, watchdog_host);
    _exit(134);
}

void install_watchdog_handler() {
    struct sigaction action{};
    action.sa_sigaction = print_watchdog_signal;
    action.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&action.sa_mask);
    sigaction(SIGUSR2, &action, nullptr);
}

class FixedMemory {
public:
    FixedMemory() {
        code = mmap(reinterpret_cast<void*>(code_page), page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        stack = mmap(reinterpret_cast<void*>(stack_page), page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (code == MAP_FAILED || stack == MAP_FAILED) {
            std::perror("mmap");
            std::exit(2);
        }
    }

    ~FixedMemory() {
        munmap(code, page_size);
        munmap(stack, page_size);
    }

    void put_code(std::uint32_t instruction) {
        std::memcpy(reinterpret_cast<void*>(code_address), &instruction, sizeof(instruction));
    }

    std::uint64_t read_stack(std::uint64_t address) const {
        std::uint64_t value = 0;
        std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
        return value;
    }

    void write_stack(std::uint64_t address, std::uint64_t value) {
        std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
    }

    void* code;
    void* stack;
};

class Callbacks final : public Dynarmic::A64::UserCallbacks {
public:
    explicit Callbacks(FixedMemory& memory)
            : memory(memory) {}

    std::uint64_t callback_reads = 0;
    std::uint64_t callback_writes = 0;

    std::optional<std::uint32_t> MemoryReadCode(std::uint64_t address) override {
        ++callback_reads;
        std::uint32_t value = 0;
        std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
        return value;
    }

    std::uint8_t MemoryRead8(std::uint64_t address) override { return read<std::uint8_t>(address); }
    std::uint16_t MemoryRead16(std::uint64_t address) override { return read<std::uint16_t>(address); }
    std::uint32_t MemoryRead32(std::uint64_t address) override { return read<std::uint32_t>(address); }
    std::uint64_t MemoryRead64(std::uint64_t address) override { return read<std::uint64_t>(address); }
    Dynarmic::A64::Vector MemoryRead128(std::uint64_t address) override {
        return {read<std::uint64_t>(address), read<std::uint64_t>(address + 8)};
    }

    void MemoryWrite8(std::uint64_t address, std::uint8_t value) override { write(address, value); }
    void MemoryWrite16(std::uint64_t address, std::uint16_t value) override { write(address, value); }
    void MemoryWrite32(std::uint64_t address, std::uint32_t value) override { write(address, value); }
    void MemoryWrite64(std::uint64_t address, std::uint64_t value) override { write(address, value); }
    void MemoryWrite128(std::uint64_t address, Dynarmic::A64::Vector value) override {
        write(address, value[0]);
        write(address + 8, value[1]);
    }

    void InterpreterFallback(std::uint64_t, std::size_t) override {}
    void CallSVC(std::uint32_t) override {}
    void ExceptionRaised(std::uint64_t, Dynarmic::A64::Exception) override {}
    void AddTicks(std::uint64_t) override {}
    std::uint64_t GetTicksRemaining() override { return 1; }
    std::uint64_t GetCNTPCT() override { return 0; }

private:
    template <typename T>
    T read(std::uint64_t address) {
        ++callback_reads;
        T value{};
        std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
        return value;
    }

    template <typename T>
    void write(std::uint64_t address, T value) {
        ++callback_writes;
        std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
    }

    FixedMemory& memory;
};

struct Result {
    bool returned = false;
    bool pass = false;
    std::uint64_t pc = 0;
    std::uint64_t sp = 0;
    std::uint64_t first = 0;
    std::uint64_t second = 0;
    std::uint64_t callback_reads = 0;
    std::uint64_t callback_writes = 0;
    std::uint64_t host_block = 0;
};

Result run_case(bool fastmem, std::uint32_t instruction) {
    FixedMemory memory;
    memory.put_code(instruction);
    Callbacks callbacks(memory);
    Dynarmic::A64::UserConfig config{&callbacks};
    config.optimizations = Dynarmic::no_optimizations;
    config.check_halt_on_memory_access = true;
    config.enable_cycle_counting = false;
    if (fastmem) {
        config.fastmem_pointer = 0;
        config.fastmem_address_space_bits = 64;
        config.silently_mirror_fastmem = false;
        config.recompile_on_fastmem_failure = false;
    }
    Dynarmic::ExclusiveMonitor monitor{1};
    config.global_monitor = &monitor;
    Dynarmic::A64::Jit jit{config};
    jit.SetPC(code_address);
    jit.SetSP(stack_address);
    jit.SetRegister(21, x21_value);
    jit.SetRegister(22, x22_value);
    jit.SetRegister(0, 41);
    watchdog_pc = jit.GetPC();
    watchdog_sp = jit.GetSP();
    watchdog_host = 0;
    returned.store(false, std::memory_order_release);
    execution_thread = pthread_self();
    std::thread watchdog([&] {
        usleep(1500000);
        if (!returned.load(std::memory_order_acquire)) {
            pthread_kill(execution_thread, SIGUSR2);
        }
    });
    const auto reason = jit.Step();
    returned.store(true, std::memory_order_release);
    watchdog.join();
    Result result;
    result.returned = true;
    result.pc = jit.GetPC();
    result.sp = jit.GetSP();
    result.first = memory.read_stack(stack_address - 0x30);
    result.second = memory.read_stack(stack_address - 0x28);
    result.callback_reads = callbacks.callback_reads;
    result.callback_writes = callbacks.callback_writes;
    result.pass = Dynarmic::Has(reason, Dynarmic::HaltReason::Step) && result.pc == code_address + 4;
    if (instruction == stp_x22_x21) {
        result.pass = result.pass && result.sp == stack_address - 0x30 && result.first == x22_value && result.second == x21_value;
    } else {
        result.pass = result.pass && result.sp == stack_address && jit.GetRegister(0) == 42;
    }
    return result;
}

void print_result(const char* label, bool fastmem, std::uint32_t instruction, const Result& result) {
    std::printf("%s FASTMEM=%s instruction=%#010x\n", label, fastmem ? "ON" : "OFF", instruction);
    std::printf("TEST_BEGIN\n");
    std::printf("BEFORE pc=%#" PRIx64 " sp=%#" PRIx64 "\n", code_address, stack_address);
    if (result.returned) {
        std::printf("STEP_RETURNED\n");
    }
    std::printf("AFTER pc=%#" PRIx64 " sp=%#" PRIx64 "\n", result.pc, result.sp);
    std::printf("callbacks reads=%" PRIu64 " writes=%" PRIu64 "\n", result.callback_reads, result.callback_writes);
    std::printf("TEST_%s\n", result.pass ? "PASS" : "FAIL");
}

}  // namespace

int main() {
    install_watchdog_handler();
    const auto register_off = run_case(false, add_x0_x0_one);
    print_result("REGISTER_ONLY", false, add_x0_x0_one, register_off);
    const auto stp_off = run_case(false, stp_x22_x21);
    print_result("STP", false, stp_x22_x21, stp_off);
    const auto stp_on = run_case(true, stp_x22_x21);
    print_result("STP", true, stp_x22_x21, stp_on);
    return register_off.pass && stp_off.pass && stp_on.pass ? 0 : 1;
}
