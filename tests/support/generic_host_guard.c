/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Test-only syscall boundary. No BPF request reaches the kernel. */
#include <stdarg.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#ifdef LMB_GUARD_PRELOAD
#include <dlfcn.h>
#include <errno.h>
#include <stdatomic.h>
#endif

/* Each scripted test supplies this interface. A preload guard has no
 * script and rejects every BPF request, including feature probes. */
extern long lmb_test_bpf_dispatch(int command, void *attr, unsigned int size)
    __attribute__((weak));

#ifdef LMB_GUARD_PRELOAD
typedef long (*syscall_function)(long, ...);
static _Atomic(syscall_function) real_syscall;
static _Thread_local int resolving;
static syscall_function guard_resolve(void) {
    int saved_errno = errno;
    syscall_function found = atomic_load_explicit(&real_syscall, memory_order_acquire);
    if (!found) {
        if (resolving) _exit(96);
        resolving = 1;
        found = (syscall_function)dlsym(RTLD_NEXT, "syscall");
        resolving = 0;
        if (!found) _exit(96);
        syscall_function expected = NULL;
        if (!atomic_compare_exchange_strong_explicit(&real_syscall, &expected, found,
                memory_order_acq_rel, memory_order_acquire))
            found = expected;
    }
    errno = saved_errno;
    return found;
}
__attribute__((constructor)) static void guard_init(void) { (void)guard_resolve(); }
/* Keep ASan confined to instrumented binaries, with leak checks enabled.
 * The guard itself also runs in CTest/shell utilities. */
const char *__asan_default_options(void) {
    return "verify_asan_link_order=0:detect_leaks=1";
}
#define GUARD_SYSCALL syscall
#define REAL_SYSCALL guard_resolve()
#else
long __real_syscall(long number, ...);
#define GUARD_SYSCALL __wrap_syscall
#define REAL_SYSCALL __real_syscall
#endif

long GUARD_SYSCALL(long number, ...) {
    va_list args;
    if (number == SYS_bpf) {
        if (lmb_test_bpf_dispatch) {
            va_start(args, number);
            int command = va_arg(args, int);
            void *attr = va_arg(args, void *);
            unsigned int size = va_arg(args, unsigned int);
            va_end(args);
            return lmb_test_bpf_dispatch(command, attr, size);
        }
        fputs("HOST GUARD: stopped unscripted SYS_bpf before execution\n", stderr);
        _exit(99);
    }
    /* Forward only signatures known to these host tests. Never read six
     * variadic arguments or forward an unknown syscall signature. */
    if (number == SYS_getpid || number == SYS_gettid)
        return REAL_SYSCALL(number);
    if (number == SYS_memfd_create) {
        va_start(args, number);
        const char *name = va_arg(args, const char *);
        unsigned int flags = va_arg(args, unsigned int);
        va_end(args);
        return REAL_SYSCALL(number, name, flags);
    }
    if (number == SYS_rseq) {
        va_start(args, number);
        void *pointer = va_arg(args, void *);
        uint32_t length = va_arg(args, uint32_t);
        uint32_t flags = va_arg(args, uint32_t);
        uint32_t signature = va_arg(args, uint32_t);
        va_end(args);
        return REAL_SYSCALL(number, pointer, length, flags, signature);
    }
    fprintf(stderr, "HOST GUARD: stopped unexpected syscall %ld\n", number);
    _exit(98);
}
