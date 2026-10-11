/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Test-only syscall boundary. No BPF request reaches the kernel. */
#include <stdarg.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifdef LMB_GUARD_PRELOAD
#include <dlfcn.h>
#endif

/* Each scripted test supplies this interface. A preload guard has no
 * script and rejects every BPF request, including feature probes. */
extern long lmb_test_bpf_dispatch(int command, void *attr, unsigned int size)
    __attribute__((weak));

#ifdef LMB_GUARD_PRELOAD
static long (*real_syscall)(long, ...);
__attribute__((constructor)) static void guard_init(void) {
    real_syscall = (long (*)(long, ...))dlsym(RTLD_NEXT, "syscall");
    if (!real_syscall) _exit(96);
}
/* Keep ASan confined to instrumented binaries, with leak checks enabled.
 * The guard itself also runs in CTest/shell utilities. */
const char *__asan_default_options(void) {
    return "verify_asan_link_order=0:detect_leaks=1";
}
#define GUARD_SYSCALL syscall
#define REAL_SYSCALL real_syscall
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
    fprintf(stderr, "HOST GUARD: stopped unexpected syscall %ld\n", number);
    _exit(98);
}
