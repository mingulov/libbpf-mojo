/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Independent downstream oracle: no syscall below reaches the kernel. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <linux/bpf.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *mode;
static atomic_uint resolutions, downstream;
static pthread_barrier_t resolving_barrier;
static _Thread_local uint32_t storage, length, flags, signature;
static _Thread_local long wanted_return;
static _Thread_local int wanted_errno;

static long observed_syscall(long number, ...) {
    atomic_fetch_add(&downstream, 1);
    va_list args;
    if (number == SYS_rseq) {
        va_start(args, number);
        void *pointer = va_arg(args, void *);
        uint32_t got_length = va_arg(args, uint32_t);
        uint32_t got_flags = va_arg(args, uint32_t);
        uint32_t got_signature = va_arg(args, uint32_t);
        va_end(args);
        assert(pointer == &storage && got_length == length);
        assert(got_flags == flags && got_signature == signature);
    } else if (number == SYS_memfd_create) {
        va_start(args, number);
        const char *name = va_arg(args, const char *);
        unsigned int got_flags = va_arg(args, unsigned int);
        va_end(args);
        assert(!strcmp(name, "guard-exact-name") && got_flags == 3);
    } else {
        assert(number == SYS_getpid || number == SYS_gettid);
    }
    if (wanted_return < 0) errno = wanted_errno;
    return wanted_return;
}

void *__wrap_dlsym(void *handle, const char *name) {
    assert(handle == RTLD_NEXT && !strcmp(name, "syscall"));
    atomic_fetch_add(&resolutions, 1);
    errno = EDOM; /* Resolver must not replace the caller's errno. */
    if (mode && !strcmp(mode, "unresolved")) return NULL;
    if (mode && !strcmp(mode, "recursive")) {
        syscall(SYS_gettid);
        _exit(94);
    }
    if (mode && !strcmp(mode, "concurrent"))
        pthread_barrier_wait(&resolving_barrier);
    return (void *)observed_syscall;
}

static void *forward(void *unused) {
    (void)unused;
    length = UINT32_C(0x87654321);
    flags = UINT32_C(0xfedcba98);
    signature = UINT32_C(0x53053053);
    wanted_return = 37;
    errno = EPROTO;
    assert(syscall(SYS_rseq, (void *)&storage, length, flags, signature) == 37);
    assert(errno == EPROTO);
    wanted_return = -1; wanted_errno = EINVAL; errno = E2BIG;
    assert(syscall(SYS_rseq, (void *)&storage, length, flags, signature) == -1);
    assert(errno == EINVAL);
    return NULL;
}

/* Runs before the guard's default-priority constructor, like the actual
 * Mojo allocator. The concurrent variant resolves from two threads here. */
__attribute__((constructor(101))) static void before_guard_constructor(void) {
    mode = getenv("LMB_GUARD_TEST_MODE");
    if (mode && !strcmp(mode, "bpf")) {
        union bpf_attr attr = {0};
        syscall(SYS_bpf, BPF_PROG_LOAD, &attr, (unsigned int)sizeof(attr));
        _exit(94);
    }
    if (mode && !strcmp(mode, "unknown")) {
        syscall(SYS_uname, (void *)&storage);
        _exit(94);
    }
    if (mode && !strcmp(mode, "concurrent")) {
        pthread_t a, b;
        assert(!pthread_barrier_init(&resolving_barrier, NULL, 2));
        assert(!pthread_create(&a, NULL, forward, NULL));
        assert(!pthread_create(&b, NULL, forward, NULL));
        assert(!pthread_join(a, NULL) && !pthread_join(b, NULL));
        assert(!pthread_barrier_destroy(&resolving_barrier));
        assert(atomic_load(&resolutions) == 2 && atomic_load(&downstream) == 4);
    } else {
        forward(NULL);
        assert(atomic_load(&resolutions) == 1 && atomic_load(&downstream) == 2);
    }
}

static void child(const char *executable, const char *variant, int expected) {
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        assert(!setenv("LMB_GUARD_TEST_MODE", variant, 1));
        execl(executable, executable, "child", (char *)NULL);
        _exit(93);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == expected);
}

int main(int argc, char **argv) {
    if (argc == 2) return 0;
    assert(argc == 1);
    wanted_return = 41; errno = EPROTO;
    assert(syscall(SYS_getpid) == 41 && errno == EPROTO);
    assert(syscall(SYS_gettid) == 41 && errno == EPROTO);
    assert(syscall(SYS_memfd_create, "guard-exact-name", (unsigned int)3) == 41);
    assert(errno == EPROTO && atomic_load(&resolutions) == 1);
    child(argv[0], "concurrent", 0);
    child(argv[0], "unresolved", 96);
    child(argv[0], "recursive", 96);
    child(argv[0], "unknown", 98);
    child(argv[0], "bpf", 99);
    puts("host guard: exact rseq/finite forwards, errno, early/concurrent resolution, fail-closed controls PASS");
    return 0;
}
