/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Producer/mapping and finite syscall seams. libbpf owns the reader. */
#include <dirent.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "generic_events_host.h"
#include "generic_events.h"

static unsigned checks, failures;
static uint64_t calls[GE_FAULT_HITS + 1];
static int ring_fd = -1, epoll_fd = -1, program_fd = 12345;
static uint8_t *writer;
static size_t page_size, writer_size;
static int alloc_active, info_code, new_code, new_null, attach_code, attach_null;
static int destroy_code, epoll_create_code, register_code, wait_result = 1, wait_errno;
static int consume_code, overwrite, last_timeout, map_fd_code, epoll_fd_code;
static char expected_category[257] = "syscalls", expected_event[257] = "sys_enter_getpid";
static const void *category_source, *event_source;
void ge_attach_targets(const char *category, const char *event, const void *a, const void *b) {
    CHECK(strlen(category) <= 256 && strlen(event) <= 256);
    strcpy(expected_category, category); strcpy(expected_event, event);
    category_source = a; event_source = b;
}
void ge_map_fd_fault(int fd) { map_fd_code = fd; }
void ge_epoll_fd_fault(int code) { epoll_fd_code = code; }
int __real_ring_buffer__epoll_fd(const struct ring_buffer *);
int __wrap_ring_buffer__epoll_fd(const struct ring_buffer *rb) {
    return epoll_fd_code ? epoll_fd_code : __real_ring_buffer__epoll_fd(rb);
}
int ge_ring_fd(void) { return ring_fd; }
int ge_last_timeout(void) { return last_timeout; }
static unsigned alloc_ordinal, alloc_seen, mmap_ordinal, mmap_seen;
static struct {void *address; size_t length;} mappings[32];
static void *tokens[32];

void ge_check(int condition, const char *expression, unsigned line) {
    checks++;
    if (!condition) { failures++; fprintf(stderr, "FAIL line %u: %s\n", line, expression); }
}
static void stop(const char *text) {
    fprintf(stderr, "EVENT HOST GUARD: %s\n", text); _exit(99);
}
void lmb_events_reset(void) {
    info_code = new_code = attach_code = destroy_code = 0;
    new_null = attach_null = epoll_create_code = register_code = wait_errno = consume_code = 0;
    wait_result = 1; overwrite = 0; map_fd_code = epoll_fd_code = 0; mmap_ordinal = mmap_seen = 0;
    alloc_active = 0; alloc_ordinal = alloc_seen = 0; program_fd = 12345;
}
void lmb_events_scenario(uint32_t scenario) {
    lmb_events_reset();
    if (scenario == 1) ge_wait_result(-1, EINTR);
    else if (scenario != 0) stop("unknown test scenario");
}
uint64_t lmb_events_call_count(uint32_t query) {
    return query && query <= GE_FAULT_HITS ? calls[query] : 0;
}
uint64_t lmb_events_close_count(void) { return calls[GE_OBJECT_CLOSE]; }
void ge_alloc_fault(unsigned n) { alloc_active = 1; alloc_ordinal = n; alloc_seen = 0; }
unsigned ge_alloc_finish(void) { alloc_active = 0; return alloc_seen; }
static int allocation_fail(void) {
    if (!alloc_active) return 0;
    alloc_seen++; calls[GE_ALLOCS]++;
    if (alloc_ordinal && alloc_seen == alloc_ordinal) {
        calls[GE_FAULT_HITS]++; errno = ENOMEM; return 1;
    }
    return 0;
}
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void *__wrap_malloc(size_t n) { return allocation_fail() ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t n, size_t s) { return allocation_fail() ? NULL : __real_calloc(n, s); }
void *__wrap_realloc(void *p, size_t n) { return allocation_fail() ? NULL : __real_realloc(p, n); }

void ge_map_fault(unsigned n) { mmap_ordinal = n; mmap_seen = 0; }
void ge_info_fault(int code) { info_code = code; }
void ge_epoll_fault(int create_code, int reg_code) {
    epoll_create_code = create_code; register_code = reg_code;
}
void ge_attach_fault(int code, int null_result) { attach_code = code; attach_null = null_result; }
void ge_destroy_fault(int code) { destroy_code = code; }
void ge_program_fd(int fd) { program_fd = fd; }
void ge_new_fault(int code, int null_result) { new_code = code; new_null = null_result; }
void ge_wait_result(int result, int error) { wait_result = result; wait_errno = error; }
void ge_consume_fault(int code) { consume_code = code; }
void ge_overwrite_source(int enabled) { overwrite = enabled; }

int __wrap_bpf_object__load(struct bpf_object *object) {
    CHECK(object != NULL); return 0; /* Aggregate loaded-state seam only. */
}
void __real_bpf_object__close(struct bpf_object *);
void __wrap_bpf_object__close(struct bpf_object *object) {
    if (object) calls[GE_OBJECT_CLOSE]++;
    __real_bpf_object__close(object);
}
int __wrap_bpf_program__fd(const struct bpf_program *program) {
    CHECK(program != NULL); return program_fd;
}
int __wrap_bpf_map__fd(const struct bpf_map *map) {
    if (!map || strcmp(bpf_map__name(map), "events")) stop("unexpected map FD request");
    return map_fd_code ? map_fd_code : ring_fd;
}
struct bpf_link *__wrap_bpf_program__attach_tracepoint(const struct bpf_program *program,
        const char *category, const char *event) {
    calls[GE_ATTACH]++;
    CHECK(program != NULL && !strcmp(bpf_program__name(program), "on_getpid"));
    CHECK(category && !strcmp(category, expected_category) && category != category_source);
    CHECK(event && !strcmp(event, expected_event) && event != event_source);
    if (attach_code) {
        errno = attach_null ? -attach_code : ENOTTY;
        return attach_null ? NULL : (void *)(intptr_t)attach_code;
    }
    void *token = __real_calloc(1, 16);
    CHECK(token != NULL);
    for (size_t i = 0; i < 32; i++) if (!tokens[i]) { tokens[i] = token; return token; }
    stop("test link token limit"); return NULL;
}
int __wrap_bpf_link__destroy(struct bpf_link *link) {
    for (size_t i = 0; i < 32; i++) if (tokens[i] == link && link) {
        calls[GE_DESTROY]++; free(tokens[i]); tokens[i] = NULL;
        errno = ENOTTY; return destroy_code;
    }
    stop("unowned link destruction"); return -EINVAL;
}

long lmb_test_bpf_dispatch(int command, void *raw, unsigned int size) {
    union bpf_attr *attr = raw;
    if (command != BPF_OBJ_GET_INFO_BY_FD || !attr ||
        attr->info.bpf_fd != (uint32_t)ring_fd || !attr->info.info)
        stop("unscripted BPF command");
    CHECK(size == offsetof(union bpf_attr, info) + sizeof(attr->info));
    CHECK(attr->info.info_len == sizeof(struct bpf_map_info));
    struct bpf_map_info *info = (void *)(uintptr_t)attr->info.info;
    ge_sentinel(info, sizeof(*info), 0); calls[GE_INFO]++;
    if (info_code) { errno = -info_code; return -1; }
    info->type = BPF_MAP_TYPE_RINGBUF; info->max_entries = GENERIC_EVENTS_CAPACITY;
    return 0;
}
void *__real_mmap(void *, size_t, int, int, int, off_t);
void *__wrap_mmap(void *address, size_t length, int prot, int flags, int fd, off_t offset) {
    if (fd != ring_fd) return __real_mmap(address, length, prot, flags, fd, offset);
    mmap_seen++;
    CHECK(address == NULL && flags == MAP_SHARED);
    CHECK((offset == 0 && length == page_size && prot == (PROT_READ | PROT_WRITE)) ||
        (offset == (off_t)page_size && length == page_size + 2 * GENERIC_EVENTS_CAPACITY && prot == PROT_READ));
    if (mmap_ordinal && mmap_seen == mmap_ordinal) { errno = ENOMEM; return MAP_FAILED; }
    void *p = __real_mmap(address, length, prot, flags, fd, offset);
    if (p != MAP_FAILED) {
        calls[GE_MAPS]++;
        for (size_t i = 0; i < 32; i++) if (!mappings[i].address) {
            mappings[i].address = p; mappings[i].length = length; return p;
        }
        stop("mapping registry full");
    }
    return p;
}
/* The pinned libbpf build enables FILE_OFFSET_BITS=64 and calls mmap64.
 * Both entry points share the same finite owned-FD mapping oracle. */
void *__wrap_mmap64(void *address, size_t length, int prot, int flags, int fd, off64_t offset) {
    CHECK(offset >= 0 && (uint64_t)offset <= INT64_MAX);
    return __wrap_mmap(address, length, prot, flags, fd, (off_t)offset);
}
int __real_munmap(void *, size_t);
int __wrap_munmap(void *p, size_t length) {
    for (size_t i = 0; i < 32; i++) if (mappings[i].address == p) {
        CHECK(mappings[i].length == length); mappings[i].address = NULL;
        calls[GE_MAPS]--; break;
    }
    return __real_munmap(p, length);
}
int __real_epoll_create1(int);
int __wrap_epoll_create1(int flags) {
    CHECK(flags == EPOLL_CLOEXEC);
    if (epoll_create_code) { errno = -epoll_create_code; return -1; }
    epoll_fd = __real_epoll_create1(flags); return epoll_fd;
}
int __wrap_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    if (fd != ring_fd || epfd != epoll_fd || !event || op != EPOLL_CTL_ADD)
        stop("unexpected epoll registration");
    CHECK(event->events == EPOLLIN && event->data.fd == 0);
    if (register_code) { errno = -register_code; return -1; }
    return 0; /* The memfd is deliberately never registered as a kernel ring. */
}
int __wrap_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    CHECK(epfd == epoll_fd && events && maxevents == 1 && timeout >= -1);
    calls[GE_WAIT]++; last_timeout = timeout;
    events->data.u64 = (uint64_t)(int64_t)timeout;
    if (wait_result < 0) errno = wait_errno;
    return wait_result;
}
struct ring_buffer *__real_ring_buffer__new(int, ring_buffer_sample_fn, void *, const struct ring_buffer_opts *);
struct ring_buffer *__wrap_ring_buffer__new(int fd, ring_buffer_sample_fn callback,
        void *ctx, const struct ring_buffer_opts *opts) {
    CHECK(fd == ring_fd && callback && ctx && opts == NULL); calls[GE_NEW]++;
    if (new_code) {
        errno = new_null ? -new_code : ENOTTY;
        return new_null ? NULL : (void *)(intptr_t)new_code;
    }
    return __real_ring_buffer__new(fd, callback, ctx, opts);
}
int __real_ring_buffer__consume_n(struct ring_buffer *, size_t);
int __wrap_ring_buffer__consume_n(struct ring_buffer *rb, size_t n) {
    CHECK(n == 1); calls[GE_CONSUME]++;
    if (consume_code) { errno = ENOTTY; return consume_code; }
    uint64_t before = ge_consumer();
    int result = __real_ring_buffer__consume_n(rb, n);
    if (overwrite && ge_consumer() != before) {
        uint8_t bytes[4097]; memset(bytes, 0xcc, sizeof(bytes));
        size_t offset = (size_t)(before & (GENERIC_EVENTS_CAPACITY - 1));
        uint32_t size; memcpy(&size, writer + 2 * page_size + offset, 4);
        size &= 0x3fffffffu;
        CHECK(size <= sizeof(bytes));
        for (size_t i = 0; i < size; i++) {
            size_t at = (offset + 8 + i) & (GENERIC_EVENTS_CAPACITY - 1);
            writer[2 * page_size + at] = bytes[i];
            writer[2 * page_size + GENERIC_EVENTS_CAPACITY + at] = bytes[i];
        }
    }
    return result;
}

unsigned ge_fd_count(void) {
    DIR *dir = opendir("/proc/self/fd"); CHECK(dir != NULL);
    if (!dir) exit(1);
    unsigned n = 0; struct dirent *e;
    while ((e = readdir(dir))) if (e->d_name[0] != '.') n++;
    closedir(dir); return n;
}
struct lmb_object *ge_object(const char *path, int loaded) {
    FILE *file = fopen(path, "rb"); CHECK(file != NULL);
    if (!file) exit(1);
    CHECK(!fseek(file, 0, SEEK_END)); long n = ftell(file); CHECK(n > 0);
    rewind(file); uint8_t *bytes = malloc((size_t)n); CHECK(bytes != NULL);
    if (!bytes) exit(1);
    CHECK(fread(bytes, 1, (size_t)n, file) == (size_t)n); fclose(file);
    struct lmb_object *object = NULL;
    struct lmb_object_options_v1 opts = {.abi_version = 1, .struct_size = sizeof(opts)};
    CHECK(lmb_object_open_v1(bytes, (uint64_t)n, &opts, &object) == 0 && object);
    memset(bytes, 0xcc, (size_t)n); free(bytes);
    if (!object) exit(1);
    if (loaded) CHECK(lmb_object_load_v1(object) == 0);
    return object;
}
struct lmb_attach_options_v1 ge_attach_options(void) {
    struct lmb_attach_options_v1 opts = {.abi_version = 1, .struct_size = sizeof(opts),
        .family = 1, .program = {(const uint8_t *)"on_getpid", 9},
        .target_a = {(const uint8_t *)"syscalls", 8},
        .target_b = {(const uint8_t *)"sys_enter_getpid", 16}};
    return opts;
}
struct lmb_buffer_options_v1 ge_buffer_options(void) {
    struct lmb_buffer_options_v1 opts = {.abi_version = 1, .struct_size = sizeof(opts),
        .ring = {(const uint8_t *)"events", 6}, .max_raw_bytes = 4096, .stage_slots = 1};
    return opts;
}
void ge_diagnostic(uint32_t op, uint32_t domain, int32_t code) {
    struct lmb_generic_error_v1 error = {.abi_version = 1, .struct_size = sizeof(error)};
    CHECK(lmb_generic_last_error_v1(&error) == 0);
    CHECK(error.operation == op && error.domain == domain && error.code == code);
    if (code) CHECK(error.msg_len && error.msg_len <= 1023);
    ge_sentinel(error.message + error.msg_len, 1024 - error.msg_len, 0);
}
void ge_sentinel(const void *raw, size_t n, uint8_t value) {
    const uint8_t *bytes = raw;
    for (size_t i = 0; i < n; i++) CHECK(bytes[i] == value);
}
void ge_payload(uint8_t bytes[16], uint64_t sequence) {
    for (unsigned i = 0; i < 8; i++) {
        bytes[i] = (uint8_t)(sequence >> (8 * i));
        bytes[i + 8] = (uint8_t)(~sequence >> (8 * i));
    }
}
void ge_frame(const uint8_t *bytes, uint64_t sequence) {
    static const uint8_t header[8] = {16, 0, 0, 0, 1, 0, 0, 0};
    uint8_t payload[16]; ge_payload(payload, sequence);
    CHECK(!memcmp(bytes, header, 8)); CHECK(!memcmp(bytes + 8, payload, 16));
}
uint64_t ge_consumer(void) { return *(unsigned long *)writer; }
uint64_t ge_producer(void) { return *(unsigned long *)(writer + page_size); }
void ge_empty_position(uint64_t position) {
    CHECK(ge_producer() == ge_consumer()); CHECK(!(position & 7));
    *(unsigned long *)writer = (unsigned long)position;
    *(unsigned long *)(writer + page_size) = (unsigned long)position;
}
void ge_publish(const void *bytes, size_t size, uint32_t flags) {
    CHECK(size <= 4097 && (!size || bytes));
    uint64_t pos = ge_producer(); size_t len = (size + 8 + 7) & ~(size_t)7;
    CHECK(pos - ge_consumer() + len <= GENERIC_EVENTS_CAPACITY);
    uint8_t raw[4112] = {0}; uint32_t header = (uint32_t)size | flags;
    memcpy(raw, &header, 4); if (size) memcpy(raw + 8, bytes, size);
    for (size_t i = 0; i < len; i++) {
        size_t at = (size_t)((pos + i) & (GENERIC_EVENTS_CAPACITY - 1));
        writer[2 * page_size + at] = raw[i];
        writer[2 * page_size + GENERIC_EVENTS_CAPACITY + at] = raw[i];
    }
    CHECK(!memcmp(writer + 2 * page_size,
        writer + 2 * page_size + GENERIC_EVENTS_CAPACITY, GENERIC_EVENTS_CAPACITY));
    __atomic_store_n((unsigned long *)(writer + page_size), (unsigned long)(pos + len), __ATOMIC_RELEASE);
}
void ge_unbusy(void) {
    size_t at = (size_t)(ge_consumer() & (GENERIC_EVENTS_CAPACITY - 1));
    uint32_t header; memcpy(&header, writer + 2 * page_size + at, 4); header &= ~(1u << 31);
    memcpy(writer + 2 * page_size + at, &header, 4);
    memcpy(writer + 2 * page_size + GENERIC_EVENTS_CAPACITY + at, &header, 4);
}
void ge_begin(const char *fixture) {
    (void)fixture; lmb_events_reset(); page_size = (size_t)getpagesize();
    writer_size = 2 * page_size + 2 * GENERIC_EVENTS_CAPACITY;
    ring_fd = memfd_create("lmb-events-host", MFD_CLOEXEC); CHECK(ring_fd >= 0);
    CHECK(ftruncate(ring_fd, (off_t)writer_size) == 0);
    writer = __real_mmap(NULL, writer_size, PROT_READ | PROT_WRITE, MAP_SHARED, ring_fd, 0);
    CHECK(writer != MAP_FAILED); if (writer == MAP_FAILED) exit(1);
}
int ge_end(const char *suite) {
    CHECK(calls[GE_MAPS] == 0);
    for (size_t i = 0; i < 32; i++) CHECK(!tokens[i] && !mappings[i].address);
    CHECK(__real_munmap(writer, writer_size) == 0); CHECK(close(ring_fd) == 0);
    printf("%s: %u checks, %u failures; real-reader calls=%llu, attach seams=%llu\n",
        suite, checks, failures, (unsigned long long)calls[GE_CONSUME], (unsigned long long)calls[GE_ATTACH]);
    return failures ? 1 : 0;
}
