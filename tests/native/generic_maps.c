/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Real ELF/BTF geometry and pinned libbpf map wrappers. Only the syscall
 * response and successful loaded-state/FD access are test doubles. */
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "libbpf_mojo_generic.h"

#ifdef LMB_MAPS_RED_BASELINE
#pragma weak lmb_object_map_lookup_v1
#pragma weak lmb_object_map_update_v1
#endif

static unsigned checks, failures, bpf_calls, cpu_queries, online_queries;
static unsigned map_fd_queries, native_closes, allocation_hits;
static int possible_cpus = 3, online_cpus = 1, load_result;
static int synthetic_fd = 0x1bad;
static int allocation_fault;
#define CHECK(c) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL line %u: %s\n", __LINE__, #c); } } while (0)

static struct {
    int armed, command, result;
    uint64_t flags;
    uint8_t key[4], bytes[144];
    size_t extent;
    const uint8_t *caller_output;
} script;

long lmb_test_bpf_dispatch(int command, void *raw_attr, unsigned int size) {
    union bpf_attr *attr = raw_attr;
    if (!script.armed || !attr || command != script.command ||
        (command != BPF_MAP_LOOKUP_ELEM && command != BPF_MAP_UPDATE_ELEM)) {
        fputs("HOST GUARD: unscripted BPF command stopped before execution\n", stderr);
        _exit(99);
    }
    script.armed = 0;
    bpf_calls++;
    CHECK(size == offsetof(union bpf_attr, flags) + sizeof(attr->flags));
    CHECK(attr->map_fd == (uint32_t)synthetic_fd);
    CHECK(attr->flags == script.flags);
    CHECK(attr->key && !memcmp((const void *)(uintptr_t)attr->key, script.key, 4));
    CHECK(attr->value != 0);
    uint8_t *value = (void *)(uintptr_t)attr->value;
    if (command == BPF_MAP_LOOKUP_ELEM) {
        CHECK(value != script.caller_output); /* Owned scratch, even on error. */
        memcpy(value, script.bytes, script.extent);
    } else {
        CHECK(!memcmp(value, script.bytes, script.extent));
    }
    if (script.result) { errno = -script.result; return -1; }
    return 0;
}

int __wrap_bpf_object__load(struct bpf_object *object) {
    CHECK(object != NULL);
    return load_result;
}
/* No synthetic FD is installed in the parsed object. Its real FD stays
 * -1 throughout; libbpf teardown cannot close a synthetic descriptor. */
int __wrap_bpf_map__fd(const struct bpf_map *map) {
    CHECK(map != NULL); map_fd_queries++; return synthetic_fd;
}
int __wrap_libbpf_num_possible_cpus(void) {
    cpu_queries++; errno = ENOTTY; return possible_cpus;
}
long __real_sysconf(int name);
long __wrap_sysconf(int name) {
    if (name == _SC_NPROCESSORS_ONLN) { online_queries++; return online_cpus; }
    return __real_sysconf(name);
}
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size) {
    if (allocation_fault) {
        allocation_fault = 0; allocation_hits++; errno = ENOMEM; return NULL;
    }
    return __real_malloc(size);
}
void __real_bpf_object__close(struct bpf_object *object);
void __wrap_bpf_object__close(struct bpf_object *object) {
    if (object) native_closes++;
    __real_bpf_object__close(object);
}
/* Preserve the actual pinned wrapper's signed result while contradicting
 * ambient errno. The bridge must retain the return, not rebuild it. */
int __real_bpf_map_lookup_elem(int fd, const void *key, void *value);
int __wrap_bpf_map_lookup_elem(int fd, const void *key, void *value) {
    int result = __real_bpf_map_lookup_elem(fd, key, value);
    errno = ENOTTY; return result;
}
int __real_bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
int __wrap_bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags) {
    int result = __real_bpf_map_update_elem(fd, key, value, flags);
    errno = ENOTTY; return result;
}

static struct lmb_name_v1 name_of(const char *text) {
    struct lmb_name_v1 name = {1, sizeof(name),
        {(const uint8_t *)text, (uint32_t)strlen(text), 0}};
    return name;
}
static void diagnostic(uint32_t op, uint32_t domain, int32_t code) {
    struct lmb_generic_error_v1 error = {0};
    error.abi_version = 1; error.struct_size = sizeof(error);
    CHECK(lmb_generic_last_error_v1(&error) == 0);
    CHECK(error.operation == op && error.domain == domain && error.code == code);
    CHECK(error.msg_len > 0 && error.msg_len <= 1023 && !error.message[error.msg_len]);
}
static void clear_diagnostic(void) {
    struct lmb_generic_error_v1 error = {0};
    error.abi_version = 1; error.struct_size = sizeof(error);
    CHECK(lmb_generic_last_error_v1(&error) == 0);
    CHECK(error.operation == 0 && error.domain == 0 && error.code == 0);
}
static void arm(int command, const void *key, const void *value, size_t extent,
                uint64_t flags, int result, const uint8_t *output) {
    CHECK(!script.armed && extent <= sizeof(script.bytes));
    script.armed = 1; script.command = command; script.result = result;
    script.flags = flags; script.extent = extent; script.caller_output = output;
    memcpy(script.key, key, 4); memcpy(script.bytes, value, extent);
}
static void untouched(const uint8_t *bytes, size_t count, uint8_t value) {
    for (size_t i = 0; i < count; i++) CHECK(bytes[i] == value);
}
static unsigned fd_count(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) { perror("opendir fd"); exit(1); }
    unsigned count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) if (entry->d_name[0] != '.') count++;
    closedir(directory); return count;
}
static struct lmb_object *open_fixture(const uint8_t *elf, size_t size, int loaded) {
    struct lmb_object_options_v1 options = {0};
    struct lmb_object *object = NULL;
    options.abi_version = 1; options.struct_size = sizeof(options);
    CHECK(lmb_object_open_v1(elf, size, &options, &object) == 0 && object);
    if (!object) exit(1);
    if (loaded) CHECK(lmb_object_load_v1(object) == load_result);
    return object;
}
static void invalid_lookup(struct lmb_object *object, const struct lmb_name_v1 *name,
    const uint8_t *key, uint64_t key_bytes, uint8_t *output, uint64_t capacity,
    uint64_t *needed, int result, int unchanged) {
    unsigned before = bpf_calls, cpus_before = cpu_queries;
    uint64_t saved = needed ? *needed : 0;
    CHECK(lmb_object_map_lookup_v1(object, name, key, key_bytes, output, capacity, needed) == result);
    CHECK(bpf_calls == before && cpu_queries == cpus_before);
    if (needed) CHECK(*needed == (unchanged ? saved : 0));
    diagnostic(7, 4, result);
}
static void invalid_update(struct lmb_object *object, const struct lmb_name_v1 *name,
    const uint8_t *key, uint64_t key_bytes, const uint8_t *value, uint64_t value_bytes,
    uint64_t flags, int result) {
    unsigned before = bpf_calls, cpus_before = cpu_queries;
    CHECK(lmb_object_map_update_v1(object, name, key, key_bytes, value, value_bytes, flags) == result);
    CHECK(bpf_calls == before && cpu_queries == cpus_before);
    diagnostic(8, 4, result);
}

static void validation(struct lmb_object *object, struct lmb_object *unloaded) {
    struct lmb_name_v1 name = name_of("counter"), bad;
    uint32_t key = 0;
    _Alignas(8) uint8_t output[48];
    uint64_t needed = 123, value = 41;
    memset(output, 0xa5, sizeof(output));
    invalid_lookup(NULL, &name, (void *)&key, 4, output, 8, &needed, -EINVAL, 1);
    invalid_lookup(object, NULL, (void *)&key, 4, output, 8, &needed, -EINVAL, 1);
    invalid_lookup(object, &name, (void *)&key, 4, output, 8, NULL, -EINVAL, 1);
    invalid_lookup(unloaded, &name, (void *)&key, 4, output, 8, &needed, -EINVAL, 1);
    bad = name; bad.abi_version = 0;
    invalid_lookup(NULL, &bad, NULL, 4, NULL, 8, &needed, -EINVAL, 1);
    for (int delta = -1; delta <= 1; delta += 2) {
        bad = name; bad.struct_size = sizeof(bad) + delta;
        invalid_lookup(object, &bad, (void *)&key, 4, output, 8, &needed, -EINVAL, 1);
        invalid_update(object, &bad, (void *)&key, 4, (void *)&value, 8, 0, -EINVAL);
    }
    const char *invalid_names[] = {"", "a\0b", "\xff", "\xc0\xaf", "\xed\xa0\x80", "\xe2\x82"};
    const unsigned lengths[] = {0, 3, 1, 2, 3, 2};
    for (unsigned i = 0; i < sizeof(lengths)/sizeof(*lengths); i++) {
        bad = name; bad.name.ptr = (const uint8_t *)invalid_names[i]; bad.name.len = lengths[i];
        invalid_lookup(object, &bad, (void *)&key, 4, output, 8, &needed, -EINVAL, 1);
        invalid_update(object, &bad, (void *)&key, 4, (void *)&value, 8, 0, -EINVAL);
    }
    bad = name; bad.name._pad = 1;
    invalid_lookup(object, &bad, (void *)&key, 4, output, 8, &needed, -EINVAL, 1);
    bad = name; bad.name.len = 257;
    invalid_lookup(object, &bad, (void *)&key, 4, output, 8, &needed, -EINVAL, 1);
    bad = name; bad.name.ptr = NULL;
    invalid_lookup(object, &bad, (void *)&key, 4, output, 8, &needed, -EINVAL, 1);
    bad = name; bad.name.ptr = (const void *)(UINTPTR_MAX - 1); bad.name.len = 4;
    invalid_lookup(object, &bad, (void *)&key, 4, output, 8, &needed, -EINVAL, 1);
    invalid_lookup(object, &name, NULL, 4, output, 8, &needed, -EINVAL, 1);
    invalid_lookup(object, &name, (void *)&key, 4, NULL, 8, &needed, -EINVAL, 1);
    invalid_lookup(object, &name, (const void *)(UINTPTR_MAX - 1), 4, output, 8, &needed, -EINVAL, 1);
    invalid_lookup(object, &name, (void *)&key, 4, (void *)(UINTPTR_MAX - 1), 8, &needed, -EINVAL, 1);
    invalid_lookup(object, &name, (void *)&key, UINT64_MAX, output, 8, &needed, -EINVAL, 1);
    invalid_lookup(object, &name, (void *)&key, 4, output, UINT64_MAX, &needed, -EINVAL, 1);
    unsigned calls_before = bpf_calls;
    CHECK(lmb_object_map_lookup_v1(object, &name, (void *)&key, 4, output, 8,
          (void *)(UINTPTR_MAX - 3)) == -EINVAL && bpf_calls == calls_before);
    diagnostic(7, 4, -EINVAL);
    /* Real aliased storage must be intact on rejection, including a cell
     * which starts outside the key but overlaps its final bytes. */
    invalid_lookup(object, &name, output + 16, 4, output + 32, 8,
                   (void *)(output + 16), -EINVAL, 1);
    invalid_lookup(object, &name, output + 22, 4, output + 32, 8,
                   (void *)(output + 16), -EINVAL, 1);
    invalid_lookup(object, &name, (void *)&key, 4, output + 16, 9,
                   (void *)(output + 24), -EINVAL, 1);
    untouched(output, sizeof(output), 0xa5);
    invalid_lookup(object, &name, (void *)&key, 3, output, 8, &needed, -EINVAL, 1);
    invalid_lookup(object, &name, (void *)&key, 5, output, 8, &needed, -EINVAL, 1);
    invalid_lookup(object, &name, (const void *)UINTPTR_MAX, 0, output, 8,
                   &needed, -EINVAL, 1);
    invalid_update(NULL, &name, (void *)&key, 4, (void *)&value, 8, 0, -EINVAL);
    invalid_update(object, NULL, (void *)&key, 4, (void *)&value, 8, 0, -EINVAL);
    invalid_update(unloaded, &name, (void *)&key, 4, (void *)&value, 8, 0, -EINVAL);
    invalid_update(object, &name, NULL, 4, (void *)&value, 8, 0, -EINVAL);
    invalid_update(object, &name, (void *)&key, 4, NULL, 8, 0, -EINVAL);
    invalid_update(object, &name, (const void *)(UINTPTR_MAX - 1), 4, (void *)&value, 8, 0, -EINVAL);
    invalid_update(object, &name, (void *)&key, 4, (const void *)(UINTPTR_MAX - 1), 8, 0, -EINVAL);
    invalid_update(object, &name, (void *)&key, 3, (void *)&value, 8, 0, -EINVAL);
    invalid_update(object, &name, (void *)&key, 4, (void *)&value, 7, 0, -EINVAL);
    invalid_update(object, &name, (void *)&key, 4, (void *)&value, 9, 0, -EINVAL);
    invalid_update(object, &name, (void *)&key, 4, (const void *)UINTPTR_MAX, 0, 0, -EINVAL);
    const uint64_t bad_flags[] = {3, 7, 8, 16, UINT64_C(1) << 63, UINT64_MAX};
    for (unsigned i = 0; i < sizeof(bad_flags)/sizeof(*bad_flags); i++)
        invalid_update(unloaded, &name, (void *)&key, 4, (void *)&value, 8, bad_flags[i], -EINVAL);
    bad = name_of("unknown");
    invalid_lookup(object, &bad, (void *)&key, 4, output, 8, &needed, -ENOENT, 0);
    needed = 123;
    invalid_lookup(object, &bad, (const void *)UINTPTR_MAX, 0,
                   (void *)UINTPTR_MAX, 0, &needed, -ENOENT, 0);
    invalid_update(object, &bad, (const void *)UINTPTR_MAX, 0,
                   (const void *)UINTPTR_MAX, 0, 0, -ENOENT);
    /* Correcting invalid flags changes the observed failure from span/flag
     * rejection to name lookup, proving validation precedes the owner. */
    invalid_update(object, &bad, (void *)&key, 4, (void *)&value, 8, 3, -EINVAL);
    invalid_update(object, &bad, (void *)&key, 4, (void *)&value, 8, 0, -ENOENT);
    CHECK(map_fd_queries == 0 && bpf_calls == 0);
}

static void ordinary_maps(struct lmb_object *object) {
    const char *names[] = {"counter", "values"};
    const uint64_t values[] = {41, UINT64_C(0xfedcba9876543210)};
    const uint64_t flags[] = {0, 1, 2, 4, 5, 6};
    uint32_t key = 0;
    uint8_t output[48];
    uint64_t needed;
    for (unsigned m = 0; m < 2; m++) {
        struct lmb_name_v1 name = name_of(names[m]);
        for (unsigned v = 0; v < 2; v++) {
            for (unsigned i = 0; i < 6; i++) {
                arm(BPF_MAP_UPDATE_ELEM, &key, &values[v], 8, flags[i], 0, NULL);
                CHECK(lmb_object_map_update_v1(object, &name, (void *)&key, 4,
                    (void *)&values[v], 8, flags[i]) == 0 && !script.armed);
                clear_diagnostic();
            }
            const unsigned capacities[] = {0, 7, 8, 9};
            for (unsigned c = 0; c < 4; c++) {
                unsigned capacity = capacities[c], before = bpf_calls;
                needed = 123; memset(output, 0xa5, sizeof(output));
                if (capacity >= 8) arm(BPF_MAP_LOOKUP_ELEM, &key, &values[v], 8, 0, 0, output + 16);
                int rc = lmb_object_map_lookup_v1(object, &name, (void *)&key, 4,
                                                 output + 16, capacity, &needed);
                CHECK(rc == (capacity < 8 ? -ENOSPC : 0));
                CHECK(needed == (capacity < 8 ? 8 : 0));
                CHECK(bpf_calls == before + (capacity >= 8));
                untouched(output, 16, 0xa5);
                untouched(output + 24, 24, 0xa5);
                if (capacity < 8) { untouched(output + 16, 8, 0xa5); diagnostic(7, 4, -ENOSPC); }
                else { CHECK(!memcmp(output + 16, &values[v], 8)); clear_diagnostic(); }
            }
        }
        const int native_errors[] = {-ENOENT, -EIO, -EINTR, -ENOSPC, -EOPNOTSUPP};
        for (unsigned i = 0; i < sizeof(native_errors)/sizeof(*native_errors); i++) {
            memset(output, 0xa5, sizeof(output)); needed = 123;
            arm(BPF_MAP_LOOKUP_ELEM, &key, &values[1], 8, 0, native_errors[i], output + 16);
            unsigned before = bpf_calls;
            CHECK(lmb_object_map_lookup_v1(object, &name, (void *)&key, 4,
                  output + 16, 9, &needed) == native_errors[i]);
            CHECK(needed == 0 && bpf_calls == before + 1 && errno == ENOTTY);
            untouched(output, sizeof(output), 0xa5); diagnostic(7, 3, native_errors[i]);
            arm(BPF_MAP_UPDATE_ELEM, &key, &values[1], 8, 6, native_errors[i], NULL);
            before = bpf_calls;
            CHECK(lmb_object_map_update_v1(object, &name, (void *)&key, 4,
                  (void *)&values[1], 8, 6) == native_errors[i]);
            CHECK(bpf_calls == before + 1 && errno == ENOTTY); diagnostic(8, 3, native_errors[i]);
        }
        /* Key/output alias and cells exactly adjacent to output/key. */
        _Alignas(8) uint8_t adjacent[32] = {0};
        arm(BPF_MAP_LOOKUP_ELEM, adjacent + 8, &values[1], 8, 0, 0, adjacent + 8);
        CHECK(lmb_object_map_lookup_v1(object, &name, adjacent + 8, 4,
              adjacent + 8, 8, (void *)(adjacent + 16)) == 0);
        CHECK(!memcmp(adjacent + 8, &values[1], 8));
        uint64_t zero; memcpy(&zero, adjacent + 16, 8); CHECK(zero == 0);
        memset(adjacent, 0, sizeof(adjacent));
        arm(BPF_MAP_LOOKUP_ELEM, adjacent + 8, &values[0], 8, 0, 0, adjacent + 16);
        CHECK(lmb_object_map_lookup_v1(object, &name, adjacent + 8, 4,
              adjacent + 16, 8, (void *)adjacent) == 0);
        CHECK(!memcmp(adjacent + 16, &values[0], 8));
        /* Non-null ignored empty output pointer cannot be touched. */
        needed = 123;
        CHECK(lmb_object_map_lookup_v1(object, &name, (void *)&key, 4,
              (void *)UINTPTR_MAX, 0, &needed) == -ENOSPC && needed == 8);
        needed = 123;
        CHECK(lmb_object_map_lookup_v1(object, &name, (void *)&key, 4,
              NULL, 0, &needed) == -ENOSPC && needed == 8);
        /* One owned lookup allocation, no update allocation. */
        needed = 123; memset(output, 0xa5, sizeof(output)); allocation_fault = 1;
        unsigned before = bpf_calls, hits = allocation_hits;
        CHECK(lmb_object_map_lookup_v1(object, &name, (void *)&key, 4,
              output + 16, 8, &needed) == -ENOMEM && needed == 0);
        CHECK(bpf_calls == before && allocation_hits == hits + 1 && !allocation_fault);
        untouched(output, sizeof(output), 0xa5); diagnostic(7, 1, -ENOMEM);
        arm(BPF_MAP_LOOKUP_ELEM, &key, &values[0], 8, 0, 0, output + 16);
        CHECK(lmb_object_map_lookup_v1(object, &name, (void *)&key, 4,
              output + 16, 8, &needed) == 0 && !script.armed);
    }
}

static void percpu_maps(struct lmb_object *object, struct bpf_object *parsed) {
    /* Hand-derived extents: possible CPUs include the mocked offline CPUs.
     * Slot bytes include all padding and are never derived by bridge code. */
    const struct { unsigned value, stride, cpus, extent; } cases[] = {
        {1,8,1,8}, {1,8,3,24}, {1,8,9,72},
        {7,8,1,8}, {7,8,3,24}, {7,8,9,72},
        {8,8,1,8}, {8,8,3,24}, {8,8,9,72},
        {9,16,1,16}, {9,16,3,48}, {9,16,9,144},
        {13,16,1,16}, {13,16,3,48}, {13,16,9,144}
    };
    const char *names[] = {"percpu_values", "percpu_hash"};
    uint32_t key = 0;
    for (unsigned m = 0; m < 2; m++) {
        struct bpf_map *map = bpf_object__find_map_by_name(parsed, names[m]);
        CHECK(map != NULL);
        struct lmb_name_v1 name = name_of(names[m]);
        for (unsigned c = 0; c < sizeof(cases)/sizeof(*cases); c++) {
            /* The object was never really loaded. Public pre-load setters
             * vary the parsed geometry for boundary testing only. */
            CHECK(bpf_map__set_value_size(map, cases[c].value) == 0);
            possible_cpus = (int)cases[c].cpus;
            struct lmb_map_info_v1 info = {0};
            info.abi_version = 1; info.struct_size = sizeof(info);
            unsigned queried = cpu_queries;
            CHECK(lmb_object_map_info_v1(object, &name, &info) == 0);
            CHECK(info.key_size == 4 && info.value_size == cases[c].value &&
                  info.stride == cases[c].stride && info.num_cpus == cases[c].cpus);
            CHECK(cpu_queries == queried + 1);
            uint8_t pattern[144];
            for (unsigned slot = 0; slot < cases[c].cpus; slot++)
                for (unsigned byte = 0; byte < cases[c].stride; byte++)
                    pattern[slot * cases[c].stride + byte] = (uint8_t)(17 + slot * 19 + byte);
            long page = sysconf(_SC_PAGESIZE);
            CHECK(page > 256);
            uint8_t *memory = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            CHECK(memory != MAP_FAILED);
            if (memory == MAP_FAILED) exit(1);
            CHECK(mprotect(memory + page, (size_t)page, PROT_NONE) == 0);
            for (int delta = -1; delta <= 1; delta++) {
                unsigned capacity = cases[c].extent + delta;
                uint8_t *output = memory + page - capacity;
                memset(output - 16, 0xa5, capacity + 16);
                uint64_t needed = 123;
                unsigned before = bpf_calls; queried = cpu_queries;
                if (delta >= 0) arm(BPF_MAP_LOOKUP_ELEM, &key, pattern, cases[c].extent, 0, 0, output);
                CHECK(lmb_object_map_lookup_v1(object, &name, (void *)&key, 4,
                      output, capacity, &needed) == (delta < 0 ? -ENOSPC : 0));
                CHECK(needed == (delta < 0 ? cases[c].extent : 0));
                CHECK(bpf_calls == before + (delta >= 0) && cpu_queries == queried + 1);
                untouched(output - 16, 16, 0xa5);
                if (delta < 0) untouched(output, capacity, 0xa5);
                else {
                    for (unsigned byte = 0; byte < cases[c].extent; byte++) CHECK(output[byte] == pattern[byte]);
                    if (delta > 0) CHECK(output[cases[c].extent] == 0xa5);
                }
            }
            CHECK(munmap(memory, (size_t)page * 2) == 0);
            arm(BPF_MAP_UPDATE_ELEM, &key, pattern, cases[c].extent, 2, 0, NULL);
            queried = cpu_queries;
            CHECK(lmb_object_map_update_v1(object, &name, (void *)&key, 4,
                  pattern, cases[c].extent, 2) == 0 && cpu_queries == queried + 1);
            for (int delta = -1; delta <= 1; delta += 2) {
                unsigned before = bpf_calls; queried = cpu_queries;
                CHECK(lmb_object_map_update_v1(object, &name, (void *)&key, 4,
                      pattern, cases[c].extent + delta, 0) == -EINVAL);
                CHECK(bpf_calls == before && cpu_queries == queried + 1); diagnostic(8, 4, -EINVAL);
            }
        }
        CHECK(bpf_map__set_value_size(map, 13) == 0);
    }
    CHECK(online_queries == 0);
}

static void geometry_failures(struct lmb_object *object, struct bpf_object *parsed) {
    struct lmb_name_v1 name = name_of("percpu_values");
    struct bpf_map *map = bpf_object__find_map_by_name(parsed, "percpu_values");
    uint32_t key = 0; uint8_t output[48], input[48] = {0};
    const int counts[] = {0, -EIO, -2041};
    for (unsigned i = 0; i < sizeof(counts)/sizeof(*counts); i++) {
        memset(output, 0xa5, sizeof(output)); possible_cpus = counts[i];
        uint64_t needed = 123;
        unsigned before = bpf_calls;
        int expected = counts[i] < 0 ? counts[i] : -EIO;
        CHECK(lmb_object_map_lookup_v1(object, &name, (void *)&key, 4,
              output, sizeof(output), &needed) == expected && needed == 0);
        CHECK(bpf_calls == before); untouched(output, sizeof(output), 0xa5); diagnostic(7, 2, expected);
        CHECK(lmb_object_map_update_v1(object, &name, (void *)&key, 4,
              input, sizeof(input), 0) == expected && bpf_calls == before);
        diagnostic(8, 2, expected);
    }
    const struct { uint32_t value; int cpus; } overflow[] = {
        {UINT32_MAX, 1}, {UINT32_MAX - 6, 1}, {UINT32_MAX - 7, 2}, {13, INT_MAX}
    };
    for (unsigned i = 0; i < sizeof(overflow)/sizeof(*overflow); i++) {
        CHECK(bpf_map__set_value_size(map, overflow[i].value) == 0);
        possible_cpus = overflow[i].cpus;
        uint64_t needed = 123; unsigned before = bpf_calls;
        CHECK(lmb_object_map_lookup_v1(object, &name, (void *)&key, 4,
              output, sizeof(output), &needed) == -EOVERFLOW && needed == 123);
        CHECK(bpf_calls == before); diagnostic(7, 4, -EOVERFLOW);
        CHECK(lmb_object_map_update_v1(object, &name, (void *)&key, 4,
              input, sizeof(input), 0) == -EOVERFLOW && bpf_calls == before);
        diagnostic(8, 4, -EOVERFLOW);
    }
    CHECK(bpf_map__set_value_size(map, 13) == 0); possible_cpus = 3;
    /* Wrong key extent precedes even a CPU-query failure. */
    possible_cpus = -2041;
    uint64_t needed = 123; unsigned queried = cpu_queries;
    CHECK(lmb_object_map_lookup_v1(object, &name, (void *)&key, 3,
          output, sizeof(output), &needed) == -EINVAL && needed == 123);
    CHECK(cpu_queries == queried); diagnostic(7, 4, -EINVAL);
    possible_cpus = 3;
    allocation_fault = 1; needed = 123;
    unsigned before = bpf_calls, hits = allocation_hits;
    memset(output, 0xa5, sizeof(output));
    CHECK(lmb_object_map_lookup_v1(object, &name, (void *)&key, 4,
          output, sizeof(output), &needed) == -ENOMEM && needed == 0);
    CHECK(allocation_hits == hits + 1 && bpf_calls == before && !allocation_fault);
    untouched(output, sizeof(output), 0xa5); diagnostic(7, 1, -ENOMEM);
    arm(BPF_MAP_LOOKUP_ELEM, &key, input, sizeof(input), 0, 0, output);
    CHECK(lmb_object_map_lookup_v1(object, &name, (void *)&key, 4,
          output, sizeof(output), &needed) == 0 && !script.armed);
}

static void guard_controls(const char *executable) {
    const char *modes[] = {"--guard-positive", "--guard-trap", "--guard-unknown"};
    const int exits[] = {0, 99, 98};
    for (unsigned i = 0; i < 3; i++) {
        pid_t child = fork(); CHECK(child >= 0);
        if (!child) { execl(executable, executable, modes[i], (char *)NULL); _exit(97); }
        int status = 0;
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == exits[i]);
    }
}
static struct bpf_object *opened_native;
struct bpf_object *__real_bpf_object__open_mem(const void *bytes, size_t size,
    const struct bpf_object_open_opts *options);
struct bpf_object *__wrap_bpf_object__open_mem(const void *bytes, size_t size,
    const struct bpf_object_open_opts *options) {
    opened_native = __real_bpf_object__open_mem(bytes, size, options);
    return opened_native;
}

int main(int argc, char **argv) {
#ifdef LMB_MAPS_RED_BASELINE
    if (!lmb_object_map_lookup_v1 || !lmb_object_map_update_v1) {
        fputs("FAIL missing implementation: lmb_object_map_lookup_v1 / lmb_object_map_update_v1\n", stderr);
        return 1;
    }
#endif
    if (argc == 2 && !strcmp(argv[1], "--guard-trap")) {
        union bpf_attr attr = {0};
        syscall(SYS_bpf, BPF_MAP_CREATE, &attr, (unsigned)sizeof(attr)); return 1;
    }
    if (argc == 2 && !strcmp(argv[1], "--guard-unknown")) {
        syscall(SYS_getppid); return 1;
    }
    if (argc == 2 && !strcmp(argv[1], "--guard-positive")) {
        CHECK(syscall(SYS_getpid) == getpid());
        int fd = (int)syscall(SYS_memfd_create, "guard-positive", 0U);
        CHECK(fd >= 0); if (fd >= 0) CHECK(close(fd) == 0);
        puts("guard positive: real non-BPF calls completed"); return failures ? 1 : 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--leak-control")) {
        void *memory = malloc(17);
        if (!memory) return 2;
        memset(memory, 0x17, 17); /* Intentionally unreachable at exit. */
        return 0;
    }
    if (argc != 2) { fputs("usage: generic_maps <fixture>\n", stderr); return 2; }
    guard_controls(argv[0]);
    FILE *file = fopen(argv[1], "rb");
    if (!file) { perror("fixture"); return 1; }
    CHECK(fseek(file, 0, SEEK_END) == 0);
    long length = ftell(file); CHECK(length > 0);
    rewind(file); uint8_t *elf = malloc((size_t)length); CHECK(elf != NULL);
    if (!elf || length <= 0) return 1;
    CHECK(fread(elf, 1, (size_t)length, file) == (size_t)length); CHECK(fclose(file) == 0);
    unsigned fds_before = fd_count();
    struct lmb_object *unloaded = open_fixture(elf, (size_t)length, 0);
    struct lmb_object *object = open_fixture(elf, (size_t)length, 1);
    struct bpf_object *parsed = opened_native;
    CHECK(bpf_map__type(bpf_object__find_map_by_name(parsed, "counter")) == BPF_MAP_TYPE_ARRAY);
    CHECK(bpf_map__type(bpf_object__find_map_by_name(parsed, "values")) == BPF_MAP_TYPE_HASH);
    CHECK(bpf_map__type(bpf_object__find_map_by_name(parsed, "percpu_values")) == BPF_MAP_TYPE_PERCPU_ARRAY);
    CHECK(bpf_map__type(bpf_object__find_map_by_name(parsed, "percpu_hash")) == BPF_MAP_TYPE_PERCPU_HASH);
    validation(object, unloaded);
    ordinary_maps(object);
    percpu_maps(object, parsed);
    geometry_failures(object, parsed);
    unsigned closes = native_closes;
    CHECK(lmb_object_close_v1(&object) == 0 && !object);
    CHECK(lmb_object_close_v1(&unloaded) == 0 && !unloaded);
    CHECK(native_closes == closes + 2 && fd_count() == fds_before);
    /* A failed load owner is still usable for rejection and teardown. */
    load_result = -EIO;
    object = open_fixture(elf, (size_t)length, 1);
    struct lmb_name_v1 name = name_of("counter");
    uint32_t key = 0; uint64_t value = 41, needed = 123;
    invalid_lookup(object, &name, (void *)&key, 4, (void *)&value, 8, &needed, -EINVAL, 1);
    invalid_update(object, &name, (void *)&key, 4, (void *)&value, 8, 0, -EINVAL);
    CHECK(lmb_object_close_v1(&object) == 0 && !object);
    CHECK(fd_count() == fds_before);
    free(elf);
    CHECK(!script.armed && online_queries == 0);
    printf("generic maps: %u checks, %u failures; %u scripted BPF requests, zero executed BPF calls\n",
           checks, failures, bpf_calls);
    return failures ? 1 : 0;
}
