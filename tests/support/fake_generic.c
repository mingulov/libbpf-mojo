/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Host FFI control: real bridge/parsing and pinned syscall adapters.
 * No program executes. These scenarios are byte/error oracles only.
 * Scalar control ABI: reset()->void, scenario(u32)->void,
 * call_count(u32 operation)->u64, close_count()->u64.
 * Scenarios: 0 default; 1 lookup ENOENT; 2 update EIO;
 * 3 test ENOSPC; 4 test EINTR; 5 test oversized success;
 * 6 omitted outputs (packet37/context0); 7 empty inputs/outputs;
 * 9 high u32 key; 99 deliberate unscripted BPF trap.
 * Scenarios 10-20 add key/error/ABI controls; 18/19 count key entries.
 * Operation0 counts scripted syscalls; 7/8/9 count public entries. */
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "libbpf_mojo_generic.h"

static uint32_t selected, active;
static uint64_t calls[20], closes;
static unsigned char values[4][48];

static void require(int condition, const char *what) {
    if (!condition) {
        fprintf(stderr, "generic testfake oracle mismatch: %s\n", what);
        _exit(97);
    }
}

void lmb_test_generic_reset(void) {
    selected = active = 0; closes = 0;
    memset(calls, 0, sizeof(calls));
    memset(values, 0, sizeof(values));
    uint64_t scalar = UINT64_C(0xfedcba9876543210);
    memcpy(values[0], &scalar, sizeof(scalar));
    memcpy(values[1], &scalar, sizeof(scalar));
    for (unsigned map = 2; map < 4; map++)
        for (unsigned cpu = 0; cpu < 3; cpu++)
            for (unsigned byte = 0; byte < 16; byte++)
                values[map][cpu * 16 + byte] = byte < 13 ?
                    (unsigned char)(0x21 + cpu * 17 + byte) :
                    (unsigned char)(0xe0 + cpu * 3 + byte - 13);
}

void lmb_test_generic_scenario(uint32_t number) {
    if (number == 99) {
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        syscall(SYS_bpf, BPF_PROG_LOAD, &attr, (unsigned int)sizeof(attr));
        _exit(95);
    }
    require(number <= 20 && number != 8, "known scenario ID");
    selected = number;
}

uint64_t lmb_test_generic_call_count(uint32_t operation) {
    require(operation < 20, "known operation ID");
    return calls[operation];
}
uint64_t lmb_test_generic_close_count(void) { return closes; }

int __wrap_bpf_object__load(struct bpf_object *object) {
    require(object != NULL, "real parsed object at aggregate load");
    return 0;
}
int __wrap_libbpf_num_possible_cpus(void) { return 3; }
int __real_bpf_map__fd(const struct bpf_map *map);
int __wrap_bpf_map__fd(const struct bpf_map *map) {
    static const char *const names[] = {"counter", "values", "percpu_values", "percpu_hash"};
    require(map != NULL && __real_bpf_map__fd(map) == -1, "no installed map FD");
    for (unsigned i = 0; i < 4; i++)
        if (!strcmp(bpf_map__name(map), names[i])) return (int)(6001 + i);
    require(0, "known real map name");
    return -1;
}
int __real_bpf_program__fd(const struct bpf_program *program);
int __wrap_bpf_program__fd(const struct bpf_program *program) {
    require(program != NULL && __real_bpf_program__fd(program) == -ENOENT,
            "no installed program FD");
    require(!strcmp(bpf_program__name(program), "packet_control"), "real XDP program name");
    return 7001;
}
void __real_bpf_object__close(struct bpf_object *object);
void __wrap_bpf_object__close(struct bpf_object *object) {
    if (object) {
        struct bpf_map *map;
        struct bpf_program *program;
        bpf_object__for_each_map(map, object)
            require(__real_bpf_map__fd(map) == -1, "map synthetic FD never installed");
        bpf_object__for_each_program(program, object)
            require(__real_bpf_program__fd(program) == -ENOENT, "program synthetic FD never installed");
        closes++;
    }
    __real_bpf_object__close(object);
}

int32_t lmb_test_real_map_lookup(struct lmb_object *, const struct lmb_name_v1 *,
    const uint8_t *, uint64_t, uint8_t *, uint64_t, uint64_t *);
int32_t lmb_test_real_map_update(struct lmb_object *, const struct lmb_name_v1 *,
    const uint8_t *, uint64_t, const uint8_t *, uint64_t, uint64_t);
int32_t lmb_test_real_program_test(struct lmb_object *, const struct lmb_name_v1 *,
    const struct lmb_program_test_options_v1 *, struct lmb_program_test_result_v1 *);

int32_t lmb_object_map_lookup_v1(struct lmb_object *object, const struct lmb_name_v1 *name,
    const uint8_t *key, uint64_t key_bytes, uint8_t *value, uint64_t capacity, uint64_t *needed) {
    calls[7]++; active = 7;
    int32_t rc = lmb_test_real_map_lookup(object, name, key, key_bytes, value, capacity, needed);
    active = 0; errno = ENOTTY;
    return rc;
}
int32_t lmb_object_map_update_v1(struct lmb_object *object, const struct lmb_name_v1 *name,
    const uint8_t *key, uint64_t key_bytes, const uint8_t *value, uint64_t value_bytes, uint64_t flags) {
    calls[8]++; active = 8;
    int32_t rc = lmb_test_real_map_update(object, name, key, key_bytes, value, value_bytes, flags);
    active = 0; errno = ENOTTY;
    return rc;
}
int32_t lmb_program_test_run_v1(struct lmb_object *object, const struct lmb_name_v1 *name,
    const struct lmb_program_test_options_v1 *options, struct lmb_program_test_result_v1 *result) {
    calls[9]++; active = 9;
    int32_t rc = lmb_test_real_program_test(object, name, options, result);
    active = 0; errno = ENOTTY;
    return rc;
}

/* Scenarios 10-20 extend the existing fixed host matrix without changing 0-9. */
void lmb_generic_record(uint32_t, uint32_t, int32_t, const char *);
int32_t lmb_test_real_map_delete(struct lmb_object *, const struct lmb_name_v1 *,
    const uint8_t *, uint64_t, uint64_t);
int32_t lmb_test_real_map_next_key(struct lmb_object *, const struct lmb_name_v1 *,
    uint32_t, const uint8_t *, uint64_t, uint8_t *, uint64_t, uint64_t *);
int32_t lmb_object_map_delete_v1(struct lmb_object *object, const struct lmb_name_v1 *name,
    const uint8_t *key, uint64_t key_bytes, uint64_t flags) {
    calls[18]++; active = 18;
    int32_t rc = lmb_test_real_map_delete(object, name, key, key_bytes, flags);
    active = 0; errno = ENOTTY;
    return rc;
}
int32_t lmb_object_map_next_key_v1(struct lmb_object *object, const struct lmb_name_v1 *name,
    uint32_t has_current, const uint8_t *current, uint64_t current_bytes,
    uint8_t *next, uint64_t capacity, uint64_t *needed) {
    calls[19]++; active = 19;
    int32_t rc = lmb_test_real_map_next_key(object, name, has_current, current, current_bytes, next, capacity, needed);
    if (rc == -ENOENT) {
        if (selected == 14) lmb_generic_record(18, 3, rc, "wrong operation");
        if (selected == 15) lmb_generic_record(19, 4, rc, "bridge missing map");
        if (selected == 16) lmb_generic_record(19, 3, -EIO, "wrong code");
        if (selected == 17) lmb_generic_record(0, 0, 0, "stale diagnostic");
    }
    active = 0; errno = ENOTTY;
    return rc;
}

long lmb_test_bpf_dispatch(int command, void *raw, unsigned int size) {
    union bpf_attr *attr = raw;
    if (!attr || !active ||
        !((command == BPF_MAP_LOOKUP_ELEM && active == 7) ||
          (command == BPF_MAP_UPDATE_ELEM && active == 8) ||
          (command == BPF_PROG_TEST_RUN && active == 9) ||
          (command == BPF_MAP_DELETE_ELEM && active == 18) ||
          (command == BPF_MAP_GET_NEXT_KEY && active == 19))) {
        fputs("HOST GUARD: generic testfake stopped unscripted BPF before execution\n", stderr);
        _exit(99);
    }
    calls[0]++;
    if (command == BPF_MAP_DELETE_ELEM || command == BPF_MAP_GET_NEXT_KEY) {
        require(attr->map_fd == 6001 || attr->map_fd == 6002, "ordinary keyed map FD");
        uint32_t key = 0;
        if (attr->key) memcpy(&key, (const void *)(uintptr_t)attr->key, sizeof(key));
        if (command == BPF_MAP_DELETE_ELEM) {
            require(size == offsetof(union bpf_attr, flags) + sizeof(attr->flags), "delete attr size");
            if (selected == 20) require(key == UINT32_C(0x89abcdef) && attr->flags == UINT64_C(0x80000000ffffffff), "full key and u64 flag sentinel");
            else require(attr->flags == 0, "zero default delete flags");
            if (selected == 11 || selected == 18 || selected == 19) { errno = selected == 11 ? ENOENT : selected == 18 ? 4093 : EPERM; return -1; }
            return 0;
        }
        require(size == offsetof(union bpf_attr, next_key) + sizeof(attr->next_key), "next-key attr size");
        require(attr->next_key != 0, "owned next key scratch");
        uint32_t next = attr->key ? UINT32_C(0xffffffff) : UINT32_C(0x80000000);
        memcpy((void *)(uintptr_t)attr->next_key, &next, sizeof(next));
        if ((selected >= 10 && selected <= 17) || key == UINT32_C(0xffffffff)) {
            errno = selected == 12 ? EPERM : selected == 13 ? 4093 : ENOENT;
            return -1;
        }
        return 0;
    }
    if (command == BPF_MAP_LOOKUP_ELEM || command == BPF_MAP_UPDATE_ELEM) {
        require(size == offsetof(union bpf_attr, flags) + sizeof(attr->flags), "map attr size");
        require(attr->map_fd >= 6001 && attr->map_fd <= 6004, "synthetic map FD");
        unsigned map = attr->map_fd - 6001;
        size_t extent = map < 2 ? 8 : 48;
        uint32_t key;
        require(attr->key != 0 && attr->value != 0, "map byte pointers");
        memcpy(&key, (const void *)(uintptr_t)attr->key, sizeof(key));
        if (selected == 9) require(key == UINT32_C(0x89abcdef), "full native-endian u32 key");
        unsigned char *value = (void *)(uintptr_t)attr->value;
        if (command == BPF_MAP_LOOKUP_ELEM) {
            if (selected == 1 || (key && selected != 9)) {
                memset(value, 0xd7, extent); errno = ENOENT; return -1;
            }
            memcpy(value, values[map], extent);
        } else {
            require(attr->flags == 0 || attr->flags == 1 || attr->flags == 2 ||
                    attr->flags == 4 || attr->flags == 5 || attr->flags == 6, "exact permitted update flag");
            if (selected == 2) { errno = EIO; return -1; }
            memcpy(values[map], value, extent);
        }
        return 0;
    }
    require(size == offsetof(union bpf_attr, test) + sizeof(attr->test), "test attr size");
    require(attr->test.prog_fd == 7001, "synthetic program FD");
    require(attr->test.repeat == 1 || attr->test.repeat == 2, "exact repeat");
    require(attr->test.flags == 0 && attr->test.cpu == 0 && attr->test.batch_size == 0,
            "test zero flags/cpu/batch");
    require(attr->test.retval == 0 && attr->test.duration == 0, "test result fields initially zero");
    uint8_t *data = (void *)(uintptr_t)attr->test.data_out;
    uint8_t *ctx = (void *)(uintptr_t)attr->test.ctx_out;
    const uint8_t *data_in = (const void *)(uintptr_t)attr->test.data_in;
    const uint8_t *ctx_in = (const void *)(uintptr_t)attr->test.ctx_in;
    if (selected == 7) {
        require(attr->test.data_size_in == 0 && attr->test.ctx_size_in == 0 &&
                attr->test.data_size_out == 0 && attr->test.ctx_size_out == 0,
                "four empty lengths");
        require(!data && !ctx && !data_in && !ctx_in, "four omitted native pointers");
    } else {
        require(attr->test.data_size_in == 61 && attr->test.ctx_size_in == 24,
                "independent input lengths");
        require(data_in && ctx_in, "snapshot input pointers");
        for (unsigned i = 0; i < 61; i++) require(data_in[i] == (uint8_t)(i * 3 + 7), "packet snapshot bytes");
        for (unsigned i = 0; i < 24; i++) require(ctx_in[i] == (uint8_t)(0xc0 - i), "context snapshot bytes");
        if (selected == 6) {
            require(attr->test.data_size_out == 0 && attr->test.ctx_size_out == 0 && !data && !ctx,
                    "independently omitted outputs");
        } else {
            require(attr->test.data_size_out == 97 && attr->test.ctx_size_out == 40 && data && ctx,
                    "independent output capacities");
            require(data != data_in && ctx != ctx_in, "separate native output scratch");
            for (unsigned i = 0; i < 37; i++) data[i] = (uint8_t)(0x5b + i * 3);
            for (unsigned i = 0; i < 16; i++) ctx[i] = (uint8_t)(0x9d - i * 7);
        }
    }
    attr->test.data_size_out = selected == 5 ? 98 : selected == 7 ? 11 : 37;
    attr->test.ctx_size_out = selected == 6 || selected == 7 ? 0 : 16;
    attr->test.retval = 2; attr->test.duration = 123;
    if (selected == 3 || selected == 4) {
        errno = selected == 3 ? ENOSPC : EINTR;
        return -1;
    }
    return 0;
}
