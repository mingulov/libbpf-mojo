/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
#include <errno.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "generic_internal.h"

static int32_t fail(uint32_t op, uint32_t domain, int32_t code,
                    const char *message) {
    lmb_generic_record(op, domain, code, message);
    return code;
}

static struct bpf_map *find_map(struct lmb_object *object,
                                const struct lmb_name_v1 *name) {
    char text[257];
    memcpy(text, name->name.ptr, name->name.len);
    text[name->name.len] = 0;
    return bpf_object__find_map_by_name(object->obj, text);
}

/* Read each geometry field once. Per-CPU slots use possible CPUs, including
 * offline CPUs, and retain the ABI's u32 bound on the complete spread. */
static int32_t map_extent(const struct bpf_map *map, uint64_t key_bytes,
                          uint64_t *extent, uint32_t *domain) {
    uint32_t key_size = bpf_map__key_size(map);
    uint32_t value_size = bpf_map__value_size(map);
    enum bpf_map_type type = bpf_map__type(map);
    *domain = LMB_GENERIC_DOMAIN_BRIDGE;
    if (key_bytes != key_size) return -EINVAL;
    int percpu = type == BPF_MAP_TYPE_PERCPU_HASH || type == BPF_MAP_TYPE_PERCPU_ARRAY ||
        type == BPF_MAP_TYPE_LRU_PERCPU_HASH || type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE;
    if (!percpu) { *extent = value_size; return 0; }
    if (value_size > UINT32_MAX - 7u) return -EOVERFLOW;
    uint32_t stride = (value_size + 7u) & ~7u;
    int cpus = libbpf_num_possible_cpus();
    if (cpus <= 0) {
        *domain = LMB_GENERIC_DOMAIN_LIBBPF;
        return cpus < 0 ? cpus : -EIO;
    }
    if (stride && (uint32_t)cpus > UINT32_MAX / stride) return -EOVERFLOW;
    *extent = (uint64_t)stride * (uint32_t)cpus;
    if (*extent > SIZE_MAX) return -EOVERFLOW;
    return 0;
}

int32_t lmb_object_map_lookup_v1(struct lmb_object *object,
    const struct lmb_name_v1 *name, const uint8_t *key, uint64_t key_bytes,
    uint8_t *value, uint64_t capacity, uint64_t *needed) {
    const uint32_t op = LMB_GENERIC_OP_MAP_LOOKUP;
    uint64_t extent;
    uint32_t domain;
    int32_t code;
    struct bpf_map *map;
    uint8_t *scratch;
    if (!needed || !lmb_generic_check_span(needed, sizeof(*needed)) || !name)
        return fail(op, 4, -EINVAL, "invalid map lookup arguments");
    if (!lmb_generic_check_name(name) || !lmb_generic_check_span(key, key_bytes) ||
        !lmb_generic_check_span(value, capacity))
        return fail(op, 4, -EINVAL, "invalid map lookup span or name");
    if (lmb_generic_ranges_overlap(needed, sizeof(*needed), key, key_bytes) ||
        lmb_generic_ranges_overlap(needed, sizeof(*needed), value, capacity))
        return fail(op, 4, -EINVAL, "size output aliases map storage");
    if (!lmb_object_need_loaded(object, op)) return -EINVAL;
    map = find_map(object, name);
    if (!map) {
        *needed = 0;
        return fail(op, 4, -ENOENT, "map not found");
    }
    /* A bloom value is membership input, not an output value: refuse
     * before extent math, allocation, or the native call. Insertion
     * keeps its input-value contract on the update path. */
    if (bpf_map__type(map) == BPF_MAP_TYPE_BLOOM_FILTER) {
        *needed = 0;
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EOPNOTSUPP,
                    "bloom lookup needs membership input");
    }
    code = map_extent(map, key_bytes, &extent, &domain);
    if (code) {
        if (domain == LMB_GENERIC_DOMAIN_LIBBPF) *needed = 0;
        return fail(op, domain, code, "cannot determine map extent");
    }
    if (capacity < extent) {
        *needed = extent;
        return fail(op, 4, -ENOSPC, "map destination is too short");
    }
    *needed = 0;
    scratch = malloc((size_t)extent);
    if (!scratch) return fail(op, 1, -ENOMEM, "allocation failed");
    code = bpf_map_lookup_elem(bpf_map__fd(map), key_bytes ? key : NULL, scratch);
    if (!code && extent) memcpy(value, scratch, (size_t)extent);
    free(scratch);
    if (code) return fail(op, 3, code, "map lookup failed");
    lmb_generic_clear();
    return 0;
}

int32_t lmb_object_map_update_v1(struct lmb_object *object,
    const struct lmb_name_v1 *name, const uint8_t *key, uint64_t key_bytes,
    const uint8_t *value, uint64_t value_bytes, uint64_t flags) {
    const uint32_t op = LMB_GENERIC_OP_MAP_UPDATE;
    uint64_t extent;
    uint32_t domain;
    int32_t code;
    struct bpf_map *map;
    if (!name) return fail(op, 4, -EINVAL, "invalid map update arguments");
    if (!lmb_generic_check_name(name) || !lmb_generic_check_span(key, key_bytes) ||
        !lmb_generic_check_span(value, value_bytes))
        return fail(op, 4, -EINVAL, "invalid map update span or name");
    if ((flags & ~UINT64_C(7)) || (flags & UINT64_C(3)) == 3)
        return fail(op, 4, -EINVAL, "unsupported map update flags");
    if (!lmb_object_need_loaded(object, op)) return -EINVAL;
    map = find_map(object, name);
    if (!map) return fail(op, 4, -ENOENT, "map not found");
    code = map_extent(map, key_bytes, &extent, &domain);
    if (code) return fail(op, domain, code, "cannot determine map extent");
    if (value_bytes != extent)
        return fail(op, 4, -EINVAL, "map value has the wrong extent");
    code = bpf_map_update_elem(bpf_map__fd(map), key_bytes ? key : NULL,
                               value_bytes ? value : NULL, flags);
    if (code) return fail(op, 3, code, "map update failed");
    lmb_generic_clear();
    return 0;
}
