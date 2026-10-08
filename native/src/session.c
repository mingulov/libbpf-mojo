/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/* Session ownership: open/load/close/detach/stats plus map access.
 * Map operations live here because maps are owned by the session's
 * loaded object. */
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "internal.h"

static int is_percpu(uint32_t type) {
    /* Every map type whose values transfer as a per-CPU spread must
     * be listed: missing one under-sizes caller buffers. */
    return type == BPF_MAP_TYPE_PERCPU_HASH ||
           type == BPF_MAP_TYPE_PERCPU_ARRAY ||
           type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
           type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE;
}

static uint32_t round8(uint32_t v) {
    return (v + 7u) & ~7u;
}

int32_t lmb_open(const uint8_t *elf, uint64_t elf_bytes,
                 const struct lmb_options_v1 *options,
                 struct lmb_session **out) {
    struct lmb_session *s;
    /* Diagnostics flow only through the sanitized thread-local
     * record. This silences the bridge's private static libbpf; the
     * call is idempotent and atomic. */
    libbpf_set_print(NULL);
    if (!out) {
        lmb_record(LMB_OP_OPEN, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_open: null out handle");
        return -EINVAL;
    }
    *out = NULL;
    if (!options ||
        !lmb_check_header(options->abi_version, options->struct_size,
                          sizeof(*options)) ||
        !lmb_check_bytes(&options->ring, LMB_MAX_NAME_BYTES, 1) ||
        options->max_raw_bytes == 0 ||
        options->max_raw_bytes > LMB_MAX_RAW_BYTES ||
        options->stage_slots != 1 || options->flags != 0 ||
        options->_reserved != 0) {
        lmb_record(LMB_OP_OPEN, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_open: invalid options");
        return -EINVAL;
    }
    if (!elf || elf_bytes == 0) {
        lmb_record(LMB_OP_OPEN, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_open: invalid ELF input");
        return -EINVAL;
    }
    s = calloc(1, sizeof(*s));
    if (!s) {
        lmb_record(LMB_OP_OPEN, LMB_DOMAIN_POSIX, -ENOMEM,
                   "lmb_open: out of memory");
        return -ENOMEM;
    }
    s->elf = malloc(elf_bytes);
    if (!s->elf) {
        free(s);
        lmb_record(LMB_OP_OPEN, LMB_DOMAIN_POSIX, -ENOMEM,
                   "lmb_open: out of memory");
        return -ENOMEM;
    }
    memcpy(s->elf, elf, elf_bytes);
    s->elf_len = elf_bytes;
    if (!lmb_copy_name(&options->ring, &s->ring_name)) {
        free(s->elf);
        free(s);
        lmb_record(LMB_OP_OPEN, LMB_DOMAIN_POSIX, -ENOMEM,
                   "lmb_open: out of memory");
        return -ENOMEM;
    }
    s->max_raw_bytes = options->max_raw_bytes;
    s->ring_fd = -1;
    *out = s;
    return 0;
}

int32_t lmb_load(struct lmb_session *session) {
    long err;
    struct bpf_map *map;
    if (!session) {
        lmb_record(LMB_OP_LOAD, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_load: null session");
        return -EINVAL;
    }
    if (session->loaded) {
        lmb_record(LMB_OP_LOAD, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_load: session already loaded");
        return -EINVAL;
    }
    session->obj = bpf_object__open_mem(session->elf, (size_t)session->elf_len,
                                        NULL);
    err = libbpf_get_error(session->obj);
    if (err) {
        session->obj = NULL;
        lmb_record(LMB_OP_LOAD, LMB_DOMAIN_LIBBPF, (int32_t)err,
                   "lmb_load: cannot open ELF object");
        session->last_native_error = (int32_t)err;
        return (int32_t)err;
    }
    /* Never honor map pin metadata: the bridge owns its maps
     * privately and must leave no filesystem pins behind, on
     * success or on any later failure. Clearing before loading
     * disables both auto-pinning and pinned-map reuse. */
    map = NULL;
    while ((map = bpf_object__next_map(session->obj, map)) != NULL)
        bpf_map__set_pin_path(map, NULL);
    err = bpf_object__load(session->obj);
    if (err) {
        bpf_object__close(session->obj);
        session->obj = NULL;
        lmb_record(LMB_OP_LOAD, LMB_DOMAIN_LIBBPF, (int32_t)err,
                   "lmb_load: object load failed");
        session->last_native_error = (int32_t)err;
        return (int32_t)err;
    }
    map = bpf_object__find_map_by_name(session->obj, session->ring_name);
    if (!map) {
        bpf_object__close(session->obj);
        session->obj = NULL;
        lmb_record(LMB_OP_LOAD, LMB_DOMAIN_BRIDGE, -ENOENT,
                   "lmb_load: ring map not found in object");
        return -ENOENT;
    }
    session->ring_fd = bpf_map__fd(map);
    session->rb = ring_buffer__new(session->ring_fd, lmb_ring_sample,
                                   session, NULL);
    if (!session->rb) {
        int code = errno ? -errno : -EIO;
        bpf_object__close(session->obj);
        session->obj = NULL;
        session->ring_fd = -1;
        lmb_record(LMB_OP_LOAD, LMB_DOMAIN_LIBBPF, (int32_t)code,
                   "lmb_load: cannot consume ring map");
        session->last_native_error = (int32_t)code;
        return (int32_t)code;
    }
    session->loaded = 1;
    return 0;
}

int32_t lmb_stats(struct lmb_session *session, struct lmb_stats_v1 *out) {
    if (!out || !lmb_check_header(out->abi_version, out->struct_size,
                                  sizeof(*out)))
        return -EINVAL;
    if (!session) {
        lmb_record(LMB_OP_STATS, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_stats: null session");
        return -EINVAL;
    }
    out->received = session->received;
    out->delivered = session->delivered;
    out->staged = session->stage_len ? 1 : 0;
    out->malformed = session->malformed;
    out->dropped = session->dropped;
    out->last_error = session->last_native_error;
    out->_reserved = 0;
    return 0;
}

int32_t lmb_detach(struct lmb_session *session) {
    uint32_t i;
    int32_t first = 0;
    if (!session) {
        lmb_record(LMB_OP_DETACH, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_detach: null session");
        return -EINVAL;
    }
    /* Destroy every link exactly once, then report the first
     * teardown error, if any. Ownership state clears regardless. */
    for (i = 0; i < session->nlinks; i++) {
        int err = bpf_link__destroy(session->links[i]);
        if (err && !first)
            first = (int32_t)err;
    }
    free(session->links);
    session->links = NULL;
    session->nlinks = 0;
    session->link_cap = 0;
    session->attached = 0;
    if (first) {
        lmb_record(LMB_OP_DETACH, LMB_DOMAIN_LIBBPF, first,
                   "lmb_detach: link teardown failed");
        session->last_native_error = first;
        return first;
    }
    return 0;
}

int32_t lmb_close(struct lmb_session **session) {
    struct lmb_session *s;
    int32_t derr;
    if (!session || !*session)
        return 0;
    s = *session;
    derr = lmb_detach(s);
    if (s->rb)
        ring_buffer__free(s->rb);
    if (s->obj)
        bpf_object__close(s->obj);
    free(s->ring_name);
    free(s->elf);
    free(s);
    *session = NULL;
    if (derr) {
        lmb_record(LMB_OP_CLOSE, LMB_DOMAIN_LIBBPF, derr,
                   "lmb_close: teardown failed");
        return derr;
    }
    return 0;
}

static struct bpf_map *find_map(struct lmb_session *s,
                                const struct lmb_name_v1 *name,
                                uint32_t op, int32_t *code) {
    char *text = NULL;
    struct bpf_map *map;
    if (!name) {
        lmb_record(op, LMB_DOMAIN_BRIDGE, -EINVAL, "map: null name");
        *code = -EINVAL;
        return NULL;
    }
    if (!lmb_check_header(name->abi_version, name->struct_size,
                          sizeof(*name)) ||
        !lmb_check_bytes(&name->name, LMB_MAX_NAME_BYTES, 1)) {
        lmb_record(op, LMB_DOMAIN_BRIDGE, -EINVAL, "map: invalid name");
        *code = -EINVAL;
        return NULL;
    }
    if (!lmb_copy_name(&name->name, &text)) {
        lmb_record(op, LMB_DOMAIN_POSIX, -ENOMEM, "map: out of memory");
        s->last_native_error = -ENOMEM;
        *code = -ENOMEM;
        return NULL;
    }
    map = bpf_object__find_map_by_name(s->obj, text);
    free(text);
    if (!map) {
        lmb_record(op, LMB_DOMAIN_BRIDGE, -ENOENT, "map: not found");
        *code = -ENOENT;
        return NULL;
    }
    *code = 0;
    return map;
}

static int need_loaded(struct lmb_session *s, uint32_t op, const char *what) {
    if (!s) {
        lmb_record(op, LMB_DOMAIN_BRIDGE, -EINVAL, "null session");
        return 0;
    }
    if (!s->loaded) {
        char msg[64];
        snprintf(msg, sizeof(msg), "%s: session not loaded", what);
        lmb_record(op, LMB_DOMAIN_BRIDGE, -EINVAL, msg);
        return 0;
    }
    return 1;
}

int32_t lmb_map_info(struct lmb_session *session,
                     const struct lmb_name_v1 *name,
                     struct lmb_map_info_v1 *out) {
    struct bpf_map *map;
    int32_t fcode;
    int ncpus;
    if (!out || !lmb_check_header(out->abi_version, out->struct_size,
                                  sizeof(*out)))
        return -EINVAL;
    if (!need_loaded(session, LMB_OP_MAP_INFO, "lmb_map_info"))
        return -EINVAL;
    map = find_map(session, name, LMB_OP_MAP_INFO, &fcode);
    if (!map)
        return fcode;
    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) {
        int32_t code = ncpus < 0 ? (int32_t)ncpus : -EIO;
        lmb_record(LMB_OP_MAP_INFO, LMB_DOMAIN_LIBBPF, code,
                   "lmb_map_info: cannot count CPUs");
        session->last_native_error = code;
        return code;
    }
    out->type = (uint32_t)bpf_map__type(map);
    out->key_size = bpf_map__key_size(map);
    out->value_size = bpf_map__value_size(map);
    out->max_entries = bpf_map__max_entries(map);
    out->map_flags = bpf_map__map_flags(map);
    out->num_cpus = (uint32_t)ncpus;
    out->stride = is_percpu(out->type) ? round8(out->value_size) : 0;
    out->_reserved = 0;
    return 0;
}

/* Required value bytes for one access: the single value, or the full
 * per-CPU spread. Returns 0 with *need set, -EOVERFLOW when the
 * spread cannot fit u32 (bridge capacity rule), or the propagated
 * possible-CPU query failure. The two failures stay distinct. */
static int32_t spread_need(const struct bpf_map *map, uint32_t *need) {
    uint32_t type = (uint32_t)bpf_map__type(map);
    uint32_t value = bpf_map__value_size(map);
    int ncpus;
    uint64_t total;
    if (!is_percpu(type)) {
        *need = value;
        return 0;
    }
    if (value > UINT32_MAX - 7u)
        return -EOVERFLOW;
    ncpus = libbpf_num_possible_cpus();
    if (ncpus < 0)
        return (int32_t)ncpus;
    if (ncpus == 0)
        return -EIO;
    total = (uint64_t)round8(value) * (uint64_t)ncpus;
    if (total > UINT32_MAX)
        return -EOVERFLOW;
    *need = (uint32_t)total;
    return 0;
}

static int32_t spread_fail(struct lmb_session *s, uint32_t op,
                           int32_t code, const char *what) {
    char msg[96];
    if (code == -EOVERFLOW) {
        snprintf(msg, sizeof(msg), "%s: value spread does not fit", what);
        lmb_record(op, LMB_DOMAIN_BRIDGE, code, msg);
        return code;
    }
    snprintf(msg, sizeof(msg), "%s: cannot query CPU count", what);
    lmb_record(op, LMB_DOMAIN_LIBBPF, code, msg);
    s->last_native_error = code;
    return code;
}

int32_t lmb_map_read(struct lmb_session *session,
                     const struct lmb_name_v1 *name, const uint8_t *key,
                     uint32_t key_bytes, uint8_t *dst, uint32_t capacity,
                     uint32_t *required) {
    struct bpf_map *map;
    uint32_t need;
    int32_t spread_rc;
    int rc;
    if (!required || (!dst && capacity > 0)) {
        lmb_record(LMB_OP_MAP_READ, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_map_read: invalid destination");
        return -EINVAL;
    }
    if (lmb_ranges_overlap(required, sizeof(*required), key, key_bytes) ||
        lmb_ranges_overlap(required, sizeof(*required), dst, capacity)) {
        lmb_record(LMB_OP_MAP_READ, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_map_read: output aliases input");
        return -EINVAL;
    }
    if (!need_loaded(session, LMB_OP_MAP_READ, "lmb_map_read"))
        return -EINVAL;
    map = find_map(session, name, LMB_OP_MAP_READ, &spread_rc);
    if (!map)
        return spread_rc;
    if (!key || key_bytes != (uint32_t)bpf_map__key_size(map)) {
        lmb_record(LMB_OP_MAP_READ, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_map_read: key size mismatch");
        return -EINVAL;
    }
    /* Arguments validated: other failures report required as 0. */
    *required = 0;
    spread_rc = spread_need(map, &need);
    if (spread_rc)
        return spread_fail(session, LMB_OP_MAP_READ, spread_rc,
                           "lmb_map_read");
    if (capacity < need) {
        *required = need;
        lmb_record(LMB_OP_MAP_READ, LMB_DOMAIN_BRIDGE, -ENOSPC,
                   "lmb_map_read: destination too short");
        return -ENOSPC;
    }
    rc = bpf_map_lookup_elem(bpf_map__fd(map), key, dst);
    if (rc) {
        lmb_record(LMB_OP_MAP_READ, LMB_DOMAIN_KERNEL, (int32_t)rc,
                   "lmb_map_read: kernel lookup failed");
        session->last_native_error = (int32_t)rc;
        return (int32_t)rc;
    }
    return 0;
}

int32_t lmb_map_write(struct lmb_session *session,
                      const struct lmb_name_v1 *name, const uint8_t *key,
                      uint32_t key_bytes, const uint8_t *value,
                      uint32_t value_bytes) {
    struct bpf_map *map;
    uint32_t need;
    int32_t spread_rc;
    int rc;
    if (!need_loaded(session, LMB_OP_MAP_WRITE, "lmb_map_write"))
        return -EINVAL;
    map = find_map(session, name, LMB_OP_MAP_WRITE, &spread_rc);
    if (!map)
        return spread_rc;
    if (!key || key_bytes != bpf_map__key_size(map) || !value) {
        lmb_record(LMB_OP_MAP_WRITE, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_map_write: key size mismatch");
        return -EINVAL;
    }
    spread_rc = spread_need(map, &need);
    if (spread_rc)
        return spread_fail(session, LMB_OP_MAP_WRITE, spread_rc,
                           "lmb_map_write");
    if (value_bytes != need) {
        lmb_record(LMB_OP_MAP_WRITE, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_map_write: value size mismatch");
        return -EINVAL;
    }
    rc = bpf_map_update_elem(bpf_map__fd(map), key, value, BPF_ANY);
    if (rc) {
        lmb_record(LMB_OP_MAP_WRITE, LMB_DOMAIN_KERNEL, (int32_t)rc,
                   "lmb_map_write: kernel update failed");
        session->last_native_error = (int32_t)rc;
        return (int32_t)rc;
    }
    return 0;
}
