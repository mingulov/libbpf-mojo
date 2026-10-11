/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/* Generic ABI contract probe: executable acceptance battery for
 * docs/generic-abi-v1.md. Uses only the public headers plus dlsym,
 * so this binary links before the generic implementation lands.
 *
 * Usage: probe <lib.so> [fixture.bpf.o]
 * Part A always runs: C layout smoke, v1 presence, hidden upstream
 * symbols, generic presence report. Part B (behavior battery)
 * runs only when all twenty generic symbols resolve; otherwise it
 * reports SKIP, never PASS. Live sections additionally need the
 * fixture and collection privilege; without them they SKIP.
 * LMB_GENERIC_LIB overrides the Part B dlopen path (differential
 * exercise against another build); LMB_TEST_RUN_PROGRAM overrides
 * the test-run program name (default on_getpid, the only program
 * with a pinned expected retval). LMB_ASSUME_PRIVILEGE=1 bypasses
 * the privilege gate for differential stub exercise with
 * LMB_GENERIC_LIB only; standard runs must not set it.
 */
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "libbpf_mojo.h"
#include "libbpf_mojo_generic.h"

/* The frozen contract names -ESTALE for stale views; the value is
 * part of the contract on this platform. */
_Static_assert(ESTALE == 116, "stale views must report ESTALE 116");

static int oks = 0;
static int skips = 0;
static int failures = 0;

#define OK(name)                                   \
    do {                                           \
        printf("ok %s\n", (name));                 \
        oks++;                                     \
    } while (0)
#define FAIL(name, ...)                            \
    do {                                           \
        printf("FAIL %s: ", (name));               \
        printf(__VA_ARGS__);                       \
        printf("\n");                              \
        failures++;                                \
    } while (0)
#define CHECK(cond, name, ...)                     \
    do {                                           \
        if (cond)                                  \
            OK(name);                              \
        else                                       \
            FAIL(name, __VA_ARGS__);               \
    } while (0)
#define SKIP(name, reason)                         \
    do {                                           \
        printf("SKIP %s: %s\n", (name), (reason)); \
        skips++;                                   \
    } while (0)

typedef int32_t (*fn_open)(const uint8_t *, uint64_t,
                           const struct lmb_object_options_v1 *,
                           struct lmb_object **);
typedef int32_t (*fn_config)(
    struct lmb_object *, const struct lmb_program_options_v1 *);
typedef int32_t (*fn_load)(struct lmb_object *);
typedef int32_t (*fn_pinfo)(struct lmb_object *,
                            const struct lmb_name_v1 *,
                            struct lmb_program_info_v1 *);
typedef int32_t (*fn_minfo)(struct lmb_object *,
                            const struct lmb_name_v1 *,
                            struct lmb_map_info_v1 *);
typedef int32_t (*fn_close)(struct lmb_object **);
typedef void (*fn_release)(struct lmb_object **);
typedef int32_t (*fn_lasterr)(struct lmb_generic_error_v1 *);
typedef int32_t (*fn_lookup)(struct lmb_object *,
                             const struct lmb_name_v1 *,
                             const uint8_t *, uint64_t, uint8_t *,
                             uint64_t, uint64_t *);
typedef int32_t (*fn_update)(struct lmb_object *,
                             const struct lmb_name_v1 *,
                             const uint8_t *, uint64_t, const uint8_t *,
                             uint64_t, uint64_t);
typedef int32_t (*fn_testrun)(
    struct lmb_object *, const struct lmb_name_v1 *,
    const struct lmb_program_test_options_v1 *,
    struct lmb_program_test_result_v1 *);
typedef int32_t (*fn_attach)(struct lmb_object *,
                             const struct lmb_attach_options_v1 *,
                             struct lmb_link **);
typedef int32_t (*fn_linkclose)(struct lmb_link **);
typedef int32_t (*fn_bufopen)(struct lmb_object *,
                              const struct lmb_buffer_options_v1 *,
                              struct lmb_buffer **);
typedef int32_t (*fn_bufpoll)(struct lmb_buffer *, uint8_t *, uint64_t,
                              int32_t, uint64_t *, uint64_t *);
typedef int32_t (*fn_bufclose)(struct lmb_buffer **);
typedef int32_t (*fn_ref)(struct lmb_object *);
typedef void (*fn_unref)(struct lmb_object *);
typedef int32_t (*fn_gen)(const struct lmb_object *, uint64_t *);
typedef int32_t (*fn_gencheck)(const struct lmb_object *, uint64_t);

typedef int32_t (*fn_v1open)(const uint8_t *, uint64_t,
                            const struct lmb_options_v1 *,
                            struct lmb_session **);
typedef int32_t (*fn_v1lasterr)(struct lmb_error_v1 *);

struct v1_api {
    fn_v1open open;
    fn_v1lasterr lasterr;
};

struct gen_api {
    fn_open open;
    fn_config config;
    fn_load load;
    fn_pinfo pinfo;
    fn_minfo minfo;
    fn_close close;
    fn_release release;
    fn_lasterr lasterr;
    fn_lookup lookup;
    fn_update update;
    fn_testrun testrun;
    fn_attach attach;
    fn_linkclose linkclose;
    fn_bufopen bufopen;
    fn_bufpoll bufpoll;
    fn_bufclose bufclose;
    fn_ref ref;
    fn_unref unref;
    fn_gen gen;
    fn_gencheck gencheck;
};

static const char *gen_names[20] = {
    "lmb_object_open_v1",           "lmb_object_configure_program_v1",
    "lmb_object_load_v1",           "lmb_object_program_info_v1",
    "lmb_object_map_info_v1",       "lmb_object_close_v1",
    "lmb_object_release_v1",        "lmb_generic_last_error_v1",
    "lmb_object_map_lookup_v1",     "lmb_object_map_update_v1",
    "lmb_program_test_run_v1",      "lmb_object_attach_v1",
    "lmb_link_close_v1",            "lmb_buffer_open_v1",
    "lmb_buffer_poll_v1",           "lmb_buffer_close_v1",
    "lmb_object_ref_v1",            "lmb_object_unref_v1",
    "lmb_object_gen_v1",            "lmb_object_gen_check_v1",
};

static const char *v1_names[11] = {
    "lmb_open",      "lmb_load",      "lmb_attach",   "lmb_poll",
    "lmb_map_info",  "lmb_map_read",  "lmb_map_write", "lmb_stats",
    "lmb_last_error", "lmb_detach",   "lmb_close",
};

/* Upstream entry points the bridge calls internally. None may be
 * resolvable from the candidate library: dlsym("bpf_...") must not
 * expose the hidden bundled instance. */
static const char *hidden_names[8] = {
    "bpf_object__open_mem",       "bpf_object__load",
    "bpf_map_lookup_elem",        "bpf_map_update_elem",
    "ring_buffer__new",           "ring_buffer__consume_n",
    "libbpf_set_print",           "bpf_program__attach_tracepoint",
};

/* POSIX-safe dlsym-to-function-pointer assignment (no ISO-violating
 * object/function pointer cast, clean under -Wextra). */
static void resolve(void *hdl, const char *name, void *slot,
                    size_t slotsz) {
    void *sym = dlsym(hdl, name);
    if (sym == NULL) {
        memset(slot, 0, slotsz);
        return;
    }
    memcpy(slot, &sym, slotsz < sizeof(sym) ? slotsz : sizeof(sym));
}

static void make_oopts(struct lmb_object_options_v1 *o) {
    memset(o, 0, sizeof(*o));
    o->abi_version = LMB_GENERIC_ABI_VERSION;
    o->struct_size = sizeof(*o);
    o->log_level = LMB_LOG_ON_FAILURE;
    o->log_capacity = 65536;
}

static void make_popts(struct lmb_program_options_v1 *o,
                       const char *prog) {
    memset(o, 0, sizeof(*o));
    o->abi_version = LMB_GENERIC_ABI_VERSION;
    o->struct_size = sizeof(*o);
    o->program.ptr = (const uint8_t *)prog;
    o->program.len = (uint64_t)strlen(prog);
}

static void make_pinfo(struct lmb_program_info_v1 *o) {
    memset(o, 0, sizeof(*o));
    o->abi_version = LMB_GENERIC_ABI_VERSION;
    o->struct_size = sizeof(*o);
}

static void make_v1name(struct lmb_name_v1 *n, const char *s) {
    memset(n, 0, sizeof(*n));
    n->abi_version = LMB_ABI_VERSION;
    n->struct_size = sizeof(*n);
    n->name.ptr = (const uint8_t *)s;
    n->name.len = (uint32_t)strlen(s);
}

static void make_topts(struct lmb_program_test_options_v1 *o) {
    memset(o, 0, sizeof(*o));
    o->abi_version = LMB_GENERIC_ABI_VERSION;
    o->struct_size = sizeof(*o);
    o->repeat = 1;
}

static void make_tresult(struct lmb_program_test_result_v1 *o) {
    memset(o, 0, sizeof(*o));
    o->abi_version = LMB_GENERIC_ABI_VERSION;
    o->struct_size = sizeof(*o);
}

static void make_aopts(struct lmb_attach_options_v1 *o,
                       const char *prog) {
    memset(o, 0, sizeof(*o));
    o->abi_version = LMB_GENERIC_ABI_VERSION;
    o->struct_size = sizeof(*o);
    o->program.ptr = (const uint8_t *)prog;
    o->program.len = (uint64_t)strlen(prog);
    o->family = LMB_ATTACH_FAMILY_TRACEPOINT;
}

static void make_bopts(struct lmb_buffer_options_v1 *o,
                       const char *ring) {
    memset(o, 0, sizeof(*o));
    o->abi_version = LMB_GENERIC_ABI_VERSION;
    o->struct_size = sizeof(*o);
    o->ring.ptr = (const uint8_t *)ring;
    o->ring.len = (uint64_t)strlen(ring);
    o->max_raw_bytes = 4096;
    o->stage_slots = 1;
}

static void set_trace_targets(struct lmb_attach_options_v1 *o) {
    o->target_a.ptr = (const uint8_t *)"syscalls";
    o->target_a.len = sizeof("syscalls") - 1;
    o->target_b.ptr = (const uint8_t *)"sys_enter_getpid";
    o->target_b.len = sizeof("sys_enter_getpid") - 1;
}

static int gen_is(struct gen_api *g, uint32_t op, uint32_t domain,
                  int32_t *code) {
    struct lmb_generic_error_v1 err;
    memset(&err, 0, sizeof(err));
    err.abi_version = LMB_GENERIC_ABI_VERSION;
    err.struct_size = sizeof(err);
    if (g->lasterr(&err) != 0 || err.operation != op ||
        err.domain != domain)
        return 0;
    if (code != NULL)
        *code = err.code;
    return 1;
}

static int read_file(const char *path, uint8_t **bytes, uint64_t *len) {
    FILE *in = fopen(path, "rb");
    long size;
    uint8_t *data;
    if (!in)
        return -1;
    if (fseek(in, 0, SEEK_END) != 0) {
        fclose(in);
        return -1;
    }
    size = ftell(in);
    if (size < 0 || fseek(in, 0, SEEK_SET) != 0) {
        fclose(in);
        return -1;
    }
    data = malloc((size_t)size ? (size_t)size : 1);
    if (!data) {
        fclose(in);
        return -1;
    }
    if (size > 0 && fread(data, 1, (size_t)size, in) != (size_t)size) {
        free(data);
        fclose(in);
        return -1;
    }
    fclose(in);
    *bytes = data;
    *len = (uint64_t)size;
    return 0;
}

/* Privilege eligibility via a trivial map creation, independent of
 * any fixture: only EPERM/EACCES count as missing privileges. */
static int has_privilege(void) {
    union bpf_attr attr;
    int fd;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 4;
    attr.max_entries = 1;
    fd = (int)syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return errno != EPERM && errno != EACCES;
}

static long count_fds(void) {
    DIR *dir = opendir("/proc/self/fd");
    struct dirent *ent;
    long count = 0;
    if (!dir)
        return -1;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;
        count++;
    }
    closedir(dir);
    return count;
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static void put_le64(uint8_t *p, uint64_t v) {
    unsigned i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

/* Part A: layout smoke, v1 presence, hidden upstream symbols,
 * generic presence report. Runs against every candidate library. */
static int part_a(const char *libpath) {
    void *hdl;
    int i;
    int present = 0;
    hdl = dlopen(libpath, RTLD_NOW | RTLD_LOCAL);
    if (!hdl) {
        printf("probe: cannot dlopen %s: %s\n", libpath, dlerror());
        return -1;
    }
    CHECK(sizeof(struct lmb_span_v1) == 16 &&
              sizeof(struct lmb_out_span_v1) == 16 &&
              sizeof(struct lmb_object_options_v1) == 64 &&
              sizeof(struct lmb_program_options_v1) == 48 &&
              sizeof(struct lmb_program_info_v1) == 72 &&
              sizeof(struct lmb_generic_error_v1) == 1048 &&
              sizeof(struct lmb_program_test_options_v1) == 88 &&
              sizeof(struct lmb_program_test_result_v1) == 40 &&
              sizeof(struct lmb_attach_options_v1) == 72 &&
              sizeof(struct lmb_buffer_options_v1) == 40,
          "a-sizes", "generic record sizes must match the contract");
    CHECK(sizeof(struct lmb_name_v1) == 24 &&
              sizeof(struct lmb_map_info_v1) == 40,
          "a-shared-sizes", "shared v1 structs keep their sizes");
    CHECK(_Alignof(struct lmb_span_v1) == 8 &&
              _Alignof(struct lmb_out_span_v1) == 8 &&
              _Alignof(struct lmb_object_options_v1) == 8 &&
              _Alignof(struct lmb_program_options_v1) == 8 &&
              _Alignof(struct lmb_program_info_v1) == 8 &&
              _Alignof(struct lmb_generic_error_v1) == 4 &&
              _Alignof(struct lmb_program_test_options_v1) == 8 &&
              _Alignof(struct lmb_program_test_result_v1) == 8 &&
              _Alignof(struct lmb_attach_options_v1) == 8 &&
              _Alignof(struct lmb_buffer_options_v1) == 8,
          "a-aligns", "generic alignments must match the contract");
    for (i = 0; i < 11; i++) {
        int ok = dlsym(hdl, v1_names[i]) != NULL;
        char name[64];
        snprintf(name, sizeof(name), "a-v1-%s", v1_names[i]);
        CHECK(ok, name, "old symbol must resolve");
    }
    for (i = 0; i < 8; i++) {
        int hidden = dlsym(hdl, hidden_names[i]) == NULL;
        char name[80];
        snprintf(name, sizeof(name), "a-hidden-%s", hidden_names[i]);
        CHECK(hidden, name, "bundled upstream symbol must stay hidden");
    }
    for (i = 0; i < 20; i++)
        present += dlsym(hdl, gen_names[i]) != NULL;
    printf("note a-generic-present: %d of 20 generic symbols resolve\n",
           present);
    dlclose(hdl);
    return 0;
}

static const uint8_t garbage_elf[64] = "not an ELF object at all";

/* B1: object-open validation, handle clearing, eager parse. The
 * garbage input parses nowhere, so every row runs unprivileged. */
static void part_b1(struct gen_api *g) {
    struct lmb_object_options_v1 o;
    struct lmb_object *obj;
    struct lmb_object *sentinel =
        (struct lmb_object *)(uintptr_t)0xDEAD;
    int32_t code = 0;
    static const uint8_t bad8[1] = {0xFF};
    static const uint8_t nulpath[4] = {'a', 0, 'b', 0};
    static uint8_t longname[257];
    static uint8_t longpath[4097];

    memset(longname, 'n', sizeof(longname));
    memset(longpath, 'p', sizeof(longpath));

    make_oopts(&o);
    o.abi_version = 99;
    obj = sentinel;
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
                  -EINVAL &&
              obj == NULL,
          "b1-bad-version", "bad version must fail cleared");
    CHECK(gen_is(g, LMB_GENERIC_OP_OBJECT_OPEN,
                 LMB_GENERIC_DOMAIN_BRIDGE, NULL),
          "b1-bad-version-record", "open failure must report bridge");

    make_oopts(&o);
    o.struct_size = sizeof(o) - 1;
    obj = sentinel;
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
                  -EINVAL &&
              obj == NULL,
          "b1-short-struct", "short struct must fail cleared");
    make_oopts(&o);
    o.struct_size = sizeof(o) + 8;
    obj = sentinel;
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
                  -EINVAL &&
              obj == NULL,
          "b1-long-struct", "oversized struct must fail cleared");

    make_oopts(&o);
    o.flags = 1;
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
              -EINVAL,
          "b1-flags", "nonzero flags must fail");
    make_oopts(&o);
    o._reserved = 1;
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
              -EINVAL,
          "b1-reserved", "nonzero reserved must fail");
    make_oopts(&o);
    o.log_level = 3;
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
              -EINVAL,
          "b1-log-level", "unknown log level must fail");
    make_oopts(&o);
    o.log_capacity = (uint64_t)LMB_GENERIC_MAX_LOG_BYTES + 1;
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
              -EINVAL,
          "b1-log-capacity", "oversized log capacity must fail");

    make_oopts(&o);
    o.name.ptr = longname;
    o.name.len = sizeof(longname);
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
              -EINVAL,
          "b1-name-long", "overlong name must fail");
    make_oopts(&o);
    o.name.ptr = bad8;
    o.name.len = sizeof(bad8);
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
              -EINVAL,
          "b1-name-utf8", "invalid UTF-8 name must fail");
    make_oopts(&o);
    o.custom_btf.ptr = nulpath;
    o.custom_btf.len = sizeof(nulpath);
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
              -EINVAL,
          "b1-btf-nul", "NUL in BTF path must fail");
    make_oopts(&o);
    o.custom_btf.ptr = longpath;
    o.custom_btf.len = sizeof(longpath);
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
              -EINVAL,
          "b1-btf-long", "overlong BTF path must fail");

    make_oopts(&o);
    CHECK(g->open(NULL, sizeof(garbage_elf), &o, &obj) == -EINVAL,
          "b1-null-elf", "null ELF must fail");
    make_oopts(&o);
    CHECK(g->open(garbage_elf, 0, &o, &obj) == -EINVAL,
          "b1-empty-elf", "empty ELF must fail");
    make_oopts(&o);
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), NULL, &obj) ==
              -EINVAL,
          "b1-null-opts", "null options must fail");
    make_oopts(&o);
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, NULL) ==
              -EINVAL,
          "b1-null-out", "null out handle must fail");

    /* Open parses eagerly: garbage fails here (libbpf domain), not
     * at load. A failed open is retrievable with no object. */
    make_oopts(&o);
    obj = sentinel;
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) != 0 &&
              obj == NULL,
          "b1-garbage-cleared", "garbage ELF must fail cleared");
    CHECK(gen_is(g, LMB_GENERIC_OP_OBJECT_OPEN,
                 LMB_GENERIC_DOMAIN_LIBBPF, &code) &&
              code < 0,
          "b1-garbage-record", "parse failure keeps signed libbpf code");
}

/* One valid unloaded object for validation isolation, or NULL
 * when the fixture is unavailable. Parsing needs no privilege. */
static struct lmb_object *open_valid(struct gen_api *g,
                                     const uint8_t *elf,
                                     uint64_t elf_len) {
    struct lmb_object_options_v1 o;
    struct lmb_object *obj = NULL;
    if (elf == NULL)
        return NULL;
    make_oopts(&o);
    o.log_level = LMB_LOG_DISCARD;
    o.log_capacity = 0;
    if (g->open(elf, elf_len, &o, &obj) != 0 || obj == NULL)
        return NULL;
    return obj;
}

/* Forward declaration: B3a validation isolation loads its owner;
 * the definition lives with the other load-gated helpers. */
static int open_loaded(struct gen_api *g, const uint8_t *elf,
                       uint64_t elf_len, uint32_t log_level,
                       uint64_t log_capacity, struct lmb_object **obj);

/* B2: configure/info/inspection validation. Null-object rows use
 * otherwise-valid records; every other validation row uses a
 * valid unloaded owner, so only the input under test is
 * defective. A null owner would fail closed for its own sake
 * and prove nothing about the named check. */
static void part_b2(struct gen_api *g, const uint8_t *elf,
                    uint64_t elf_len) {
    struct lmb_program_options_v1 po;
    struct lmb_program_info_v1 pi, pi_before;
    struct lmb_map_info_v1 mi, mi_before;
    struct lmb_generic_error_v1 e1, e2;
    struct lmb_name_v1 name;
    struct lmb_object_options_v1 o;
    struct lmb_object *obj = NULL;
    struct lmb_object *valid = NULL;
    static const uint8_t bad8[1] = {0xFF};

    /* Isolated null-object rows: valid records, null owner only. */
    make_popts(&po, "on_getpid");
    CHECK(g->config(NULL, &po) == -EINVAL, "b2-config-null",
          "null object must fail closed");
    make_v1name(&name, "on_getpid");
    make_pinfo(&pi);
    CHECK(g->pinfo(NULL, &name, &pi) == -EINVAL, "b2-pinfo-null",
          "null object must fail closed");
    memset(&mi, 0, sizeof(mi));
    mi.abi_version = LMB_ABI_VERSION;
    mi.struct_size = sizeof(mi);
    make_v1name(&name, "test_hash");
    CHECK(g->minfo(NULL, &name, &mi) == -EINVAL, "b2-minfo-null",
          "null object must fail closed");

    /* Inspection failures preserve the stored record. */
    make_oopts(&o);
    o.abi_version = 99;
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
              -EINVAL,
          "b2-seed-failure", "seed failure must fail");
    CHECK(g->lasterr(NULL) == -EINVAL, "b2-lasterr-null",
          "null inspection must fail");
    memset(&e1, 0, sizeof(e1));
    e1.abi_version = LMB_GENERIC_ABI_VERSION;
    e1.struct_size = sizeof(e1);
    CHECK(g->lasterr(&e1) == 0 &&
              e1.operation == LMB_GENERIC_OP_OBJECT_OPEN &&
              e1.domain == LMB_GENERIC_DOMAIN_BRIDGE,
          "b2-lasterr-ok", "inspection must retrieve the record");
    e2 = e1;
    e2.struct_size = 1;
    CHECK(g->lasterr(&e2) == -EINVAL, "b2-lasterr-short",
          "short inspection struct must fail");
    memset(&e2, 0, sizeof(e2));
    e2.abi_version = LMB_GENERIC_ABI_VERSION;
    e2.struct_size = sizeof(e2);
    CHECK(g->lasterr(&e2) == 0 && memcmp(&e1, &e2, sizeof(e1)) == 0,
          "b2-lasterr-preserved",
          "retrieval preserves; failure preserves too");

    /* Record-validation rows need a valid owner: without the
     * fixture they SKIP rather than confound the named defect
     * with a null owner. */
    valid = open_valid(g, elf, elf_len);
    if (valid == NULL) {
        SKIP("b2-validation",
             "needs the fixture ELF for a valid owner");
        return;
    }

    make_popts(&po, "on_getpid");
    po.abi_version = 99;
    CHECK(g->config(valid, &po) == -EINVAL, "b2-config-bad-version",
          "bad version must fail");
    make_popts(&po, "on_getpid");
    po.struct_size = sizeof(po) - 1;
    CHECK(g->config(valid, &po) == -EINVAL, "b2-config-short",
          "short struct must fail");
    make_popts(&po, "on_getpid");
    po.flags = 1;
    CHECK(g->config(valid, &po) == -EINVAL, "b2-config-flags",
          "nonzero flags must fail");
    make_popts(&po, "on_getpid");
    po.autoload = 3;
    CHECK(g->config(valid, &po) == -EINVAL, "b2-config-autoload",
          "unknown autoload value must fail");
    make_popts(&po, "on_getpid");
    po.program.ptr = NULL;
    po.program.len = 0;
    CHECK(g->config(valid, &po) == -EINVAL, "b2-config-empty-program",
          "empty program name must fail");
    make_popts(&po, "on_getpid");
    po.program.ptr = bad8;
    po.program.len = sizeof(bad8);
    CHECK(g->config(valid, &po) == -EINVAL, "b2-config-program-utf8",
          "invalid UTF-8 program must fail");
    make_popts(&po, "on_getpid");
    po.attach_target.ptr = bad8;
    po.attach_target.len = sizeof(bad8);
    CHECK(g->config(valid, &po) == -EINVAL, "b2-config-target-utf8",
          "invalid UTF-8 target must fail");

    /* Info validation leaves the output struct untouched. */
    make_v1name(&name, "on_getpid");
    memset(&pi, 0xAA, sizeof(pi));
    pi.abi_version = 99;
    pi.struct_size = sizeof(pi);
    pi_before = pi;
    CHECK(g->pinfo(valid, &name, &pi) == -EINVAL &&
              memcmp(&pi, &pi_before, sizeof(pi)) == 0,
          "b2-pinfo-untouched", "failed info must not touch output");
    make_pinfo(&pi);
    CHECK(g->pinfo(valid, NULL, &pi) == -EINVAL, "b2-pinfo-null-name",
          "null name must fail closed");
    CHECK(g->pinfo(valid, &name, NULL) == -EINVAL, "b2-pinfo-null-out",
          "null out struct must fail closed");
    memset(&mi, 0xAA, sizeof(mi));
    mi.abi_version = LMB_ABI_VERSION;
    mi.struct_size = 1;
    mi_before = mi;
    make_v1name(&name, "test_hash");
    CHECK(g->minfo(valid, &name, &mi) == -EINVAL &&
              memcmp(&mi, &mi_before, sizeof(mi)) == 0,
          "b2-minfo-untouched", "failed info must not touch output");

    CHECK(g->close(&valid) == 0 && valid == NULL, "b2-close",
          "close must release the validation owner");
}

/* B3a: map/test/attach/buffer validation on a loaded owner.
 * Null-object rows use otherwise-valid arguments and run
 * unprivileged. Every bounds, flag, and alias row uses a loaded
 * owner with valid names and attach targets, so only the input
 * under test is defective. Load-gating reports the same
 * BRIDGE/-EINVAL as validation, so an unloaded owner cannot
 * distinguish the rejecting check: with one, omitting every
 * named validation below still passes. The loaded owner plus
 * the per-operation controls (unknown names reach lookup with
 * ENOENT; a valid test-run reaches the kernel) proves the named
 * check rejected. Every -EINVAL row additionally verifies the
 * rejecting domain immediately (operation + BRIDGE + signed
 * -EINVAL): a backend that skips validation and falls through
 * to a KERNEL/-EINVAL decline keeps the rc but fails the paired
 * record check. Without the fixture, or without the privilege
 * to load one, the validation rows SKIP; a differential stub
 * whose load needs no privilege still exercises them. */
static void part_b3a(struct gen_api *g, const uint8_t *elf,
                     uint64_t elf_len) {
    struct lmb_name_v1 name;
    struct lmb_name_v1 prog;
    struct lmb_program_test_options_v1 to;
    struct lmb_program_test_result_v1 tr, tr_before;
    struct lmb_attach_options_v1 ao;
    struct lmb_buffer_options_v1 bo;
    struct lmb_link *link;
    struct lmb_buffer *buf;
    struct lmb_object *valid = NULL;
    struct lmb_link *lsentinel =
        (struct lmb_link *)(uintptr_t)0xDEAD;
    struct lmb_buffer *bsentinel =
        (struct lmb_buffer *)(uintptr_t)0xDEAD;
    uint8_t key[4] = {7, 0, 0, 0};
    uint8_t val[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t dst[16];
    uint8_t out[64];
    uint64_t needed = 123;
    static uint8_t big[16];
    int32_t dcode = 0;

    /* Isolated null-object rows: valid arguments, null owner only. */
    make_v1name(&name, "test_hash");
    make_v1name(&prog, "on_getpid");
    CHECK(g->lookup(NULL, &name, key, sizeof(key), dst, sizeof(dst),
                    &needed) == -EINVAL,
          "b3a-lookup-null-object", "null object must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_LOOKUP,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-lookup-null-object-record",
          "null object reports lookup BRIDGE/-EINVAL");
    CHECK(g->update(NULL, &name, key, sizeof(key), val, sizeof(val),
                    LMB_MAP_UPDATE_ANY) == -EINVAL,
          "b3a-update-null-object", "null object must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_UPDATE,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-update-null-object-record",
          "null object reports update BRIDGE/-EINVAL");
    make_topts(&to);
    make_tresult(&tr);
    CHECK(g->testrun(NULL, &prog, &to, &tr) == -EINVAL,
          "b3a-testrun-null-object", "null object must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_TEST_RUN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-testrun-null-object-record",
          "null object reports test-run BRIDGE/-EINVAL");
    make_aopts(&ao, "on_getpid");
    set_trace_targets(&ao);
    link = lsentinel;
    CHECK(g->attach(NULL, &ao, &link) == -EINVAL && link == NULL,
          "b3a-attach-null-object", "null object must fail cleared");
    CHECK(gen_is(g, LMB_GENERIC_OP_ATTACH,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-attach-null-object-record",
          "null object reports attach BRIDGE/-EINVAL");
    make_bopts(&bo, "events");
    buf = bsentinel;
    CHECK(g->bufopen(NULL, &bo, &buf) == -EINVAL && buf == NULL,
          "b3a-bufopen-null-object", "null object must fail cleared");
    CHECK(gen_is(g, LMB_GENERIC_OP_BUFFER_OPEN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-bufopen-null-object-record",
          "null object reports buffer-open BRIDGE/-EINVAL");

    /* Record-validation rows need a loaded owner: an unloaded one
     * fails closed for its own sake and proves nothing about the
     * named check. Try the load first so a privileged lane FAILs
     * honestly while an unprivileged lane SKIP-reports. */
    if (elf == NULL) {
        SKIP("b3a-validation",
             "needs the fixture ELF for a loaded owner");
        return;
    }
    if (open_loaded(g, elf, elf_len, LMB_LOG_DISCARD, 0, &valid) !=
            0 ||
        valid == NULL) {
        if (!has_privilege()) {
            SKIP("b3a-validation",
                 "needs privilege to load a validation owner");
        } else {
            FAIL("b3a-load",
                 "fixture must load for validation isolation");
        }
        return;
    }

    make_v1name(&name, "test_hash");
    CHECK(g->lookup(valid, &name, key, sizeof(key), dst, sizeof(dst),
                    NULL) == -EINVAL,
          "b3a-lookup-null-needed", "null needed cell must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_LOOKUP,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-lookup-null-needed-record",
          "cell rejection reports lookup BRIDGE/-EINVAL");
    needed = 123;
    CHECK(g->lookup(valid, &name, key, sizeof(key), NULL, 8,
                    &needed) == -EINVAL &&
              needed == 123,
          "b3a-lookup-null-dst", "null dst with capacity must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_LOOKUP,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-lookup-null-dst-record",
          "null dst reports lookup BRIDGE/-EINVAL");
    /* Alias rejection must leave the ACTUAL passed storage
     * untouched: the size cell is the 8 bytes at the passed
     * address, not a separate local. A backend that overwrites
     * the aliased bytes before rejecting violates the
     * leave-unchanged rule and must FAIL here. */
    {
        uint8_t keycell[8] = {7, 0, 0, 0, 0xA5, 0xA5, 0xA5, 0xA5};
        uint8_t keycell_before[8];
        memcpy(keycell_before, keycell, sizeof(keycell));
        CHECK(g->lookup(valid, &name, keycell, 4, dst, sizeof(dst),
                        (uint64_t *)keycell) == -EINVAL &&
                  memcmp(keycell, keycell_before, sizeof(keycell)) == 0,
              "b3a-lookup-needed-in-key",
              "needed inside key must fail storage-intact");
    }
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_LOOKUP,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-lookup-needed-in-key-record",
          "key alias reports lookup BRIDGE/-EINVAL");
    memset(dst, 0x5A, sizeof(dst));
    {
        uint8_t dst_before[16];
        memcpy(dst_before, dst, sizeof(dst));
        CHECK(g->lookup(valid, &name, key, sizeof(key), dst, sizeof(dst),
                        (uint64_t *)(dst + 8)) == -EINVAL &&
                  memcmp(dst, dst_before, sizeof(dst)) == 0,
              "b3a-lookup-needed-in-dst",
              "needed inside dst must fail storage-intact");
    }
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_LOOKUP,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-lookup-needed-in-dst-record",
          "dst alias reports lookup BRIDGE/-EINVAL");
    needed = 123;
    CHECK(g->lookup(valid, NULL, key, sizeof(key), dst, sizeof(dst),
                    &needed) == -EINVAL &&
              needed == 123,
          "b3a-lookup-null-name", "null name must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_LOOKUP,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-lookup-null-name-record",
          "null name reports lookup BRIDGE/-EINVAL");
    /* Validation precedes lookup: a defective record against an
     * unknown map still reports EINVAL, while the fixed record
     * reaches lookup and reports ENOENT. */
    make_v1name(&name, "no_such_map");
    CHECK(g->lookup(valid, &name, key, sizeof(key), dst, sizeof(dst),
                    NULL) == -EINVAL,
          "b3a-lookup-order", "span errors precede map lookup");
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_LOOKUP,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-lookup-order-record",
          "order proof reports lookup BRIDGE/-EINVAL");
    needed = 123;
    CHECK(g->lookup(valid, &name, key, sizeof(key), dst, sizeof(dst),
                    &needed) == -ENOENT &&
              needed == 0,
          "b3a-lookup-control", "unknown map must report ENOENT");

    /* Update validation: spans, then flags, then the lookup
     * control with an otherwise-valid record. */
    make_v1name(&name, "test_hash");
    CHECK(g->update(valid, NULL, key, sizeof(key), val, sizeof(val),
                    LMB_MAP_UPDATE_ANY) == -EINVAL,
          "b3a-update-null-name", "null name must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_UPDATE,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-update-null-name-record",
          "null name reports update BRIDGE/-EINVAL");
    CHECK(g->update(valid, &name, NULL, sizeof(key), val, sizeof(val),
                    LMB_MAP_UPDATE_ANY) == -EINVAL,
          "b3a-update-null-key", "null key with size must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_UPDATE,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-update-null-key-record",
          "null key reports update BRIDGE/-EINVAL");
    CHECK(g->update(valid, &name, key, sizeof(key), NULL, sizeof(val),
                    LMB_MAP_UPDATE_ANY) == -EINVAL,
          "b3a-update-null-value", "null value with size must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_UPDATE,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-update-null-value-record",
          "null value reports update BRIDGE/-EINVAL");
    CHECK(g->update(valid, &name, key, sizeof(key), val, sizeof(val),
                    3) == -EINVAL,
          "b3a-update-flags-combo", "NOEXIST|EXIST must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_UPDATE,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-update-flags-record",
          "flag rejection reports update BRIDGE/-EINVAL");
    CHECK(g->update(valid, &name, key, sizeof(key), val, sizeof(val),
                    8) == -EINVAL,
          "b3a-update-flags-high", "high flag bits must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_UPDATE,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-update-flags-high-record",
          "high flags report update BRIDGE/-EINVAL");
    make_v1name(&name, "no_such_map");
    CHECK(g->update(valid, &name, key, sizeof(key), val, sizeof(val),
                    LMB_MAP_UPDATE_ANY) == -ENOENT,
          "b3a-update-control", "unknown map must report ENOENT");

    /* Test-run validation: bounds, repeat, flags, out/out alias.
     * Failed validation leaves the result struct untouched. */
    memset(&tr_before, 0xAA, sizeof(tr_before));
    tr_before.abi_version = LMB_GENERIC_ABI_VERSION;
    tr_before.struct_size = sizeof(tr_before);
    make_topts(&to);
    to.data_in.ptr = big;
    to.data_in.len = (uint64_t)LMB_GENERIC_MAX_TEST_BYTES + 1;
    tr = tr_before;
    CHECK(g->testrun(valid, &prog, &to, &tr) == -EINVAL &&
              memcmp(&tr, &tr_before, sizeof(tr)) == 0,
          "b3a-testrun-big-data", "oversized packet input must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_TEST_RUN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-testrun-big-data-record",
          "big packet reports test-run BRIDGE/-EINVAL");
    make_topts(&to);
    to.ctx_in.ptr = big;
    to.ctx_in.len = (uint64_t)LMB_GENERIC_MAX_TEST_BYTES + 1;
    tr = tr_before;
    CHECK(g->testrun(valid, &prog, &to, &tr) == -EINVAL &&
              memcmp(&tr, &tr_before, sizeof(tr)) == 0,
          "b3a-testrun-big-ctx", "oversized context input must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_TEST_RUN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-testrun-big-ctx-record",
          "big context reports test-run BRIDGE/-EINVAL");
    make_topts(&to);
    to.data_out.ptr = out;
    to.data_out.len = (uint64_t)LMB_GENERIC_MAX_TEST_BYTES + 1;
    tr = tr_before;
    CHECK(g->testrun(valid, &prog, &to, &tr) == -EINVAL &&
              memcmp(&tr, &tr_before, sizeof(tr)) == 0,
          "b3a-testrun-big-out", "oversized packet output must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_TEST_RUN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-testrun-big-out-record",
          "big output reports test-run BRIDGE/-EINVAL");
    make_topts(&to);
    to.repeat = 0;
    tr = tr_before;
    CHECK(g->testrun(valid, &prog, &to, &tr) == -EINVAL &&
              memcmp(&tr, &tr_before, sizeof(tr)) == 0,
          "b3a-testrun-repeat-zero", "repeat 0 must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_TEST_RUN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-testrun-repeat-zero-record",
          "zero repeat reports test-run BRIDGE/-EINVAL");
    make_topts(&to);
    to.repeat = (uint64_t)0xFFFFFFFF + 1;
    tr = tr_before;
    CHECK(g->testrun(valid, &prog, &to, &tr) == -EINVAL &&
              memcmp(&tr, &tr_before, sizeof(tr)) == 0,
          "b3a-testrun-repeat-huge", "huge repeat must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_TEST_RUN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-testrun-repeat-huge-record",
          "huge repeat reports test-run BRIDGE/-EINVAL");
    make_topts(&to);
    to.flags = 1;
    tr = tr_before;
    CHECK(g->testrun(valid, &prog, &to, &tr) == -EINVAL &&
              memcmp(&tr, &tr_before, sizeof(tr)) == 0,
          "b3a-testrun-flags", "nonzero flags must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_TEST_RUN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-testrun-flags-record",
          "flag rejection reports test-run BRIDGE/-EINVAL");
    make_topts(&to);
    to.data_out.ptr = out;
    to.data_out.len = sizeof(out);
    to.ctx_out.ptr = out + 32;
    to.ctx_out.len = 32;
    tr = tr_before;
    CHECK(g->testrun(valid, &prog, &to, &tr) == -EINVAL &&
              memcmp(&tr, &tr_before, sizeof(tr)) == 0,
          "b3a-testrun-out-alias",
          "overlapping outputs must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_TEST_RUN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-testrun-out-alias-record",
          "output alias reports test-run BRIDGE/-EINVAL");
    make_topts(&to);
    to.abi_version = 99;
    tr = tr_before;
    CHECK(g->testrun(valid, &prog, &to, &tr) == -EINVAL &&
              memcmp(&tr, &tr_before, sizeof(tr)) == 0,
          "b3a-testrun-untouched",
          "failed test-run must not touch result");
    CHECK(gen_is(g, LMB_GENERIC_OP_TEST_RUN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-testrun-untouched-record",
          "bad version reports test-run BRIDGE/-EINVAL");
    /* Control: a fully valid record reaches past validation.
     * Success checks the output shape; a kernel decline keeps
     * its signed code with the result untouched. BRIDGE/-EINVAL
     * here would mean the valid record was rejected. */
    make_topts(&to);
    to.data_in.ptr = big;
    to.data_in.len = sizeof(big);
    to.data_out.ptr = out;
    to.data_out.len = sizeof(out);
    tr = tr_before;
    {
        int32_t rc = g->testrun(valid, &prog, &to, &tr);
        if (rc == 0) {
            CHECK(tr.data_actual <= sizeof(out) &&
                      tr.ctx_actual == 0 && tr._pad == 0,
                  "b3a-testrun-control",
                  "valid test-run outputs must be bounded");
        } else {
            int32_t code = 0;
            CHECK(gen_is(g, LMB_GENERIC_OP_TEST_RUN,
                         LMB_GENERIC_DOMAIN_KERNEL, &code) &&
                      code < 0 &&
                      memcmp(&tr, &tr_before, sizeof(tr)) == 0,
                  "b3a-testrun-control",
                  "kernel decline keeps signed code, result intact");
        }
    }

    /* Attach validation clears output handles first. Every row
     * carries valid names and targets except the input under
     * test; span checks precede the enum checks, so empty
     * targets here would mask the family/flag rows. */
    make_aopts(&ao, "on_getpid");
    set_trace_targets(&ao);
    ao.abi_version = 99;
    link = lsentinel;
    CHECK(g->attach(valid, &ao, &link) == -EINVAL && link == NULL,
          "b3a-attach-cleared", "failed attach must clear handle");
    CHECK(gen_is(g, LMB_GENERIC_OP_ATTACH,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-attach-cleared-record",
          "bad version reports attach BRIDGE/-EINVAL");
    make_aopts(&ao, "on_getpid");
    set_trace_targets(&ao);
    ao.family = 0;
    link = lsentinel;
    CHECK(g->attach(valid, &ao, &link) == -EINVAL && link == NULL,
          "b3a-attach-family", "unknown family must fail cleared");
    CHECK(gen_is(g, LMB_GENERIC_OP_ATTACH,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-attach-family-record",
          "family rejection reports attach BRIDGE/-EINVAL");
    make_aopts(&ao, "on_getpid");
    set_trace_targets(&ao);
    ao.flags = 1;
    link = lsentinel;
    CHECK(g->attach(valid, &ao, &link) == -EINVAL && link == NULL,
          "b3a-attach-flags", "nonzero flags must fail cleared");
    CHECK(gen_is(g, LMB_GENERIC_OP_ATTACH,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-attach-flags-record",
          "flags rejection reports attach BRIDGE/-EINVAL");
    make_aopts(&ao, "on_getpid");
    set_trace_targets(&ao);
    ao._reserved = 1;
    link = lsentinel;
    CHECK(g->attach(valid, &ao, &link) == -EINVAL && link == NULL,
          "b3a-attach-reserved", "nonzero reserved must fail cleared");
    CHECK(gen_is(g, LMB_GENERIC_OP_ATTACH,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-attach-reserved-record",
          "reserved rejection reports attach BRIDGE/-EINVAL");
    make_aopts(&ao, "on_getpid");
    set_trace_targets(&ao);
    ao.program.ptr = NULL;
    ao.program.len = 0;
    link = lsentinel;
    CHECK(g->attach(valid, &ao, &link) == -EINVAL && link == NULL,
          "b3a-attach-empty-program", "empty program must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_ATTACH,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-attach-empty-program-record",
          "empty program reports attach BRIDGE/-EINVAL");
    make_aopts(&ao, "on_getpid");
    link = lsentinel;
    CHECK(g->attach(valid, &ao, &link) == -EINVAL && link == NULL,
          "b3a-attach-empty-targets", "empty targets must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_ATTACH,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-attach-empty-targets-record",
          "empty targets report attach BRIDGE/-EINVAL");
    /* Order proof: family validation precedes program lookup, and
     * the fully valid record reaches lookup with ENOENT. */
    make_aopts(&ao, "no_such_program");
    set_trace_targets(&ao);
    ao.family = 0;
    link = lsentinel;
    CHECK(g->attach(valid, &ao, &link) == -EINVAL && link == NULL,
          "b3a-attach-order",
          "family errors precede program lookup");
    CHECK(gen_is(g, LMB_GENERIC_OP_ATTACH,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-attach-order-record",
          "order proof reports attach BRIDGE/-EINVAL");
    make_aopts(&ao, "no_such_program");
    set_trace_targets(&ao);
    link = lsentinel;
    CHECK(g->attach(valid, &ao, &link) == -ENOENT && link == NULL,
          "b3a-attach-control",
          "unknown program must report ENOENT cleared");

    /* Buffer validation clears output handles first. */
    make_bopts(&bo, "events");
    bo.abi_version = 99;
    buf = bsentinel;
    CHECK(g->bufopen(valid, &bo, &buf) == -EINVAL && buf == NULL,
          "b3a-bufopen-cleared", "failed buffer open must clear");
    CHECK(gen_is(g, LMB_GENERIC_OP_BUFFER_OPEN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-bufopen-cleared-record",
          "bad version reports buffer-open BRIDGE/-EINVAL");
    make_bopts(&bo, "events");
    bo.ring.ptr = NULL;
    bo.ring.len = 0;
    buf = bsentinel;
    CHECK(g->bufopen(valid, &bo, &buf) == -EINVAL && buf == NULL,
          "b3a-bufopen-empty-ring", "empty ring name must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_BUFFER_OPEN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-bufopen-empty-ring-record",
          "empty ring reports buffer-open BRIDGE/-EINVAL");
    make_bopts(&bo, "events");
    bo.max_raw_bytes = 0;
    buf = bsentinel;
    CHECK(g->bufopen(valid, &bo, &buf) == -EINVAL && buf == NULL,
          "b3a-bufopen-raw-zero", "zero raw cap must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_BUFFER_OPEN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-bufopen-raw-zero-record",
          "zero cap reports buffer-open BRIDGE/-EINVAL");
    make_bopts(&bo, "events");
    bo.max_raw_bytes = LMB_GENERIC_MAX_RAW_BYTES + 1;
    buf = bsentinel;
    CHECK(g->bufopen(valid, &bo, &buf) == -EINVAL && buf == NULL,
          "b3a-bufopen-raw-huge", "huge raw cap must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_BUFFER_OPEN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-bufopen-raw-huge-record",
          "huge cap reports buffer-open BRIDGE/-EINVAL");
    make_bopts(&bo, "events");
    bo.stage_slots = 0;
    buf = bsentinel;
    CHECK(g->bufopen(valid, &bo, &buf) == -EINVAL && buf == NULL,
          "b3a-bufopen-slots", "zero stage slots must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_BUFFER_OPEN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-bufopen-slots-record",
          "zero slots report buffer-open BRIDGE/-EINVAL");
    make_bopts(&bo, "events");
    bo.flags = 1;
    buf = bsentinel;
    CHECK(g->bufopen(valid, &bo, &buf) == -EINVAL && buf == NULL,
          "b3a-bufopen-flags", "nonzero flags must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_BUFFER_OPEN,
                 LMB_GENERIC_DOMAIN_BRIDGE, &dcode) &&
              dcode == -EINVAL,
          "b3a-bufopen-flags-record",
          "flag rejection reports buffer-open BRIDGE/-EINVAL");
    make_bopts(&bo, "no_such_ring");
    buf = bsentinel;
    CHECK(g->bufopen(valid, &bo, &buf) == -ENOENT && buf == NULL,
          "b3a-bufopen-control",
          "unknown ring must report ENOENT cleared");

    CHECK(g->close(&valid) == 0 && valid == NULL, "b3a-close",
          "close must release the validation owner");
}

/* B3b: pre-load behavior on a valid unloaded object. Needs the
 * fixture ELF; parsing it needs no privilege. */
static void part_b3b(struct gen_api *g, const uint8_t *elf,
                     uint64_t elf_len) {
    struct lmb_object_options_v1 o;
    struct lmb_program_options_v1 po;
    struct lmb_program_info_v1 pi;
    struct lmb_map_info_v1 mi;
    struct lmb_name_v1 name, prog;
    struct lmb_program_test_options_v1 to;
    struct lmb_program_test_result_v1 tr;
    struct lmb_attach_options_v1 ao;
    struct lmb_buffer_options_v1 bo;
    struct lmb_object *obj = NULL;
    struct lmb_link *link = NULL;
    struct lmb_buffer *buf = NULL;
    uint8_t key[4] = {7, 0, 0, 0};
    uint8_t dst[16];
    uint8_t logbuf[64];
    uint64_t needed = 0;
    static const uint8_t bad8[1] = {0xFF};
    static const char objname[] = "probe-obj";

    make_oopts(&o);
    o.name.ptr = (const uint8_t *)objname;
    o.name.len = sizeof(objname) - 1;
    CHECK(g->open(elf, elf_len, &o, &obj) == 0 && obj != NULL,
          "b3b-open-valid", "valid fixture must open unprivileged");
    if (obj == NULL)
        return;
    make_oopts(&o);
    o.custom_btf.ptr = (const uint8_t *)"/nonexistent-btf-path";
    o.custom_btf.len = sizeof("/nonexistent-btf-path") - 1;
    {
        struct lmb_object *bad = NULL;
        int32_t code = 0;
        CHECK(g->open(elf, elf_len, &o, &bad) != 0 && bad == NULL,
              "b3b-open-bad-btf", "missing custom BTF must fail");
        CHECK(gen_is(g, LMB_GENERIC_OP_OBJECT_OPEN,
                     LMB_GENERIC_DOMAIN_LIBBPF, &code) &&
                  code < 0,
              "b3b-open-bad-btf-record",
              "BTF failure keeps signed libbpf code");
    }

    /* Program metadata is available before load; unknown names
     * fail; span errors precede lookup (order proof). */
    make_v1name(&prog, "on_getpid");
    make_pinfo(&pi);
    memset(logbuf, 0xAA, sizeof(logbuf));
    pi.log.ptr = logbuf;
    pi.log.len = sizeof(logbuf);
    CHECK(g->pinfo(obj, &prog, &pi) == 0 &&
              pi.prog_type == BPF_PROG_TYPE_TRACEPOINT &&
              pi.insn_count > 0 && pi.generation == 0 &&
              pi.autoload == 1 && pi.log_actual == 0 &&
              pi.log_truncated == 0 && pi._reserved == 0,
          "b3b-pinfo-preload", "pre-load metadata must be valid");
    CHECK(logbuf[0] == 0xAA && logbuf[sizeof(logbuf) - 1] == 0xAA,
          "b3b-pinfo-log-untouched",
          "empty log must copy zero bytes");
    make_v1name(&prog, "no_such_program");
    make_pinfo(&pi);
    CHECK(g->pinfo(obj, &prog, &pi) == -ENOENT,
          "b3b-pinfo-unknown", "unknown program must report ENOENT");
    CHECK(gen_is(g, LMB_GENERIC_OP_PROGRAM_INFO,
                 LMB_GENERIC_DOMAIN_BRIDGE, NULL),
          "b3b-pinfo-unknown-record", "unknown program is a bridge miss");

    /* Configuration churns the generation; the info call observes
     * it (the C-visible half of stale-view validation). */
    make_popts(&po, "on_getpid");
    po.autoload = LMB_AUTOLOAD_DISABLE;
    CHECK(g->config(obj, &po) == 0, "b3b-config-disable",
          "autoload disable must succeed");
    make_v1name(&prog, "on_getpid");
    make_pinfo(&pi);
    CHECK(g->pinfo(obj, &prog, &pi) == 0 && pi.autoload == 0 &&
              pi.generation == 1,
          "b3b-generation-churn", "configure must bump the generation");
    make_popts(&po, "on_getpid");
    po.autoload = LMB_AUTOLOAD_ENABLE;
    CHECK(g->config(obj, &po) == 0, "b3b-config-enable",
          "autoload re-enable must succeed");
    make_pinfo(&pi);
    CHECK(g->pinfo(obj, &prog, &pi) == 0 && pi.autoload == 1 &&
              pi.generation == 2,
          "b3b-generation-churn2", "second configure bumps again");
    make_popts(&po, "no_such_program");
    CHECK(g->config(obj, &po) == -ENOENT, "b3b-config-unknown",
          "unknown program configure must report ENOENT");
    make_popts(&po, "no_such_program");
    po.attach_target.ptr = bad8;
    po.attach_target.len = sizeof(bad8);
    CHECK(g->config(obj, &po) == -EINVAL, "b3b-config-span-first",
          "span errors precede program lookup");
    make_popts(&po, "on_getpid_small");
    po.attach_target.ptr = (const uint8_t *)"some_symbol";
    po.attach_target.len = sizeof("some_symbol") - 1;
    CHECK(g->config(obj, &po) != 0, "b3b-config-target-rejected",
          "tracing target on tracepoint program must fail");

    /* Map/test/attach/buffer calls are load-gated. */
    make_v1name(&name, "test_hash");
    memset(&mi, 0, sizeof(mi));
    mi.abi_version = LMB_ABI_VERSION;
    mi.struct_size = sizeof(mi);
    CHECK(g->minfo(obj, &name, &mi) == -EINVAL,
          "b3b-minfo-unloaded", "map info needs a loaded object");
    CHECK(g->lookup(obj, &name, key, sizeof(key), dst, sizeof(dst),
                    &needed) == -EINVAL,
          "b3b-lookup-unloaded", "lookup needs a loaded object");
    CHECK(g->update(obj, &name, key, sizeof(key), dst, sizeof(dst),
                    LMB_MAP_UPDATE_ANY) == -EINVAL,
          "b3b-update-unloaded", "update needs a loaded object");
    make_topts(&to);
    make_tresult(&tr);
    make_v1name(&prog, "on_getpid");
    CHECK(g->testrun(obj, &prog, &to, &tr) == -EINVAL,
          "b3b-testrun-unloaded", "test-run needs a loaded object");
    make_aopts(&ao, "on_getpid");
    ao.target_a.ptr = (const uint8_t *)"syscalls";
    ao.target_a.len = sizeof("syscalls") - 1;
    ao.target_b.ptr = (const uint8_t *)"sys_enter_getpid";
    ao.target_b.len = sizeof("sys_enter_getpid") - 1;
    CHECK(g->attach(obj, &ao, &link) == -EINVAL && link == NULL,
          "b3b-attach-unloaded", "attach needs a loaded object");
    make_bopts(&bo, "events");
    CHECK(g->bufopen(obj, &bo, &buf) == -EINVAL && buf == NULL,
          "b3b-bufopen-unloaded", "buffer open needs a loaded object");

    CHECK(g->close(&obj) == 0 && obj == NULL, "b3b-close",
          "close must release the unloaded object");
}

/* B3c: retained owner-bound views on a valid unloaded object.
 * Views hold native references (ref/unref), capture the
 * configuration generation (gen), and reject stale use
 * (gen_check). None of it needs load or privilege: views,
 * moves, and parent release all work pre-load. */
static void part_b3c(struct gen_api *g, const uint8_t *elf,
                     uint64_t elf_len) {
    struct lmb_object_options_v1 o;
    struct lmb_program_options_v1 po;
    struct lmb_object *obj = NULL;
    struct lmb_object *moved = NULL;
    struct lmb_object *alias = NULL;
    uint64_t gen0 = 0xDEAD;
    uint64_t gen1 = 0xDEAD;
    uint64_t cur = 0xDEAD;
    int32_t code = 0;

    make_oopts(&o);
    o.log_level = LMB_LOG_DISCARD;
    o.log_capacity = 0;
    CHECK(g->open(elf, elf_len, &o, &obj) == 0 && obj != NULL,
          "b3c-open", "valid fixture must open unprivileged");
    if (obj == NULL)
        return;

    /* View-pointer validation uses its own operations. */
    CHECK(g->ref(NULL) == -EINVAL, "b3c-ref-null",
          "null view ref must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_VIEW_REF,
                 LMB_GENERIC_DOMAIN_BRIDGE, NULL),
          "b3c-ref-null-record", "ref failure must report view-ref");
    CHECK(g->gen(NULL, &cur) == -EINVAL, "b3c-gen-null-object",
          "null gen object must fail");
    CHECK(g->gen(obj, NULL) == -EINVAL, "b3c-gen-null-cell",
          "null gen cell must fail");
    CHECK(g->gencheck(NULL, 0) == -EINVAL, "b3c-check-null",
          "null check object must fail");
    g->unref(NULL);
    OK("b3c-unref-null");

    /* One view reference: capture, validate, view-only BUSY. */
    CHECK(g->ref(obj) == 0, "b3c-ref", "view ref must succeed");
    CHECK(g->gen(obj, &gen0) == 0 && gen0 == 0, "b3c-gen-zero",
          "fresh object generation must be zero");
    CHECK(g->gencheck(obj, gen0) == 0, "b3c-check-fresh",
          "fresh capture must validate");
    CHECK(g->close(&obj) == -EBUSY && obj != NULL,
          "b3c-view-busy", "close with only a view must report BUSY");
    CHECK(g->gen(obj, &cur) == 0 && cur == gen0,
          "b3c-busy-usable", "BUSY owner must stay usable");
    /* References count, not just mark: two refs need two unrefs. */
    CHECK(g->ref(obj) == 0, "b3c-ref-second",
          "second ref must succeed");
    g->unref(obj);
    CHECK(g->close(&obj) == -EBUSY && obj != NULL,
          "b3c-still-busy", "one surviving view must stay BUSY");
    g->unref(obj);
    CHECK(g->close(&obj) == 0 && obj == NULL, "b3c-close",
          "childless close must succeed");

    /* Stale-view rejection across a configuration bump. */
    make_oopts(&o);
    o.log_level = LMB_LOG_DISCARD;
    o.log_capacity = 0;
    CHECK(g->open(elf, elf_len, &o, &obj) == 0 && obj != NULL,
          "b3c-reopen", "valid fixture must open again");
    if (obj == NULL)
        return;
    CHECK(g->ref(obj) == 0, "b3c-stale-ref",
          "view ref must succeed");
    CHECK(g->gen(obj, &gen0) == 0, "b3c-stale-capture",
          "capture must succeed");
    make_popts(&po, "on_getpid");
    po.autoload = LMB_AUTOLOAD_DISABLE;
    CHECK(g->config(obj, &po) == 0, "b3c-stale-bump",
          "configure must bump the generation");
    CHECK(g->gen(obj, &gen1) == 0 && gen1 == gen0 + 1,
          "b3c-stale-churn", "generation must advance by one");
    CHECK(g->gencheck(obj, gen0) == -ESTALE, "b3c-stale",
          "superseded capture must report ESTALE");
    CHECK(gen_is(g, LMB_GENERIC_OP_VIEW_CHECK,
                 LMB_GENERIC_DOMAIN_BRIDGE, &code) &&
              code == -ESTALE,
          "b3c-stale-record", "stale check keeps signed ESTALE");
    CHECK(g->gencheck(obj, gen1) == 0, "b3c-current",
          "current capture must validate");
    g->unref(obj);
    CHECK(g->close(&obj) == 0 && obj == NULL, "b3c-stale-close",
          "close must succeed");

    /* Moves transfer the external handle; the view is unaffected. */
    make_oopts(&o);
    o.log_level = LMB_LOG_DISCARD;
    o.log_capacity = 0;
    CHECK(g->open(elf, elf_len, &o, &obj) == 0 && obj != NULL,
          "b3c-move-open", "valid fixture must open again");
    if (obj == NULL)
        return;
    CHECK(g->ref(obj) == 0, "b3c-move-ref",
          "view ref must succeed");
    CHECK(g->gen(obj, &gen0) == 0, "b3c-move-capture",
          "capture must succeed");
    moved = obj;
    obj = NULL;
    g->release(&obj);
    CHECK(obj == NULL, "b3c-move-nulls",
          "moved-from release must stay a no-op");
    CHECK(g->gen(moved, &cur) == 0 && cur == gen0,
          "b3c-moved-usable", "view must survive the owner move");
    CHECK(g->gencheck(moved, gen0) == 0, "b3c-moved-check",
          "capture must validate after the move");
    g->unref(moved);
    CHECK(g->close(&moved) == 0 && moved == NULL, "b3c-moved-close",
          "close must succeed");

    /* Parent release drops the external reference; the view keeps
     * the native state alive until the last unref. */
    make_oopts(&o);
    o.log_level = LMB_LOG_DISCARD;
    o.log_capacity = 0;
    CHECK(g->open(elf, elf_len, &o, &obj) == 0 && obj != NULL,
          "b3c-release-open", "valid fixture must open again");
    if (obj == NULL)
        return;
    CHECK(g->ref(obj) == 0, "b3c-release-ref",
          "view ref must succeed");
    CHECK(g->gen(obj, &gen0) == 0, "b3c-release-capture",
          "capture must succeed");
    alias = obj;
    g->release(&obj);
    CHECK(obj == NULL, "b3c-release-nulls",
          "release must null the owner with a live view");
    CHECK(g->gen(alias, &cur) == 0 && cur == gen0,
          "b3c-orphan-usable", "view must survive parent release");
    CHECK(g->gencheck(alias, gen0) == 0, "b3c-orphan-check",
          "capture must validate after release");
    g->unref(alias);
    OK("b3c-orphan-destroyed");
}

/* B4: diagnostic semantics. Needs a valid open for the
 * success-clears row, so the fixture gates only that row. */
static void part_b4(struct gen_api *g, struct v1_api *v1,
                    const uint8_t *elf, uint64_t elf_len) {
    struct lmb_object_options_v1 o;
    struct lmb_generic_error_v1 e1, e2;
    struct lmb_object *obj = NULL;
    uint32_t i;
    int tail_zero = 1;

    make_oopts(&o);
    o.abi_version = 99;
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
              -EINVAL,
          "b4-seed-failure", "seed failure must fail");
    memset(&e1, 0xAA, sizeof(e1));
    e1.abi_version = LMB_GENERIC_ABI_VERSION;
    e1.struct_size = sizeof(e1);
    CHECK(g->lasterr(&e1) == 0 &&
              e1.abi_version == LMB_GENERIC_ABI_VERSION &&
              e1.struct_size == sizeof(e1) &&
              e1.operation == LMB_GENERIC_OP_OBJECT_OPEN &&
              e1.domain == LMB_GENERIC_DOMAIN_BRIDGE &&
              e1.code == -EINVAL &&
              e1.msg_len <= LMB_GENERIC_MAX_MSG_LEN,
          "b4-record-shape", "record fields must be fully determined");
    for (i = e1.msg_len; i < LMB_GENERIC_ERROR_MSG_CAP; i++) {
        if (e1.message[i] != 0)
            tail_zero = 0;
    }
    CHECK(tail_zero, "b4-message-tail",
          "message tail past msg_len must be zeroed");
    memset(&e2, 0, sizeof(e2));
    e2.abi_version = LMB_GENERIC_ABI_VERSION;
    e2.struct_size = sizeof(e2);
    CHECK(g->lasterr(&e2) == 0 && memcmp(&e1, &e2, sizeof(e1)) == 0,
          "b4-retrieval-preserves",
          "consecutive retrieval must be identical");

    /* v1 and generic diagnostics are independent thread-local
     * records: failing one side never clobbers the other. */
    {
        struct lmb_error_v1 verr;
        struct lmb_session *sess = NULL;
        memset(&verr, 0, sizeof(verr));
        verr.abi_version = LMB_ABI_VERSION;
        verr.struct_size = sizeof(verr);
        CHECK(v1->open(garbage_elf, sizeof(garbage_elf), NULL, &sess) ==
                      -EINVAL &&
                  g->open(garbage_elf, sizeof(garbage_elf), &o,
                          &obj) == -EINVAL,
              "b4-seed-both", "both sides must fail");
        CHECK(v1->lasterr(&verr) == 0 &&
                  verr.operation == LMB_OP_OPEN &&
                  verr.domain == LMB_DOMAIN_BRIDGE,
              "b4-v1-intact", "generic failure must not clobber v1");
        CHECK(gen_is(g, LMB_GENERIC_OP_OBJECT_OPEN,
                     LMB_GENERIC_DOMAIN_BRIDGE, NULL),
              "b4-generic-intact",
              "v1 inspection must not clobber generic");
    }

    if (elf == NULL) {
        SKIP("b4-success-clears", "needs the fixture ELF");
        return;
    }
    make_oopts(&o);
    CHECK(g->open(elf, elf_len, &o, &obj) == 0 && obj != NULL,
          "b4-open-valid", "valid fixture must open");
    if (obj == NULL)
        return;
    memset(&e1, 0xAA, sizeof(e1));
    e1.abi_version = LMB_GENERIC_ABI_VERSION;
    e1.struct_size = sizeof(e1);
    CHECK(g->lasterr(&e1) == 0 && e1.operation == 0 &&
              e1.domain == 0 && e1.code == 0 && e1.msg_len == 0 &&
              e1.message[0] == 0,
          "b4-success-clears", "success must clear the generic record");
    CHECK(g->close(&obj) == 0, "b4-close", "close must succeed");
}

/* B5: pre-load ownership: null handling, double close, and the
 * success-clears side of trivial closes. */
static void part_b5(struct gen_api *g) {
    struct lmb_object_options_v1 o;
    struct lmb_object *obj = NULL;
    struct lmb_link *link = NULL;
    struct lmb_buffer *buf = NULL;

    CHECK(g->close(NULL) == -EINVAL, "b5-close-null-arg",
          "null close argument must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_OBJECT_CLOSE,
                 LMB_GENERIC_DOMAIN_BRIDGE, NULL),
          "b5-close-null-record", "close failure must report close op");
    CHECK(g->close(&obj) == 0, "b5-close-null-pointee",
          "null-pointee close must succeed");
    CHECK(gen_is(g, LMB_GENERIC_OP_NONE, LMB_GENERIC_DOMAIN_NONE,
                 NULL),
          "b5-close-null-clears",
          "trivial close success clears the record");
    g->release(NULL);
    OK("b5-release-null-arg");
    g->release(&obj);
    OK("b5-release-null-pointee");
    CHECK(g->linkclose(NULL) == -EINVAL, "b5-linkclose-null-arg",
          "null link close argument must fail");
    CHECK(g->linkclose(&link) == 0, "b5-linkclose-null-pointee",
          "null-pointee link close must succeed");
    CHECK(g->bufclose(NULL) == -EINVAL, "b5-bufclose-null-arg",
          "null buffer close argument must fail");
    CHECK(g->bufclose(&buf) == 0, "b5-bufclose-null-pointee",
          "null-pointee buffer close must succeed");

    /* A failing call followed by a trivial close leaves a clear
     * record: successes always clear, even trivial ones. */
    make_oopts(&o);
    o.abi_version = 99;
    CHECK(g->open(garbage_elf, sizeof(garbage_elf), &o, &obj) ==
                  -EINVAL &&
              g->close(&obj) == 0,
          "b5-seed-then-trivial", "seed then trivial close");
    CHECK(gen_is(g, LMB_GENERIC_OP_NONE, LMB_GENERIC_DOMAIN_NONE,
                 NULL),
          "b5-trivial-clears", "trivial success clears the record");
}

static int open_loaded(struct gen_api *g, const uint8_t *elf,
                       uint64_t elf_len, uint32_t log_level,
                       uint64_t log_capacity, struct lmb_object **obj) {
    struct lmb_object_options_v1 o;
    make_oopts(&o);
    o.log_level = log_level;
    o.log_capacity = log_capacity;
    *obj = NULL;
    if (g->open(elf, elf_len, &o, obj) != 0 || *obj == NULL)
        return -1;
    if (g->load(*obj) != 0) {
        g->close(obj);
        return -1;
    }
    return 0;
}

/* B6a: load, post-load gating, verifier-log consistency. */
static void part_b6a(struct gen_api *g, const uint8_t *elf,
                     uint64_t elf_len) {
    struct lmb_object *obj = NULL;
    struct lmb_object *discard = NULL;
    struct lmb_program_options_v1 po;
    struct lmb_program_info_v1 pi;
    struct lmb_name_v1 prog;
    uint8_t storage[8];
    uint64_t actual = 0;
    uint32_t trunc = 0;

    CHECK(open_loaded(g, elf, elf_len, LMB_LOG_ALWAYS, 4096, &obj) ==
                  0 &&
              obj != NULL,
          "b6a-load", "valid fixture must load with privilege");
    if (obj == NULL)
        return;
    CHECK(g->load(obj) == -EINVAL, "b6a-second-load",
          "second load must fail");
    make_popts(&po, "on_getpid");
    po.autoload = LMB_AUTOLOAD_UNCHANGED;
    CHECK(g->config(obj, &po) == -EINVAL, "b6a-config-after-load",
          "configure after load must fail");
    CHECK(gen_is(g, LMB_GENERIC_OP_PROGRAM_CONFIGURE,
                 LMB_GENERIC_DOMAIN_BRIDGE, NULL),
          "b6a-config-after-load-record",
          "late configure reports configure op");

    /* Log copy-out consistency holds whatever the log size is. */
    make_v1name(&prog, "on_getpid");
    make_pinfo(&pi);
    CHECK(g->pinfo(obj, &prog, &pi) == 0, "b6a-pinfo-loaded",
          "post-load info must succeed");
    actual = pi.log_actual;
    trunc = pi.log_truncated;
    CHECK(trunc == (actual > 0 ? 1u : 0u), "b6a-log-flag",
          "truncated flag must match actual length");
    memset(storage, 0xA5, sizeof(storage));
    make_pinfo(&pi);
    pi.log.ptr = storage;
    pi.log.len = sizeof(storage);
    CHECK(g->pinfo(obj, &prog, &pi) == 0 &&
              pi.log_actual == actual &&
              pi.log_truncated == (actual > sizeof(storage) ? 1u : 0u),
          "b6a-log-consistent", "log lengths must be storage-stable");
    if (actual < sizeof(storage)) {
        uint64_t i;
        int intact = 1;
        for (i = actual; i < sizeof(storage); i++) {
            if (storage[i] != 0xA5)
                intact = 0;
        }
        CHECK(intact, "b6a-log-tail",
              "log copy must write exactly actual bytes");
    } else {
        printf("note b6a-log-tail: log fills the 8-byte window\n");
    }
    /* Forced truncation: ALWAYS with capacity over a fixture
     * that verifies verbosely is the controlled nonempty seed:
     * the kernel log for on_getpid is deterministically
     * nonempty, so empty retention is a bridge defect and FAILs
     * here (the DISCARD check below is the contrast control,
     * proving empty means discarded, never silently truncated).
     * A short window must then deliver the exact prefix with
     * the flag set and the guard bytes intact. */
    CHECK(actual > 0, "b6a-log-nonempty",
          "ALWAYS load must retain a nonempty log");
    printf("note b6a-log-seed: %llu retained bytes\n",
           (unsigned long long)actual);
    {
        uint64_t small =
            actual > 16 ? 16 : (actual > 1 ? actual - 1 : 0);
        uint8_t *full = malloc(actual ? (size_t)actual : 1);
        uint8_t *part = malloc((size_t)small + 16);
        if (full == NULL || part == NULL) {
            FAIL("b6a-truncated-alloc", "out of memory");
        } else {
            uint64_t i;
            int intact = 1;
            make_pinfo(&pi);
            pi.log.ptr = full;
            pi.log.len = actual;
            CHECK(g->pinfo(obj, &prog, &pi) == 0 &&
                      pi.log_actual == actual &&
                      pi.log_truncated == 0,
                  "b6a-log-full",
                  "full window must deliver without truncation");
            for (i = 0; i < 16; i++)
                part[small + i] = 0xA5;
            make_pinfo(&pi);
            pi.log.ptr = part;
            pi.log.len = small;
            CHECK(g->pinfo(obj, &prog, &pi) == 0 &&
                      pi.log_actual == actual &&
                      pi.log_truncated == 1 &&
                      memcmp(part, full, (size_t)small) == 0,
                  "b6a-truncated",
                  "short window must deliver the exact prefix");
            for (i = 0; i < 16; i++) {
                if (part[small + i] != 0xA5)
                    intact = 0;
            }
            CHECK(intact, "b6a-truncated-guard",
                  "truncated copy must not overrun");
        }
        free(full);
        free(part);
    }
    CHECK(g->close(&obj) == 0, "b6a-close", "close must succeed");

    /* Discard mode retains nothing, deterministically. */
    CHECK(open_loaded(g, elf, elf_len, LMB_LOG_DISCARD, 0, &discard) ==
                  0 &&
              discard != NULL,
          "b6a-load-discard", "discard-mode load must succeed");
    if (discard == NULL)
        return;
    make_pinfo(&pi);
    CHECK(g->pinfo(discard, &prog, &pi) == 0 && pi.log_actual == 0 &&
              pi.log_truncated == 0,
          "b6a-discard-empty", "discard mode must retain no log");
    CHECK(g->close(&discard) == 0, "b6a-close-discard",
          "close must succeed");
}

/* B6b: checked map access on a loaded object. */
static void part_b6b(struct gen_api *g, const uint8_t *elf,
                     uint64_t elf_len) {
    struct lmb_object *obj = NULL;
    struct lmb_name_v1 name;
    struct lmb_map_info_v1 mi;
    uint32_t key = 7;
    uint32_t pkey = 0;
    uint64_t value = 0x0102030405060708ULL;
    uint64_t got = 0;
    uint64_t needed = 0;
    uint8_t small[4] = {0xAA, 0xAA, 0xAA, 0xAA};
    uint32_t ncpus = 0;
    uint32_t i;

    CHECK(open_loaded(g, elf, elf_len, LMB_LOG_DISCARD, 0, &obj) ==
                  0 &&
              obj != NULL,
          "b6b-load", "fixture must load");
    if (obj == NULL)
        return;
    make_v1name(&name, "test_hash");
    memset(&mi, 0, sizeof(mi));
    mi.abi_version = LMB_ABI_VERSION;
    mi.struct_size = sizeof(mi);
    CHECK(g->minfo(obj, &name, &mi) == 0 &&
              mi.type == BPF_MAP_TYPE_HASH && mi.key_size == 4 &&
              mi.value_size == 8 && mi.max_entries == 64,
          "b6b-hash-info", "hash geometry must match the fixture");
    make_v1name(&name, "no_such_map");
    CHECK(g->minfo(obj, &name, &mi) == -ENOENT,
          "b6b-unknown-map", "unknown map must report ENOENT");
    make_v1name(&name, "test_hash");
    CHECK(g->update(obj, &name, (const uint8_t *)&key, 4,
                    (const uint8_t *)&value, 8,
                    LMB_MAP_UPDATE_ANY) == 0,
          "b6b-write", "hash write must succeed");
    needed = 0;
    CHECK(g->lookup(obj, &name, (const uint8_t *)&key, 4,
                    (uint8_t *)&got, 8, &needed) == 0 &&
              got == value && needed == 0,
          "b6b-roundtrip", "hash read must return the written value");
    key = 0xBEEF;
    needed = 0;
    {
        int32_t code = 0;
        CHECK(g->lookup(obj, &name, (const uint8_t *)&key, 4,
                        (uint8_t *)&got, 8, &needed) == -ENOENT &&
                  needed == 0,
              "b6b-missing-key", "missing key must report ENOENT");
        CHECK(gen_is(g, LMB_GENERIC_OP_MAP_LOOKUP,
                     LMB_GENERIC_DOMAIN_KERNEL, &code) &&
                  code < 0,
              "b6b-missing-key-record",
              "kernel miss keeps signed code");
    }
    key = 7;
    CHECK(g->lookup(obj, &name, (const uint8_t *)&key, 8,
                    (uint8_t *)&got, 8, &needed) == -EINVAL,
          "b6b-bad-key-size", "wrong key size must fail");
    CHECK(g->update(obj, &name, (const uint8_t *)&key, 4,
                    (const uint8_t *)&value, 4,
                    LMB_MAP_UPDATE_ANY) == -EINVAL,
          "b6b-bad-value-size", "wrong value size must fail");
    needed = 0;
    CHECK(g->lookup(obj, &name, (const uint8_t *)&key, 4, small,
                    sizeof(small), &needed) == -ENOSPC &&
              needed == 8 && small[0] == 0xAA,
          "b6b-short-read", "short read must report needed untouched");
    CHECK(gen_is(g, LMB_GENERIC_OP_MAP_LOOKUP,
                 LMB_GENERIC_DOMAIN_BRIDGE, NULL),
          "b6b-short-read-record", "short read reports bridge ENOSPC");
    {
        uint8_t zone[16 + 8 + 16];
        for (i = 0; i < 16; i++) {
            zone[i] = 0xA5;
            zone[16 + 8 + i] = 0xA5;
        }
        needed = 0;
        CHECK(g->lookup(obj, &name, (const uint8_t *)&key, 4,
                        zone + 16, 8, &needed) == 0 &&
                  memcmp(zone + 16, &value, 8) == 0 &&
                  zone[0] == 0xA5 && zone[16 + 8] == 0xA5,
              "b6b-guarded", "guarded read must match exactly");
    }

    /* Explicit update flags reach the kernel unchanged. */
    key = 0xC0DE;
    CHECK(g->update(obj, &name, (const uint8_t *)&key, 4,
                    (const uint8_t *)&value, 8,
                    LMB_MAP_UPDATE_NOEXIST) == 0,
          "b6b-noexist-new", "NOEXIST on missing key must create");
    CHECK(g->update(obj, &name, (const uint8_t *)&key, 4,
                    (const uint8_t *)&value, 8,
                    LMB_MAP_UPDATE_NOEXIST) == -EEXIST,
          "b6b-noexist-existing", "NOEXIST on present key must fail");
    key = 0xDEAD;
    CHECK(g->update(obj, &name, (const uint8_t *)&key, 4,
                    (const uint8_t *)&value, 8,
                    LMB_MAP_UPDATE_EXIST) == -ENOENT,
          "b6b-exist-missing", "EXIST on missing key must fail");
    key = 7;
    CHECK(g->update(obj, &name, (const uint8_t *)&key, 4,
                    (const uint8_t *)&value, 8, 3) == -EINVAL,
          "b6b-flags-combo", "NOEXIST|EXIST must fail");
    CHECK(g->update(obj, &name, (const uint8_t *)&key, 4,
                    (const uint8_t *)&value, 8, 8) == -EINVAL,
          "b6b-flags-high", "high flag bits must fail");
    {
        int32_t code = 0;
        CHECK(g->update(obj, &name, (const uint8_t *)&key, 4,
                        (const uint8_t *)&value, 8,
                        LMB_MAP_UPDATE_LOCK) != 0,
              "b6b-flags-lock", "LOCK without spinlock must fail");
        CHECK(gen_is(g, LMB_GENERIC_OP_MAP_UPDATE,
                     LMB_GENERIC_DOMAIN_KERNEL, &code) &&
                  code < 0,
              "b6b-flags-lock-record",
              "kernel flag refusal keeps signed code");
    }

    /* Per-CPU spread sizing. */
    make_v1name(&name, "test_percpu");
    memset(&mi, 0, sizeof(mi));
    mi.abi_version = LMB_ABI_VERSION;
    mi.struct_size = sizeof(mi);
    CHECK(g->minfo(obj, &name, &mi) == 0 &&
              mi.type == BPF_MAP_TYPE_PERCPU_ARRAY &&
              mi.value_size == 8 && mi.stride == 8 &&
              mi.num_cpus > 0,
          "b6b-percpu-info", "percpu geometry must match");
    ncpus = mi.num_cpus;
    {
        uint64_t need = (uint64_t)mi.stride * ncpus;
        uint8_t *spread = malloc(need ? (size_t)need : 1);
        int match = 1;
        if (spread == NULL) {
            FAIL("b6b-percpu-alloc", "out of memory");
        } else {
            for (i = 0; i < ncpus; i++)
                memcpy(spread + (size_t)i * mi.stride, &value, 8);
            CHECK(g->update(obj, &name, (const uint8_t *)&pkey, 4,
                            spread, need - 1,
                            LMB_MAP_UPDATE_ANY) != 0,
                  "b6b-percpu-short-write",
                  "partial spread write must fail");
            CHECK(g->update(obj, &name, (const uint8_t *)&pkey, 4,
                            spread, need,
                            LMB_MAP_UPDATE_ANY) == 0,
                  "b6b-percpu-write", "full spread write must succeed");
            memset(spread, 0, (size_t)need);
            needed = 0;
            CHECK(g->lookup(obj, &name, (const uint8_t *)&pkey, 4,
                            spread, need, &needed) == 0,
                  "b6b-percpu-read", "full spread read must succeed");
            for (i = 0; i < ncpus; i++) {
                uint64_t slot = 0;
                memcpy(&slot, spread + (size_t)i * mi.stride, 8);
                if (slot != value)
                    match = 0;
            }
            CHECK(match, "b6b-percpu-roundtrip",
                  "spread slots must match");
            needed = 0;
            CHECK(g->lookup(obj, &name, (const uint8_t *)&pkey, 4,
                            spread, need - 1, &needed) == -ENOSPC &&
                      needed == need,
                  "b6b-percpu-short-read",
                  "short spread read must report size");
            free(spread);
        }
    }
    CHECK(g->close(&obj) == 0, "b6b-close", "close must succeed");
}

/* B6c: program test-run. The kernel may decline tracepoint
 * execution on some targets; both outcomes prove their output
 * table (success fields vs unchanged-on-failure). */
static void check_testrun(struct gen_api *g, struct lmb_object *obj,
                          const char *progname, int same_buffer,
                          int expect_retval) {
    struct lmb_name_v1 prog;
    struct lmb_program_test_options_v1 to;
    struct lmb_program_test_result_v1 tr, tr_before;
    uint8_t data[128];
    uint8_t ctx[16];
    /* Function scope: the input span below borrows this buffer
     * through the test-run call, so it must outlive the call. */
    uint8_t pkt[64];
    uint64_t i;
    int32_t rc;
    int intact;

    make_v1name(&prog, progname);
    make_topts(&to);
    for (i = 0; i < sizeof(data); i++)
        data[i] = (uint8_t)(i & 0xFF);
    memset(ctx, 0xA5, sizeof(ctx));
    if (same_buffer) {
        to.data_in.ptr = data;
        to.data_in.len = 64;
        to.data_out.ptr = data;
        to.data_out.len = sizeof(data);
    } else {
        for (i = 0; i < sizeof(pkt); i++)
            pkt[i] = (uint8_t)(0xC0 + (i & 0x3F));
        memset(data, 0xA5, sizeof(data));
        to.data_in.ptr = pkt;
        to.data_in.len = sizeof(pkt);
        to.data_out.ptr = data;
        to.data_out.len = sizeof(data);
    }
    to.ctx_out.ptr = ctx;
    to.ctx_out.len = sizeof(ctx);
    memset(&tr_before, 0xAA, sizeof(tr_before));
    tr_before.abi_version = LMB_GENERIC_ABI_VERSION;
    tr_before.struct_size = sizeof(tr_before);
    tr = tr_before;
    rc = g->testrun(obj, &prog, &to, &tr);
    if (rc == 0) {
        intact = 1;
        CHECK(tr.data_actual <= sizeof(data) && tr.ctx_actual == 0 &&
                  tr._pad == 0,
              same_buffer ? "b6c-aliased-shape" : "b6c-shape",
              "success outputs must be bounded and padded zero");
        if (expect_retval)
            CHECK(tr.retval == 0, "b6c-retval",
                  "tracepoint fixture must return 0");
        for (i = tr.data_actual; i < sizeof(data); i++) {
            uint8_t want =
                same_buffer ? (uint8_t)(i & 0xFF) : 0xA5;
            if (data[i] != want)
                intact = 0;
        }
        for (i = tr.ctx_actual; i < sizeof(ctx); i++) {
            if (ctx[i] != 0xA5)
                intact = 0;
        }
        CHECK(intact, same_buffer ? "b6c-aliased-guards" : "b6c-guards",
              "outputs must write exactly actual bytes");
        printf("note b6c-duration: %llu ns\n",
               (unsigned long long)tr.duration_ns);
        return;
    }
    {
        int32_t code = 0;
        CHECK(gen_is(g, LMB_GENERIC_OP_TEST_RUN,
                     LMB_GENERIC_DOMAIN_KERNEL, &code) &&
                  code < 0,
              same_buffer ? "b6c-aliased-declined" : "b6c-declined",
              "kernel decline keeps signed code");
    }
    CHECK(memcmp(&tr, &tr_before, sizeof(tr)) == 0,
          same_buffer ? "b6c-aliased-unchanged" : "b6c-unchanged",
          "runtime failure must leave the result unchanged");
    intact = 1;
    for (i = 0; i < sizeof(data); i++) {
        uint8_t want = same_buffer ? (uint8_t)(i & 0xFF) : 0xA5;
        if (data[i] != want)
            intact = 0;
    }
    for (i = 0; i < sizeof(ctx); i++) {
        if (ctx[i] != 0xA5)
            intact = 0;
    }
    CHECK(intact, same_buffer ? "b6c-aliased-out-untouched"
                              : "b6c-out-untouched",
          "runtime failure must leave outputs untouched");
    SKIP(same_buffer ? "b6c-aliased-exec" : "b6c-exec",
         "target declined tracepoint test-run execution");
}

static void part_b6c(struct gen_api *g, const uint8_t *elf,
                     uint64_t elf_len) {
    struct lmb_object *obj = NULL;
    const char *prog = getenv("LMB_TEST_RUN_PROGRAM");
    int pinned = 0;
    if (prog == NULL || prog[0] == '\0')
        prog = "on_getpid";
    pinned = strcmp(prog, "on_getpid") == 0;

    CHECK(open_loaded(g, elf, elf_len, LMB_LOG_DISCARD, 0, &obj) ==
                  0 &&
              obj != NULL,
          "b6c-load", "fixture must load");
    if (obj == NULL)
        return;
    check_testrun(g, obj, prog, 0, pinned);
    check_testrun(g, obj, prog, 1, pinned);
    CHECK(g->close(&obj) == 0, "b6c-close", "close must succeed");
}

/* Arm the fixture PID filter for this process (keys 0/1/2:
 * TGID plus st_dev/st_ino of our PID namespace). */
static int arm_filter(struct gen_api *g, struct lmb_object *obj) {
    struct lmb_name_v1 name;
    struct stat st;
    uint32_t key;
    uint8_t val[8];
    uint64_t tgid;
    make_v1name(&name, "filter");
    tgid = (uint64_t)getpid();
    if (stat("/proc/self/ns/pid", &st) != 0)
        return -1;
    key = 0;
    put_le64(val, tgid);
    if (g->update(obj, &name, (const uint8_t *)&key, 4, val, 8,
                  LMB_MAP_UPDATE_ANY) != 0)
        return -1;
    key = 1;
    put_le64(val, (uint64_t)st.st_dev);
    if (g->update(obj, &name, (const uint8_t *)&key, 4, val, 8,
                  LMB_MAP_UPDATE_ANY) != 0)
        return -1;
    key = 2;
    put_le64(val, (uint64_t)st.st_ino);
    if (g->update(obj, &name, (const uint8_t *)&key, 4, val, 8,
                  LMB_MAP_UPDATE_ANY) != 0)
        return -1;
    return 0;
}

/* B6d: attach, buffer open, poll contract, and one exact event. */
static void part_b6d(struct gen_api *g, const uint8_t *elf,
                     uint64_t elf_len) {
    struct lmb_object *obj = NULL;
    struct lmb_link *link = NULL;
    struct lmb_buffer *buf = NULL;
    struct lmb_attach_options_v1 ao;
    struct lmb_buffer_options_v1 bo;
    uint8_t dst[4104];
    uint8_t tiny[23];
    uint64_t used = 0;
    uint64_t needed = 0;
    uint64_t tgid;
    int i;
    int drained;

    CHECK(open_loaded(g, elf, elf_len, LMB_LOG_DISCARD, 0, &obj) ==
                  0 &&
              obj != NULL,
          "b6d-load", "fixture must load");
    if (obj == NULL)
        return;
    make_aopts(&ao, "on_getpid");
    ao.target_a.ptr = (const uint8_t *)"syscalls";
    ao.target_a.len = sizeof("syscalls") - 1;
    ao.target_b.ptr = (const uint8_t *)"sys_enter_getpid";
    ao.target_b.len = sizeof("sys_enter_getpid") - 1;
    CHECK(g->attach(obj, &ao, &link) == 0 && link != NULL,
          "b6d-attach", "tracepoint attach must succeed");
    if (link == NULL) {
        g->close(&obj);
        return;
    }
    {
        struct lmb_link *bad = NULL;
        make_aopts(&ao, "no_such_program");
        ao.target_a.ptr = (const uint8_t *)"syscalls";
        ao.target_a.len = sizeof("syscalls") - 1;
        ao.target_b.ptr = (const uint8_t *)"sys_enter_getpid";
        ao.target_b.len = sizeof("sys_enter_getpid") - 1;
        CHECK(g->attach(obj, &ao, &bad) == -ENOENT && bad == NULL,
              "b6d-attach-unknown",
              "unknown program attach must fail cleared");
    }
    make_bopts(&bo, "events");
    CHECK(g->bufopen(obj, &bo, &buf) == 0 && buf != NULL,
          "b6d-bufopen", "buffer open must succeed");
    if (buf == NULL) {
        g->linkclose(&link);
        g->close(&obj);
        return;
    }
    {
        struct lmb_buffer *bad = NULL;
        make_bopts(&bo, "no_such_ring");
        CHECK(g->bufopen(obj, &bo, &bad) == -ENOENT && bad == NULL,
              "b6d-bufopen-unknown",
              "unknown ring open must fail cleared");
    }

    /* Timeout and output-cell validation need no events. */
    used = 99;
    needed = 99;
    CHECK(g->bufpoll(buf, dst, sizeof(dst), 0, &used, &needed) == 0 &&
              used == 0 && needed == 0,
          "b6d-timeout", "empty poll must report 0/0");
    CHECK(g->bufpoll(buf, dst, sizeof(dst), 0, NULL, &needed) ==
              -EINVAL,
          "b6d-poll-null-used", "null used cell must fail");
    CHECK(g->bufpoll(buf, dst, sizeof(dst), 0, &used, &used) ==
              -EINVAL,
          "b6d-poll-same-cells", "shared out cells must fail");
    CHECK(g->bufpoll(buf, dst, sizeof(dst), 0, (uint64_t *)(dst + 8),
                     &needed) == -EINVAL,
          "b6d-poll-used-in-dst", "used inside dst must fail");
    CHECK(g->bufpoll(buf, dst, sizeof(dst), 0, &used,
                     (uint64_t *)(dst + 8)) == -EINVAL,
          "b6d-poll-needed-in-dst", "needed inside dst must fail");

    /* One exact event: drain, arm, trap once, then prove
     * retain-across-retries plus exactly-once delivery. */
    if (arm_filter(g, obj) != 0) {
        FAIL("b6d-arm", "filter arming must succeed");
        goto out;
    }
    drained = 1;
    for (i = 0; i < 10; i++) {
        used = 99;
        needed = 99;
        if (g->bufpoll(buf, dst, sizeof(dst), 0, &used, &needed) !=
                0 ||
            used != 0 || needed != 0) {
            drained = 0;
            break;
        }
    }
    CHECK(drained, "b6d-drain", "pre-workload ring must be empty");
    tgid = (uint64_t)getpid();
    syscall(SYS_getpid);
    used = 99;
    needed = 99;
    CHECK(g->bufpoll(buf, NULL, 0, 100, &used, &needed) == -ENOSPC &&
              used == 0 && needed == 24,
          "b6d-staged", "one trap must stage one 24-byte frame");
    for (i = 0; i < 3; i++) {
        memset(tiny, 0xA5, sizeof(tiny));
        used = 99;
        needed = 99;
        if (g->bufpoll(buf, tiny, sizeof(tiny), 0, &used,
                       &needed) != -ENOSPC ||
            used != 0 || needed != 24 || tiny[0] != 0xA5 ||
            tiny[sizeof(tiny) - 1] != 0xA5) {
            FAIL("b6d-retained", "short retry %d must retain", i);
            goto out;
        }
    }
    OK("b6d-retained");
    memset(dst, 0xA5, sizeof(dst));
    used = 0;
    needed = 0;
    CHECK(g->bufpoll(buf, dst, 24, 0, &used, &needed) == 0 &&
              used == 24 && needed == 0 && le32(dst) == 16 &&
              le16(dst + 4) == LMB_GENERIC_FRAME_VERSION &&
              le16(dst + 6) == 0 && le32(dst + 8) == (uint32_t)tgid &&
              le32(dst + 12) == 0xA02u,
          "b6d-deliver", "retry must deliver the frame exactly once");
    used = 99;
    needed = 99;
    CHECK(g->bufpoll(buf, dst, sizeof(dst), 0, &used, &needed) == 0 &&
              used == 0 && needed == 0,
          "b6d-consumed", "delivered frame must not repeat");

out:
    CHECK(g->bufclose(&buf) == 0 && buf == NULL, "b6d-bufclose",
          "buffer close must succeed");
    CHECK(g->bufclose(&buf) == 0, "b6d-bufclose-again",
          "double buffer close must succeed");
    CHECK(g->linkclose(&link) == 0 && link == NULL, "b6d-linkclose",
          "link close must succeed");
    CHECK(g->linkclose(&link) == 0, "b6d-linkclose-again",
          "double link close must succeed");
    CHECK(g->close(&obj) == 0, "b6d-close", "close must succeed");
}

/* B6e: explicit-close BUSY versus destructor release, with FD
 * stability across both teardown orders. */
static void part_b6e(struct gen_api *g, const uint8_t *elf,
                     uint64_t elf_len) {
    struct lmb_object *obj = NULL;
    struct lmb_link *link = NULL;
    struct lmb_buffer *buf = NULL;
    struct lmb_object *view = NULL;
    struct lmb_attach_options_v1 ao;
    struct lmb_buffer_options_v1 bo;
    struct lmb_name_v1 name;
    struct lmb_map_info_v1 mi;
    uint8_t dst[64];
    uint64_t used = 0;
    uint64_t needed = 0;
    uint64_t vgen = 0;
    long fds0, fds1, fds2;

    make_aopts(&ao, "on_getpid");
    ao.target_a.ptr = (const uint8_t *)"syscalls";
    ao.target_a.len = sizeof("syscalls") - 1;
    ao.target_b.ptr = (const uint8_t *)"sys_enter_getpid";
    ao.target_b.len = sizeof("sys_enter_getpid") - 1;
    make_bopts(&bo, "events");
    make_v1name(&name, "test_hash");

    /* Child-first teardown, then a clean explicit close. */
    fds0 = count_fds();
    CHECK(open_loaded(g, elf, elf_len, LMB_LOG_DISCARD, 0, &obj) ==
              0,
          "b6e-load-y", "fixture must load");
    if (obj == NULL)
        return;
    CHECK(g->attach(obj, &ao, &link) == 0 && link != NULL,
          "b6e-attach-y", "attach must succeed");
    CHECK(g->bufopen(obj, &bo, &buf) == 0 && buf != NULL,
          "b6e-bufopen-y", "buffer open must succeed");
    if (link == NULL || buf == NULL) {
        /* A surviving child keeps explicit close BUSY, so drop
         * children first and release the parent: no reference
         * may be lost on a failure exit. */
        if (buf != NULL)
            g->bufclose(&buf);
        if (link != NULL)
            g->linkclose(&link);
        g->release(&obj);
        return;
    }
    CHECK(g->bufclose(&buf) == 0 && buf == NULL, "b6e-bufclose-y",
          "child-first buffer close must succeed");
    CHECK(g->linkclose(&link) == 0 && link == NULL, "b6e-linkclose-y",
          "child-first link close must succeed");
    CHECK(g->close(&obj) == 0 && obj == NULL, "b6e-close-y",
          "childless close must succeed");
    fds1 = count_fds();
    CHECK(fds0 >= 0 && fds1 == fds0, "b6e-fds-y",
          "child-first cycle must leak no FDs");

    /* Release-first teardown: BUSY preserves a usable owner;
     * release nulls it while children survive. */
    CHECK(open_loaded(g, elf, elf_len, LMB_LOG_DISCARD, 0, &obj) ==
              0,
          "b6e-load-x", "fixture must load again");
    if (obj == NULL)
        return;
    CHECK(g->attach(obj, &ao, &link) == 0 && link != NULL,
          "b6e-attach-x", "attach must succeed");
    CHECK(g->bufopen(obj, &bo, &buf) == 0 && buf != NULL,
          "b6e-bufopen-x", "buffer open must succeed");
    if (link == NULL || buf == NULL) {
        /* Same BUSY-safe unwind as the child-first cycle. */
        if (buf != NULL)
            g->bufclose(&buf);
        if (link != NULL)
            g->linkclose(&link);
        g->release(&obj);
        return;
    }
    CHECK(g->close(&obj) == -EBUSY && obj != NULL,
          "b6e-busy", "close with live children must report BUSY");
    CHECK(gen_is(g, LMB_GENERIC_OP_OBJECT_CLOSE,
                 LMB_GENERIC_DOMAIN_BRIDGE, NULL),
          "b6e-busy-record", "BUSY must report the close op");
    memset(&mi, 0, sizeof(mi));
    mi.abi_version = LMB_ABI_VERSION;
    mi.struct_size = sizeof(mi);
    CHECK(g->minfo(obj, &name, &mi) == 0, "b6e-busy-usable",
          "BUSY owner must stay usable");
    used = 99;
    needed = 99;
    CHECK(g->bufpoll(buf, dst, sizeof(dst), 0, &used, &needed) == 0 &&
              used == 0 && needed == 0,
          "b6e-child-usable", "child of BUSY owner must work");
    /* A retained view joins the children: it survives the
     * release with them and counts toward the last release. */
    CHECK(g->ref(obj) == 0, "b6e-view-ref",
          "view ref must succeed");
    CHECK(g->gen(obj, &vgen) == 0, "b6e-view-capture",
          "capture must succeed");
    view = obj;
    g->release(&obj);
    CHECK(obj == NULL, "b6e-release-nulls",
          "release must null the owner with children");
    used = 99;
    needed = 99;
    CHECK(g->bufpoll(buf, dst, sizeof(dst), 0, &used, &needed) == 0 &&
              used == 0 && needed == 0,
          "b6e-orphan-usable", "child must survive parent release");
    CHECK(g->gencheck(view, vgen) == 0, "b6e-view-orphan",
          "view must survive parent release");
    CHECK(g->bufclose(&buf) == 0 && buf == NULL, "b6e-bufclose-x",
          "orphaned buffer close must succeed");
    CHECK(g->linkclose(&link) == 0 && link == NULL, "b6e-linkclose-x",
          "orphaned link close must succeed");
    g->unref(view);
    OK("b6e-view-unref");
    g->release(&obj);
    OK("b6e-release-again");
    fds2 = count_fds();
    CHECK(fds2 == fds0, "b6e-fds-x",
          "release-first cycle must leak no FDs");
}

static void part_b6(struct gen_api *g, const uint8_t *elf,
                    uint64_t elf_len) {
    if (elf == NULL) {
        SKIP("b6", "needs the fixture ELF");
        return;
    }
    if (!has_privilege()) {
        const char *force = getenv("LMB_ASSUME_PRIVILEGE");
        if (force == NULL || strcmp(force, "1") != 0) {
            SKIP("b6", "missing collection privileges");
            return;
        }
        printf("note b6-assumed-privilege: load-gated sections run "
               "without host privilege (differential stub only)\n");
    }
    part_b6a(g, elf, elf_len);
    part_b6b(g, elf, elf_len);
    part_b6c(g, elf, elf_len);
    part_b6d(g, elf, elf_len);
    part_b6e(g, elf, elf_len);
}

int main(int argc, char **argv) {
    const char *bpath;
    const char *fixture = NULL;
    uint8_t *elf = NULL;
    uint64_t elf_len = 0;
    void *bhdl = NULL;
    struct gen_api g;
    struct v1_api v1;
    int present = 0;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <lib.so> [fixture.bpf.o]\n",
                argv[0]);
        return 2;
    }
    if (part_a(argv[1]) != 0)
        return 2;
    const char *host_only = getenv("LMB_HOST_ONLY");
    if (host_only != NULL && strcmp(host_only, "1") == 0) {
        printf("NOT_RUN generic-behavior: host-only scope\n");
        printf("probe: Part A %d ok, %d skipped, %d failed; "
               "Part B NOT_RUN\n", oks, skips, failures);
        return failures ? 1 : 0;
    }
    bpath = getenv("LMB_GENERIC_LIB");
    if (bpath == NULL || bpath[0] == '\0')
        bpath = argv[1];
    bhdl = dlopen(bpath, RTLD_NOW | RTLD_LOCAL);
    if (!bhdl) {
        printf("probe: cannot dlopen %s: %s\n", bpath, dlerror());
        return 2;
    }
    resolve(bhdl, gen_names[0], &g.open, sizeof(g.open));
    resolve(bhdl, gen_names[1], &g.config, sizeof(g.config));
    resolve(bhdl, gen_names[2], &g.load, sizeof(g.load));
    resolve(bhdl, gen_names[3], &g.pinfo, sizeof(g.pinfo));
    resolve(bhdl, gen_names[4], &g.minfo, sizeof(g.minfo));
    resolve(bhdl, gen_names[5], &g.close, sizeof(g.close));
    resolve(bhdl, gen_names[6], &g.release, sizeof(g.release));
    resolve(bhdl, gen_names[7], &g.lasterr, sizeof(g.lasterr));
    resolve(bhdl, gen_names[8], &g.lookup, sizeof(g.lookup));
    resolve(bhdl, gen_names[9], &g.update, sizeof(g.update));
    resolve(bhdl, gen_names[10], &g.testrun, sizeof(g.testrun));
    resolve(bhdl, gen_names[11], &g.attach, sizeof(g.attach));
    resolve(bhdl, gen_names[12], &g.linkclose, sizeof(g.linkclose));
    resolve(bhdl, gen_names[13], &g.bufopen, sizeof(g.bufopen));
    resolve(bhdl, gen_names[14], &g.bufpoll, sizeof(g.bufpoll));
    resolve(bhdl, gen_names[15], &g.bufclose, sizeof(g.bufclose));
    resolve(bhdl, gen_names[16], &g.ref, sizeof(g.ref));
    resolve(bhdl, gen_names[17], &g.unref, sizeof(g.unref));
    resolve(bhdl, gen_names[18], &g.gen, sizeof(g.gen));
    resolve(bhdl, gen_names[19], &g.gencheck, sizeof(g.gencheck));
    resolve(bhdl, "lmb_open", &v1.open, sizeof(v1.open));
    resolve(bhdl, "lmb_last_error", &v1.lasterr, sizeof(v1.lasterr));
    present = (g.open != NULL) + (g.config != NULL) +
              (g.load != NULL) + (g.pinfo != NULL) +
              (g.minfo != NULL) + (g.close != NULL) +
              (g.release != NULL) + (g.lasterr != NULL) +
              (g.lookup != NULL) + (g.update != NULL) +
              (g.testrun != NULL) + (g.attach != NULL) +
              (g.linkclose != NULL) + (g.bufopen != NULL) +
              (g.bufpoll != NULL) + (g.bufclose != NULL) +
              (g.ref != NULL) + (g.unref != NULL) +
              (g.gen != NULL) + (g.gencheck != NULL);
    if (present < 20) {
        printf("SKIP generic-behavior: %d of 20 symbols in %s\n",
               present, bpath);
        skips++;
        goto done;
    }
    if (argc == 3) {
        fixture = argv[2];
        if (read_file(fixture, &elf, &elf_len) != 0 || elf_len == 0) {
            printf("probe: cannot read fixture %s\n", fixture);
            dlclose(bhdl);
            return 2;
        }
    }
    part_b1(&g);
    part_b2(&g, elf, elf_len);
    part_b3a(&g, elf, elf_len);
    if (elf != NULL) {
        part_b3b(&g, elf, elf_len);
        part_b3c(&g, elf, elf_len);
    } else {
        SKIP("b3b", "needs the fixture ELF");
        SKIP("b3c", "needs the fixture ELF");
    }
    if (v1.open != NULL && v1.lasterr != NULL) {
        part_b4(&g, &v1, elf, elf_len);
    } else {
        SKIP("b4", "v1 entry points absent from behavior library");
    }
    part_b5(&g);
    part_b6(&g, elf, elf_len);

done:
    printf("probe: %d ok, %d skipped, %d failed\n", oks, skips,
           failures);
    free(elf);
    if (bhdl != NULL)
        dlclose(bhdl);
    return failures ? 1 : 0;
}
