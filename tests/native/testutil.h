/* Shared helpers for libbpf-mojo native tests. */
#ifndef LMB_TESTUTIL_H
#define LMB_TESTUTIL_H

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "libbpf_mojo.h"

static int lmb_failures = 0;

/* Skip exit code; CTest maps it via SKIP_RETURN_CODE, never as pass. */
#define LMB_SKIP_CODE 77

#define LMB_OK(name) printf("ok %s\n", (name))
#define LMB_FAIL(name, ...)                                \
    do {                                                   \
        printf("FAIL %s: ", (name));                       \
        printf(__VA_ARGS__);                               \
        printf("\n");                                      \
        lmb_failures++;                                    \
    } while (0)
#define LMB_CHECK(cond, name, ...)                         \
    do {                                                   \
        if (cond)                                          \
            LMB_OK(name);                                  \
        else                                               \
            LMB_FAIL(name, __VA_ARGS__);                   \
    } while (0)
#define LMB_SKIP(reason)                                   \
    do {                                                   \
        printf("SKIP %s\n", (reason));                     \
        return LMB_SKIP_CODE;                              \
    } while (0)

__attribute__((unused)) static const char *lmb_fixture(int argc,
                                                       char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <fixture.bpf.o>\n", argv[0]);
        exit(2);
    }
    return argv[1];
}

__attribute__((unused)) static int lmb_read_file(const char *path,
                                                 uint8_t **bytes,
                                                 uint64_t *len) {
    FILE *file = fopen(path, "rb");
    long size;
    uint8_t *data;
    if (!file)
        return -1;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }
    data = malloc((size_t)size ? (size_t)size : 1);
    if (!data) {
        fclose(file);
        return -1;
    }
    if (size > 0 && fread(data, 1, (size_t)size, file) != (size_t)size) {
        free(data);
        fclose(file);
        return -1;
    }
    fclose(file);
    *bytes = data;
    *len = (uint64_t)size;
    return 0;
}

__attribute__((unused)) static void lmb_make_options(
    struct lmb_options_v1 *o, const char *ring, uint32_t max_raw) {
    memset(o, 0, sizeof(*o));
    o->abi_version = LMB_ABI_VERSION;
    o->struct_size = sizeof(*o);
    o->ring.ptr = (const uint8_t *)ring;
    o->ring.len = (uint32_t)strlen(ring);
    o->max_raw_bytes = max_raw;
    o->stage_slots = 1;
}

__attribute__((unused)) static void lmb_make_attach(
    struct lmb_attach_v1 *s, const char *prog, uint32_t kind, const char *a,
    const char *b) {
    memset(s, 0, sizeof(*s));
    s->abi_version = LMB_ABI_VERSION;
    s->struct_size = sizeof(*s);
    s->program.ptr = (const uint8_t *)prog;
    s->program.len = (uint32_t)strlen(prog);
    s->kind = kind;
    s->target_a.ptr = (const uint8_t *)a;
    s->target_a.len = (uint32_t)strlen(a);
    s->target_b.ptr = (const uint8_t *)b;
    s->target_b.len = (uint32_t)strlen(b);
}

__attribute__((unused)) static void lmb_make_name(struct lmb_name_v1 *n,
                                                  const char *s) {
    memset(n, 0, sizeof(*n));
    n->abi_version = LMB_ABI_VERSION;
    n->struct_size = sizeof(*n);
    n->name.ptr = (const uint8_t *)s;
    n->name.len = (uint32_t)strlen(s);
}

/* Privilege eligibility, established independently of the fixture:
 * a verifier rejection can also return EACCES, so fixture error codes
 * must never decide between SKIP and FAIL. Only EPERM/EACCES from a
 * trivial map creation counts as missing privileges; anything else
 * (including success) means the test runs and fixture errors fail. */
__attribute__((unused)) static int lmb_has_collection_privilege(void) {
    int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, 4, 4, 1, NULL);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return errno != EPERM && errno != EACCES;
}

__attribute__((unused)) static int lmb_error_is(uint32_t op,
                                              uint32_t domain) {
    struct lmb_error_v1 err;
    memset(&err, 0, sizeof(err));
    err.abi_version = LMB_ABI_VERSION;
    err.struct_size = sizeof(err);
    return lmb_last_error(&err) == 0 && err.operation == op &&
           err.domain == domain;
}

__attribute__((unused)) static long lmb_count_fds(void) {
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

__attribute__((unused)) static uint32_t lmb_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

__attribute__((unused)) static uint16_t lmb_le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

#endif /* LMB_TESTUTIL_H */
