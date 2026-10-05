/* Map introspection and access against fixture maps. Requires a
 * loaded object; reports SKIP when the kernel refuses the load. */
#include <linux/bpf.h>

#include "testutil.h"

int main(int argc, char **argv) {
    const char *fixture = lmb_fixture(argc, argv);
    uint8_t *elf = NULL;
    uint64_t elf_len = 0;
    struct lmb_options_v1 o;
    struct lmb_name_v1 name;
    struct lmb_map_info_v1 info;
    struct lmb_session *s = NULL;
    uint32_t key = 7;
    uint32_t pkey = 0;
    uint64_t value = 0x0102030405060708ULL;
    uint64_t got = 0;
    uint8_t small[4] = {0xAA, 0xAA, 0xAA, 0xAA};
    uint8_t *spread = NULL;
    uint32_t required = 0;
    uint32_t i, ncpus;
    int spread_ok = 1;

    if (lmb_read_file(fixture, &elf, &elf_len) != 0 || elf_len == 0) {
        LMB_FAIL("fixture-load", "cannot read %s", fixture);
        return 1;
    }
    lmb_make_options(&o, "events", 4096);
    if (lmb_open(elf, elf_len, &o, &s) != 0 || !s) {
        LMB_FAIL("setup-open", "open must succeed");
        free(elf);
        return 1;
    }
    if (lmb_load(s) != 0) {
        int eligible = lmb_has_collection_privilege();
        lmb_close(&s);
        free(elf);
        if (!eligible)
            LMB_SKIP("missing collection privileges");
        LMB_FAIL("setup-load", "load failed despite privileges");
        return 1;
    }

    lmb_make_name(&name, "no_such_map");
    memset(&info, 0, sizeof(info));
    info.abi_version = LMB_ABI_VERSION;
    info.struct_size = sizeof(info);
    LMB_CHECK(lmb_map_info(s, &name, &info) != 0, "unknown-map",
              "unknown map must fail");
    LMB_CHECK(lmb_error_is(LMB_OP_MAP_INFO, LMB_DOMAIN_BRIDGE),
              "unknown-map-record",
              "unknown map must report bridge ENOENT");

    LMB_CHECK(lmb_map_info(s, NULL, &info) == -EINVAL &&
                  lmb_error_is(LMB_OP_MAP_INFO, LMB_DOMAIN_BRIDGE),
              "null-name-info", "null name must fail closed");
    LMB_CHECK(lmb_map_read(s, NULL, (const uint8_t *)&key, 4,
                           (uint8_t *)&got, 8, &required) == -EINVAL &&
                  lmb_error_is(LMB_OP_MAP_READ, LMB_DOMAIN_BRIDGE),
              "null-name-read", "null name must fail closed");
    LMB_CHECK(lmb_map_write(s, NULL, (const uint8_t *)&key, 4,
                            (const uint8_t *)&value, 8) == -EINVAL &&
                  lmb_error_is(LMB_OP_MAP_WRITE, LMB_DOMAIN_BRIDGE),
              "null-name-write", "null name must fail closed");

    lmb_make_name(&name, "test_hash");
    memset(&info, 0, sizeof(info));
    info.abi_version = LMB_ABI_VERSION;
    info.struct_size = sizeof(info);
    LMB_CHECK(lmb_map_info(s, &name, &info) == 0 &&
                  info.type == BPF_MAP_TYPE_HASH && info.key_size == 4 &&
                  info.value_size == 8 && info.max_entries == 64,
              "hash-info", "hash map info must match fixture");

    LMB_CHECK(lmb_map_write(s, &name, (const uint8_t *)&key, 4,
                            (const uint8_t *)&value, 8) == 0,
              "hash-write", "hash write must succeed");
    LMB_CHECK(lmb_map_read(s, &name, (const uint8_t *)&key, 4,
                           (uint8_t *)&got, 8, &required) == 0 &&
                  got == value,
              "hash-roundtrip", "hash read must return written value");

    LMB_CHECK(lmb_map_read(s, &name, (const uint8_t *)&key, 8,
                           (uint8_t *)&got, 8, &required) != 0,
              "bad-key-size", "wrong key size must fail");
    LMB_CHECK(lmb_map_write(s, &name, (const uint8_t *)&key, 4,
                            (const uint8_t *)&value, 4) != 0,
              "bad-value-size", "wrong value size must fail");

    name.name._pad = 1;
    LMB_CHECK(lmb_map_info(s, &name, &info) != 0, "name-pad",
              "nonzero name padding must fail");
    name.name._pad = 0;
    name.name.ptr = (const uint8_t *)"\xff";
    name.name.len = 1;
    LMB_CHECK(lmb_map_info(s, &name, &info) != 0, "name-utf8",
              "invalid UTF-8 name must fail");
    lmb_make_name(&name, "test_hash");
    required = 0;
    LMB_CHECK(lmb_map_read(s, &name, (const uint8_t *)&key, 4, small,
                           sizeof(small), &required) == -ENOSPC &&
                  required == 8 && small[0] == 0xAA,
              "short-read", "short read must report required=8 untouched");
    LMB_CHECK(lmb_error_is(LMB_OP_MAP_READ, LMB_DOMAIN_BRIDGE),
              "short-read-record",
              "short read must replace the error record");

    /* Guarded round-trip: exact bytes, guards intact. */
    {
        uint8_t zone[16 + 8 + 16];
        uint32_t k;
        for (k = 0; k < 16; k++) {
            zone[k] = 0xA5;
            zone[16 + 8 + k] = 0xA5;
        }
        for (k = 0; k < 8; k++)
            zone[16 + k] = 0x5A;
        got = 0;
        LMB_CHECK(lmb_map_read(s, &name, (const uint8_t *)&key, 4,
                               zone + 16, 8, &required) == 0 &&
                      memcmp(zone + 16, &value, 8) == 0 &&
                      zone[0] == 0xA5 && zone[16 + 8] == 0xA5,
                  "hash-guarded",
                  "guarded read must match exactly");
    }

    lmb_make_name(&name, "test_percpu");
    memset(&info, 0, sizeof(info));
    info.abi_version = LMB_ABI_VERSION;
    info.struct_size = sizeof(info);
    LMB_CHECK(lmb_map_info(s, &name, &info) == 0 &&
                  info.type == BPF_MAP_TYPE_PERCPU_ARRAY &&
                  info.value_size == 8 && info.stride == 8 &&
                  info.num_cpus > 0,
              "percpu-info", "percpu info must match fixture");

    ncpus = info.num_cpus;
    spread = malloc((size_t)info.stride * ncpus);
    if (!spread) {
        LMB_FAIL("percpu-alloc", "out of memory");
        lmb_close(&s);
        free(elf);
        return 1;
    }
    /* Short lengths derive from the queried spread so the checks hold
     * on a single-CPU system too (need-1, possibly zero). */
    {
        uint32_t need = info.stride * ncpus;
        uint32_t short_len = need - 1;
        LMB_CHECK(lmb_map_write(s, &name, (const uint8_t *)&pkey, 4,
                                spread, short_len) != 0,
                  "percpu-short-write",
                  "partial spread write must fail");
        for (i = 0; i < ncpus; i++)
            memcpy(spread + (size_t)i * info.stride, &value, 8);
        LMB_CHECK(lmb_map_write(s, &name, (const uint8_t *)&pkey, 4,
                                spread, need) == 0,
                  "percpu-write", "full spread write must succeed");
        memset(spread, 0, (size_t)need);
        required = 0;
        LMB_CHECK(lmb_map_read(s, &name, (const uint8_t *)&pkey, 4,
                               spread, need, &required) == 0,
                  "percpu-read", "full spread read must succeed");
        for (i = 0; i < ncpus; i++) {
            uint64_t slot = 0;
            memcpy(&slot, spread + (size_t)i * info.stride, 8);
            if (slot != value)
                spread_ok = 0;
        }
        LMB_CHECK(spread_ok, "percpu-roundtrip",
                  "spread read must match written values");
        required = 0;
        LMB_CHECK(lmb_map_read(s, &name, (const uint8_t *)&pkey, 4,
                               short_len ? spread : NULL, short_len,
                               &required) == -ENOSPC &&
                      required == need,
                  "percpu-short-read",
                  "short spread read must report size");
    }

    /* LRU per-CPU maps use spread sizing like other per-CPU maps. */
    lmb_make_name(&name, "test_lru");
    memset(&info, 0, sizeof(info));
    info.abi_version = LMB_ABI_VERSION;
    info.struct_size = sizeof(info);
    LMB_CHECK(lmb_map_info(s, &name, &info) == 0 &&
                  info.type == BPF_MAP_TYPE_LRU_PERCPU_HASH &&
                  info.value_size == 8 && info.stride == 8 &&
                  info.num_cpus == ncpus,
              "lru-info", "lru percpu info must match fixture");
    {
        uint32_t need = info.stride * info.num_cpus;
        uint8_t *lspread = malloc(need ? need : 1);
        int lok = 1;
        if (!lspread) {
            LMB_FAIL("lru-alloc", "out of memory");
            lok = 0;
        } else {
            for (i = 0; i < info.num_cpus; i++)
                memcpy(lspread + (size_t)i * info.stride, &value,
                       8);
            if (lmb_map_write(s, &name, (const uint8_t *)&pkey, 4,
                              lspread, need) != 0)
                lok = 0;
            memset(lspread, 0, need);
            if (lmb_map_read(s, &name, (const uint8_t *)&pkey, 4,
                             lspread, need, &required) != 0)
                lok = 0;
            for (i = 0; i < info.num_cpus && lok; i++) {
                uint64_t slot = 0;
                memcpy(&slot, lspread + (size_t)i * info.stride, 8);
                if (slot != value)
                    lok = 0;
            }
            free(lspread);
        }
        LMB_CHECK(lok, "lru-roundtrip",
                  "lru percpu spread must round-trip");
    }
    /* A value-sized buffer is short when CPUs spread it: the bridge
     * must refuse before the kernel can write past it. On a
     * single-CPU host the spread equals the value and there is
     * nothing to prove. */
    if (ncpus > 1) {
        uint8_t *zone = malloc(16 + 8 + 16);
        int zok = zone != NULL;
        if (zok) {
            uint32_t k;
            for (k = 0; k < 16; k++) {
                zone[k] = 0xA5;
                zone[16 + 8 + k] = 0xA5;
            }
            required = 0;
            zok = lmb_map_read(s, &name, (const uint8_t *)&pkey, 4,
                               zone + 16, 8, &required) == -ENOSPC &&
                  required == info.stride * info.num_cpus &&
                  zone[0] == 0xA5 && zone[16 + 8] == 0xA5;
            free(zone);
        }
        LMB_CHECK(zok, "lru-short-guarded",
                  "short spread read must refuse untouched");
    } else {
        printf("note lru-short-guarded: single CPU, vacuous\n");
    }

    /* Odd value sizes exercise stride padding. */
    lmb_make_name(&name, "test_odd");
    memset(&info, 0, sizeof(info));
    info.abi_version = LMB_ABI_VERSION;
    info.struct_size = sizeof(info);
    LMB_CHECK(lmb_map_info(s, &name, &info) == 0 &&
                  info.value_size == 5 && info.stride == 0,
              "odd-info", "odd hash info must match fixture");
    {
        static const uint8_t odd5[5] = {9, 8, 7, 6, 5};
        uint8_t got5[5] = {0};
        LMB_CHECK(lmb_map_write(s, &name, (const uint8_t *)&key, 4,
                                odd5, sizeof(odd5)) == 0 &&
                      lmb_map_read(s, &name, (const uint8_t *)&key, 4,
                                   got5, sizeof(got5), &required) ==
                          0 &&
                      memcmp(got5, odd5, sizeof(odd5)) == 0,
                  "odd-roundtrip",
                  "5-byte value must round-trip exactly");
    }
    lmb_make_name(&name, "test_percpu_odd");
    memset(&info, 0, sizeof(info));
    info.abi_version = LMB_ABI_VERSION;
    info.struct_size = sizeof(info);
    LMB_CHECK(lmb_map_info(s, &name, &info) == 0 &&
                  info.type == BPF_MAP_TYPE_PERCPU_ARRAY &&
                  info.value_size == 5 && info.stride == 8 &&
                  info.num_cpus == ncpus,
              "percpu-odd-info", "odd percpu info must match fixture");
    {
        /* Per-CPU update replicates one slot value to every CPU, so
         * every slot carries the same 5 value bytes plus padding.
         * Padding replication is kernel-defined and not asserted;
         * the bridge proves sizing (stride 8) and value bytes. */
        static const uint8_t oddslot[8] = {9, 8, 7, 6, 5, 4, 3, 2};
        uint32_t need = info.stride * info.num_cpus;
        uint8_t *ospread = malloc(need ? need : 1);
        int ook = 1;
        if (!ospread) {
            LMB_FAIL("percpu-odd-alloc", "out of memory");
            ook = 0;
        } else {
            for (i = 0; i < info.num_cpus; i++)
                memcpy(ospread + (size_t)i * info.stride, oddslot,
                       8);
            if (lmb_map_write(s, &name, (const uint8_t *)&pkey, 4,
                              ospread, need) != 0)
                ook = 0;
            memset(ospread, 0, need);
            if (lmb_map_read(s, &name, (const uint8_t *)&pkey, 4,
                             ospread, need, &required) != 0)
                ook = 0;
            for (i = 0; i < info.num_cpus && ook; i++) {
                if (memcmp(ospread + (size_t)i * info.stride,
                           oddslot, 5) != 0)
                    ook = 0;
            }
            free(ospread);
        }
        LMB_CHECK(ook, "percpu-odd-roundtrip",
                  "odd spread values must round-trip per slot");
    }

    lmb_make_name(&name, "no_such_map");
    LMB_CHECK(lmb_map_read(s, &name, (const uint8_t *)&key, 4,
                           (uint8_t *)&got, 8, &required) != 0,
              "read-unknown-map", "read on unknown map must fail");
    LMB_CHECK(lmb_map_write(s, &name, (const uint8_t *)&key, 4,
                            (const uint8_t *)&value, 8) != 0,
              "write-unknown-map", "write on unknown map must fail");
    LMB_CHECK(lmb_close(&s) == 0 && s == NULL, "close-ok",
              "close must succeed");

    free(spread);
    free(elf);
    return lmb_failures ? 1 : 0;
}
