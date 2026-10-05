/* Partial ABI stub: every lmb_* operation except lmb_close.
 *
 * Test-only fixture proving that NativeLib validation rejects an
 * incompatible library before any handle exists. Never installed
 * or packaged; the Mojo suite locates it via LMB_STUB_LIB.
 */
#include <stdint.h>

int32_t lmb_open(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    return 0;
}

int32_t lmb_load(uint64_t s) {
    (void)s;
    return 0;
}

int32_t lmb_attach(uint64_t s, uint64_t sites, uint32_t n) {
    (void)s;
    (void)sites;
    (void)n;
    return 0;
}

int32_t lmb_poll(uint64_t s, uint64_t dst, uint32_t cap, uint64_t w,
                 uint64_t r, int32_t t) {
    (void)s;
    (void)dst;
    (void)cap;
    (void)w;
    (void)r;
    (void)t;
    return 0;
}

int32_t lmb_map_info(uint64_t s, uint64_t n, uint64_t o) {
    (void)s;
    (void)n;
    (void)o;
    return 0;
}

int32_t lmb_map_read(uint64_t s, uint64_t n, uint64_t k, uint32_t kb,
                     uint64_t d, uint32_t c, uint64_t r) {
    (void)s;
    (void)n;
    (void)k;
    (void)kb;
    (void)d;
    (void)c;
    (void)r;
    return 0;
}

int32_t lmb_map_write(uint64_t s, uint64_t n, uint64_t k, uint32_t kb,
                      uint64_t v, uint32_t vb) {
    (void)s;
    (void)n;
    (void)k;
    (void)kb;
    (void)v;
    (void)vb;
    return 0;
}

int32_t lmb_stats(uint64_t s, uint64_t o) {
    (void)s;
    (void)o;
    return 0;
}

int32_t lmb_last_error(uint64_t o) {
    (void)o;
    return 0;
}

int32_t lmb_detach(uint64_t s) {
    (void)s;
    return 0;
}

/* NOTE: lmb_close is deliberately absent. */
