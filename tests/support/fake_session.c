/* SPDX-License-Identifier: GPL-3.0-or-later */

/* Test-only synthetic input switch for the Mojo boundary tests.
 *
 * This library exists so the Mojo tests can drive the REAL native
 * framing, staging, and stats code without kernel privileges, the
 * same way tests/native/fake_source.c does for C. It links the
 * bridge internals statically and exposes only lmb_test_* helpers.
 *
 * NEVER installed or packaged: production builds expose no
 * synthetic input switch. The armed-session trick (loaded plus a
 * dummy ring pointer) is test-only; poll is safe only while a
 * record is staged, exactly as in fake_source.c.
 *
 * Session addresses cross the Mojo boundary as uint64_t to keep
 * every test FFI value fixed-width.
 */
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "internal.h"

int32_t lmb_test_fake_arm(uint64_t session) {
    struct lmb_session *s = (struct lmb_session *)(uintptr_t)session;
    if (!s)
        return -EINVAL;
    s->loaded = 1;
    s->rb = (struct ring_buffer *)(uintptr_t)1;
    return 0;
}

int32_t lmb_test_fake_sample(uint64_t session, const uint8_t *data,
                             uint32_t len) {
    struct lmb_session *s = (struct lmb_session *)(uintptr_t)session;
    if (!s || (!data && len > 0))
        return -EINVAL;
    return (int32_t)lmb_ring_sample(s, (void *)data, (size_t)len);
}

int32_t lmb_test_fake_disarm(uint64_t session) {
    struct lmb_session *s = (struct lmb_session *)(uintptr_t)session;
    if (!s)
        return -EINVAL;
    s->loaded = 0;
    s->rb = NULL;
    return 0;
}

/* Privilege eligibility, independent of any fixture: only
 * EPERM/EACCES from a trivial map creation counts as missing
 * privileges. Mirrors lmb_has_collection_privilege in the native
 * testutil. Returns 1 when the test must run the privileged path. */
int32_t lmb_test_has_privilege(void) {
    int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, 4, 4, 1, NULL);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return errno != EPERM && errno != EACCES;
}
