/* SPDX-License-Identifier: GPL-3.0-or-later */

/* Thread-local error records and strict input validation. */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

static _Thread_local struct lmb_error_v1 tls_err;

void lmb_record(uint32_t op, uint32_t domain, int32_t code,
                const char *msg) {
    size_t n = strlen(msg);
    if (n > LMB_MAX_MSG_LEN)
        n = LMB_MAX_MSG_LEN;
    tls_err.abi_version = LMB_ABI_VERSION;
    tls_err.struct_size = sizeof(tls_err);
    tls_err.operation = op;
    tls_err.domain = domain;
    tls_err.code = code;
    memcpy(tls_err.message, msg, n);
    tls_err.message[n] = 0;
    tls_err.msg_len = (uint32_t)n;
}

int32_t lmb_last_error(struct lmb_error_v1 *out) {
    /* Inspection failures preserve the stored record. */
    if (!out)
        return -EINVAL;
    if (out->abi_version != LMB_ABI_VERSION ||
        out->struct_size != sizeof(*out))
        return -EINVAL;
    memcpy(out, &tls_err, sizeof(*out));
    return 0;
}

int lmb_check_header(uint32_t abi_version, uint32_t struct_size,
                     uint32_t want) {
    return abi_version == LMB_ABI_VERSION && struct_size == want;
}

/* Strict UTF-8 with no embedded NUL: rejects overlong encodings,
 * surrogates, and code points above U+10FFFF. */
static int utf8_ok(const uint8_t *p, uint32_t len) {
    uint32_t i = 0;
    while (i < len) {
        uint8_t c = p[i];
        uint32_t cp, need, j;
        if (c == 0)
            return 0;
        if (c < 0x80) {
            i++;
            continue;
        }
        if (c < 0xC2)
            return 0;
        if (c < 0xE0) {
            need = 1;
            cp = (uint32_t)(c & 0x1F);
        } else if (c < 0xF0) {
            need = 2;
            cp = (uint32_t)(c & 0x0F);
        } else if (c < 0xF5) {
            need = 3;
            cp = (uint32_t)(c & 0x07);
        } else {
            return 0;
        }
        if (i + need >= len)
            return 0;
        for (j = 0; j < need; j++) {
            uint8_t d = p[i + 1 + j];
            if ((d & 0xC0) != 0x80)
                return 0;
            cp = (cp << 6) | (uint32_t)(d & 0x3F);
        }
        if (cp > 0x10FFFF)
            return 0;
        if (cp >= 0xD800 && cp <= 0xDFFF)
            return 0;
        if ((need == 1 && cp < 0x80) || (need == 2 && cp < 0x800) ||
            (need == 3 && cp < 0x10000))
            return 0;
        i += 1 + need;
    }
    return 1;
}

int lmb_check_bytes(const struct lmb_bytes_v1 *in, uint32_t max,
                    int required) {
    if (!in || in->len > max || in->_pad != 0)
        return 0;
    if (in->len == 0)
        return !required;
    if (!in->ptr)
        return 0;
    return utf8_ok(in->ptr, in->len);
}

int lmb_ranges_overlap(const void *a, uint32_t a_len, const void *b,
                       uint32_t b_len) {
    uintptr_t as = (uintptr_t)a;
    uintptr_t bs = (uintptr_t)b;
    if (a_len == 0 || b_len == 0)
        return 0;
    if (!a || !b)
        return 1;
    return as < bs + b_len && bs < as + a_len;
}

int lmb_copy_name(const struct lmb_bytes_v1 *in, char **out) {
    char *copy;
    if (!lmb_check_bytes(in, LMB_MAX_NAME_BYTES, 1))
        return 0;
    copy = malloc(in->len + 1);
    if (!copy)
        return 0;
    memcpy(copy, in->ptr, in->len);
    copy[in->len] = 0;
    *out = copy;
    return 1;
}
