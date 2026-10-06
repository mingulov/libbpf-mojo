/* SPDX-License-Identifier: GPL-3.0-or-later */

/* Explicit attachment transactions: all sites attach or none do. */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "internal.h"

#define LMB_MAX_SITES 64

static int check_site(const struct lmb_attach_v1 *s) {
    if (!lmb_check_header(s->abi_version, s->struct_size, sizeof(*s)) ||
        !lmb_check_bytes(&s->program, LMB_MAX_NAME_BYTES, 1) ||
        s->flags != 0)
        return 0;
    if (s->kind == LMB_ATTACH_TRACEPOINT) {
        return lmb_check_bytes(&s->target_a, LMB_MAX_NAME_BYTES, 1) &&
               lmb_check_bytes(&s->target_b, LMB_MAX_NAME_BYTES, 1);
    }
    if (s->kind == LMB_ATTACH_TRACING) {
        return lmb_check_bytes(&s->target_a, LMB_MAX_NAME_BYTES, 1) &&
               lmb_check_bytes(&s->target_b, LMB_MAX_NAME_BYTES, 0) &&
               s->target_b.len == 0;
    }
    return 0;
}

/* Copy validated bytes into a stack-friendly NUL-terminated buffer. */
static void stash(const struct lmb_bytes_v1 *in, char *buf) {
    memcpy(buf, in->ptr, in->len);
    buf[in->len] = 0;
}

/* Verify a tracing program's ELF-declared target against target_a. */
static int tracing_target_ok(const struct bpf_program *prog,
                             const struct lmb_bytes_v1 *want) {
    static const char *kinds[] = {"fentry/", "fexit/", "fmod_ret/"};
    const char *section = bpf_program__section_name(prog);
    size_t i;
    if (!section)
        return 0;
    for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        size_t pre = strlen(kinds[i]);
        if (strncmp(section, kinds[i], pre) == 0 &&
            strlen(section + pre) == want->len &&
            memcmp(section + pre, want->ptr, want->len) == 0)
            return 1;
    }
    return 0;
}

static void rollback(struct lmb_session *s, uint32_t from) {
    while (s->nlinks > from) {
        s->nlinks--;
        bpf_link__destroy(s->links[s->nlinks]);
        s->links[s->nlinks] = NULL;
    }
}

int32_t lmb_attach(struct lmb_session *session,
                   const struct lmb_attach_v1 *sites, uint32_t count) {
    uint32_t i, base;
    if (!session) {
        lmb_record(LMB_OP_ATTACH, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_attach: null session");
        return -EINVAL;
    }
    if (!session->loaded) {
        lmb_record(LMB_OP_ATTACH, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_attach: session not loaded");
        return -EINVAL;
    }
    if (session->attached) {
        lmb_record(LMB_OP_ATTACH, LMB_DOMAIN_BRIDGE, -EBUSY,
                   "lmb_attach: session already attached");
        return -EBUSY;
    }
    if (!sites || count == 0 || count > LMB_MAX_SITES) {
        lmb_record(LMB_OP_ATTACH, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_attach: invalid site list");
        return -EINVAL;
    }
    for (i = 0; i < count; i++) {
        if (!check_site(&sites[i])) {
            lmb_record(LMB_OP_ATTACH, LMB_DOMAIN_BRIDGE, -EINVAL,
                       "lmb_attach: invalid site");
            return -EINVAL;
        }
    }
    base = session->nlinks;
    for (i = 0; i < count; i++) {
        const struct lmb_attach_v1 *site = &sites[i];
        char prog[LMB_MAX_NAME_BYTES + 1];
        struct bpf_program *bprog;
        struct bpf_link *link;
        long err;
        stash(&site->program, prog);
        bprog = (struct bpf_program *)bpf_object__find_program_by_name(
            session->obj, prog);
        if (!bprog) {
            rollback(session, base);
            lmb_record(LMB_OP_ATTACH, LMB_DOMAIN_BRIDGE, -ENOENT,
                       "lmb_attach: program not found");
            return -ENOENT;
        }
        if (site->kind == LMB_ATTACH_TRACEPOINT) {
            char cat[LMB_MAX_NAME_BYTES + 1];
            char evt[LMB_MAX_NAME_BYTES + 1];
            stash(&site->target_a, cat);
            stash(&site->target_b, evt);
            link = bpf_program__attach_tracepoint(bprog, cat, evt);
        } else {
            if (!tracing_target_ok(bprog, &site->target_a)) {
                rollback(session, base);
                lmb_record(LMB_OP_ATTACH, LMB_DOMAIN_BRIDGE, -EINVAL,
                           "lmb_attach: tracing target mismatch");
                return -EINVAL;
            }
            link = bpf_program__attach(bprog);
        }
        err = libbpf_get_error(link);
        if (err) {
            rollback(session, base);
            lmb_record(LMB_OP_ATTACH, LMB_DOMAIN_LIBBPF, (int32_t)err,
                       "lmb_attach: attach failed");
            session->last_native_error = (int32_t)err;
            return (int32_t)err;
        }
        if (session->nlinks == session->link_cap) {
            uint32_t want = session->link_cap ? session->link_cap * 2 : 4;
            struct bpf_link **grown =
                realloc(session->links, want * sizeof(*grown));
            if (!grown) {
                bpf_link__destroy(link);
                rollback(session, base);
                lmb_record(LMB_OP_ATTACH, LMB_DOMAIN_POSIX, -ENOMEM,
                           "lmb_attach: out of memory");
                session->last_native_error = -ENOMEM;
                return -ENOMEM;
            }
            session->links = grown;
            session->link_cap = want;
        }
        session->links[session->nlinks++] = link;
    }
    session->attached = 1;
    return 0;
}
