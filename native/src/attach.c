/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/* Explicit attachment transactions: all sites attach or none do. */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "internal.h"

#define LMB_MAX_SITES 64

static int symbol_initial(uint8_t ch) {
    return ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}

int lmb_probe_symbol_ok(const uint8_t *text, uint64_t length) {
    if (!text || !length || length > LMB_MAX_NAME_BYTES) return 0;
    uint64_t start = 0;
    for (uint64_t i = 0; i < length; i++) {
        if (text[i] != ':') continue;
        if (start || !i || i + 1 == length) return 0;
        start = i + 1;
    }
    for (uint64_t i = 0; start && i < start - 1; i++)
        if (!symbol_initial(text[i]) && !(text[i] >= '0' && text[i] <= '9')) return 0;
    if (!symbol_initial(text[start])) return 0;
    for (uint64_t i = start + 1; i < length; i++)
        if (!symbol_initial(text[i]) && !(text[i] >= '0' && text[i] <= '9') && text[i] != '.') return 0;
    return 1;
}

static int check_site(const struct lmb_attach_v1 *s) {
    if (!lmb_check_header(s->abi_version, s->struct_size, sizeof(*s)) ||
        !lmb_check_bytes(&s->program, LMB_MAX_NAME_BYTES, 1) ||
        s->flags != 0)
        return 0;
    if (s->kind == LMB_ATTACH_TRACEPOINT) {
        return lmb_check_bytes(&s->target_a, LMB_MAX_NAME_BYTES, 1) &&
               lmb_check_bytes(&s->target_b, LMB_MAX_NAME_BYTES, 1);
    }
    if (s->kind == LMB_ATTACH_TRACING || s->kind == LMB_ATTACH_KPROBE ||
        s->kind == LMB_ATTACH_KRETPROBE) {
        return lmb_check_bytes(&s->target_a, LMB_MAX_NAME_BYTES, 1) &&
               lmb_check_bytes(&s->target_b, LMB_MAX_NAME_BYTES, 0) &&
               s->target_b.len == 0 &&
               (s->kind == LMB_ATTACH_TRACING || lmb_probe_symbol_ok(s->target_a.ptr, s->target_a.len));
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

int lmb_probe_program_ok(const struct bpf_program *program, int retprobe) {
    const char *section = bpf_program__section_name(program);
    const char *prefix = retprobe ? "kretprobe" : "kprobe";
    size_t n = strlen(prefix);
    return bpf_program__type(program) == BPF_PROG_TYPE_KPROBE && section &&
        !strncmp(section, prefix, n) && (section[n] == 0 || section[n] == '/');
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
        } else if (site->kind == LMB_ATTACH_KPROBE || site->kind == LMB_ATTACH_KRETPROBE) {
            char symbol[LMB_MAX_NAME_BYTES + 1];
            int retprobe = site->kind == LMB_ATTACH_KRETPROBE;
            if (!lmb_probe_program_ok(bprog, retprobe)) {
                rollback(session, base);
                lmb_record(LMB_OP_ATTACH, LMB_DOMAIN_BRIDGE, -EOPNOTSUPP,
                           "lmb_attach: program is not the requested probe kind");
                return -EOPNOTSUPP;
            }
            stash(&site->target_a, symbol);
            link = bpf_program__attach_kprobe(bprog, retprobe, symbol);
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
