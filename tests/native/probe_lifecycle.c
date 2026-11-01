/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
#include <fcntl.h>
#include <bpf/libbpf.h>
#include "internal.h"
#include "generic_internal.h"
#include "testutil.h"
static unsigned attached, destroyed, order[64], next_id, fail_at;
static int failure = -ENOENT, destroy_failure;
static const char *expected_symbol = "lmb_test_target";
static const char *invalid_symbols[] = {"target\nforeign", "target argument", "target\tfield",
    "target+0x1", "0xffffffff", "module::target", "module:", ":target", "module/target",
    "target*", "target?", "t\xc3\xa4rget"};
static const char *valid_symbols[] = {"lmb_test_target", "module:lmb_test_target", "9p:lmb_test_target.isra.3"};
struct token { unsigned id; int fd; };
int __wrap_bpf_object__load(struct bpf_object *obj) { return obj ? 0 : -EINVAL; }
int __wrap_bpf_program__fd(const struct bpf_program *p) { return p ? 12345 : -1; }
struct bpf_link *__wrap_bpf_program__attach_kprobe(const struct bpf_program *p,
        bool retprobe, const char *name) {
    attached++;
    LMB_CHECK(!strcmp(name, expected_symbol) && name != expected_symbol, "symbol", "exact copied symbol");
    LMB_CHECK(!strcmp(bpf_program__name(p), retprobe ? "probe_return" : "probe_entry"),
        "kind", "entry/return adapter matches requested program");
    if (fail_at && attached == fail_at) { errno = -failure; return NULL; }
    struct token *t = calloc(1, sizeof(*t));
    t->id = ++next_id; t->fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    LMB_CHECK(t->fd >= 0, "token-fd", "owned test descriptor");
    return (void *)t;
}
int __wrap_bpf_link__destroy(struct bpf_link *link) {
    struct token *t = (void *)link;
    order[destroyed++] = t->id;
    LMB_CHECK(close(t->fd) == 0, "fd-close", "destroy each owned descriptor once");
    int rc = destroy_failure ? destroy_failure - (int)t->id : 0;
    free(t); return rc;
}
static struct lmb_span_v1 span(const char *s) {
    return (struct lmb_span_v1){(const uint8_t *)s, strlen(s)};
}
int main(int argc, char **argv) {
    uint8_t *elf; uint64_t size;
    if (argc != 2 || lmb_read_file(argv[1], &elf, &size)) return 2;
    long baseline = lmb_count_fds();
    struct lmb_session *s = calloc(1, sizeof(*s));
    s->obj = bpf_object__open_mem(elf, size, NULL); s->loaded = 1;
    if (libbpf_get_error(s->obj)) return 2;
    struct bpf_program *tracing = bpf_object__find_program_by_name(s->obj, "probe_tracing");
    LMB_CHECK(tracing && bpf_program__type(tracing)==BPF_PROG_TYPE_TRACING &&
        bpf_program__expected_attach_type(tracing)==BPF_TRACE_FENTRY &&
        !strcmp(bpf_program__section_name(tracing), "fentry/__do_sys_getpid"),
        "tracing-target", "compiled fentry target matches the selected kernel BTF function");
    long object_fds = lmb_count_fds();
    _Static_assert(LMB_ATTACH_KPROBE == 3 && LMB_ATTACH_KRETPROBE == 4, "session kinds");
    _Static_assert(LMB_ATTACH_FAMILY_KPROBE == 3 && LMB_ATTACH_FAMILY_KRETPROBE == 4, "generic kinds");
    for (unsigned kind=3; kind<=4; kind++) {
        struct lmb_attach_v1 site;
        for (unsigned i=0;i<sizeof(invalid_symbols)/sizeof(*invalid_symbols);i++) {
            expected_symbol=invalid_symbols[i];
            lmb_make_attach(&site,kind==3 ? "probe_entry" : "probe_return",kind,expected_symbol,"");
            unsigned before=attached;
            int code=lmb_attach(s,&site,1);
            LMB_CHECK(code == -EINVAL && attached==before,"session-symbol-grammar","reject command syntax before native calls");
            if (!code) lmb_detach(s);
        }
        for (unsigned i=0;i<sizeof(valid_symbols)/sizeof(*valid_symbols);i++) {
            expected_symbol=valid_symbols[i];
            lmb_make_attach(&site,kind==3 ? "probe_entry" : "probe_return",kind,expected_symbol,"");
            LMB_CHECK(lmb_attach(s,&site,1)==0,"session-symbols","forward explicit symbol syntax");
            LMB_CHECK(lmb_detach(s)==0,"session-symbol-clean","retire every accepted site");
        }
    }
    expected_symbol="lmb_test_target"; attached=destroyed=next_id=0;
    struct lmb_attach_v1 specs[3];
    lmb_make_attach(&specs[0], "probe_return", 4, "lmb_test_target", "");
    lmb_make_attach(&specs[1], "probe_entry", 3, "lmb_test_target", "");
    specs[2] = specs[1];
    int rc = lmb_attach(s, specs, 3);
    LMB_CHECK(rc == 0 && attached == 3, "session-probes", "attach typed probe sites in input order");
    destroy_failure = -EIO;
    rc = lmb_detach(s);
    LMB_CHECK(rc == -EIO-3 && destroyed == 3 && order[0] == 3 && order[1] == 2 && order[2] == 1,
        "reverse-detach", "reverse all links despite teardown failure");
    LMB_CHECK(lmb_count_fds() == object_fds && !s->attached && !s->nlinks,
        "detach-ownership", "release all links and descriptors");
    destroy_failure = 0;
    for (unsigned i = 1; i <= 3; i++) {
        attached = destroyed = next_id = 0; fail_at = i;
        rc = lmb_attach(s, specs, 3);
        LMB_CHECK(rc == -ENOENT && attached == i && destroyed == i-1,
            "partial-rollback", "reach each attach failure and roll back");
        for (unsigned j = 0; j < destroyed; j++)
            LMB_CHECK(order[j] == i-1-j, "rollback-order", "rollback reverses successful attachments");
        LMB_CHECK(lmb_count_fds() == object_fds && !s->attached && !s->nlinks,
            "rollback-fds", "no partial ownership remains");
    }
    fail_at = 0; attached = destroyed = next_id = 0;
    LMB_CHECK(lmb_attach(s, specs, 2) == 0, "reattach", "usable after rollback");
    LMB_CHECK(lmb_close(&s) == 0 && !s && destroyed == 2 && order[0] == 2 && order[1] == 1,
        "close-order", "implicit session teardown reverses links");
    LMB_CHECK(lmb_count_fds() == baseline, "session-close-fds", "parser and links retire together");
    struct lmb_object_options_v1 opts = {.abi_version=1, .struct_size=sizeof(opts)};
    struct lmb_object *object = NULL;
    LMB_CHECK(lmb_object_open_v1(elf, size, &opts, &object) == 0, "generic-open", "real ELF parser");
    LMB_CHECK(lmb_object_load_v1(object) == 0, "generic-load", "controlled no-kernel load");
    object_fds = lmb_count_fds();
    struct lmb_attach_options_v1 a = {.abi_version=1, .struct_size=sizeof(a),
        .program=span("probe_entry"), .family=3, .target_a=span("lmb_test_target")};
    for (unsigned kind=3; kind<=4; kind++) {
        a.family=kind; a.program=span(kind==3 ? "probe_entry" : "probe_return");
        for (unsigned i=0;i<sizeof(invalid_symbols)/sizeof(*invalid_symbols);i++) {
            struct lmb_attach_options_v1 rejected=a;
            expected_symbol=invalid_symbols[i]; rejected.target_a=span(expected_symbol);
            struct lmb_link *absent=NULL; unsigned before=attached;
            int code=lmb_object_attach_v1(object,&rejected,&absent);
            LMB_CHECK(code == -EINVAL && !absent && attached==before,"generic-symbol-grammar","reject command syntax before native calls");
            if (absent) lmb_link_close_v1(&absent);
        }
        for (unsigned i=0;i<sizeof(valid_symbols)/sizeof(*valid_symbols);i++) {
            struct lmb_attach_options_v1 accepted=a;
            expected_symbol=valid_symbols[i]; accepted.target_a=span(expected_symbol);
            struct lmb_link *child=NULL;
            LMB_CHECK(lmb_object_attach_v1(object,&accepted,&child)==0 && child,"generic-symbols","forward copied symbol syntax");
            LMB_CHECK(lmb_link_close_v1(&child)==0,"generic-symbol-clean","retire accepted symbol");
        }
        expected_symbol="lmb_test_target";
        for (unsigned bad=0;bad<5;bad++) {
            struct lmb_attach_options_v1 rejected=a;
            if (bad==0) rejected.program=span(kind==3 ? "probe_return" : "probe_entry");
            if (bad==1) rejected.target_b=span("not-empty");
            if (bad==2) rejected.target_a=span("");
            if (bad==3) rejected.flags=1;
            if (bad==4) rejected.program=span("probe_tracing");
            struct lmb_link *absent=(void *)1; unsigned before=attached;
            LMB_CHECK(lmb_object_attach_v1(object,&rejected,&absent)==(bad==0 || bad==4 ? -EOPNOTSUPP : -EINVAL) && !absent && attached==before,
                "probe-validation", "probe kind and names reject before native attachment");
        }
        const int errors[] = {-ENOENT, -EINVAL, -EPERM, -EACCES};
        for (unsigned i=0; i<4; i++) {
            attached=0; fail_at=1; failure=errors[i];
            struct lmb_link *link=(void *)1;
            rc=lmb_object_attach_v1(object, &a, &link);
            LMB_CHECK(rc == errors[i] && !link && attached==1,
                "generic-failure", "missing/blacklisted/lockdown native errors reach actual adapter");
            struct lmb_generic_error_v1 e={.abi_version=1,.struct_size=sizeof(e)};
            LMB_CHECK(lmb_generic_last_error_v1(&e)==0 && e.operation==10 && e.domain==2 && e.code==errors[i],
                "generic-diagnostic", "preserve signed error and domain");
            LMB_CHECK(atomic_load(&object->refs)==1 && lmb_count_fds()==object_fds,
                "generic-failed-owner", "failed attach releases reference and descriptors");
        }
        attached=0; fail_at=0;
        struct lmb_link *link=NULL;
        LMB_CHECK(lmb_object_attach_v1(object, &a, &link)==0 && link && attached==1,
            "generic-probe", "entry and return links own resources");
        if (link) {
            LMB_CHECK(lmb_object_close_v1(&object)==-EBUSY, "parent-busy", "live link retains object");
            LMB_CHECK(lmb_link_close_v1(&link)==0 && !link, "generic-close", "close consumes native owner");
        }
        LMB_CHECK(lmb_count_fds()==object_fds, "generic-close-fds", "return to baseline");
    }
    LMB_CHECK(lmb_object_close_v1(&object)==0 && !object, "object-close", "object retires");
    LMB_CHECK(lmb_count_fds() == baseline, "object-close-fds", "all object resources retire");
    free(elf);
    return lmb_failures ? 1 : 0;
}
