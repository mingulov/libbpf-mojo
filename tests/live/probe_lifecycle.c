/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
#include <sys/syscall.h>
#include "testutil.h"
#include "libbpf_mojo_generic.h"
static struct lmb_span_v1 span(const char *s) {
    return (struct lmb_span_v1){(const uint8_t *)s, strlen(s)};
}
static struct lmb_name_v1 name(void) {
    struct lmb_name_v1 n = {.abi_version=1, .struct_size=sizeof(n)};
    n.name.ptr=(const uint8_t *)"counts"; n.name.len=6; return n;
}
static int native_failure(int code, uint32_t operation) {
    struct lmb_generic_error_v1 error={.abi_version=1,.struct_size=sizeof(error)};
    if (code >= 0 || lmb_generic_last_error_v1(&error)) return 0;
    printf("native-negative code=%d domain=%u operation=%u\n", code, error.domain, error.operation);
    return error.code==code && error.operation==operation &&
        error.domain==LMB_GENERIC_DOMAIN_LIBBPF;
}
static int native_attach_failure(int code) {
    return native_failure(code,LMB_GENERIC_OP_ATTACH);
}
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    if (strcmp(argv[2], "--positive") && strcmp(argv[2], "--lockdown") &&
        (strcmp(argv[2], "--blacklist") || argc != 4)) return 2;
    uint8_t *elf; uint64_t size;
    if (lmb_read_file(argv[1], &elf, &size)) return 2;
    long baseline=lmb_count_fds();
    struct lmb_object_options_v1 opts={.abi_version=1,.struct_size=sizeof(opts)};
    struct lmb_object *object=NULL;
    if (lmb_object_open_v1(elf,size,&opts,&object)) { free(elf); return 1; }
    int rc=lmb_object_load_v1(object);
    if (!strcmp(argv[2], "--lockdown")) {
        if (rc) {
            LMB_CHECK(native_failure(rc,LMB_GENERIC_OP_OBJECT_LOAD) &&
                (rc==-EPERM || rc==-EACCES), "lockdown-load", "native permission refusal at load");
        } else {
            long loaded=lmb_count_fds();
            for (unsigned kind=3;kind<=4;kind++) {
                struct lmb_attach_options_v1 probe={.abi_version=1,.struct_size=sizeof(probe),
                    .program=span(kind==3 ? "probe_entry" : "probe_return"), .family=kind,
                    .target_a=span("__x64_sys_getpid")};
                struct lmb_link *link=NULL;
                rc=lmb_object_attach_v1(object,&probe,&link);
                printf("lockdown-probe kind=%u\n",kind);
                LMB_CHECK(native_attach_failure(rc) && (rc==-EPERM || rc==-EACCES) &&
                    !link && lmb_count_fds()==loaded,"lockdown-attach","native permission refusal at attach");
                if (link) LMB_CHECK(lmb_link_close_v1(&link)==0,
                    "lockdown-unexpected-clean","retire unexpectedly attached link");
                LMB_CHECK(!link && lmb_count_fds()==loaded,
                    "lockdown-probe-clean","probe resources return to loaded baseline");
            }
        }
        LMB_CHECK(lmb_object_close_v1(&object)==0 && !object && lmb_count_fds()==baseline,
            "lockdown-clean", "denial releases all resources");
        free(elf); return lmb_failures ? 1 : 0;
    }
    if (rc) { lmb_object_close_v1(&object); free(elf); return 1; }
    long loaded=lmb_count_fds();
    struct lmb_attach_options_v1 a={.abi_version=1,.struct_size=sizeof(a),
        .program=span("probe_entry"), .family=LMB_ATTACH_FAMILY_KPROBE,
        .target_a=span("lmb_symbol_that_must_not_exist_785aee")};
    struct lmb_link *entry=NULL, *exit=NULL;
    for (unsigned kind=3; kind<=4; kind++) {
        a.family=kind; a.program=span(kind==3 ? "probe_entry" : "probe_return");
        rc=lmb_object_attach_v1(object,&a,&entry);
        LMB_CHECK(native_attach_failure(rc) && !entry && lmb_count_fds()==loaded, "missing-symbol", "native missing symbol refuses and cleans up");
        if (entry) LMB_CHECK(lmb_link_close_v1(&entry)==0,"unexpected-missing-clean","retire unexpected successful attachment");
    }
    if (!strcmp(argv[2], "--blacklist")) {
        a.target_a=span(argv[3]);
        for (unsigned kind=3; kind<=4; kind++) {
            a.family=kind; a.program=span(kind==3 ? "probe_entry" : "probe_return");
            struct lmb_attach_options_v1 control=a;
            control.target_a=span("__x64_sys_getpid");
            rc=lmb_object_attach_v1(object,&control,&entry);
            LMB_CHECK(rc==0 && entry,"blacklist-control","known-good control attach rc=%d",rc);
            if (entry) LMB_CHECK(lmb_link_close_v1(&entry)==0,"blacklist-control-close","retire known-good control");
            LMB_CHECK(lmb_count_fds()==loaded,"blacklist-control-fds","control returns to loaded baseline");
            rc=lmb_object_attach_v1(object,&a,&entry);
            LMB_CHECK(native_attach_failure(rc) && !entry && lmb_count_fds()==loaded, "blacklisted-symbol", "selected blacklist symbol refuses and cleans up");
            if (entry) lmb_link_close_v1(&entry);
        }
    } else {
        struct lmb_name_v1 n=name(); uint32_t key=3; uint64_t pid=(uint64_t)getpid(); uint64_t tid=(uint64_t)syscall(SYS_gettid);
        a.target_a=span("__x64_sys_getpid");
        LMB_CHECK(lmb_object_attach_v1(object,&a,&exit)==0 && exit, "return-attach", "return hook first");
        a.family=3; a.program=span("probe_entry");
        LMB_CHECK(lmb_object_attach_v1(object,&a,&entry)==0 && entry, "entry-attach", "entry hook second");
        LMB_CHECK(lmb_object_map_update_v1(object,&n,(void *)&key,4,(void *)&tid,8,0)==0,
            "owner-filter", "configure independent process scope");
        for (unsigned i=0;i<257;i++) LMB_CHECK(syscall(SYS_getpid)==(long)pid,"trigger","independent syscall ledger");
        uint64_t disabled=0;
        LMB_CHECK(lmb_object_map_update_v1(object,&n,(void *)&key,4,(void *)&disabled,8,0)==0,
            "close-window", "disable fixture admission before teardown");
        int entry_close=lmb_link_close_v1(&entry);
        int exit_close=lmb_link_close_v1(&exit);
        LMB_CHECK(entry_close==0 && exit_close==0, "close-pair", "explicit reverse teardown");
        for (key=0;key<2;key++) {
            uint64_t value=0,needed=0;
            LMB_CHECK(lmb_object_map_lookup_v1(object,&n,(void *)&key,4,(void *)&value,8,&needed)==0 && value==257,
                "probe-ledger", "entry and return counters equal independent ledger");
        }
        LMB_CHECK(lmb_count_fds()==loaded,"pair-fds","link descriptors retired");
    }
    LMB_CHECK(lmb_object_close_v1(&object)==0 && lmb_count_fds()==baseline,"generic-unload","all object resources retired");
    if (!strcmp(argv[2], "--positive")) {
        struct lmb_options_v1 o; struct lmb_session *session=NULL;
        lmb_make_options(&o,"events",4096);
        rc=lmb_open(elf,size,&o,&session);
        if (!rc) rc=lmb_load(session);
        LMB_CHECK(rc==0,"session-load","real tracing/probe object load");
        if (!rc) {
            struct lmb_name_v1 n=name(); uint32_t key=3; uint64_t pid=getpid(); uint64_t tid=(uint64_t)syscall(SYS_gettid);
            struct lmb_attach_v1 sites[3];
            lmb_make_attach(&sites[0],"probe_return",4,"__x64_sys_getpid","");
            lmb_make_attach(&sites[1],"probe_tracing",2,"__x64_sys_getpid","");
            lmb_make_attach(&sites[2],"probe_entry",3,"__x64_sys_getpid","");
            LMB_CHECK(lmb_attach(session,sites,3)==0,"session-attach","tracing and typed probes");
            LMB_CHECK(lmb_map_write(session,&n,(void *)&key,4,(void *)&tid,8)==0,"session-filter","process scope");
            for (unsigned i=0;i<257;i++) LMB_CHECK(syscall(SYS_getpid)==(long)pid,"session-trigger","independent syscall ledger");
            uint64_t disabled=0;
            LMB_CHECK(lmb_map_write(session,&n,(void *)&key,4,(void *)&disabled,8)==0,"session-close-window","disable admission");
            LMB_CHECK(lmb_detach(session)==0,"session-detach","reverse ordered teardown");
            for (key=0;key<3;key++) {
                uint64_t value=0; uint32_t needed=0;
                LMB_CHECK(lmb_map_read(session,&n,(void *)&key,4,(void *)&value,8,&needed)==0 && value==257,
                    "session-ledger","all three hook counters equal ledger");
            }
        }
        LMB_CHECK(lmb_close(&session)==0 && lmb_count_fds()==baseline,"session-unload","object and links retire");
    }
    free(elf); return lmb_failures ? 1 : 0;
}
