/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Test-only public-API responses for the live gate's negative controls. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libbpf_mojo_generic.h"
static int owner, loaded, live, controls, negatives, closes, object_closes, owner_fd=-1;
static int32_t error_code;
static uint32_t error_domain, error_operation=LMB_GENERIC_OP_ATTACH;
struct token { int fd; unsigned kind; };
static int scenario(const char *name) { const char *s=getenv("LMB_GATE_CASE"); return s && !strcmp(s,name); }
int32_t __wrap_lmb_object_open_v1(const uint8_t *elf, uint64_t size,
        const struct lmb_object_options_v1 *opts, struct lmb_object **out) {
    if (!elf || !size || !opts || !out) _exit(91);
    owner_fd=open("/dev/null",O_RDONLY|O_CLOEXEC);
    if (owner_fd<0) _exit(92);
    *out=(void *)&owner; return 0;
}
int32_t __wrap_lmb_object_load_v1(struct lmb_object *object) {
    if (object!=(void *)&owner) _exit(91);
    const char *mode=getenv("LMB_GATE_CASE");
    if (mode && !strncmp(mode,"lockdown-load-",14)) {
        error_code=scenario("lockdown-load-access") ? -EACCES : -EPERM;
        if (scenario("lockdown-load-other")) error_code=-EINVAL;
        error_domain=scenario("lockdown-load-bridge") ? LMB_GENERIC_DOMAIN_BRIDGE : LMB_GENERIC_DOMAIN_LIBBPF;
        error_operation=scenario("lockdown-load-operation") ? LMB_GENERIC_OP_ATTACH : LMB_GENERIC_OP_OBJECT_LOAD;
        int code=error_code;
        if (scenario("lockdown-load-code")) error_code=-EINVAL;
        printf("load-refusal code=%d\n",code);
        return code;
    }
    loaded=1; return 0;
}
int32_t __wrap_lmb_object_close_v1(struct lmb_object **object) {
    if (live) return -EBUSY;
    if (close(owner_fd)) _exit(92);
    owner_fd=-1; object_closes++;
    *object=NULL; loaded=0; return 0;
}
int32_t __wrap_lmb_object_attach_v1(struct lmb_object *object,
        const struct lmb_attach_options_v1 *opts, struct lmb_link **out) {
    if (!loaded || object!=(void *)&owner || !opts || !out) _exit(91);
    *out=NULL;
    if (opts->family!=3 && opts->family!=4) _exit(91);
    const char *program=opts->family==3 ? "probe_entry" : "probe_return";
    if (opts->program.len!=strlen(program) || memcmp(opts->program.ptr,program,strlen(program)) ||
            opts->target_b.len || opts->flags || opts->_reserved) _exit(91);
    int control=opts->target_a.len==sizeof("__x64_sys_getpid")-1 && !memcmp(opts->target_a.ptr,"__x64_sys_getpid",sizeof("__x64_sys_getpid")-1);
    int missing=opts->target_a.len==sizeof("lmb_symbol_that_must_not_exist_785aee")-1 && !memcmp(opts->target_a.ptr,"lmb_symbol_that_must_not_exist_785aee",sizeof("lmb_symbol_that_must_not_exist_785aee")-1);
    if (control) { controls++; printf("control kind=%u\n",opts->family); }
    if (control && (scenario("lockdown-denied") || scenario("lockdown-bridge") ||
            scenario("lockdown-operation") || scenario("lockdown-code") || scenario("lockdown-other"))) {
        error_code=opts->family==3 ? -EPERM : -EACCES;
        if (scenario("lockdown-other")) error_code=-ENOENT;
        error_domain=scenario("lockdown-bridge") ? LMB_GENERIC_DOMAIN_BRIDGE : LMB_GENERIC_DOMAIN_LIBBPF;
        error_operation=scenario("lockdown-operation") ? LMB_GENERIC_OP_OBJECT_LOAD : LMB_GENERIC_OP_ATTACH;
        int code=error_code;
        if (scenario("lockdown-code")) error_code=-EINVAL;
        return code;
    }
    if (!control && !missing) {
        if (opts->target_a.len!=18 || memcmp(opts->target_a.ptr,"blacklisted_target",18)) _exit(91);
        negatives++;
    }
    if (scenario("blanket") || (!control && !(missing && scenario("missing-success")))) {
        error_code=scenario("blanket") ? -EPERM : -EINVAL;
        error_domain=(!control && !missing && scenario("bridge")) ? LMB_GENERIC_DOMAIN_BRIDGE : LMB_GENERIC_DOMAIN_LIBBPF;
        return error_code;
    }
    struct token *token=malloc(sizeof(*token));
    if (!token) _exit(92);
    token->fd=open("/dev/null",O_RDONLY|O_CLOEXEC);
    if (token->fd<0) _exit(92);
    token->kind=opts->family; live++; *out=(void *)token; return 0;
}
int32_t __wrap_lmb_link_close_v1(struct lmb_link **cell) {
    if (cell && *cell) {
        struct token *token=(void *)*cell;
        unsigned kind=token->kind;
        if (close(token->fd)) _exit(92);
        free(token); live--; *cell=NULL;
        closes++; printf("close kind=%u\n",kind);
        if (scenario("pair-close-error") && kind==3) return -EIO;
    }
    return 0;
}
int32_t __wrap_lmb_generic_last_error_v1(struct lmb_generic_error_v1 *out) {
    *out=(struct lmb_generic_error_v1){.abi_version=1,.struct_size=sizeof(*out),
        .operation=error_operation,.domain=error_domain,.code=error_code};
    return 0;
}
/* Only reach the real positive runner's pair-cleanup branch. These map
 * responses are not event evidence; the later session route is refused. */
int32_t __wrap_lmb_object_map_update_v1(struct lmb_object *object,
        const struct lmb_name_v1 *name, const uint8_t *key, uint64_t key_bytes,
        const uint8_t *value, uint64_t value_bytes, uint64_t flags) {
    if (!scenario("pair-close-error") || object!=(void *)&owner || !name || !key ||
            key_bytes!=4 || !value || value_bytes!=8 || flags) _exit(91);
    return 0;
}
int32_t __wrap_lmb_object_map_lookup_v1(struct lmb_object *object,
        const struct lmb_name_v1 *name, const uint8_t *key, uint64_t key_bytes,
        uint8_t *value, uint64_t capacity, uint64_t *needed) {
    if (!scenario("pair-close-error") || object!=(void *)&owner || !name || !key ||
            key_bytes!=4 || !value || capacity!=8 || !needed) _exit(91);
    uint64_t count=257; memcpy(value,&count,sizeof(count)); *needed=sizeof(count); return 0;
}
int32_t __wrap_lmb_open(const uint8_t *elf, uint64_t size,
        const struct lmb_options_v1 *opts, struct lmb_session **out) {
    if (!scenario("pair-close-error") || !elf || !size || !opts || !out) _exit(91);
    *out=NULL; puts("NOT_RUN gate session follow-on"); return -EIO;
}
__attribute__((destructor)) static void result(void) {
    printf("gate-oracle controls=%d negatives=%d live=%d\n",controls,negatives,live);
    printf("cleanup-oracle closes=%d object_closes=%d owner_fd_open=%d\n",closes,object_closes,owner_fd>=0);
}
