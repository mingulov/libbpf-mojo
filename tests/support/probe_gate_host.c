/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Test-only public-API responses for the live gate's negative controls. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libbpf_mojo_generic.h"
static int owner, loaded, live, controls, negatives;
static int32_t error_code;
static uint32_t error_domain;
struct token { int fd; };
static int scenario(const char *name) { const char *s=getenv("LMB_GATE_CASE"); return s && !strcmp(s,name); }
int32_t __wrap_lmb_object_open_v1(const uint8_t *elf, uint64_t size,
        const struct lmb_object_options_v1 *opts, struct lmb_object **out) {
    if (!elf || !size || !opts || !out) _exit(91);
    *out=(void *)&owner; return 0;
}
int32_t __wrap_lmb_object_load_v1(struct lmb_object *object) {
    if (object!=(void *)&owner) _exit(91);
    loaded=1; return 0;
}
int32_t __wrap_lmb_object_close_v1(struct lmb_object **object) {
    if (live) return -EBUSY;
    *object=NULL; loaded=0; return 0;
}
int32_t __wrap_lmb_object_attach_v1(struct lmb_object *object,
        const struct lmb_attach_options_v1 *opts, struct lmb_link **out) {
    if (!loaded || object!=(void *)&owner || !opts || !out) _exit(91);
    *out=NULL;
    if (opts->family!=3 && opts->family!=4) _exit(91);
    int control=opts->target_a.len==sizeof("__x64_sys_getpid")-1 && !memcmp(opts->target_a.ptr,"__x64_sys_getpid",sizeof("__x64_sys_getpid")-1);
    int missing=opts->target_a.len==sizeof("lmb_symbol_that_must_not_exist_785aee")-1 && !memcmp(opts->target_a.ptr,"lmb_symbol_that_must_not_exist_785aee",sizeof("lmb_symbol_that_must_not_exist_785aee")-1);
    if (control) { controls++; printf("control kind=%u\n",opts->family); }
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
    live++; *out=(void *)token; return 0;
}
int32_t __wrap_lmb_link_close_v1(struct lmb_link **cell) {
    if (cell && *cell) {
        struct token *token=(void *)*cell;
        if (close(token->fd)) _exit(92);
        free(token); live--; *cell=NULL;
    }
    return 0;
}
int32_t __wrap_lmb_generic_last_error_v1(struct lmb_generic_error_v1 *out) {
    out->operation=LMB_GENERIC_OP_ATTACH; out->domain=error_domain; out->code=error_code; return 0;
}
__attribute__((destructor)) static void result(void) {
    printf("gate-oracle controls=%d negatives=%d live=%d\n",controls,negatives,live);
}
