/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Script only the syscall boundary; retain parsed geometry and libbpf wrappers. */
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <gelf.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "libbpf_mojo_generic.h"
#ifdef LMB_MAP_KEYS_RED_BASELINE
extern int32_t lmb_object_map_delete_v1(struct lmb_object *, const struct lmb_name_v1 *, const uint8_t *, uint64_t, uint64_t) __attribute__((weak));
extern int32_t lmb_object_map_next_key_v1(struct lmb_object *, const struct lmb_name_v1 *, uint32_t, const uint8_t *, uint64_t, uint8_t *, uint64_t, uint64_t *) __attribute__((weak));
#endif
static unsigned checks, failures, calls, allocations, closes;
static int allocation_fault;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr,"FAIL %u: %s\n",__LINE__,#c); } } while(0)
static struct { int armed, command, result, first; size_t size; uint64_t flags; uint8_t key[13], output[13]; const void *caller; } script;
long lmb_test_bpf_dispatch(int command, void *raw, unsigned size) {
    union bpf_attr *a = raw;
    if (!script.armed || command != script.command || (command != BPF_MAP_DELETE_ELEM && command != BPF_MAP_GET_NEXT_KEY)) _exit(99);
    script.armed = 0; calls++;
    CHECK(a && a->map_fd == 6001);
    CHECK(size == (command == BPF_MAP_DELETE_ELEM ?
        offsetof(union bpf_attr, flags) + sizeof(a->flags) :
        offsetof(union bpf_attr, next_key) + sizeof(a->next_key)));
    if (command == BPF_MAP_DELETE_ELEM) CHECK(a->flags == script.flags);
    if (script.first) CHECK(a->key == 0);
    else CHECK(a->key && !memcmp((void *)(uintptr_t)a->key, script.key, script.size));
    if (command == BPF_MAP_GET_NEXT_KEY) {
        CHECK(a->next_key && (void *)(uintptr_t)a->next_key != script.caller);
        memcpy((void *)(uintptr_t)a->next_key, script.output, script.size);
    }
    if (script.result) { errno = -script.result; return -1; }
    return 0;
}
int __wrap_bpf_object__load(struct bpf_object *o) { CHECK(o != NULL); return 0; }
int __real_bpf_map__fd(const struct bpf_map *m);
int __wrap_bpf_map__fd(const struct bpf_map *m) { CHECK(__real_bpf_map__fd(m) == -1); return 6001; }
static struct bpf_object *parsed;
struct bpf_object *__real_bpf_object__open_mem(const void *, size_t, const struct bpf_object_open_opts *);
struct bpf_object *__wrap_bpf_object__open_mem(const void *b, size_t n, const struct bpf_object_open_opts *o) { parsed = __real_bpf_object__open_mem(b,n,o); return parsed; }
void __real_bpf_object__close(struct bpf_object *o);
void __wrap_bpf_object__close(struct bpf_object *o) { if (o) { struct bpf_map *m; bpf_object__for_each_map(m,o) CHECK(__real_bpf_map__fd(m) == -1); closes++; } __real_bpf_object__close(o); }
void *__real_malloc(size_t n);
void *__wrap_malloc(size_t n) { if (allocation_fault && ++allocations == (unsigned)allocation_fault) return NULL; return __real_malloc(n); }
int __real_bpf_map_delete_elem_flags(int, const void *, __u64);
int __wrap_bpf_map_delete_elem_flags(int fd, const void *k, __u64 f) { int r = __real_bpf_map_delete_elem_flags(fd,k,f); errno=ENOTTY; return r; }
int __real_bpf_map_get_next_key(int, const void *, void *);
int __wrap_bpf_map_get_next_key(int fd, const void *k, void *o) { int r = __real_bpf_map_get_next_key(fd,k,o); errno=ENOTTY; return r; }
static struct lmb_name_v1 name_of(const char *s) { struct lmb_name_v1 n={1,sizeof(n),{(const uint8_t *)s,(uint32_t)strlen(s),0}}; return n; }
static void diagnostic(unsigned op, unsigned domain, int rc) { struct lmb_generic_error_v1 e={.abi_version=1,.struct_size=sizeof(e)}; CHECK(lmb_generic_last_error_v1(&e)==0); CHECK(e.operation==op && e.domain==domain && e.code==rc); }
static void arm(int command, const uint8_t *key, size_t n, uint64_t flags, int result, const void *output) { CHECK(!script.armed); memset(&script,0,sizeof(script)); script.armed=1; script.command=command; script.size=n; script.flags=flags; script.result=result; script.first=!key; script.caller=output; if(key) memcpy(script.key,key,n); for(size_t i=0;i<n;i++) script.output[i]=(uint8_t)(0x80+i); }
static void untouched(const uint8_t *b,size_t n) { for(size_t i=0;i<n;i++) CHECK(b[i]==0xa5); }
static void test_null_first_and_exact_current(struct lmb_object *o) {
    struct lmb_name_v1 n=name_of("values"); uint8_t key[4]={0xff,0x80,0x42,0x91}, out[24]; uint64_t needed=123;
    memset(out,0xa5,sizeof(out)); arm(BPF_MAP_GET_NEXT_KEY,NULL,4,0,0,out);
    CHECK(lmb_object_map_next_key_v1(o,&n,0,(void *)1,0,out,sizeof(out),&needed)==0); CHECK(needed==4); CHECK(!memcmp(out,script.output,4)); untouched(out+4,20);
    arm(BPF_MAP_GET_NEXT_KEY,key,4,0,0,out); CHECK(lmb_object_map_next_key_v1(o,&n,1,key,4,out,4,&needed)==0);
    memcpy(out,key,4); arm(BPF_MAP_GET_NEXT_KEY,key,4,0,0,out); CHECK(lmb_object_map_next_key_v1(o,&n,1,out,4,out,4,&needed)==0); CHECK(!memcmp(out,script.output,4));
}
static void test_next_key_end_is_native_enoent(struct lmb_object *o) {
    struct lmb_name_v1 n=name_of("values"); uint8_t out[16]; uint64_t needed;
    for(int rc=-2;rc>=-4093;rc-=4091) { memset(out,0xa5,sizeof(out)); needed=123; arm(BPF_MAP_GET_NEXT_KEY,NULL,4,0,rc,out); CHECK(lmb_object_map_next_key_v1(o,&n,0,NULL,0,out,sizeof(out),&needed)==rc); CHECK(needed==0); diagnostic(19,3,rc); untouched(out,sizeof(out)); }
}
static void test_delete_exact_flags_and_signed_error(struct lmb_object *o) {
    struct lmb_name_v1 n=name_of("values"); uint8_t key[4]={0xff,0x80,0x42,0x91}; uint64_t flags=UINT64_C(0x80000000ffffffff);
    int errors[]={0,-2,-1,-4093};
    for(unsigned i=0;i<4;i++) { arm(BPF_MAP_DELETE_ELEM,key,4,flags,errors[i],NULL); CHECK(lmb_object_map_delete_v1(o,&n,key,4,flags)==errors[i]); if(errors[i]) diagnostic(18,3,errors[i]); }
}
static void invalid(struct lmb_object *o, struct lmb_name_v1 *n, unsigned has, const uint8_t *key, uint64_t bytes, uint8_t *out, uint64_t cap, uint64_t *needed, int expected) { unsigned before=calls; CHECK(lmb_object_map_next_key_v1(o,n,has,key,bytes,out,cap,needed)==expected); CHECK(calls==before); diagnostic(19,4,expected); }
static void test_key_capacity_guards_alias_and_allocation(struct lmb_object *o,struct lmb_object *unloaded) {
    struct lmb_name_v1 n=name_of("values"); _Alignas(8) uint8_t out[64]; uint8_t key[4]={0}; uint64_t needed=123;
    memset(out,0xa5,sizeof(out));
    invalid(o,&n,2,key,4,out,8,&needed,-EINVAL); invalid(o,&n,0,key,4,out,8,&needed,-EINVAL); invalid(o,&n,1,key,0,out,8,&needed,-EINVAL); invalid(o,&n,1,key,3,out,8,&needed,-EINVAL); invalid(o,&n,1,NULL,4,out,8,&needed,-EINVAL);
    invalid(unloaded,&n,0,NULL,0,out,8,&needed,-EINVAL); invalid(NULL,&n,0,NULL,0,out,8,&needed,-EINVAL);
    invalid(o,&n,0,NULL,0,NULL,8,&needed,-EINVAL); invalid(o,&n,0,NULL,0,(void *)(UINTPTR_MAX-1),4,&needed,-EINVAL); invalid(o,&n,0,NULL,0,out,UINT64_MAX,&needed,-EINVAL);
    invalid(o,&n,1,(void *)(UINTPTR_MAX-1),4,out,8,&needed,-EINVAL); invalid(o,&n,0,NULL,0,out,8,NULL,-EINVAL); invalid(o,&n,0,NULL,0,out,8,(void *)(UINTPTR_MAX-3),-EINVAL);
    invalid(o,&n,0,NULL,0,out,8,(void *)out,-EINVAL); invalid(o,&n,1,out+14,4,out+32,8,(void *)(out+8),-EINVAL);
    invalid(o,&n,0,NULL,0,out,8,(void *)&n,-EINVAL);
    uint8_t name_bytes[16] = "values";
    struct lmb_name_v1 alias=name_of((char *)name_bytes);
    invalid(o,&alias,0,NULL,0,out+32,8,(void *)name_bytes,-EINVAL);
    CHECK(!strcmp((char *)name_bytes,"values"));
    CHECK(needed==123); untouched(out,sizeof(out));
    for(unsigned cap=0;cap<4;cap++) { needed=123; invalid(o,&n,0,NULL,0,out,cap,&needed,-ENOSPC); CHECK(needed==4); untouched(out,sizeof(out)); }
    for(int fault=1;fault<=2;fault++) { allocation_fault=fault; allocations=0; needed=123; CHECK(lmb_object_map_next_key_v1(o,&n,1,key,4,out,8,&needed)==-ENOMEM); allocation_fault=0; CHECK(allocations==(unsigned)fault && needed==123); diagnostic(19,1,-ENOMEM); untouched(out,sizeof(out)); }
    n=name_of("absent"); needed=123; invalid(o,&n,0,NULL,0,out,8,&needed,-ENOENT); CHECK(needed==123);
    n=name_of("bloom_filter"); invalid(o,&n,0,NULL,0,out,8,&needed,-EOPNOTSUPP); CHECK(lmb_object_map_delete_v1(o,&n,NULL,0,0)==-EOPNOTSUPP); diagnostic(18,4,-EOPNOTSUPP);
}
static void test_geometry_derivatives(const uint8_t *elf,size_t len) {
    for(unsigned bytes=1;bytes<=13;bytes+=12) {
        struct lmb_object_options_v1 opts={.abi_version=1,.struct_size=sizeof(opts)}; struct lmb_object *o=NULL;
        CHECK(lmb_object_open_v1(elf,len,&opts,&o)==0); struct bpf_map *map=bpf_object__find_map_by_name(parsed,"values"); CHECK(bpf_map__set_key_size(map,bytes)==0); CHECK(lmb_object_load_v1(o)==0);
        struct lmb_name_v1 n=name_of("values"); uint8_t key[13],out[20]; memset(key,0x91,sizeof(key)); memset(out,0xa5,sizeof(out)); uint64_t needed=123;
        arm(BPF_MAP_GET_NEXT_KEY,key,bytes,0,0,out); CHECK(lmb_object_map_next_key_v1(o,&n,1,key,bytes,out,sizeof(out),&needed)==0); CHECK(needed==bytes); CHECK(!memcmp(out,script.output,bytes)); untouched(out+bytes,sizeof(out)-bytes);
        arm(BPF_MAP_DELETE_ELEM,key,bytes,0,0,NULL); CHECK(lmb_object_map_delete_v1(o,&n,key,bytes,0)==0); CHECK(lmb_object_close_v1(&o)==0);
    }
}
typedef int32_t (*delete_fn)(struct lmb_object *, const struct lmb_name_v1 *, const uint8_t *, uint64_t, uint64_t);
typedef int32_t (*next_fn)(struct lmb_object *, const struct lmb_name_v1 *, uint32_t, const uint8_t *, uint64_t, uint8_t *, uint64_t, uint64_t *);
typedef int32_t (*stats_fn)(struct lmb_buffer *, struct lmb_buffer_stats_v1 *);
_Static_assert(_Generic(&lmb_object_map_delete_v1, delete_fn: 1, default: 0), "delete scalar/pointer signature");
_Static_assert(_Generic(&lmb_buffer_stats_v1, stats_fn: 1, default: 0), "stats scalar/pointer signature");
_Static_assert(_Generic(&lmb_object_map_next_key_v1, next_fn: 1, default: 0), "next-key scalar/pointer signature");
_Static_assert(sizeof(int) == 4 && sizeof(void *) == 8 && sizeof(uint64_t) == 8, "LP64 boundary");
static void test_exact_candidate_abi(const char *path) {
    static const char *const names[] = {
        "lmb_open", "lmb_load", "lmb_attach", "lmb_poll", "lmb_map_info", "lmb_map_read", "lmb_map_write", "lmb_stats", "lmb_last_error", "lmb_detach", "lmb_close",
        "lmb_object_open_v1", "lmb_object_configure_program_v1", "lmb_object_load_v1", "lmb_object_program_info_v1", "lmb_object_map_info_v1", "lmb_object_close_v1", "lmb_object_release_v1", "lmb_generic_last_error_v1", "lmb_object_map_lookup_v1", "lmb_object_map_update_v1", "lmb_program_test_run_v1", "lmb_object_attach_v1", "lmb_link_close_v1", "lmb_buffer_open_v1", "lmb_buffer_poll_v1", "lmb_buffer_close_v1", "lmb_object_ref_v1", "lmb_object_unref_v1", "lmb_object_gen_v1", "lmb_object_gen_check_v1", "lmb_object_map_delete_v1", "lmb_object_map_next_key_v1", "lmb_buffer_stats_v1"
    };
    unsigned seen[34] = {0}, count = 0, soname = 0;
    CHECK(elf_version(EV_CURRENT) != EV_NONE);
    int fd = open(path, O_RDONLY); CHECK(fd >= 0); if (fd < 0) return;
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL); CHECK(elf != NULL); if (!elf) { close(fd); return; }
    Elf_Scn *section = NULL;
    while ((section = elf_nextscn(elf, section))) {
        GElf_Shdr header; CHECK(gelf_getshdr(section, &header) != NULL);
        if (header.sh_type != SHT_DYNSYM && header.sh_type != SHT_DYNAMIC) continue;
        Elf_Data *data = elf_getdata(section, NULL); CHECK(data != NULL);
        for (size_t i = 0; i < header.sh_size / header.sh_entsize; i++) {
            if (header.sh_type == SHT_DYNAMIC) {
                GElf_Dyn dynamic; CHECK(gelf_getdyn(data, (int)i, &dynamic) != NULL);
                if (dynamic.d_tag == DT_SONAME) { const char *name = elf_strptr(elf, header.sh_link, dynamic.d_un.d_val); CHECK(name && !strcmp(name,"libbpf_mojo.so.1")); soname++; }
                continue;
            }
            GElf_Sym symbol; CHECK(gelf_getsym(data, (int)i, &symbol) != NULL);
            if (symbol.st_shndx == SHN_UNDEF || GELF_ST_TYPE(symbol.st_info) != STT_FUNC) continue;
            const char *name = elf_strptr(elf, header.sh_link, symbol.st_name); unsigned found = 0;
            for (unsigned j = 0; j < 34; j++) if (name && !strcmp(name,names[j])) { seen[j]++; found++; }
            CHECK(found == 1); count++;
        }
    }
    CHECK(count == 34 && soname == 1); for (unsigned j=0;j<34;j++) CHECK(seen[j] == 1);
    CHECK(elf_end(elf) == 0); CHECK(close(fd) == 0);
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL); CHECK(library != NULL); if (!library) return;
    for (unsigned j=0;j<34;j++) CHECK(dlvsym(library,names[j],j<11?"LIBBPF_MOJO_1":"LIBBPF_MOJO_GENERIC_1") != NULL);
    delete_fn deletion = (delete_fn)dlvsym(library,"lmb_object_map_delete_v1","LIBBPF_MOJO_GENERIC_1");
    next_fn iteration = (next_fn)dlvsym(library,"lmb_object_map_next_key_v1","LIBBPF_MOJO_GENERIC_1");
    stats_fn snapshot = (stats_fn)dlvsym(library,"lmb_buffer_stats_v1","LIBBPF_MOJO_GENERIC_1");
    struct lmb_name_v1 n=name_of("values");uint8_t key[4]={0xff,0x80,0x42,0x91},out[8];uint64_t needed=123;memset(out,0xa5,sizeof(out));
    struct lmb_buffer_stats_v1 st; memset(&st,0,sizeof(st)); st.abi_version=1; st.struct_size=sizeof(st);
    CHECK(deletion(NULL,&n,key,4,UINT64_C(0x80000000ffffffff)) == -EINVAL);
    CHECK(iteration(NULL,&n,1,key,4,out,sizeof(out),&needed) == -EINVAL); CHECK(needed == 123); untouched(out,sizeof(out));
    CHECK(snapshot != NULL && snapshot(NULL,&st) == -EINVAL);
    /* No static-instance opaque owner crosses into the opened library. */
    CHECK(dlclose(library) == 0);
}
static void test_protected_pages_and_adjacent_spans(struct lmb_object *o) {
    long page=sysconf(_SC_PAGESIZE); CHECK(page > 64);
    uint8_t *memory=mmap(NULL,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); CHECK(memory != MAP_FAILED); if(memory==MAP_FAILED)return;
    CHECK(mprotect(memory+page,(size_t)page,PROT_NONE)==0);
    uint8_t *edge=memory+page-4;memset(edge,0x91,4);struct lmb_name_v1 n=name_of("values");uint64_t needed=123;
    arm(BPF_MAP_GET_NEXT_KEY,edge,4,0,0,edge);CHECK(lmb_object_map_next_key_v1(o,&n,1,edge,4,edge,4,&needed)==0);CHECK(needed==4);
    arm(BPF_MAP_DELETE_ELEM,edge,4,0,0,NULL);CHECK(lmb_object_map_delete_v1(o,&n,edge,4,0)==0);
    uint8_t *key=memory+16,*out=memory+20;uint64_t *adjacent=(void *)(memory+8);memset(key,0x91,4);*adjacent=123;
    arm(BPF_MAP_GET_NEXT_KEY,key,4,0,0,out);CHECK(lmb_object_map_next_key_v1(o,&n,1,key,4,out,4,adjacent)==0);CHECK(*adjacent==4);
    CHECK(munmap(memory,(size_t)page*2)==0);
}
static void test_delete_missing_is_error(struct lmb_object *o) {
    struct lmb_name_v1 n=name_of("values");uint8_t key[4]={0};arm(BPF_MAP_DELETE_ELEM,key,4,0,-ENOENT,NULL);CHECK(lmb_object_map_delete_v1(o,&n,key,4,0)==-ENOENT);diagnostic(18,3,-ENOENT);
    unsigned before=calls;CHECK(lmb_object_map_delete_v1(o,&n,key,3,0)==-EINVAL);CHECK(lmb_object_map_delete_v1(o,&n,NULL,4,0)==-EINVAL);CHECK(lmb_object_map_delete_v1(o,&n,(void *)(UINTPTR_MAX-1),4,0)==-EINVAL);CHECK(calls==before);
}
static void test_error_does_not_copy_dirty_scratch(struct lmb_object *o) {
    struct lmb_name_v1 n=name_of("values");uint8_t key[4]={0xff,0x42,0x80,0x91},out[12];int errors[]={-EPERM,-EINTR,-4093};
    for(unsigned i=0;i<3;i++){memset(out,0xa5,sizeof(out));uint64_t needed=123;unsigned before=calls;arm(BPF_MAP_GET_NEXT_KEY,key,4,0,errors[i],out);CHECK(lmb_object_map_next_key_v1(o,&n,1,key,4,out,sizeof(out),&needed)==errors[i]);CHECK(needed==0&&calls==before+1);diagnostic(19,3,errors[i]);untouched(out,sizeof(out));}
}
static void test_hash_array_and_unsupported_operation_are_distinct(struct lmb_object *o) {
    struct lmb_name_v1 n=name_of("values");uint32_t keys[]={0,UINT32_C(0x80000000),UINT32_MAX};uint8_t current[4]={0},out[4];uint64_t needed=0;
    for(unsigned i=0;i<3;i++){arm(BPF_MAP_GET_NEXT_KEY,i?current:NULL,4,0,0,out);memcpy(script.output,&keys[i],4);CHECK(lmb_object_map_next_key_v1(o,&n,i?1:0,i?current:NULL,i?4:0,out,4,&needed)==0);CHECK(!memcmp(out,&keys[i],4));memcpy(current,out,4);for(unsigned j=0;j<i;j++)CHECK(keys[i]!=keys[j]);}
    /* A removed cursor can restart at first; the bridge forwards it once. */
    arm(BPF_MAP_GET_NEXT_KEY,current,4,0,0,out);memcpy(script.output,&keys[0],4);CHECK(lmb_object_map_next_key_v1(o,&n,1,current,4,out,4,&needed)==0);CHECK(!memcmp(out,&keys[0],4));
}
int main(int argc,char **argv) {
#ifdef LMB_MAP_KEYS_RED_BASELINE
    CHECK(lmb_object_map_delete_v1 != NULL); CHECK(lmb_object_map_next_key_v1 != NULL);
    if(failures) { fputs("expected RED: both new retained map operations absent\n",stderr); return 1; }
#endif
    if (argc == 2 && !strcmp(argv[1], "--guard-trap")) {
        union bpf_attr a = {0};
        syscall(SYS_bpf, BPF_MAP_CREATE, &a, (unsigned)sizeof(a));
        return 1;
    }
    if(argc!=3) return 2;
    test_exact_candidate_abi(argv[2]);
    FILE *f=fopen(argv[1],"rb"); if(!f) return 2; CHECK(fseek(f,0,SEEK_END)==0); long len=ftell(f); rewind(f); uint8_t *elf=malloc((size_t)len); CHECK(elf && fread(elf,1,(size_t)len,f)==(size_t)len); CHECK(fclose(f)==0);
    struct lmb_object_options_v1 opts={.abi_version=1,.struct_size=sizeof(opts)}; struct lmb_object *o=NULL,*unloaded=NULL;
    CHECK(lmb_object_open_v1(elf,(size_t)len,&opts,&unloaded)==0); CHECK(lmb_object_open_v1(elf,(size_t)len,&opts,&o)==0); CHECK(lmb_object_load_v1(o)==0);
    test_protected_pages_and_adjacent_spans(o); test_delete_missing_is_error(o); test_error_does_not_copy_dirty_scratch(o); test_hash_array_and_unsupported_operation_are_distinct(o);
    test_null_first_and_exact_current(o); test_next_key_end_is_native_enoent(o); test_delete_exact_flags_and_signed_error(o); test_key_capacity_guards_alias_and_allocation(o,unloaded);
    struct lmb_name_v1 array=name_of("counter"); uint8_t key[4]={0},out[4]; uint64_t needed=0; arm(BPF_MAP_GET_NEXT_KEY,NULL,4,0,0,out); CHECK(lmb_object_map_next_key_v1(o,&array,0,NULL,0,out,4,&needed)==0); arm(BPF_MAP_DELETE_ELEM,key,4,0,-EINVAL,NULL); CHECK(lmb_object_map_delete_v1(o,&array,key,4,0)==-EINVAL); diagnostic(18,3,-EINVAL);
    CHECK(lmb_object_close_v1(&o)==0); CHECK(lmb_object_close_v1(&unloaded)==0); test_geometry_derivatives(elf,(size_t)len); free(elf); CHECK(!script.armed && closes==4);
    printf("map keys: %u checks, %u failures, %u scripted requests, zero executed BPF calls\n",checks,failures,calls); return failures?1:0;
}
