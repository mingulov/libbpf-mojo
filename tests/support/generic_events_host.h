/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
#ifndef LMB_GENERIC_EVENTS_HOST_H
#define LMB_GENERIC_EVENTS_HOST_H
#include <stdint.h>
#include <stddef.h>
#include "libbpf_mojo_generic.h"
/* Test-only controls: no BPF load/attach or perf-event syscall is forwarded. */
enum ge_query { GE_ATTACH = 1, GE_DESTROY, GE_NEW, GE_CONSUME, GE_WAIT,
    GE_INFO, GE_MAPS, GE_OBJECT_CLOSE, GE_ALLOCS, GE_FAULT_HITS,
    GE_RING_FREE, GE_RECEIVED, GE_DELIVERED, GE_STAGED, GE_MALFORMED, GE_DROPPED,
    GE_CONSUMER_POSITION, GE_PRODUCER_POSITION, GE_FAILURES, GE_OPEN_READERS,
    GE_OWNED_FDS, GE_WRITER_ACTIVE, GE_LIVE_LINKS, GE_ATTACH_ENTRY,
    GE_LINK_CLOSE_ENTRY, GE_BUFFER_OPEN_ENTRY, GE_BUFFER_POLL_ENTRY,
    GE_BUFFER_CLOSE_ENTRY };
enum ge_scenario { GE_DEFAULT = 0, GE_EINTR, GE_BEGIN, GE_PUBLISH_A,
    GE_PUBLISH_B, GE_OVERWRITE_A, GE_CONSUME_ENOSPC, GE_ATTACH_EIO,
    GE_DESTROY_EIO, GE_NEW_ENOMEM, GE_END };
void ge_check(int condition, const char *expression, unsigned line);
#define CHECK(c) ge_check(!!(c), #c, __LINE__)
int ge_ring_fd(void);
int ge_last_timeout(void);
void ge_begin(const char *fixture);
int ge_end(const char *suite);
struct lmb_object *ge_object(const char *fixture, int loaded);
struct lmb_attach_options_v1 ge_attach_options(void);
struct lmb_buffer_options_v1 ge_buffer_options(void);
void ge_diagnostic(uint32_t operation, uint32_t domain, int32_t code);
unsigned ge_fd_count(void);
void ge_alloc_fault(unsigned ordinal);
unsigned ge_alloc_finish(void);
void ge_map_fault(unsigned ordinal);
void ge_info_fault(int code);
void ge_epoll_fault(int create_code, int register_code);
void ge_attach_fault(int code, int null_result);
void ge_destroy_fault(int code);
void ge_program_fd(int fd);
void ge_map_fd_fault(int fd);
void ge_epoll_fd_fault(int code);
void ge_attach_targets(const char *category, const char *event, const void *category_source, const void *event_source);
void ge_new_fault(int code, int null_result);
void ge_wait_result(int result, int error);
void ge_consume_fault(int code);
void ge_overwrite_source(int enabled);
void ge_publish(const void *bytes, size_t size, uint32_t flags);
void ge_unbusy(void);
uint64_t ge_consumer(void);
uint64_t ge_producer(void);
void ge_empty_position(uint64_t position);
void ge_payload(uint8_t bytes[16], uint64_t sequence);
void ge_frame(const uint8_t *bytes, uint64_t sequence);
void ge_sentinel(const void *bytes, size_t length, uint8_t value);
/* These four scalar controls are available to later boundary tests. */
void lmb_events_reset(void);
void lmb_events_scenario(uint32_t scenario);
uint64_t lmb_events_call_count(uint32_t query);
uint64_t lmb_events_close_count(void);
#endif
