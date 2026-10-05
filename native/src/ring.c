/* Ring consumption with one owned staging slot. Each poll delivers at
 * most one framed event: bounded waits use the ring's epoll fd, and
 * consumption is capped at one record so retention never overflows. */
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>

#include <bpf/libbpf.h>

#include "internal.h"

int lmb_ring_sample(void *ctx, void *data, size_t size) {
    struct lmb_session *s = ctx;
    s->received++;
    /* Empty and oversized records are unusable data: malformed. A
     * valid record that arrives while the single slot is occupied is
     * unavoidable capacity loss: dropped. An empty record cannot be
     * staged because a zero stage length reads back as no record, so
     * it is declared malformed to keep the conservation identity
     * exact. */
    if (size == 0 || size > s->max_raw_bytes) {
        s->malformed++;
        return 0;
    }
    if (s->stage_len != 0) {
        s->dropped++;
        return 0;
    }
    memcpy(s->stage, data, size);
    s->stage_len = (uint32_t)size;
    return 0;
}

static void put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void put_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

/* Bounded malformed skip per call: consume until one record stages,
 * the ring drains, or this many records pass without staging. */
#define LMB_MAX_SKIP 64

/* Consume at most one record per step until one stages or the ring
 * drains. Returns 0 with stage_len set, 1 when drained, or a
 * negative libbpf error (recorded, latched). */
static int drain_one(struct lmb_session *session) {
    int i;
    for (i = 0; i < LMB_MAX_SKIP && session->stage_len == 0; i++) {
        int rc = ring_buffer__consume_n(session->rb, 1);
        if (rc < 0) {
            lmb_record(LMB_OP_POLL, LMB_DOMAIN_LIBBPF, (int32_t)rc,
                       "lmb_poll: ring consumption failed");
            session->last_native_error = (int32_t)rc;
            return (int32_t)rc;
        }
        if (rc == 0)
            return 1;
    }
    return session->stage_len == 0 ? 1 : 0;
}

int32_t lmb_poll(struct lmb_session *session, uint8_t *dst,
                 uint32_t capacity, uint32_t *written, uint32_t *required,
                 int32_t timeout_ms) {
    uint32_t frame_len;
    int rc;
    if (!session) {
        lmb_record(LMB_OP_POLL, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_poll: null session");
        return -EINVAL;
    }
    if (!written || !required || (!dst && capacity > 0) ||
        timeout_ms < -1 || written == required ||
        lmb_ranges_overlap(written, sizeof(*written), dst, capacity) ||
        lmb_ranges_overlap(required, sizeof(*required), dst, capacity)) {
        lmb_record(LMB_OP_POLL, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_poll: invalid arguments");
        return -EINVAL;
    }
    if (!session->loaded || !session->rb) {
        lmb_record(LMB_OP_POLL, LMB_DOMAIN_BRIDGE, -EINVAL,
                   "lmb_poll: session not loaded");
        return -EINVAL;
    }
    *written = 0;
    *required = 0;
    if (session->stage_len == 0) {
        if (timeout_ms != 0) {
            struct epoll_event ev;
            int epfd = ring_buffer__epoll_fd(session->rb);
            if (epfd < 0) {
                lmb_record(LMB_OP_POLL, LMB_DOMAIN_LIBBPF, (int32_t)epfd,
                           "lmb_poll: cannot wait on ring");
                session->last_native_error = (int32_t)epfd;
                return (int32_t)epfd;
            }
            rc = epoll_wait(epfd, &ev, 1, timeout_ms);
            if (rc < 0) {
                int code = errno ? -errno : -EIO;
                lmb_record(LMB_OP_POLL, LMB_DOMAIN_POSIX, (int32_t)code,
                           code == -EINTR ? "lmb_poll: wait interrupted"
                                          : "lmb_poll: wait failed");
                if (code != -EINTR)
                    session->last_native_error = (int32_t)code;
                return (int32_t)code;
            }
            if (rc == 0)
                return 0;
        }
        rc = drain_one(session);
        if (rc < 0)
            return rc;
    }
    if (session->stage_len == 0)
        return 0;
    frame_len = LMB_FRAME_HEADER_SIZE + session->stage_len;
    if (capacity < frame_len) {
        *required = frame_len;
        lmb_record(LMB_OP_POLL, LMB_DOMAIN_BRIDGE, -ENOSPC,
                   "lmb_poll: destination too short, record retained");
        return -ENOSPC;
    }
    put_le32(dst, session->stage_len);
    put_le16(dst + 4, LMB_FRAME_VERSION);
    put_le16(dst + 6, 0);
    memcpy(dst + LMB_FRAME_HEADER_SIZE, session->stage,
           session->stage_len);
    *written = frame_len;
    session->stage_len = 0;
    session->delivered++;
    return 0;
}
