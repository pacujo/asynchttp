#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <fsdyn/fsalloc.h>
#include <fstrace.h>
#include "h2frame_yield.h"
#include "h2frame_constants.h"
#include "asynchttp_version.h"

typedef enum {
    YIELD_READING_PREFIX,
    YIELD_READING_HEADER,
    YIELD_READING_PAYLOAD,
    YIELD_SKIPPING,
    YIELD_AWAITING_PAYLOAD_CLOSE,
    YIELD_READING_ERRORED,
    YIELD_EXHAUSTED,
    YIELD_ERRORED,
    YIELD_ZOMBIE
} yield_state_t;

struct h2frame_yield {
    async_t *async;
    uint64_t uid;
    bytestream_1 source;
    const char *prefix;
    yield_state_t state;
    action_1 callback;
    union {
        struct {
            size_t cursor;
            uint8_t buffer[9];
        } header;
        struct {
            size_t cursor;
            h2frame_raw_t *frame;
            action_1 callback;
        } payload;
    };
};

static const char *trace_yield_state(void *pstate)
{
    switch (*(yield_state_t *) pstate) {
        case YIELD_READING_PREFIX:
            return "YIELD_READING_PREFIX";
        case YIELD_READING_HEADER:
            return "YIELD_READING_HEADER";
        case YIELD_READING_PAYLOAD:
            return "YIELD_READING_PAYLOAD";
        case YIELD_SKIPPING:
            return "YIELD_SKIPPING";
        case YIELD_AWAITING_PAYLOAD_CLOSE:
            return "YIELD_AWAITING_PAYLOAD_CLOSE";
        case YIELD_READING_ERRORED:
            return "YIELD_READING_ERRORED";
        case YIELD_EXHAUSTED:
            return "YIELD_EXHAUSTED";
        case YIELD_ERRORED:
            return "YIELD_ERRORED";
        case YIELD_ZOMBIE:
            return "YIELD_ZOMBIE";
        default:
            return fstrace_unsigned_repr(*(yield_state_t *) pstate);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_SET_STATE, "UID=%64u OLD=%I NEW=%I");

static void set_yield_state(h2frame_yield_t *yield, yield_state_t state)
{
    FSTRACE(ASYNCHTTP_H2F_YIELD_SET_STATE, yield->uid,
            trace_yield_state, &yield->state,
            trace_yield_state, &state);
    yield->state = state;
}

FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_PROBE, "UID=%64u");

static void probe(h2frame_yield_t *yield)
{
    FSTRACE(ASYNCHTTP_H2F_YIELD_PROBE, yield->uid);
    switch (yield->state) {
        case YIELD_READING_PREFIX:
        case YIELD_READING_HEADER:
            action_1_perf(yield->callback);
            break;
        default:
            action_1_perf(yield->payload.callback);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_CREATE, "UID=%64u PTR=%p ASYNC=%p SOURCE=%p");

h2frame_yield_t *open_h2frame_yield(async_t *async, bytestream_1 source,
                                    const char *prefix)
{
    h2frame_yield_t *yield = fsalloc(sizeof *yield);
    yield->async = async;
    yield->uid = fstrace_get_unique_id();
    FSTRACE(ASYNCHTTP_H2F_YIELD_CREATE, yield->uid, yield, async, source.obj);
    yield->source = source;
    yield->prefix = prefix;
    yield->state = YIELD_READING_PREFIX;
    yield->callback = NULL_ACTION_1;
    yield->header.cursor = 0;
    action_1 probe_cb = { yield, (act_1) probe };
    bytestream_1_register_callback(yield->source, probe_cb);
    return yield;
}

FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_READ_WHILE_ERRORED, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_PREMATURE_EOF, "UID=%64u");

static ssize_t do_read_payload(h2frame_yield_t *yield, void *buf, size_t count)
{
    switch (yield->state) {
        default:
            assert(false);
        case YIELD_READING_ERRORED:
            FSTRACE(ASYNCHTTP_H2F_YIELD_READ_WHILE_ERRORED, yield->uid);
            errno = EPROTO;
            return -1;
        case YIELD_READING_PAYLOAD:
        case YIELD_AWAITING_PAYLOAD_CLOSE:
            ;
    }
    if (yield->payload.cursor >= yield->payload.frame->payload_length)
        return 0;
    size_t remaining =
        yield->payload.frame->payload_length - yield->payload.cursor;
    if (remaining < count)
        count = remaining;
    ssize_t n = bytestream_1_read(yield->source, buf, count);
    if (n < 0)
        return -1;
    if (n == 0) {
        FSTRACE(ASYNCHTTP_H2F_YIELD_PREMATURE_EOF, yield->uid);
        set_yield_state(yield, YIELD_READING_ERRORED);
        errno = EPROTO;
        return -1;
    }
    yield->payload.cursor += n;
    return n;
}

FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_READ, "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_READ_DUMP, "UID=%64u DATA=%B");

static ssize_t read_payload(h2frame_yield_t *yield, void *buf, size_t count)
{
    ssize_t n = do_read_payload(yield, buf, count);
    FSTRACE(ASYNCHTTP_H2F_YIELD_READ, yield->uid, count, n);
    FSTRACE(ASYNCHTTP_H2F_YIELD_READ_DUMP, yield->uid, buf, n);
    return n;
}

static ssize_t frame_read(void *obj, void *buf, size_t count)
{
    return read_payload(obj, buf, count);
}

FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_CLOSE_PAYLOAD, "UID=%64u");

static void close_payload(h2frame_yield_t *yield)
{
    FSTRACE(ASYNCHTTP_H2F_YIELD_CLOSE_PAYLOAD, yield->uid);
    switch (yield->state) {
        case YIELD_READING_ERRORED:
            fsfree(yield->payload.frame);
            set_yield_state(yield, YIELD_ERRORED);
            break;
        case YIELD_READING_PAYLOAD:
            set_yield_state(yield, YIELD_SKIPPING);
            async_execute(yield->async, yield->callback);
            break;
        case YIELD_AWAITING_PAYLOAD_CLOSE:
            fsfree(yield->payload.frame);
            bytestream_1_close(yield->source);
            set_yield_state(yield, YIELD_ZOMBIE);
            async_wound(yield->async, yield);
            break;
        default:
            assert(false);
    }
}

static void frame_close(void *obj)
{
    close_payload(obj);
}

static void register_payload_callback(h2frame_yield_t *yield, action_1 action)
{
    bytestream_1_register_callback(yield->source, action);
}

static void frame_register_callback(void *obj, action_1 action)
{
    register_payload_callback(obj, action);
}

static void unregister_payload_callback(h2frame_yield_t *yield)
{
    bytestream_1_unregister_callback(yield->source);
}

static void frame_unregister_callback(void *obj)
{
    unregister_payload_callback(obj);
}

static const struct bytestream_1_vt h2frame_vt = {
    .read = frame_read,
    .close = frame_close,
    .register_callback = frame_register_callback,
    .unregister_callback = frame_unregister_callback,
};

FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_RECEIVE_EOF, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_RECEIVE,
             "UID=%64u LENGTH=%z TYPE=%I FLAGS=%u STREAM-ID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_RECEIVE_BAD_EOF, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_RECEIVE_FAIL, "UID=%64u ERRNO=%e");

static h2frame_raw_t *receive_header(h2frame_yield_t *yield)
{
    do {
        size_t remaining = sizeof yield->header.buffer - yield->header.cursor;
        ssize_t count =
            bytestream_1_read(yield->source,
                              yield->header.buffer + yield->header.cursor,
                              remaining);
        if (count < 0) {
            FSTRACE(ASYNCHTTP_H2F_YIELD_RECEIVE_FAIL, yield->uid);
            return NULL;
        }
        if (count == 0) {
            if (yield->header.cursor) {
                FSTRACE(ASYNCHTTP_H2F_YIELD_RECEIVE_BAD_EOF, yield->uid);
                set_yield_state(yield, YIELD_ERRORED);
                errno = EPROTO;
                return NULL;
            }
            FSTRACE(ASYNCHTTP_H2F_YIELD_RECEIVE_EOF, yield->uid);
            set_yield_state(yield, YIELD_EXHAUSTED);
            errno = 0;
            return NULL;
        }
        yield->header.cursor += count;
    } while (yield->header.cursor < sizeof yield->header.buffer);
    const uint8_t *p = yield->header.buffer;
    h2frame_raw_t *frame = fsalloc(sizeof *frame);
    frame->payload_length = *p++ << 16;
    frame->payload_length |= *p++ << 8;
    frame->payload_length |= *p++;
    frame->type = *p++;
    frame->flags = *p++;
    frame->stream_id = (*p++ & 0x7f) << 24;
    frame->stream_id |= *p++ << 16;
    frame->stream_id |= *p++ << 8;
    frame->stream_id |= *p;
    frame->payload = (bytestream_1) { yield, &h2frame_vt };
    set_yield_state(yield, YIELD_READING_PAYLOAD);
    yield->payload.frame = frame;
    yield->payload.cursor = 0;
    yield->payload.callback = NULL_ACTION_1;
    FSTRACE(ASYNCHTTP_H2F_YIELD_RECEIVE, yield->uid,
            frame->payload_length,
            trace_frame_type,
            &frame->type,
            (unsigned) frame->flags,
            (uint64_t) frame->stream_id);
    return yield->payload.frame;
}

FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_SKIP_FAIL, "UID=%64u ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_SKIP_BAD_EOF, "UID=%64u");

static bool skip(h2frame_yield_t *yield)
{
    for (;;) {
        size_t remaining =
            yield->payload.frame->payload_length - yield->payload.cursor;
        if (!remaining) {
            fsfree(yield->payload.frame);
            set_yield_state(yield, YIELD_READING_HEADER);
            yield->header.cursor = 0;
            return true;
        }
        uint8_t skip_buffer[10000];
        if (remaining > sizeof skip_buffer)
            remaining = sizeof skip_buffer;
        ssize_t count =
            bytestream_1_read(yield->source, skip_buffer, remaining);
        if (count < 0) {
            FSTRACE(ASYNCHTTP_H2F_YIELD_SKIP_FAIL, yield->uid);
            return false;
        }
        if (count == 0) {
            fsfree(yield->payload.frame);
            if (yield->payload.cursor) {
                FSTRACE(ASYNCHTTP_H2F_YIELD_SKIP_BAD_EOF, yield->uid);
                set_yield_state(yield, YIELD_ERRORED);
                return false;
            }
            set_yield_state(yield, YIELD_EXHAUSTED);
            return true;
        }
        yield->payload.cursor += count;
    }
}

FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_SKIP_PREFIX, "UID=%64u PREFIX=%s");
FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_SKIP_PREFIX_DONE, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_SKIP_PREFIX_READ_FAIL, "UID=%64u ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_SKIP_PREFIX_READ_EOF, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_SKIP_PREFIX_READ_UNEXPECTED,
             "UID=%64u GOT=%A");

static h2frame_raw_t *skip_prefix(h2frame_yield_t *yield)
{
    for (;;) {
        FSTRACE(ASYNCHTTP_H2F_YIELD_SKIP_PREFIX, yield->uid, yield->prefix);
        size_t remaining = strlen(yield->prefix);
        if (!remaining) {
            FSTRACE(ASYNCHTTP_H2F_YIELD_SKIP_PREFIX_DONE, yield->uid);
            set_yield_state(yield, YIELD_READING_HEADER);
            return h2frame_yield_receive(yield);
        }
        char buffer[strlen(yield->prefix)];
        ssize_t count = bytestream_1_read(yield->source, buffer, remaining);
        if (count < 0) {
            FSTRACE(ASYNCHTTP_H2F_YIELD_SKIP_PREFIX_READ_FAIL, yield->uid);
            return NULL;
        }
        if (count == 0) {
            FSTRACE(ASYNCHTTP_H2F_YIELD_SKIP_PREFIX_READ_EOF, yield->uid);
            set_yield_state(yield, YIELD_READING_ERRORED);
            return h2frame_yield_receive(yield);
        }
        if (memcmp(yield->prefix, buffer, count)) {
            FSTRACE(ASYNCHTTP_H2F_YIELD_SKIP_PREFIX_READ_UNEXPECTED,
                    yield->uid, buffer, count);
            set_yield_state(yield, YIELD_READING_ERRORED);
            return h2frame_yield_receive(yield);
        }
        yield->prefix += count;
    }
}

FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_RECEIVE_WHILE_ERRORED, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_SPURIOUS_RECEIVE, "UID=%64u");

h2frame_raw_t *h2frame_yield_receive(h2frame_yield_t *yield)
{
    for (;;)
        switch (yield->state) {
            case YIELD_EXHAUSTED:
                FSTRACE(ASYNCHTTP_H2F_YIELD_RECEIVE_EOF, yield->uid);
                errno = 0;
                return NULL;
            case YIELD_ERRORED:
                FSTRACE(ASYNCHTTP_H2F_YIELD_RECEIVE_WHILE_ERRORED, yield->uid);
                errno = EPROTO;
                return NULL;
            case YIELD_READING_PAYLOAD:
            case YIELD_READING_ERRORED:
                FSTRACE(ASYNCHTTP_H2F_YIELD_SPURIOUS_RECEIVE, yield->uid);
                errno = EAGAIN;
                return NULL;
            case YIELD_READING_PREFIX:
                return skip_prefix(yield);
            case YIELD_READING_HEADER:
                return receive_header(yield);
            case YIELD_SKIPPING:
                if (!skip(yield))
                    return NULL;
                break;
            default:
                assert(false);
        }
}

FSTRACE_DECL(ASYNCHTTP_H2F_YIELD_CLOSE, "UID=%64u");

void h2frame_yield_close(h2frame_yield_t *yield)
{
    FSTRACE(ASYNCHTTP_H2F_YIELD_CLOSE, yield->uid);
    switch (yield->state) {
        case YIELD_READING_HEADER:
        case YIELD_READING_ERRORED:
        case YIELD_EXHAUSTED:
        case YIELD_ERRORED:
            bytestream_1_close(yield->source);
            set_yield_state(yield, YIELD_ZOMBIE);
            async_wound(yield->async, yield);
            break;
        case YIELD_SKIPPING:
            fsfree(yield->payload.frame);
            bytestream_1_close(yield->source);
            set_yield_state(yield, YIELD_ZOMBIE);
            async_wound(yield->async, yield);
            break;
        case YIELD_READING_PAYLOAD:
            set_yield_state(yield, YIELD_AWAITING_PAYLOAD_CLOSE);
            break;
        default:
            assert(false);
    }
}

void h2frame_yield_register_callback(h2frame_yield_t *yield, action_1 action)
{
    yield->callback = action;
}

void h2frame_yield_unregister_callback(h2frame_yield_t *yield)
{
    yield->callback = NULL_ACTION_1;
}

static void *_receive(void *obj)
{
    return h2frame_yield_receive(obj);
}

static void _close(void *obj)
{
    h2frame_yield_close(obj);
}

static void _register_callback(void *obj, action_1 action)
{
    h2frame_yield_register_callback(obj, action);
}

static void _unregister_callback(void *obj)
{
    h2frame_yield_unregister_callback(obj);
}

static const struct yield_1_vt h2frame_yield_vt = {
    .receive = _receive,
    .close = _close,
    .register_callback = _register_callback,
    .unregister_callback = _unregister_callback
};
    
yield_1 h2frame_yield_as_yield_1(h2frame_yield_t *yield)
{
    return (yield_1) { yield, &h2frame_yield_vt };
}
