#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <fsdyn/fsalloc.h>
#include <fsdyn/hashtable.h>
#include <fsdyn/avltree.h>
#include <fsdyn/charstr.h>
#include <fsdyn/list.h>
#include <async/emptystream.h>
#include <async/blobstream.h>
#include <async/stringstream.h>
#include <async/queuestream.h>
#include <fstrace.h>
#include "h2connection.h"
#include "h2frame_constants.h"
#include "h2frame_decoder.h"
#include "h2frame_yield.h"
#include "h2frame.h"
#include "hpack.h"

enum {
    LOCAL_INITIAL_WINDOW = 0xffff,
    DEFAULT_WEIGHT = 16,        /* RFC 7540 § 5.3.5 */
};

typedef enum {
    CONN_ACTIVE,
    CONN_PASSIVE,
    CONN_ERRORED,
    CONN_ZOMBIE,
} conn_state_t;

struct h2conn {
    async_t *async;
    uint64_t uid;
    uint32_t next_strid, next_peer_strid;
    conn_state_t state;
    int error;
    struct {
        uint32_t header_table_size;
        uint32_t enable_push;
        uint32_t max_concurrent_streams;
        uint32_t initial_window_size;
        uint32_t max_frame_size;
        uint32_t max_header_list_size;
    } peer;
    struct {
        size_t max_envelope_size;
        bool allow_push;
        h2frame_decoder_t *decoder;
        action_1 callback;
        hpack_table_t *hunpack;
        h2op_t *data_receiver;
        h2frame_t *pending_data;
        size_t pending_credit;
    } input;
    struct {
        queuestream_t *stream;
        hpack_table_t *hpack;
        action_1 callback, peer_closed_callback;
        async_event_t *event;
        uint8_t data_chunk[10000];
        int64_t credit;
    } output;
    hash_table_t *ops;          /* stream_id -> h2op_t */
    avl_tree_t *top_level;      /* of h2op_t */
    list_t *new_ops;            /* of h2op_t */
};

typedef enum {
    OP_LIVE,
    OP_ERRORED,
    OP_ZOMBIE,
} op_state_t;

/* Track what has been delivered to the peer. */
typedef enum {
    XMIT_PROCESSING,            /* server only */
    XMIT_SENDING_DATA,
    XMIT_FINISHED,
} xmit_state_t;

/* Track what has been received from the peer. */
typedef enum {
    RECV_AWAITING_CONTINUATION_PROMISE, /* client only */
    RECV_AWAITING_RESPONSE_HEADER,      /* client only */
    RECV_AWAITING_CONTINUATION_HEADER,
    RECV_AWAITING_FINAL_CONTINUATION_HEADER,
    RECV_AWAITING_DATA,
    RECV_AWAITING_CONTINUATION_TRAILER,
    RECV_FINISHED,
    RECV_RESET,
} recv_state_t;

/* Track what has been delivered to the user. */
typedef enum {
    API_AWAITING_PROMISE,       /* client only */
    API_AWAITING_RESPONSE,      /* client only */
    API_AWAITING_REQUEST,       /* server only */
    API_ENVELOPE_PASSED,
    API_CONTENT_PASSED,
    API_CONTENT_EXHAUSTED,
    API_CONTENT_CLOSED,
} api_state_t;

struct h2op {
    h2conn_t *conn;
    uint32_t strid;
    char *opid;
    op_state_t state;
    struct {
        xmit_state_t state;
        const http_env_t *envelope;
        ssize_t content_length;
        bytestream_1 content;
        int64_t credit;
    } xmit;
    struct {
        recv_state_t state;
        size_t env_space_remaining;
        http_env_t *promise_envelope, *envelope;   /* may be NULL */
        size_t read_cursor, space_remaining;
        uint8_t *window;
        size_t pending_credit;
        action_1 callback, content_callback;
        uint32_t error_code;    /* RECV_RESET */
    } recv;
    struct {
        api_state_t state;
        async_event_t *event;
    } api;
    struct {
        struct h2op *parent;    /* NULL for top-level */
        bool exclusive;
        avl_tree_t *dependents; /* of h2op_t */
        unsigned weight;
        int64_t account;
    } priority;
    int err;                    /* if OP_ERRORED */
};

static const char *trace_conn_state(void *p)
{
    switch (*(conn_state_t *) p) {
        case CONN_ACTIVE:
            return "CONN_ACTIVE";
        case CONN_PASSIVE:
            return "CONN_PASSIVE";
        case CONN_ERRORED:
            return "CONN_ERRORED";
        case CONN_ZOMBIE:
            return "CONN_ZOMBIE";
        default:
            return fstrace_unsigned_repr(*(conn_state_t *) p);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_CONN_SET_STATE, "UID=%64u OLD=%I NEW=%I");

static void set_conn_state(h2conn_t *conn, conn_state_t state)
{
    FSTRACE(ASYNCHTTP_H2C_CONN_SET_STATE, conn->uid,
            trace_conn_state, &conn->state, trace_conn_state, &state);
    conn->state = state;
}

static const char *trace_op_state(void *p)
{
    switch (*(op_state_t *) p) {
        case OP_LIVE:
            return "OP_LIVE";
        case OP_ERRORED:
            return "OP_ERRORED";
        case OP_ZOMBIE:
            return "OP_ZOMBIE";
        default:
            return fstrace_unsigned_repr(*(op_state_t *) p);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_OP_SET_STATE, "OPID=%s OLD=%I NEW=%I");

static void set_op_state(h2op_t *op, op_state_t state)
{
    FSTRACE(ASYNCHTTP_H2C_OP_SET_STATE, op->opid,
            trace_op_state, &op->state, trace_op_state, &state);
    op->state = state;
}

static const char *trace_xmit_state(void *p)
{
    switch (*(xmit_state_t *) p) {
        case XMIT_PROCESSING:
            return "XMIT_PROCESSING";
        case XMIT_SENDING_DATA:
            return "XMIT_SENDING_DATA";
        case XMIT_FINISHED:
            return "XMIT_FINISHED";
        default:
            return fstrace_unsigned_repr(*(xmit_state_t *) p);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_OP_SET_XMIT_STATE, "OPID=%s OLD=%I NEW=%I");

static void set_xmit_state(h2op_t *op, xmit_state_t state)
{
    FSTRACE(ASYNCHTTP_H2C_OP_SET_XMIT_STATE, op->opid,
            trace_xmit_state, &op->xmit.state, trace_xmit_state, &state);
    op->xmit.state = state;
}

static const char *trace_recv_state(void *p)
{
    switch (*(recv_state_t *) p) {
        case RECV_AWAITING_CONTINUATION_PROMISE:
            return "RECV_AWAITING_CONTINUATION_PROMISE";
        case RECV_AWAITING_RESPONSE_HEADER:
            return "RECV_AWAITING_RESPONSE_HEADER";
        case RECV_AWAITING_CONTINUATION_HEADER:
            return "RECV_AWAITING_CONTINUATION_HEADER";
        case RECV_AWAITING_FINAL_CONTINUATION_HEADER:
            return "RECV_AWAITING_FINAL_CONTINUATION_HEADER";
        case RECV_AWAITING_DATA:
            return "RECV_AWAITING_DATA";
        case RECV_AWAITING_CONTINUATION_TRAILER:
            return "RECV_AWAITING_CONTINUATION_TRAILER";
        case RECV_FINISHED:
            return "RECV_FINISHED";
        case RECV_RESET:
            return "RECV_RESET";
        default:
            return fstrace_unsigned_repr(*(recv_state_t *) p);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_OP_SET_RECV_STATE, "OPID=%s OLD=%I NEW=%I");

static void set_recv_state(h2op_t *op, recv_state_t state)
{
    FSTRACE(ASYNCHTTP_H2C_OP_SET_RECV_STATE, op->opid,
            trace_recv_state, &op->recv.state, trace_recv_state, &state);
    op->recv.state = state;
}

static const char *trace_api_state(void *p)
{
    switch (*(api_state_t *) p) {
        case API_AWAITING_PROMISE:
            return "API_AWAITING_PROMISE";
        case API_AWAITING_RESPONSE:
            return "API_AWAITING_RESPONSE";
        case API_AWAITING_REQUEST:
            return "API_AWAITING_REQUEST";
        case API_ENVELOPE_PASSED:
            return "API_ENVELOPE_PASSED";
        case API_CONTENT_PASSED:
            return "API_CONTENT_PASSED";
        case API_CONTENT_EXHAUSTED:
            return "API_CONTENT_EXHAUSTED";
        case API_CONTENT_CLOSED:
            return "API_CONTENT_CLOSED";
        default:
            return fstrace_unsigned_repr(*(api_state_t *) p);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_OP_SET_API_STATE, "OPID=%s OLD=%I NEW=%I");

static void set_api_state(h2op_t *op, api_state_t state)
{
    FSTRACE(ASYNCHTTP_H2C_OP_SET_API_STATE, op->opid,
            trace_api_state, &op->api.state, trace_api_state, &state);
    op->api.state = state;
}

static void do_signal(h2conn_t *conn, h2frame_t *frame)
{
    if (conn->output.stream)
        queuestream_enqueue(conn->output.stream,
                            h2frame_encode(conn->async, frame));
}

FSTRACE_DECL(ASYNCHTTP_H2C_ACK_SETTINGS, "UID=%64u");

static void ack_settings(h2conn_t *conn)
{
    FSTRACE(ASYNCHTTP_H2C_ACK_SETTINGS, conn->uid);
    h2frame_t ack = {
        .frame_type = H2FRAME_TYPE_SETTINGS,
        .settings = {
            .ack = 1,
            .settings = make_list()
        }
    };
    do_signal(conn, &ack);
    destroy_list(ack.settings.settings);
}

FSTRACE_DECL(ASYNCHTTP_H2C_SET_XMIT_CREDIT, "OPID=%s OLD=%64d NEW=%64d");

static void increment_window(avl_tree_t *ops, int32_t increment)
{
    avl_elem_t *e;
    for (e = avl_tree_get_first(ops); e; e = avl_tree_next(e)) {
        h2op_t *op = (h2op_t *) avl_elem_get_value(e);
        FSTRACE(ASYNCHTTP_H2C_SET_XMIT_CREDIT, op->opid, op->xmit.credit,
                op->xmit.credit + increment);
        op->xmit.credit += increment;
        increment_window(op->priority.dependents, increment);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_SET_INIT_WINDOW, "UID=%64u SIZE=%z INCR=%d");

static void set_initial_window_size(h2conn_t *conn, size_t size)
{
    /* RFC 7540 § 6.9.2: a negative increment is ok*/
    int32_t increment = size - conn->peer.initial_window_size;
    FSTRACE(ASYNCHTTP_H2C_SET_INIT_WINDOW, conn->uid, size, (int) increment);
    conn->peer.initial_window_size = size;
    conn->output.credit += increment;
    increment_window(conn->top_level, increment);
    if (increment > 0)
        async_event_trigger(conn->output.event);
}

FSTRACE_DECL(ASYNCHTTP_H2C_ISSUE_GOAWAY, "UID=%64u LAST=%64u ERR=%I");

static void issue_goaway(h2conn_t *conn, uint32_t error_code)
{
    h2frame_t goaway = {
        .frame_type = H2FRAME_TYPE_GOAWAY,
        .goaway = {
            .error_code = error_code,
        }
    };            
    if (conn->next_peer_strid > 2)
        goaway.goaway.last_stream_id = conn->next_peer_strid - 2;
    FSTRACE(ASYNCHTTP_H2C_ISSUE_GOAWAY, conn->uid,
            (uint64_t) goaway.goaway.last_stream_id,
            h2frame_trace_error_code, &error_code);
    do_signal(conn, &goaway);
}

FSTRACE_DECL(ASYNCHTTP_H2C_TRIGGER_USER, "OPID=%s");

static void trigger_user(h2op_t *op)
{
    FSTRACE(ASYNCHTTP_H2C_TRIGGER_USER, op->opid);
    async_event_trigger(op->api.event);
}

FSTRACE_DECL(ASYNCHTTP_H2C_RESET_OP, "OPID=%s ERR=%I");

static void reset_op(h2op_t *op, uint32_t error_code)
{
    FSTRACE(ASYNCHTTP_H2C_RESET_OP, op->opid,
            h2frame_trace_error_code, &error_code);
    switch (op->recv.state) {
        case RECV_RESET:
            return;
        case RECV_AWAITING_RESPONSE_HEADER:
            op->recv.envelope = NULL;
            break;
        default:
            ;
    }
    set_recv_state(op, RECV_RESET);
    op->recv.error_code = error_code;
    switch (op->xmit.state) {
        case XMIT_SENDING_DATA:
            bytestream_1_close(op->xmit.content);
            set_xmit_state(op, XMIT_FINISHED);
            break;
        case XMIT_FINISHED:
            break;
        default:
            assert(false);
    }
    switch (op->api.state) {
        case API_AWAITING_REQUEST:
        case API_AWAITING_PROMISE:
            async_execute(op->conn->async,
                          (action_1) { op, (act_1) h2op_close });
            break;
        case API_AWAITING_RESPONSE:
            trigger_user(op);
            break;
        case API_CONTENT_PASSED:
            trigger_user(op);
            break;
        default:
            ;
    }
    set_op_state(op, OP_ERRORED);
    op->err = ECONNRESET;
}

static void reset_ops(avl_tree_t *ops, uint32_t good_strid,
                      uint32_t error_code)
{
    avl_elem_t *e;
    for (e = avl_tree_get_first(ops); e; e = avl_tree_next(e)) {
        h2op_t *op = (h2op_t *) avl_elem_get_value(e);
        if (op->strid > good_strid)
            reset_op(op, error_code);
        reset_ops(op->priority.dependents, good_strid, error_code);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_CONN_ERROR, "UID=%64u ERR=%I");

static void connection_error(h2conn_t *conn, uint32_t error_code)
{
    FSTRACE(ASYNCHTTP_H2C_CONN_ERROR, conn->uid,
            h2frame_trace_error_code, &error_code);
    issue_goaway(conn, error_code);
    set_conn_state(conn, CONN_ERRORED);
    reset_ops(conn->top_level, 0, error_code);
}

static void proto_error(h2conn_t *conn)
{
    connection_error(conn, H2FRAME_ERR_PROTOCOL_ERROR);
}

FSTRACE_DECL(ASYNCHTTP_H2C_SET_HEADER_TABLE_SIZE, "UID=%64u VALUE=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_SET_ENABLE_PUSH, "UID=%64u VALUE=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_BAD_ENABLE_PUSH, "UID=%64u VALUE=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_SET_MAX_CONCURRENT_STREAMS, "UID=%64u VALUE=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_BAD_INITIAL_WINDOW, "UID=%64u VALUE=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_SET_MAX_FRAME_SIZE, "UID=%64u VALUE=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_BAD_MAX_FRAME_SIZE, "UID=%64u VALUE=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_SET_MAX_HEADER_LIST_SIZE, "UID=%64u VALUE=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_ILLEGAL_SETTING, "UID=%64u PARAM=%64u");

static bool apply_setting(h2conn_t *conn, h2frame_setting_t *setting)
{
    switch (setting->parameter) {
        case H2FRAME_SETTINGS_HEADER_TABLE_SIZE:
            FSTRACE(ASYNCHTTP_H2C_SET_HEADER_TABLE_SIZE, conn->uid,
                    (uint64_t) setting->value);
            conn->peer.header_table_size = setting->value;
            return true;
        case H2FRAME_SETTINGS_ENABLE_PUSH:
            if (setting->value > 1) {
                FSTRACE(ASYNCHTTP_H2C_GOT_BAD_ENABLE_PUSH, conn->uid,
                        (uint64_t) setting->value);
                proto_error(conn);
                return false;
            }
            FSTRACE(ASYNCHTTP_H2C_SET_ENABLE_PUSH, conn->uid,
                    (uint64_t) setting->value);
            conn->peer.enable_push = setting->value;
            return true;
        case H2FRAME_SETTINGS_MAX_CONCURRENT_STREAMS:
            FSTRACE(ASYNCHTTP_H2C_SET_MAX_CONCURRENT_STREAMS, conn->uid,
                    (uint64_t) setting->value);
            conn->peer.max_concurrent_streams = setting->value;
            return true;
        case H2FRAME_SETTINGS_INITIAL_WINDOW_SIZE:
            if (setting->value > 0x7ffffff) {
                FSTRACE(ASYNCHTTP_H2C_GOT_BAD_INITIAL_WINDOW, conn->uid,
                        (uint64_t) setting->value);
                proto_error(conn);
                return false;
            }
            /* traced in set_initial_window_size */
            set_initial_window_size(conn, setting->value);
            return true;
        case H2FRAME_SETTINGS_MAX_FRAME_SIZE:
            if (setting->value < 0x4000 || setting->value > 0xffffff) {
                FSTRACE(ASYNCHTTP_H2C_GOT_BAD_MAX_FRAME_SIZE, conn->uid,
                        (uint64_t) setting->value);
                return false;
            }
            FSTRACE(ASYNCHTTP_H2C_SET_MAX_FRAME_SIZE, conn->uid,
                    (uint64_t) setting->value);
            conn->peer.max_frame_size = setting->value;
            return true;
        case H2FRAME_SETTINGS_MAX_HEADER_LIST_SIZE:
            FSTRACE(ASYNCHTTP_H2C_SET_MAX_HEADER_LIST_SIZE, conn->uid,
                    (uint64_t) setting->value);
            conn->peer.max_header_list_size = setting->value;
            return true;
        default:
            FSTRACE(ASYNCHTTP_H2C_GOT_BAD_MAX_FRAME_SIZE, conn->uid,
                    (uint64_t) setting->parameter);
            proto_error(conn);
            return false;
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_GOT_BAD_SETTINGS_ACK, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_SETTINGS_ACK, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_BAD_SETTINGS, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_SETTINGS, "UID=%64u");

static void apply_settings(h2conn_t *conn, h2frame_t *frame)
{

    if (frame->stream_id != 0) {
        FSTRACE(ASYNCHTTP_H2C_GOT_BAD_SETTINGS, conn->uid);
        proto_error(conn);
        return;
    }
    if (frame->settings.ack) {
        if (!list_empty(frame->settings.settings)) {
            FSTRACE(ASYNCHTTP_H2C_GOT_BAD_SETTINGS_ACK, conn->uid);
            connection_error(conn, H2FRAME_ERR_FRAME_SIZE_ERROR);
            return;
        }
        FSTRACE(ASYNCHTTP_H2C_GOT_SETTINGS_ACK, conn->uid);
        /* Ignore */
        return;
    }
    FSTRACE(ASYNCHTTP_H2C_GOT_SETTINGS, conn->uid);
    list_elem_t *e;
    for (e = list_get_first(frame->settings.settings); e; e = list_next(e))
        if (!apply_setting(conn, (h2frame_setting_t *) list_elem_get_value(e)))
            return;
    ack_settings(conn);
    async_event_trigger(conn->output.event);
    async_execute(conn->async, conn->input.callback);
}

static h2op_t *get_op(h2conn_t *conn, uint32_t stream_id)
{
    hash_elem_t *e = hash_table_get(conn->ops, &stream_id);
    if (!e)
        return NULL;
    return (h2op_t *) hash_elem_get_value(e);
}

static bool bad_op(h2conn_t *conn, uint32_t stream_id)
{
    return (stream_id ^ conn->next_strid) & 1 || stream_id >= conn->next_strid;
}

FSTRACE_DECL(ASYNCHTTP_H2C_GOT_BAD_WINDOW_UPDATE, "UID=%64u INCR=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_TOO_LARGE_CONN_WINDOW, "UID=%64u SIZE=%64d");
FSTRACE_DECL(ASYNCHTTP_H2C_CONN_WINDOW_UPDATE, "UID=%64u SIZE=%64d");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_BAD_OP_WINDOW_UPDATE, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_STALE_OP_WINDOW_UPDATE, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_TOO_LARGE_OP_WINDOW, "OPID=%s SIZE=%64d");
FSTRACE_DECL(ASYNCHTTP_H2C_OP_WINDOW_UPDATE, "OPID=%s SIZE=%64d");

static void update_window(h2conn_t *conn, h2frame_t *frame)
{
    if (frame->window_update.increment < 1 ||
        frame->window_update.increment > 0x7fffffff) {
        FSTRACE(ASYNCHTTP_H2C_GOT_BAD_WINDOW_UPDATE, conn->uid,
                (uint64_t) frame->window_update.increment);
        proto_error(conn);
        return;
    }
    const int64_t RIDICULOUS_WINDOW = (uint64_t) 1 << 62;
    if (frame->stream_id == 0) {
        conn->output.credit += frame->window_update.increment;
        if (conn->output.credit >= RIDICULOUS_WINDOW) {
            FSTRACE(ASYNCHTTP_H2C_TOO_LARGE_CONN_WINDOW, conn->uid,
                    conn->output.credit);
            proto_error(conn);
            return;
        }
        FSTRACE(ASYNCHTTP_H2C_CONN_WINDOW_UPDATE, conn->uid,
                conn->output.credit);
    } else {
        h2op_t *op = get_op(conn, frame->stream_id);
        if (!op) {
            if (bad_op(conn, frame->stream_id)) {
                FSTRACE(ASYNCHTTP_H2C_GOT_BAD_OP_WINDOW_UPDATE, conn->uid,
                        (uint64_t) frame->stream_id);
                proto_error(conn);
            } else FSTRACE(ASYNCHTTP_H2C_GOT_STALE_OP_WINDOW_UPDATE, conn->uid,
                           (uint64_t) frame->stream_id);
            return;
        }
        op->xmit.credit += frame->window_update.increment;
        if (conn->output.credit >= RIDICULOUS_WINDOW) {
            FSTRACE(ASYNCHTTP_H2C_TOO_LARGE_OP_WINDOW, op->opid,
                    op->xmit.credit);
            proto_error(conn);
            return;
        }
        FSTRACE(ASYNCHTTP_H2C_OP_WINDOW_UPDATE, op->opid, op->xmit.credit);
    }
    async_event_trigger(conn->output.event);
}

static size_t header_field_size(const char *name, const char *value)
{
    return strlen(name) + strlen(value) + 32; /* RFC 7540 § 6.5.2 */
}

static http_env_t *bad_response(h2conn_t *conn, http_env_t *env,
                                list_t *strings)
{
    proto_error(conn);
    if (env)
        destroy_http_env(env);
    list_foreach(strings, (void *) fsfree, NULL);
    destroy_list(strings);
    return NULL;
}

FSTRACE_DECL(ASYNCHTTP_H2C_DECODE_RESPONSE, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_DECODE_RESPONSE_OK, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_UNPACK_FAIL, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_HEADER_TOO_LARGE, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_EXTRA_PSEUDOHEADER, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_MISSING_STATUS, "UID=%64u");

static http_env_t *make_response_headers(h2conn_t *conn, list_t *fields,
                                         size_t *size_remaining)
{
    FSTRACE(ASYNCHTTP_H2C_DECODE_RESPONSE, conn->uid);
    list_elem_t *e;
    list_t *strings = make_list();
    http_env_t *env = NULL;
    for (e = list_get_first(fields); e; e = list_next(e)) {
        const hpack_header_field_t *field = list_elem_get_value(e);        
        char *name, *value;
        if (!hpack_table_decode(conn->input.hunpack, field, &name, &value)) {
            FSTRACE(ASYNCHTTP_H2C_UNPACK_FAIL, conn->uid);
            return bad_response(conn, env, strings);
        }
        size_t nominal_size = header_field_size(name, value);
        if (nominal_size > *size_remaining) {
            FSTRACE(ASYNCHTTP_H2C_HEADER_TOO_LARGE, conn->uid);
            return bad_response(conn, env, strings);
        }
        *size_remaining -= nominal_size;
        if (name[0] == ':') {
            if (env || strcmp(name, ":status")) {
                FSTRACE(ASYNCHTTP_H2C_EXTRA_PSEUDOHEADER, conn->uid);
                fsfree(name);
                fsfree(value);
                return bad_response(conn, env, strings);
            }
            env = make_http_env_response("HTTP/2", atoi(value), value);
            fsfree(name);
        } else {
            list_append(strings, name);
            list_append(strings, value);
        }
    }
    if (!env) {
        FSTRACE(ASYNCHTTP_H2C_MISSING_STATUS, conn->uid);
        return bad_response(conn, env, strings);
    }
    while (!list_empty(strings)) {
        const char *name = list_pop_first(strings);
        const char *value = list_pop_first(strings);
        http_env_add_header(env, name, value);
    }
    destroy_list(strings);
    FSTRACE(ASYNCHTTP_H2C_DECODE_RESPONSE_OK, conn->uid);
    return env;
}

FSTRACE_DECL(ASYNCHTTP_H2C_ADD_HEADERS, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_ADD_HEADERS_OK, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_BELATED_PSEUDOHEADER, "UID=%64u");

static bool add_headers(h2conn_t *conn, http_env_t *env, list_t *fields,
                        size_t *size_remaining,
                        void (*adder)(http_env_t *, const char *,
                                      const char *))
{
    FSTRACE(ASYNCHTTP_H2C_ADD_HEADERS, conn->uid);
    list_elem_t *e;
    for (e = list_get_first(fields); e; e = list_next(e)) {
        const hpack_header_field_t *field = list_elem_get_value(e);        
        char *name, *value;
        if (!hpack_table_decode(conn->input.hunpack, field, &name, &value)) {
            FSTRACE(ASYNCHTTP_H2C_UNPACK_FAIL, conn->uid);
            proto_error(conn);
            return false;
        }
        size_t nominal_size = header_field_size(name, value);
        if (nominal_size > *size_remaining) {
            FSTRACE(ASYNCHTTP_H2C_HEADER_TOO_LARGE, conn->uid);
            proto_error(conn);
            return false;
        }
        *size_remaining -= nominal_size;
        if (name[0] == ':') {
            FSTRACE(ASYNCHTTP_H2C_BELATED_PSEUDOHEADER, conn->uid);
            proto_error(conn);
            return false;
        }
        (*adder)(env, name, value);
    }
    FSTRACE(ASYNCHTTP_H2C_ADD_HEADERS_OK, conn->uid);
    return true;
}

FSTRACE_DECL(ASYNCHTTP_H2C_NOTIFY_RESPONSE, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_NOTIFY_CONTENT, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_NO_NOTIFY, "OPID=%s");

static void notify_user(h2op_t *op)
{
    switch (op->api.state) {
        case API_AWAITING_RESPONSE:
            FSTRACE(ASYNCHTTP_H2C_NOTIFY_RESPONSE, op->opid);
            action_1_perf(op->recv.callback);
            break;
        case API_CONTENT_PASSED:
            FSTRACE(ASYNCHTTP_H2C_NOTIFY_CONTENT, op->opid);
            action_1_perf(op->recv.content_callback);
            break;
        default:
            FSTRACE(ASYNCHTTP_H2C_NO_NOTIFY, op->opid);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_ADOPT_TOP_LEVEL, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_ADOPT_UNDER, "OPID=%s PARENT=%s EXCL=%b WEIGHT=%u");

static void adopt(h2op_t *op, h2op_t *parent,
                  bool exclusive, unsigned weight)
{
    op->priority.exclusive = exclusive;
    op->priority.parent = parent;
    op->priority.account = 0;
    if (parent) {
        FSTRACE(ASYNCHTTP_H2C_ADOPT_UNDER, op->opid, parent->opid,
                exclusive, weight);
        op->priority.weight = weight;
        if (exclusive) {
            avl_tree_t *t = op->priority.dependents;
            op->priority.dependents =
                op->priority.parent->priority.dependents;
            op->priority.parent->priority.dependents = t;
        }
        (void) avl_tree_put(op->priority.parent->priority.dependents, op, op);
    } else {
        FSTRACE(ASYNCHTTP_H2C_ADOPT_TOP_LEVEL, op->opid);
        op->priority.weight = DEFAULT_WEIGHT;
        (void) avl_tree_put(op->conn->top_level, op, op);
    }
}

static bool ancestor_of(h2op_t *op1, h2op_t *op2)
{
    for (; op2; op2 = op2->priority.parent)
        if (op1 == op2)
            return true;
    return false;
}

static void unparent(h2op_t *op);

FSTRACE_DECL(ASYNCHTTP_H2C_REPRIOTIZE,
             "OPID=%s PARENT=%s EXCL=%b WEIGHT=%u");
FSTRACE_DECL(ASYNCHTTP_H2C_REPRIOTIZE_STALE,
             "OPID=%s PARENT=%64u/%64u EXCL=%b WEIGHT=%u");
FSTRACE_DECL(ASYNCHTTP_H2C_REPRIOTIZE_WOULD_LOOP,
             "OPID=%s PARENT=%s EXCL=%b WEIGHT=%u");

static void reprioritize(h2op_t *op, uint32_t parent_strid,
                         bool exclusive, unsigned weight)
{
    h2op_t *new_parent = get_op(op->conn, parent_strid);
    if (!new_parent)
        FSTRACE(ASYNCHTTP_H2C_REPRIOTIZE_STALE, op->opid, op->conn->uid,
                (uint64_t) parent_strid, exclusive, weight);
    else if (ancestor_of(op, new_parent)) {
        FSTRACE(ASYNCHTTP_H2C_REPRIOTIZE_WOULD_LOOP, op->opid,
                new_parent->opid, exclusive, weight);
        proto_error(op->conn);
        return;
    } else FSTRACE(ASYNCHTTP_H2C_REPRIOTIZE, op->opid,
                   new_parent->opid, exclusive, weight);
    unparent(op);
    /* Note: unparent() might cause new_parent to be freed through
     * check_op_pulse(). */
    new_parent = get_op(op->conn, parent_strid);
    adopt(op, new_parent, exclusive, weight);
}

FSTRACE_DECL(ASYNCHTTP_H2C_NEW_OP, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_NEW_OP_NOTIFY, "OPID=%s");

static void introduce_new_op(h2op_t *op)
{
    h2conn_t *conn = op->conn;
    if (list_empty(conn->new_ops)) {
        FSTRACE(ASYNCHTTP_H2C_NEW_OP_NOTIFY, op->opid);
        async_execute(conn->async, conn->input.callback);
    } else FSTRACE(ASYNCHTTP_H2C_NEW_OP, op->opid);
    list_append(conn->new_ops, op);
}

static void introduce_op(h2op_t *op)
{
    if (op->recv.promise_envelope)
        introduce_new_op(op);
    else trigger_user(op);
}

static bool conn_is_client(h2conn_t *conn)
{
    return (conn->next_strid & 1) != 0;
}

static bool op_is_client(h2op_t *op)
{
    return conn_is_client(op->conn);
}

FSTRACE_DECL(ASYNCHTTP_H2C_GOT_BAD_OP_HEADERS, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_STALE_OP_HEADERS, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_RESPONSE_HEADERS, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_RESPONSE_TRAILERS, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_UNEXPECTED_HEADERS, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_MISSING_END_OF_STREAM, "OPID=%s");

static void receive_headers(h2conn_t *conn, h2frame_t *frame)
{
    h2op_t *op = get_op(conn, frame->stream_id);
    if (!op) {
        if (bad_op(conn, frame->stream_id)) {
            FSTRACE(ASYNCHTTP_H2C_GOT_BAD_OP_HEADERS, conn->uid,
                    (uint64_t) frame->stream_id);
            proto_error(conn);
        } else FSTRACE(ASYNCHTTP_H2C_GOT_STALE_OP_HEADERS, conn->uid,
                       (uint64_t) frame->stream_id);
        return;
    }
    switch (op->recv.state) {
        case RECV_AWAITING_RESPONSE_HEADER:
            assert(op_is_client(op));
            FSTRACE(ASYNCHTTP_H2C_GOT_RESPONSE_HEADERS, op->opid);
            op->recv.env_space_remaining = conn->input.max_envelope_size;
            op->recv.envelope =
                make_response_headers(conn, frame->headers.headers,
                                      &op->recv.env_space_remaining);
            if (!op->recv.envelope)
                return;         /* traced */
            if (frame->headers.end_stream) {
                if (frame->headers.end_headers) {
                    set_recv_state(op, RECV_FINISHED);
                    trigger_user(op);
                } else op->recv.state =
                           RECV_AWAITING_FINAL_CONTINUATION_HEADER;
            } else if (frame->headers.end_headers) {
                set_recv_state(op, RECV_AWAITING_DATA);
                introduce_op(op);
            }
            else set_recv_state(op, RECV_AWAITING_CONTINUATION_HEADER);
            break;
        case RECV_AWAITING_DATA:
            FSTRACE(ASYNCHTTP_H2C_GOT_RESPONSE_TRAILERS, op->opid);
            if (!add_headers(conn, op->recv.envelope, frame->headers.headers,
                             &op->recv.env_space_remaining,
                             http_env_add_trailer))
                return;         /* traced */
            if (!frame->headers.end_stream) {
                FSTRACE(ASYNCHTTP_H2C_MISSING_END_OF_STREAM, op->opid);
                proto_error(conn);
                return;
            }
            if (frame->headers.end_headers) {
                set_recv_state(op, RECV_FINISHED);
                trigger_user(op);
            } else {
                set_recv_state(op, RECV_AWAITING_CONTINUATION_TRAILER);
                /* Don't trigger the user yet; only give an EOF
                 * when the trailers have been received. */
            }
            break;
        default:
            FSTRACE(ASYNCHTTP_H2C_GOT_UNEXPECTED_HEADERS, op->opid);
            proto_error(conn);
            return;
    }
    if (frame->headers.priority)
        reprioritize(op, frame->headers.dependency,
                     frame->headers.exclusive,
                     frame->headers.weight);
}

FSTRACE_DECL(ASYNCHTTP_H2C_GOT_BAD_OP_CONTINUATION, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_STALE_OP_CONTINUATION, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_CONTINUATION_AFTER_RST, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_PROMISE_CONTINUATION, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_CONTINUATION, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_TRAILER_CONTINUATION, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_UNEXPECTED_CONTINUATION, "OPID=%s");

static void receive_continuation(h2conn_t *conn, h2frame_t *frame)
{
    h2op_t *op = get_op(conn, frame->stream_id);
    if (!op) {
        if (bad_op(conn, frame->stream_id)) {
            FSTRACE(ASYNCHTTP_H2C_GOT_BAD_OP_CONTINUATION, conn->uid,
                    (uint64_t) frame->stream_id);
            proto_error(conn);
        } else FSTRACE(ASYNCHTTP_H2C_GOT_STALE_OP_CONTINUATION, conn->uid,
                       (uint64_t) frame->stream_id);
        return;
    }
    switch (op->recv.state) {
        case RECV_RESET:
            FSTRACE(ASYNCHTTP_H2C_GOT_CONTINUATION_AFTER_RST, op->opid);
            proto_error(conn);
            break;
        case RECV_AWAITING_CONTINUATION_PROMISE:
            assert(op_is_client(op));
            FSTRACE(ASYNCHTTP_H2C_GOT_PROMISE_CONTINUATION, op->opid);
            if (add_headers(conn, op->recv.promise_envelope,
                            frame->continuation.headers,
                            &op->recv.env_space_remaining,
                            http_env_add_header) &&
                frame->continuation.end_headers)
                set_recv_state(op, RECV_AWAITING_RESPONSE_HEADER);
            break;
        case RECV_AWAITING_CONTINUATION_HEADER:
        case RECV_AWAITING_FINAL_CONTINUATION_HEADER:
            FSTRACE(ASYNCHTTP_H2C_GOT_CONTINUATION, op->opid);
            if (add_headers(conn, op->recv.envelope,
                            frame->continuation.headers,
                            &op->recv.env_space_remaining,
                            http_env_add_header) &&
                frame->continuation.end_headers) {
                if (op->recv.state == RECV_AWAITING_CONTINUATION_HEADER)
                    set_recv_state(op, RECV_AWAITING_DATA);
                else set_recv_state(op, RECV_FINISHED);
                introduce_op(op);
            }
            break;
        case RECV_AWAITING_CONTINUATION_TRAILER:
            FSTRACE(ASYNCHTTP_H2C_GOT_TRAILER_CONTINUATION, op->opid);
            if (add_headers(conn, op->recv.envelope,
                            frame->continuation.headers,
                            &op->recv.env_space_remaining,
                            http_env_add_trailer) &&
                frame->continuation.end_headers) {
                set_recv_state(op, RECV_FINISHED);
                trigger_user(op);
            }
            break;
        default:
            FSTRACE(ASYNCHTTP_H2C_GOT_UNEXPECTED_CONTINUATION, op->opid);
            proto_error(conn);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_GOT_BAD_OP_DATA, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_STALE_OP_DATA, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_UNEXPECTED_DATA, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_TOO_MUCH_DATA, "OPID=%s LENGTH=%z WINDOW=%z");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_DATA, "OPID=%s LENGTH=%z WINDOW=%z");

static void receive_data(h2conn_t *conn, h2frame_t *frame)
{
    h2op_t *op = get_op(conn, frame->stream_id);
    if (!op) {
        if (bad_op(conn, frame->stream_id)) {
            FSTRACE(ASYNCHTTP_H2C_GOT_BAD_OP_DATA, conn->uid,
                    (uint64_t) frame->stream_id);
            proto_error(conn);
        } else {
            FSTRACE(ASYNCHTTP_H2C_GOT_STALE_OP_DATA, conn->uid,
                    (uint64_t) frame->stream_id);
            conn->input.pending_data = frame;
            conn->input.data_receiver = NULL;
        }
        return;
    }
    if (op->recv.state != RECV_AWAITING_DATA) {
        FSTRACE(ASYNCHTTP_H2C_GOT_UNEXPECTED_DATA, op->opid);
        proto_error(conn);
        return;
    }
    if (frame->data.data_length > op->recv.space_remaining) {
        FSTRACE(ASYNCHTTP_H2C_GOT_TOO_MUCH_DATA, op->opid,
                frame->data.data_length, op->recv.space_remaining);
        connection_error(conn, H2FRAME_ERR_FLOW_CONTROL_ERROR);
        return;
    }
    FSTRACE(ASYNCHTTP_H2C_GOT_DATA, op->opid, frame->data.data_length,
            op->recv.space_remaining);
    if (frame->data.end_stream)
        set_recv_state(op, RECV_FINISHED);
    conn->input.pending_data = frame;
    conn->input.data_receiver = op;
}

FSTRACE_DECL(ASYNCHTTP_H2C_OPEN_CONN_WINDOW_NO_UPDATE,
             "UID=%64u INCR=%z NEW-WINDOW=%z");
FSTRACE_DECL(ASYNCHTTP_H2C_OPEN_CONN_WINDOW, "UID=%64u INCR=%z NEW-WINDOW=%z");

void award_conn_credit(h2conn_t *conn, size_t amount)
{
    conn->input.pending_credit += amount;
    if (conn->input.pending_credit * 2 < LOCAL_INITIAL_WINDOW) {
        FSTRACE(ASYNCHTTP_H2C_OPEN_CONN_WINDOW_NO_UPDATE, conn->uid, amount,
                conn->input.pending_credit);
        return;                 /* avoid the silly-window syndrome */
    }
    FSTRACE(ASYNCHTTP_H2C_OPEN_CONN_WINDOW, conn->uid, amount,
            conn->input.pending_credit);
    h2frame_t update = {
        .frame_type = H2FRAME_TYPE_WINDOW_UPDATE,
        .stream_id = 0,
        .window_update = {
            .increment = conn->input.pending_credit
        }
    };
    do_signal(conn, &update);
    conn->input.pending_credit = 0;
}

FSTRACE_DECL(ASYNCHTTP_H2C_OPEN_OP_WINDOW_NO_UPDATE,
             "OPID=%s INCR=%z NEW-WINDOW=%z");
FSTRACE_DECL(ASYNCHTTP_H2C_OPEN_OP_WINDOW, "OPID=%s INCR=%z NEW-WINDOW=%z");

void award_op_credit(h2op_t *op, size_t amount)
{
    op->recv.pending_credit += amount;
    if (op->recv.pending_credit * 2 < LOCAL_INITIAL_WINDOW) {
        FSTRACE(ASYNCHTTP_H2C_OPEN_OP_WINDOW_NO_UPDATE, op->opid, amount,
                op->recv.pending_credit);
        return;                 /* avoid the silly-window syndrome */
    }
    FSTRACE(ASYNCHTTP_H2C_OPEN_OP_WINDOW, op->opid, amount,
            op->recv.pending_credit);
    h2frame_t update = {
        .frame_type = H2FRAME_TYPE_WINDOW_UPDATE,
        .stream_id = op->strid,
        .window_update = {
            .increment = op->recv.pending_credit
        }
    };
    do_signal(op->conn, &update);
    op->recv.pending_credit = 0;
}

FSTRACE_DECL(ASYNCHTTP_H2C_DEPLETE_DATA, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_DEPLETE_DATA_READ,
             "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2C_DEPLETE_DATA_READ_DUMP, "UID=%64u DATA=%B");

static bool deplete_data(h2conn_t *conn)
{
    FSTRACE(ASYNCHTTP_H2C_DEPLETE_DATA, conn->uid);
    h2op_t *op = conn->input.data_receiver;
    for (;;) {
        uint8_t buf[5000];
        ssize_t count =
            bytestream_1_read(conn->input.pending_data->data.data,
                              buf, sizeof buf);
        FSTRACE(ASYNCHTTP_H2C_DEPLETE_DATA_READ, conn->uid, sizeof buf, count);
        FSTRACE(ASYNCHTTP_H2C_DEPLETE_DATA_READ_DUMP, conn->uid, buf, count);
        if (count <= 0) {
            if (count == 0)
                break;
            if (errno != EAGAIN)
                proto_error(conn);
            return false;
        }
        if (op)
            award_op_credit(op, count);
        award_conn_credit(conn, count);
    }
    bytestream_1_close(conn->input.pending_data->data.data);
    h2frame_free(conn->input.pending_data);
    conn->input.pending_data = NULL;
    return true;
}

FSTRACE_DECL(ASYNCHTTP_H2C_RELAY_DATA, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_RELAY_DATA_READ,
             "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2C_RELAY_DATA_READ_DUMP, "UID=%64u DATA=%B");

static bool relay_data(h2conn_t *conn)
{
    if (!conn->input.pending_data)
        return true;
    h2op_t *op = conn->input.data_receiver;
    if (!op || op->api.state == API_CONTENT_CLOSED)
        return deplete_data(conn);
    FSTRACE(ASYNCHTTP_H2C_RELAY_DATA, op->opid);
    bool notify = false;
    /* Note that if op->recv.space_remaining == 0, we can stop reading
     * because previous calculations have ensured that there is no
     * more data that can fit the window. */
    while (op->recv.space_remaining) {
        size_t want = op->recv.space_remaining, write_cursor;
        if (want > op->recv.read_cursor) {
            want -= op->recv.read_cursor;
            write_cursor = LOCAL_INITIAL_WINDOW - want;
        } else write_cursor = op->recv.read_cursor - want;
        uint8_t *buf = op->recv.window + write_cursor;
        ssize_t count =
            bytestream_1_read(conn->input.pending_data->data.data, buf, want);
        FSTRACE(ASYNCHTTP_H2C_RELAY_DATA_READ, conn->uid, want, count);
        FSTRACE(ASYNCHTTP_H2C_RELAY_DATA_READ_DUMP, conn->uid, buf, count);
        if (count <= 0) {
            if (count == 0)
                break;
            if (errno != EAGAIN) {
                proto_error(conn);
                return false;
            }
            if (notify)
                trigger_user(op);
            return false;
        }
        notify = true;
        op->recv.space_remaining -= count;
        award_conn_credit(conn, count);
    }
    bytestream_1_close(conn->input.pending_data->data.data);
    h2frame_free(conn->input.pending_data);
    conn->input.pending_data = NULL;
    trigger_user(op);
    return true;
}

FSTRACE_DECL(ASYNCHTTP_H2C_PING_BAD_STRID, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_PING_ACK, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_PING, "UID=%64u");

static void process_ping(h2conn_t *conn, h2frame_t *frame)
{
    if (frame->stream_id) {
        FSTRACE(ASYNCHTTP_H2C_PING_BAD_STRID, conn->uid,
                (uint64_t) frame->stream_id);
        proto_error(conn);
        return;
    }
    if (frame->ping.ack) {
        /* We never send a ping, but whatever */
        FSTRACE(ASYNCHTTP_H2C_PING_ACK, conn->uid);
        return;
    }
    FSTRACE(ASYNCHTTP_H2C_GOT_PING, conn->uid);
    frame->ping.ack = 1;
    do_signal(conn, frame);
}

FSTRACE_DECL(ASYNCHTTP_H2C_CHECK_CONN_PULSE_NOT_CLOSED, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_CHECK_CONN_PULSE_OPS_IN_FLIGHT, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_CHECK_CONN_PULSE_TRANSPORT_OPEN, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_CHECK_CONN_PULSE_RIP, "UID=%64u");

static void check_conn_pulse(h2conn_t *conn)
{
    if (conn->state != CONN_ZOMBIE) {
        FSTRACE(ASYNCHTTP_H2C_CHECK_CONN_PULSE_NOT_CLOSED, conn->uid);
        return;
    }
    if (!hash_table_empty(conn->ops)) {
        FSTRACE(ASYNCHTTP_H2C_CHECK_CONN_PULSE_OPS_IN_FLIGHT, conn->uid);
        return;
    }
    if (conn->output.stream) {
        FSTRACE(ASYNCHTTP_H2C_CHECK_CONN_PULSE_TRANSPORT_OPEN, conn->uid);
        return;
    }
    FSTRACE(ASYNCHTTP_H2C_CHECK_CONN_PULSE_RIP, conn->uid);
    if (conn->input.pending_data)
        h2frame_free(conn->input.pending_data);
    h2frame_decoder_close(conn->input.decoder);
    destroy_hpack_table(conn->input.hunpack);
    destroy_hpack_table(conn->output.hpack);
    destroy_hash_table(conn->ops);
    destroy_avl_tree(conn->top_level);
    destroy_async_event(conn->output.event);
    async_wound(conn->async, conn);
}

FSTRACE_DECL(ASYNCHTTP_H2C_CHECK_OP_PULSE_NOT_CLOSED, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_CHECK_OP_PULSE_USER_OWED, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_CHECK_OP_PULSE_MISSED_BY_CHILDREN, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_CHECK_OP_PULSE_RIP, "OPID=%s");

static void check_op_pulse(h2op_t *op)
{
    if (op->state != OP_ZOMBIE) {
        FSTRACE(ASYNCHTTP_H2C_CHECK_OP_PULSE_NOT_CLOSED, op->opid);
        return;
    }
    switch (op->api.state) {
        case API_CONTENT_PASSED:
        case API_CONTENT_EXHAUSTED:
            FSTRACE(ASYNCHTTP_H2C_CHECK_OP_PULSE_USER_OWED, op->opid);
            return;
        default:
            ;
    }
    if (!avl_tree_empty(op->priority.dependents)) {
        FSTRACE(ASYNCHTTP_H2C_CHECK_OP_PULSE_MISSED_BY_CHILDREN, op->opid);
        return;
    }
    FSTRACE(ASYNCHTTP_H2C_CHECK_OP_PULSE_RIP, op->opid);
    unparent(op);
    check_conn_pulse(op->conn);
    fsfree(op->opid);
    async_wound(op->conn->async, op);
}

static void unparent(h2op_t *op)
{
    if (op->priority.parent) {
        avl_tree_t *ops = op->priority.parent->priority.dependents;
        avl_tree_remove(ops, avl_tree_get(ops, op));
        check_op_pulse(op->priority.parent);
    } else {
        avl_tree_t *ops = op->conn->top_level;
        avl_tree_remove(ops, avl_tree_get(ops, op));
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_GOT_WEIRD_PRIORITY,
             "OPID=%64u/%64u PARENT=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_STALE_PRIORITY, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_PRIORITY, "OPID=%s");

static void process_priority(h2conn_t *conn, h2frame_t *frame)
{
    if (bad_op(conn, frame->stream_id) ||
        bad_op(conn, frame->priority.dependency)) {
        /* According to RFC 7540 § 5.1, you can receive a PRIORITY
         * frame on an idle (= future) stream. We ignore it,
         * though. */
        FSTRACE(ASYNCHTTP_H2C_GOT_WEIRD_PRIORITY, conn->uid,
                (uint64_t) frame->stream_id, conn->uid,
                (uint64_t) frame->priority.dependency);
        return;
    }
    h2op_t *op = get_op(conn, frame->stream_id);
    if (!op) {
        FSTRACE(ASYNCHTTP_H2C_GOT_STALE_PRIORITY, op->opid);
        return;
    }
    FSTRACE(ASYNCHTTP_H2C_GOT_PRIORITY, op->opid);
    reprioritize(op, frame->priority.dependency, frame->priority.exclusive,
                 frame->priority.weight);
}

FSTRACE_DECL(ASYNCHTTP_H2C_GOT_BAD_RESET, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_STALE_RESET, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_RESET, "OPID=%s");

static void process_reset(h2conn_t *conn, h2frame_t *frame)
{
    h2op_t *op = get_op(conn, frame->stream_id);
    if (!op) {
        if (bad_op(conn, frame->stream_id)) {
            FSTRACE(ASYNCHTTP_H2C_GOT_BAD_RESET, conn->uid,
                    (uint64_t) frame->stream_id);
            proto_error(conn);
        } else FSTRACE(ASYNCHTTP_H2C_GOT_STALE_RESET, conn->uid,
                       (uint64_t) frame->stream_id);
        return;
    }
    FSTRACE(ASYNCHTTP_H2C_GOT_RESET, op->opid);
    reset_op(op, frame->rst_stream.error_code);
}

FSTRACE_DECL(ASYNCHTTP_H2C_GOAWAY_BAD_STRID, "UID=%64u STRID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_GENTLE_GOAWAY, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_ROUGH_GOAWAY, "UID=%64u");

static void process_goaway(h2conn_t *conn, h2frame_t *frame)
{
    if (frame->stream_id) {
        FSTRACE(ASYNCHTTP_H2C_GOAWAY_BAD_STRID, conn->uid,
                (uint64_t) frame->stream_id);
        proto_error(conn);
        return;
    }
    if (frame->goaway.error_code == H2FRAME_ERR_NO_ERROR) {
        FSTRACE(ASYNCHTTP_H2C_GOT_GENTLE_GOAWAY, conn->uid);
        set_conn_state(conn, CONN_PASSIVE);
        reset_ops(conn->top_level, frame->goaway.last_stream_id,
                  frame->goaway.error_code);
    } else {
        FSTRACE(ASYNCHTTP_H2C_GOT_ROUGH_GOAWAY, conn->uid);
        set_conn_state(conn, CONN_ERRORED);
        reset_ops(conn->top_level, 0, frame->goaway.error_code);
    }
}

static int op_cmp(const void *a, const void *b)
{
    const h2op_t *op_a = a;
    const h2op_t *op_b = b;
    if (op_a->priority.account < op_b->priority.account)
        return -1;
    if (op_a->priority.account > op_b->priority.account)
        return 1;
    if (op_a->strid < op_b->strid)
        return -1;
    if (op_a->strid > op_b->strid)
        return 1;
    assert(a == b);
    return 0;
}

typedef struct {
    char *scheme, *authority, *path, *method;
} reqline_t;

static bool amend_reqline(reqline_t *reqline, char *name, char *value)
{
    if (!strcmp(name, ":scheme")) {
        if (reqline->scheme)
            return false;
        reqline->scheme = value;
    } else if (!strcmp(name, ":authority")) {
        if (reqline->authority)
            return false;
        reqline->authority = value;
    } else if (!strcmp(name, ":method")) {
        if (reqline->method)
            return false;
        reqline->method = value;
    } else if (!strcmp(name, ":path")) {
        if (reqline->path)
            return false;
        reqline->path = value;
    } else return false;
    fsfree(name);
    return true;
}

static http_env_t *bad_request(h2conn_t *conn, reqline_t *reqline,
                               http_env_t *env, list_t *strings)
{
    proto_error(conn);
    fsfree(reqline->scheme);
    fsfree(reqline->authority);
    fsfree(reqline->path);
    fsfree(reqline->method);
    if (env)
        destroy_http_env(env);
    list_foreach(strings, (void *) fsfree, NULL);
    destroy_list(strings);
    return NULL;
}

FSTRACE_DECL(ASYNCHTTP_H2C_DECODE_REQUEST, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_DECODE_REQUEST_OK, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_INCOMPLETE_REQUEST, "UID=%64u");

/* TODO: Right now we map HTTP/2 info on an HTTP/1 envelope, meaning
 * the scheme is ignored and the :authority is translated to "host".
 * Consider some more native HTTP/2 support for http_env_t. */
static http_env_t *make_request_headers(h2conn_t *conn, list_t *fields,
                                        size_t *size_remaining)
{
    FSTRACE(ASYNCHTTP_H2C_DECODE_REQUEST, conn->uid);
    list_elem_t *e;
    list_t *strings = make_list();
    http_env_t *env = NULL;
    reqline_t reqline = {};
    for (e = list_get_first(fields); e; e = list_next(e)) {
        const hpack_header_field_t *field = list_elem_get_value(e);        
        char *name, *value;
        if (!hpack_table_decode(conn->input.hunpack, field, &name, &value)) {
            FSTRACE(ASYNCHTTP_H2C_UNPACK_FAIL, conn->uid);
            return bad_request(conn, &reqline, env, strings);
        }
        size_t nominal_size = header_field_size(name, value);
        if (nominal_size > *size_remaining) {
            FSTRACE(ASYNCHTTP_H2C_HEADER_TOO_LARGE, conn->uid);
            return bad_request(conn, &reqline, env, strings);
        }
        *size_remaining -= nominal_size;
        if (name[0] == ':') {
            if (env || !amend_reqline(&reqline, name, value)) {
                FSTRACE(ASYNCHTTP_H2C_EXTRA_PSEUDOHEADER, conn->uid);
                fsfree(name);
                fsfree(value);
                return bad_request(conn, &reqline, env, strings);
            }
            if (reqline.scheme && reqline.authority && reqline.path &&
                reqline.method) {
                fsfree(reqline.scheme);
                env = make_http_env_request(reqline.method, reqline.path,
                                            "HTTP/2");
                list_append(strings, charstr_dupstr("host"));
                list_append(strings, reqline.authority);
            }
        } else {
            list_append(strings, name);
            list_append(strings, value);
        }
    }
    if (!env) {
        FSTRACE(ASYNCHTTP_H2C_INCOMPLETE_REQUEST, conn->uid);
        return bad_request(conn, &reqline, env, strings);
    }
    while (!list_empty(strings)) {
        const char *name = list_pop_first(strings);
        const char *value = list_pop_first(strings);
        http_env_add_header(env, name, value);
    }
    destroy_list(strings);
    FSTRACE(ASYNCHTTP_H2C_DECODE_REQUEST_OK, conn->uid);
    return env;
}

FSTRACE_DECL(ASYNCHTTP_H2C_OP_CREATE, "OPID=%s PTR=%p");

static h2op_t *make_op(h2conn_t *conn, uint32_t strid)
{
    h2op_t *op = fsalloc(sizeof *op);
    op->strid = strid;
    assert(op->strid < 0x80000000);
    op->opid = charstr_printf("%llu/%llu", (unsigned long long) conn->uid,
                              (unsigned long long) strid);
    op->conn = conn;
    FSTRACE(ASYNCHTTP_H2C_OP_CREATE, op->opid, op);
    op->state = OP_LIVE;
    op->recv.envelope = NULL;
    op->recv.window = fsalloc(LOCAL_INITIAL_WINDOW);
    op->recv.pending_credit = 0;
    op->recv.read_cursor = 0;
    op->recv.space_remaining = LOCAL_INITIAL_WINDOW;
    action_1 notify_user_cb = { op, (act_1) notify_user };
    op->api.event = make_async_event(conn->async, notify_user_cb );
    op->recv.callback = NULL_ACTION_1;
    op->xmit.credit = conn->peer.initial_window_size;
    op->priority.dependents = make_avl_tree(op_cmp);
    return op;
}

FSTRACE_DECL(ASYNCHTTP_H2C_GOT_PUSH_FROM_CLIENT, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_BAD_PUSH, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_STALE_PUSH, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_PUSH_OUT_OF_ORDER, "OPID=%64u/%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_GOT_PUSH, "OPID=%64u/%64u PARENT=%64u/%64u");

static void process_push(h2conn_t *conn, h2frame_t *frame)
{
    if (!conn_is_client(conn)) {
        FSTRACE(ASYNCHTTP_H2C_GOT_PUSH_FROM_CLIENT, conn->uid);
        proto_error(conn);
        return;
    }
    h2op_t *parent = get_op(conn, frame->stream_id);
    if (!parent) {
        if (bad_op(conn, frame->stream_id)) {
            FSTRACE(ASYNCHTTP_H2C_GOT_BAD_PUSH, conn->uid,
                    (uint64_t) frame->stream_id);
            proto_error(conn);
            return;
        }
        FSTRACE(ASYNCHTTP_H2C_GOT_STALE_PUSH, conn->uid,
                (uint64_t) frame->stream_id);
    }
    if (frame->push_promise.promised != conn->next_peer_strid) {
        FSTRACE(ASYNCHTTP_H2C_GOT_PUSH_OUT_OF_ORDER, conn->uid,
                (uint64_t) frame->stream_id);
        proto_error(conn);
        return;
    }
    FSTRACE(ASYNCHTTP_H2C_GOT_PUSH, conn->uid,
            (uint64_t) conn->next_peer_strid,
            conn->uid, (uint64_t) frame->stream_id);
    size_t env_space_remaining = conn->input.max_envelope_size;
    http_env_t *envelope =
        make_request_headers(conn, frame->push_promise.headers,
                             &env_space_remaining);
    if (!envelope)
        return;                 /* traced */
    h2op_t *op = make_op(conn, conn->next_peer_strid);
    conn->next_peer_strid += 2;
    op->xmit.envelope = NULL;
    op->xmit.content_length = 0;
    op->xmit.content = emptystream;
    op->xmit.state = XMIT_FINISHED,
    op->recv.promise_envelope = envelope;
    op->recv.env_space_remaining = env_space_remaining;
    if (frame->push_promise.end_headers)
        op->recv.state = RECV_AWAITING_RESPONSE_HEADER;
    else op->recv.state = RECV_AWAITING_CONTINUATION_PROMISE;
    op->api.state = API_AWAITING_PROMISE;
    adopt(op, parent, false, DEFAULT_WEIGHT);
}

FSTRACE_DECL(ASYNCHTTP_H2C_GOT_REQUEST, "OPID=%64u/%64u PARENT=%64u/%64u");

static void receive_new_request_headers(h2conn_t *conn, h2frame_t *frame)
{
    FSTRACE(ASYNCHTTP_H2C_GOT_REQUEST, conn->uid, (uint64_t) frame->stream_id);
    size_t env_space_remaining = conn->input.max_envelope_size;
    http_env_t *envelope =
        make_request_headers(conn, frame->headers.headers,
                             &env_space_remaining);
    if (!envelope)
        return;                 /* traced */
    h2op_t *op = make_op(conn, conn->next_peer_strid);
    conn->next_peer_strid += 2;
    op->xmit.envelope = NULL;
    op->xmit.content_length = 0;
    op->xmit.content = emptystream;
    op->xmit.state = XMIT_FINISHED,
    op->recv.envelope = envelope;
    op->recv.env_space_remaining = env_space_remaining;
    if (frame->headers.end_stream) {
        if (frame->headers.end_headers) {
            set_recv_state(op, RECV_FINISHED);
            introduce_new_op(op);
        } else op->recv.state = RECV_AWAITING_FINAL_CONTINUATION_HEADER;
    } else if (frame->headers.end_headers) {
        set_recv_state(op, RECV_AWAITING_DATA);
        introduce_new_op(op);
    } else set_recv_state(op, RECV_AWAITING_CONTINUATION_HEADER);
    op->api.state = API_AWAITING_REQUEST;
    adopt(op, NULL, false, DEFAULT_WEIGHT);
}

static bool conn_ready(h2conn_t *conn)
{
    switch (conn->state) {
        case CONN_ACTIVE:
        case CONN_PASSIVE:
            return true;
        default:
            return false;
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_DO_INPUT, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_DO_INPUT_FAIL, "UID=%64u ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2C_INPUT_DONE, "UID=%64u");

static void do_input(h2conn_t *conn)
{
    FSTRACE(ASYNCHTTP_H2C_DO_INPUT, conn->uid);
    while (conn_ready(conn) && relay_data(conn)) {
        h2frame_t *frame = h2frame_decoder_receive(conn->input.decoder);
        if (!frame) {
            FSTRACE(ASYNCHTTP_H2C_DO_INPUT_FAIL, conn->uid);
            if (errno != EAGAIN) /* even 0 and ENODATA are protocol errors */
                proto_error(conn);
            return;
        }
        switch (frame->frame_type) {
            case H2FRAME_TYPE_DATA:
                receive_data(conn, frame);
                continue;       /* don't free data frame */
            case H2FRAME_TYPE_HEADERS:
                if (conn_is_client(conn) ||
                    frame->stream_id != conn->next_peer_strid)
                    receive_headers(conn, frame);
                else receive_new_request_headers(conn, frame);
                break;
            case H2FRAME_TYPE_PRIORITY:
                process_priority(conn, frame);
                break;
            case H2FRAME_TYPE_RST_STREAM:
                process_reset(conn, frame);
                break;
            case H2FRAME_TYPE_SETTINGS:
                apply_settings(conn, frame);
                break;
            case H2FRAME_TYPE_PUSH_PROMISE:
                process_push(conn, frame);
                break;
            case H2FRAME_TYPE_PING:
                process_ping(conn, frame);
                break;
            case H2FRAME_TYPE_GOAWAY:
                process_goaway(conn, frame);
                break;
            case H2FRAME_TYPE_WINDOW_UPDATE:
                update_window(conn, frame);
                break;
            case H2FRAME_TYPE_CONTINUATION:
                receive_continuation(conn, frame);
                break;
            default:
                assert(false);
        }
        h2frame_free(frame);
    }
    FSTRACE(ASYNCHTTP_H2C_INPUT_DONE, conn->uid);
}

FSTRACE_DECL(ASYNCHTTP_H2C_PROBE_INPUT, "UID=%64u");

static void probe_input(h2conn_t *conn)
{
    FSTRACE(ASYNCHTTP_H2C_PROBE_INPUT, conn->uid);
    do_input(conn);
}

static void supply_output(h2conn_t *conn, bytestream_1 stream)
{
    if (conn->output.stream)
        queuestream_enqueue(conn->output.stream, stream);
    else bytestream_1_close(stream);
}

typedef void (*supplier_t)(h2op_t *op, bool end_headers, list_t *headers);

FSTRACE_DECL(ASYNCHTTP_H2C_SUPPLY_HEADERS, "OPID=%s END-HEADERS=%b");

static void supply_headers(h2op_t *op, bool end_headers, list_t *headers)
{
    FSTRACE(ASYNCHTTP_H2C_SUPPLY_HEADERS, op->opid, end_headers);
    h2frame_t headers_frame = {
        .frame_type = H2FRAME_TYPE_HEADERS,
        .stream_id = op->strid,
        .headers = {
            .end_stream = false,
            .end_headers = end_headers,
            .priority = false,
            .headers = headers,
        }
    };
    if (op->priority.parent) {
        headers_frame.headers.priority = true;
        headers_frame.headers.exclusive = op->priority.exclusive;
        headers_frame.headers.dependency = op->priority.parent->strid;
        headers_frame.headers.weight = op->priority.weight;
    }
    supply_output(op->conn, h2frame_encode(op->conn->async, &headers_frame));
    while (!list_empty(headers))
        hpack_free_header_field((hpack_header_field_t *)
                                list_pop_first(headers));
}

FSTRACE_DECL(ASYNCHTTP_H2C_SUPPLY_PROMISE, "OPID=%s END-HEADERS=%b");

static void supply_promise(h2op_t *op, bool end_headers, list_t *headers)
{
    FSTRACE(ASYNCHTTP_H2C_SUPPLY_PROMISE, op->opid, end_headers);
    h2frame_t promise = {
        .frame_type = H2FRAME_TYPE_PUSH_PROMISE,
        .stream_id = op->priority.parent->strid,
        .push_promise = {
            .end_headers = end_headers,
            .promised = op->strid,
            .headers = headers,
        }
    };
    supply_output(op->conn, h2frame_encode(op->conn->async, &promise));
    while (!list_empty(headers))
        hpack_free_header_field((hpack_header_field_t *)
                                list_pop_first(headers));
}

FSTRACE_DECL(ASYNCHTTP_H2C_SUPPLY_CONTINUATION, "OPID=%s END-HEADERS=%b");

static void supply_continuation(h2op_t *op, bool end_headers, list_t *headers)
{
    FSTRACE(ASYNCHTTP_H2C_SUPPLY_CONTINUATION, op->opid, end_headers);
    h2frame_t continuation = {
        .frame_type = H2FRAME_TYPE_CONTINUATION,
        .stream_id = op->strid,
        .continuation = {
            .end_headers = false,
            .headers = headers,
        }
    };
    supply_output(op->conn, h2frame_encode(op->conn->async, &continuation));
    while (!list_empty(headers))
        hpack_free_header_field((hpack_header_field_t *)
                                list_pop_first(headers));
}

static void resupply_headers(h2op_t *op, const char *name, const char *value,
                             list_t *headers, size_t *remaining,
                             supplier_t *supplier)
{
    /* break the envelope into header and continuation frames */
    size_t nominal_size = header_field_size(name, value);
    hpack_header_field_t *field =
        hpack_table_encode(op->conn->output.hpack, name, value);
    if (*remaining < nominal_size) {
        (**supplier)(op, false, headers);
        *supplier = supply_continuation;
        *remaining = op->conn->peer.max_header_list_size;
        assert(*remaining >= nominal_size);
    }
    *remaining -= nominal_size;
    list_append(headers, field);
}

FSTRACE_DECL(ASYNCHTTP_H2C_ISSUE_HEADERS, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_HEADERS_ISSUED, "OPID=%s");

static void issue_headers(h2op_t *op, list_t *headers, size_t *remaining,
                          supplier_t *supplier)
{
    FSTRACE(ASYNCHTTP_H2C_ISSUE_HEADERS, op->opid);
    http_env_iter_t *iter = NULL;
    for (;;) {
        const char *name, *value;
        iter = http_env_get_next_header(op->xmit.envelope, iter,
                                        &name, &value);
        if (!iter)
            break;
        if (charstr_case_cmp(name, "host"))
            resupply_headers(op, name, value, headers, remaining, supplier);
        else resupply_headers(op, ":authority", value,
                              headers, remaining, supplier);
    }
    if (op->xmit.content_length >= 0) {
        char *clen =
            charstr_printf("%lld", (long long) op->xmit.content_length);
        resupply_headers(op, "content-length", clen,
                         headers, remaining, supplier);
        fsfree(clen);
    }
    (**supplier)(op, true, headers);
    destroy_list(headers);
    async_event_trigger(op->conn->output.event);
    FSTRACE(ASYNCHTTP_H2C_HEADERS_ISSUED, op->opid);
}

static list_t *initial_request_headers(h2op_t *op, const http_env_t *envelope,
                                       size_t *remaining, supplier_t *supplier)
{
    *remaining = op->conn->peer.max_header_list_size;
    list_t *headers = make_list();
    resupply_headers(op, ":path", http_env_get_path(envelope),
                     headers, remaining, supplier);
    resupply_headers(op, ":method", http_env_get_method(envelope),
                     headers, remaining, supplier);
    resupply_headers(op, ":scheme", "https", headers, remaining, supplier);
    return headers;
}

FSTRACE_DECL(ASYNCHTTP_H2C_ISSUE_REQUEST, "OPID=%s");

static void issue_request(h2op_t *op)
{
    FSTRACE(ASYNCHTTP_H2C_ISSUE_REQUEST, op->opid);
    size_t remaining;
    supplier_t supplier = supply_headers;
    list_t *headers =
        initial_request_headers(op, op->xmit.envelope, &remaining, &supplier);
    issue_headers(op, headers, &remaining, &supplier);
}

FSTRACE_DECL(ASYNCHTTP_H2C_FINISH_TRANSMISSION_NO_TRAILERS, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_FINISH_TRANSMISSION_WITH_TRAILERS, "OPID=%s");

static void finish_transmission(h2op_t *op)
{
    h2conn_t *conn = op->conn;
    if (op->xmit.content_length == HTTP_ENCODE_CHUNKED) {
        const char *name, *value;
        http_env_iter_t *iter =
            http_env_get_next_trailer(op->xmit.envelope, NULL, &name, &value);
        if (iter) {
            FSTRACE(ASYNCHTTP_H2C_FINISH_TRANSMISSION_WITH_TRAILERS, op->opid);
            h2frame_t trailers = {
                .frame_type = H2FRAME_TYPE_HEADERS,
                .stream_id = op->strid,
                .headers = {
                    .end_stream = true,
                    .end_headers = true,
                    .priority = false,
                    .headers = make_list(),
                }
            };
            while (iter) {
                list_append(trailers.headers.headers,
                            hpack_table_encode(conn->output.hpack,
                                               name, value));
                iter = http_env_get_next_trailer(op->xmit.envelope, iter,
                                                 &name, &value);
            }
            supply_output(conn, h2frame_encode(conn->async, &trailers));
            list_foreach(trailers.headers.headers,
                         (void *) hpack_free_header_field, NULL);
            destroy_list(trailers.headers.headers);
            bytestream_1_close(op->xmit.content);
            set_xmit_state(op, XMIT_FINISHED);
            return;
        }
    }
    FSTRACE(ASYNCHTTP_H2C_FINISH_TRANSMISSION_NO_TRAILERS, op->opid);
    h2frame_t terminal_data = {
        .frame_type = H2FRAME_TYPE_DATA,
        .stream_id = op->strid,
        .data = {
            .end_stream = true,
            .data_length = 0,
            .data = emptystream
        }
    };
    supply_output(conn, h2frame_encode(conn->async, &terminal_data));
    bytestream_1_close(op->xmit.content);
    set_xmit_state(op, XMIT_FINISHED);
}

FSTRACE_DECL(ASYNCHTTP_H2C_ISSUE_RESET, "OPID=%s ERR=%I");

static void reset_stream(h2op_t *op, uint32_t error_code)
{
    FSTRACE(ASYNCHTTP_H2C_ISSUE_RESET, op->opid, h2frame_trace_error_code,
            &error_code);
    h2frame_t rst = {
        .frame_type = H2FRAME_TYPE_RST_STREAM,
        .stream_id = op->strid,
        .rst_stream = {
            .error_code = error_code
        }
    };
    do_signal(op->conn, &rst);
}

FSTRACE_DECL(ASYNCHTTP_H2C_SUPPLY_CONTENT_NO_CREDIT, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_SUPPLY_CONTENT_READ,
             "OPID=%s WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2C_SUPPLY_CONTENT_READ_DUMP, "OPID=%s DATA=%B");
FSTRACE_DECL(ASYNCHTTP_H2C_SUPPLY_CONTENT, "OPID=%s");

static bool supply_content(h2op_t *op)
{
    if (op->xmit.credit <= 0) {
        FSTRACE(ASYNCHTTP_H2C_SUPPLY_CONTENT_NO_CREDIT, op->opid);
        return false;
    }
    h2conn_t *conn = op->conn;
    size_t chunk_size = sizeof conn->output.data_chunk;
    if (chunk_size > op->xmit.credit)
        chunk_size = op->xmit.credit;
    ssize_t count =
        bytestream_1_read(op->xmit.content, conn->output.data_chunk,
                          chunk_size);
    FSTRACE(ASYNCHTTP_H2C_SUPPLY_CONTENT_READ, op->opid, chunk_size, count);
    FSTRACE(ASYNCHTTP_H2C_SUPPLY_CONTENT_READ_DUMP, op->opid,
            conn->output.data_chunk, count);
    if (count < 0) {
        if (errno != EAGAIN) {
            op->err = errno;
            set_op_state(op, OP_ERRORED);
            reset_stream(op, H2FRAME_ERR_STREAM_CLOSED);
            bytestream_1_close(op->xmit.content);
            set_xmit_state(op, XMIT_FINISHED);
            trigger_user(op);
        }
        return false;
    }
    if (count == 0) {
        finish_transmission(op);
        return true;
    }
    blobstream_t *payload =
        open_blobstream(conn->async, conn->output.data_chunk, count);
    h2frame_t data = {
        .frame_type = H2FRAME_TYPE_DATA,
        .stream_id = op->strid,
        .data = {
            .end_stream = false,
            .data_length = count,
            .data = blobstream_as_bytestream_1(payload)
        }
    };
    FSTRACE(ASYNCHTTP_H2C_SUPPLY_CONTENT, op->opid);
    supply_output(conn, h2frame_encode(conn->async, &data));
    return true;
}

FSTRACE_DECL(ASYNCHTTP_H2C_OP_ADVANCE_NOT_LIVE, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_OP_ADVANCE_NOT_SENDING_DATA, "OPID=%s");
FSTRACE_DECL(ASYNCHTTP_H2C_OP_ADVANCE, "OPID=%s");

static bool op_advance(h2op_t *op)
{
    if (op->state != OP_LIVE) {
        FSTRACE(ASYNCHTTP_H2C_OP_ADVANCE_NOT_LIVE, op->opid);
        return false;
    }
    switch (op->xmit.state) {
        case XMIT_PROCESSING:
        case XMIT_FINISHED:
            FSTRACE(ASYNCHTTP_H2C_OP_ADVANCE_NOT_SENDING_DATA, op->opid);
            return false;
        case XMIT_SENDING_DATA:
            FSTRACE(ASYNCHTTP_H2C_OP_ADVANCE, op->opid);
            return supply_content(op);
        default:
            assert(false);
    }
}

static bool replenish_output(avl_tree_t *ops)
{
    /* The op with the highest value on its account is advanced. The
     * sum of accounts in ops stays around 0. (It would be precisely 0
     * except for the closed operations that take their account
     * balances away from the pool.) */
    avl_elem_t *e;
    for (e = avl_tree_get_first(ops); e; e = avl_tree_next(e)) {
        h2op_t *op = (h2op_t *) avl_elem_get_value(e);
        if (replenish_output(op->priority.dependents) || op_advance(op)) {
            avl_tree_remove(ops, e);
            for (e = avl_tree_get_first(ops); e; e = avl_tree_next(e)) {
                h2op_t *other = (h2op_t *) avl_elem_get_value(e);
                other->priority.account += other->priority.weight;
                op->priority.account -= other->priority.weight;
            }
            (void) avl_tree_put(ops, op, op);
            return true;
        }
    }
    return false;
}

static ssize_t _read_output(h2conn_t *conn, void *buf, size_t count)
{
    ssize_t n = queuestream_read(conn->output.stream, buf, count);
    if (n >= 0)
        return n;
    assert(errno == EAGAIN);
    if (!replenish_output(conn->top_level)) {
        errno = EAGAIN;
        return -1;
    }
    return queuestream_read(conn->output.stream, buf, count);
}

FSTRACE_DECL(ASYNCHTTP_H2C_OUTPUT_READ,
             "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2C_OUTPUT_READ_DUMP, "UID=%64u DATA=%B");

static ssize_t read_output(void *obj, void *buf, size_t count)
{
    h2conn_t *conn = obj;
    ssize_t n = _read_output(conn, buf, count);
    FSTRACE(ASYNCHTTP_H2C_OUTPUT_READ, conn->uid, count, n);
    FSTRACE(ASYNCHTTP_H2C_OUTPUT_READ_DUMP, conn->uid, buf, n);
    return n;
}

FSTRACE_DECL(ASYNCHTTP_H2C_OUTPUT_CLOSE_UNEXPECTED, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_OUTPUT_CLOSE, "UID=%64u");

static void close_output(void *obj)
{
    h2conn_t *conn = obj;
    if (conn_ready(conn)) {
        FSTRACE(ASYNCHTTP_H2C_OUTPUT_CLOSE_UNEXPECTED, conn->uid);
        set_conn_state(conn, CONN_ERRORED);
        async_execute(conn->async, conn->output.peer_closed_callback);
    } else FSTRACE(ASYNCHTTP_H2C_OUTPUT_CLOSE, conn->uid);
    queuestream_close(conn->output.stream);
    conn->output.stream = NULL;
    check_conn_pulse(conn);
}

static void register_output_callback(void *obj, action_1 action)
{
    ((h2conn_t *) obj)->output.callback = action;
}

static void unregister_output_callback(void *obj)
{
    ((h2conn_t *) obj)->output.callback = NULL_ACTION_1;
}

static struct bytestream_1_vt h2vt = {
    .read = read_output,
    .close = close_output,
    .register_callback = register_output_callback,
    .unregister_callback = unregister_output_callback,
};

static uint64_t op_hash(const void *key)
{
    return *(const uint32_t *) key;
}

static int op_diff(const void *a, const void *b)
{
    return *(const uint32_t *) a != *(const uint32_t *) b;
}

static void probe_output(h2conn_t *conn)
{
    action_1_perf(conn->output.callback);
}

static list_t *initial_settings(h2conn_t *conn)
{
    list_t *settings = make_list();
    size_t unpack_size = hpack_table_get_size(conn->input.hunpack);
    list_append(settings,
                h2frame_make_setting(H2FRAME_SETTINGS_HEADER_TABLE_SIZE,
                                     unpack_size));
    list_append(settings,
                h2frame_make_setting(H2FRAME_SETTINGS_ENABLE_PUSH, 0));
    list_append(settings,
                h2frame_make_setting(H2FRAME_SETTINGS_MAX_CONCURRENT_STREAMS,
                                     100));
    list_append(settings,
                h2frame_make_setting(H2FRAME_SETTINGS_INITIAL_WINDOW_SIZE,
                                     LOCAL_INITIAL_WINDOW));
    /* TODO: H2FRAME_SETTINGS_MAX_FRAME_SIZE */
    list_append(settings,
                h2frame_make_setting(H2FRAME_SETTINGS_MAX_HEADER_LIST_SIZE,
                                     conn->input.max_envelope_size));
    return settings;
}

FSTRACE_DECL(ASYNCHTTP_H2C_CONN_CREATE,
             "UID=%64u PTR=%p ASYNC=%p INPUT=%p CLIENT=%b MAX-ENV-SIZE=%z");

h2conn_t *open_h2connection(async_t *async, bytestream_1 input_stream,
                            bool is_client, size_t max_envelope_size)
{
    h2conn_t *conn = fsalloc(sizeof *conn);
    conn->async = async;
    conn->uid = fstrace_get_unique_id();
    FSTRACE(ASYNCHTTP_H2C_CONN_CREATE, conn->uid, conn, async,
            input_stream.obj, is_client, max_envelope_size);
    conn->state = CONN_ACTIVE;
    if (is_client) {
        conn->next_strid = 1;
        conn->next_peer_strid = 2;
    } else {
        conn->next_strid = 2;
        conn->next_peer_strid = 1;
    }
    conn->peer.header_table_size = 4096; /* RFC 7540 § 6.5.2 */
    conn->peer.enable_push = 1;
    conn->peer.max_concurrent_streams = 0x7fffffff;
    conn->peer.initial_window_size = 0xffff;
    conn->peer.max_frame_size = 0x4000;
    conn->peer.max_header_list_size = 0xffffffff;
    h2frame_yield_t *h2yield = open_h2frame_yield(async, input_stream);
    yield_1 yield = h2frame_yield_as_yield_1(h2yield);
    conn->input.decoder = open_h2frame_decoder(async, yield, 100000);
    action_1 probe_input_cb = { conn, (act_1) probe_input };
    h2frame_decoder_register_callback(conn->input.decoder, probe_input_cb);
    conn->input.max_envelope_size = max_envelope_size;
    conn->input.allow_push = false;
    conn->input.callback = NULL_ACTION_1;
    conn->input.hunpack = make_hpack_table();
    conn->input.pending_data = NULL;
    conn->input.pending_credit = 0;
    conn->output.stream = make_queuestream(async);
    conn->output.credit = 0xffff; /* RFC 7540 § 6.9.2 */
    stringstream_t *preface =
        open_stringstream(async, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    queuestream_enqueue(conn->output.stream,
                        stringstream_as_bytestream_1(preface));
    h2frame_t settings = {
        .frame_type = H2FRAME_TYPE_SETTINGS,
        .stream_id = 0,
        .settings = {
            .settings = initial_settings(conn)
        }
    };
    do_signal(conn, &settings);
    list_foreach(settings.settings.settings, (void *) fsfree, NULL);
    destroy_list(settings.settings.settings);
    action_1 probe_output_cb = { conn, (act_1) probe_output };
    conn->output.event = make_async_event(async, probe_output_cb);
    action_1 trigger = { conn->output.event, (act_1) async_event_trigger };
    queuestream_register_callback(conn->output.stream, trigger );
    conn->output.callback = conn->output.peer_closed_callback = NULL_ACTION_1;
    conn->output.hpack = make_hpack_table();
    conn->ops = make_hash_table(100, op_hash, op_diff);
    conn->top_level = make_avl_tree(op_cmp);
    conn->new_ops = make_list();
    return conn;
}

FSTRACE_DECL(ASYNCHTTP_H2C_ALLOW_PUSH_PASSIVE, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_ALLOW_PUSH_ALREADY, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2C_ALLOW_PUSH, "UID=%64u");

void h2conn_allow_push(h2conn_t *conn)
{
    assert(conn_is_client(conn));
    if (conn->state == CONN_PASSIVE) {
        FSTRACE(ASYNCHTTP_H2C_ALLOW_PUSH_PASSIVE, conn->uid);
        return;
    }
    assert(conn->state == CONN_ACTIVE);
    if (conn->input.allow_push) {
        FSTRACE(ASYNCHTTP_H2C_ALLOW_PUSH_ALREADY, conn->uid);
        return;
    }
    FSTRACE(ASYNCHTTP_H2C_ALLOW_PUSH, conn->uid);
    conn->input.allow_push = true;
    h2frame_t settings = {
        .frame_type = H2FRAME_TYPE_SETTINGS,
        .stream_id = 0,
        .settings = {
            .settings = make_list()
        }
    };
    list_append(settings.settings.settings,
                h2frame_make_setting(H2FRAME_SETTINGS_ENABLE_PUSH, 1));
    do_signal(conn, &settings);
    list_foreach(settings.settings.settings, (void *) fsfree, NULL);
    destroy_list(settings.settings.settings);
}

FSTRACE_DECL(ASYNCHTTP_H2C_CONN_CLOSE, "UID=%64u");

void h2conn_close(h2conn_t *conn)
{
    assert(conn->state != CONN_ZOMBIE);
    FSTRACE(ASYNCHTTP_H2C_CONN_CLOSE, conn->uid);
    issue_goaway(conn, H2FRAME_ERR_NO_ERROR);
    set_conn_state(conn, CONN_ZOMBIE);
    conn->input.callback = NULL_ACTION_1;
    if (conn->output.stream)
        queuestream_terminate(conn->output.stream);
    check_conn_pulse(conn);
}

bytestream_1 h2conn_get_output_stream(h2conn_t *conn)
{
    return (bytestream_1) { conn, &h2vt };
}

static bool can_initiate(h2conn_t *conn)
{
    switch (conn->state) {
        case CONN_ACTIVE:
            if (conn->next_strid >= 0x8000000) {
                errno = ENOSR;
                return false;
            }
            return true;
        case CONN_PASSIVE:
            errno = ECONNREFUSED;
            return false;
        case CONN_ERRORED:
            errno = EBADF;
            return false;
        default:
            assert(false);
    }
}

static h2op_t *make_request(h2conn_t *conn, const http_env_t *envelope,
                            ssize_t content_length, bytestream_1 content)
{
    assert(http_env_get_type(envelope) == HTTP_ENV_REQUEST);
    h2op_t *op = make_op(conn, conn->next_strid);
    conn->next_strid += 2;
    op->xmit.envelope = envelope;
    switch (content_length) {
        case HTTP_ENCODE_CHUNKED:
        case HTTP_ENCODE_RAW:
            op->xmit.content_length = HTTP_ENCODE_CHUNKED;
            break;
        default:
            assert(content_length >= 0);
            op->xmit.content_length = content_length;
    }
    op->xmit.content = content;
    op->xmit.state = XMIT_SENDING_DATA;
    op->recv.promise_envelope = NULL;
    op->recv.state = RECV_AWAITING_RESPONSE_HEADER;
    op->api.state = API_AWAITING_RESPONSE;
    (void) hash_table_put(conn->ops, &op->strid, op);
    return op;
}

static const char *trace_content_length(void *p)
{
    switch (*(ssize_t *) p) {
        case HTTP_ENCODE_CHUNKED:
            return "HTTP_ENCODE_CHUNKED";
        case HTTP_ENCODE_RAW:
            return "HTTP_ENCODE_RAW";
        default:
            return fstrace_signed_repr(*(ssize_t *) p);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_REQUEST_FAIL, "UID=%64u ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2C_REQUEST, "OPID=%s METHOD=%s PATH=%s LENGTH=%I");

h2op_t *h2conn_request(h2conn_t *conn, const http_env_t *envelope,
                       ssize_t content_length, bytestream_1 content)
{
    assert(conn_is_client(conn));
    assert(http_env_get_type(envelope) == HTTP_ENV_REQUEST);
    if (!can_initiate(conn)) {
        FSTRACE(ASYNCHTTP_H2C_REQUEST_FAIL, conn->uid);
        return NULL;
    }
    h2op_t *op = make_request(conn, envelope, content_length, content);
    FSTRACE(ASYNCHTTP_H2C_REQUEST, op->opid,
            http_env_get_method(envelope), http_env_get_path(envelope),
            trace_content_length, &content_length);
    adopt(op, NULL, false, DEFAULT_WEIGHT);
    issue_request(op);
    return op;
}

FSTRACE_DECL(ASYNCHTTP_H2C_REQUEST_DEPENDENT_FAIL, "PARENT=%s ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2C_REQUEST_DEPENDENT,
             "OPID=%s PARENT=%s METHOD=%s PATH=%s LENGTH=%I "
             "EXCL=%b WEIGHT=%u");

h2op_t *h2op_request(h2op_t *parent, const http_env_t *envelope,
                     ssize_t content_length, bytestream_1 content,
                     bool exclusive, unsigned weight)
{
    assert(conn_is_client(parent->conn));
    if (!can_initiate(parent->conn)) {
        FSTRACE(ASYNCHTTP_H2C_REQUEST_DEPENDENT_FAIL, parent->opid);
        return NULL;
    }
    h2op_t *op =
        make_request(parent->conn, envelope, content_length, content);
    FSTRACE(ASYNCHTTP_H2C_REQUEST_DEPENDENT, op->opid, parent->opid,
            http_env_get_method(envelope), http_env_get_path(envelope),
            trace_content_length, &content_length, exclusive, weight);
    adopt(op, parent, exclusive, weight);
    issue_request(op);
    return op;
}

static void issue_response(h2op_t *op)
{
    size_t remaining = op->conn->peer.max_header_list_size;
    supplier_t supplier = supply_headers;
    list_t *headers = make_list();
    char *status = charstr_printf("%d", http_env_get_code(op->xmit.envelope));
    resupply_headers(op, ":status", status, headers, &remaining, &supplier);
    issue_headers(op, headers, &remaining, &supplier);
}

FSTRACE_DECL(ASYNCHTTP_H2C_REPLY, "OPID=%s STATUS=%d LENGTH=%I");

void h2conn_reply(h2op_t *op, const http_env_t *envelope,
                  ssize_t content_length, bytestream_1 content)
{
    assert(!op_is_client(op));
    assert(op->state == OP_LIVE);
    assert(op->xmit.state == XMIT_PROCESSING);
    assert(http_env_get_type(envelope) == HTTP_ENV_RESPONSE);
    FSTRACE(ASYNCHTTP_H2C_REPLY, op->opid, http_env_get_code(envelope),
            trace_content_length, &content_length);
    set_xmit_state(op, XMIT_SENDING_DATA);
    op->xmit.envelope = envelope;
    switch (content_length) {
        case HTTP_ENCODE_CHUNKED:
        case HTTP_ENCODE_RAW:
            op->xmit.content_length = HTTP_ENCODE_CHUNKED;
            break;
        default:
            assert(content_length >= 0);
            op->xmit.content_length = content_length;
    }
    op->xmit.content = content;
    issue_response(op);
}

bool h2conn_can_push(h2conn_t *conn)
{
    assert(!conn_is_client(conn));
    return conn->peer.enable_push != 0;
}

static h2op_t *make_push(h2conn_t *conn, const http_env_t *response,
                         ssize_t content_length, bytestream_1 content)
{
    assert(http_env_get_type(response) == HTTP_ENV_RESPONSE);
    h2op_t *op = make_op(conn, conn->next_strid);
    conn->next_strid += 2;
    op->xmit.envelope = response;
    op->xmit.content_length = content_length;
    op->xmit.content = content;
    op->xmit.state = XMIT_SENDING_DATA;
    op->recv.promise_envelope = NULL;
    op->recv.state = RECV_FINISHED;
    op->api.state = API_CONTENT_CLOSED;
    (void) hash_table_put(conn->ops, &op->strid, op);
    return op;
}

static void issue_push(h2op_t *op, const http_env_t *promise)
{
    assert(http_env_get_type(promise) == HTTP_ENV_REQUEST);
    size_t remaining;
    supplier_t supplier = supply_promise;
    list_t *headers =
        initial_request_headers(op, promise, &remaining, &supplier);
    issue_headers(op, headers, &remaining, &supplier);
}

FSTRACE_DECL(ASYNCHTTP_H2C_PUSH_NOT_ALLOWED, "UID=%64u ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2C_PUSH,
             "OPID=%s PARENT=%s METHOD=%s PATH=%s STATUS=%d LENGTH=%I "
             "EXCL=%b WEIGHT=%u");

h2op_t *h2op_push(h2op_t *parent, const http_env_t *promise,
                  const http_env_t *response,
                  ssize_t content_length, bytestream_1 content,
                  bool exclusive, unsigned weight)
{
    h2conn_t *conn = parent->conn;
    assert(!conn_is_client(conn));
    if (!h2conn_can_push(conn)) {
        errno = EPERM;
        FSTRACE(ASYNCHTTP_H2C_PUSH_NOT_ALLOWED, conn->uid);
        return NULL;
    }
    if (!can_initiate(conn)) {
        FSTRACE(ASYNCHTTP_H2C_PUSH_NOT_ALLOWED, conn->uid);
        return NULL;
    }
    h2op_t *op = make_push(conn, response, content_length, content);
    FSTRACE(ASYNCHTTP_H2C_PUSH, op->opid, parent->opid,
            http_env_get_method(promise), http_env_get_path(promise),
            http_env_get_code(response), trace_content_length, &content_length,
            exclusive, weight);
    adopt(op, parent, exclusive, weight);
    issue_push(op, promise);
    issue_response(op);
    if (exclusive || weight != DEFAULT_WEIGHT) {
        h2frame_t priority = {
            .frame_type = H2FRAME_TYPE_PRIORITY,
            .stream_id = op->strid,
            .priority = {
                .exclusive = exclusive,
                .dependency = parent->strid,
                .weight = weight,
            }
        };
        do_signal(conn, &priority);
    }
    return op;
}

FSTRACE_DECL(ASYNCHTTP_H2C_RECEIVE_REQUEST_FAIL, "UID=%64u ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2C_RECEIVE_REQUEST, "OPID=%s METHOD=%s PATH=%s");

h2op_t *h2conn_receive_request(h2conn_t *conn, const http_env_t **request)
{
    assert(!conn_is_client(conn));
    switch (conn->state) {
        case CONN_ERRORED:
            errno = ENOTCONN;
            FSTRACE(ASYNCHTTP_H2C_RECEIVE_REQUEST_FAIL, conn->uid);
            return NULL;
        case CONN_ZOMBIE:
            errno = EBADF;
            FSTRACE(ASYNCHTTP_H2C_RECEIVE_REQUEST_FAIL, conn->uid);
            return NULL;
        default:
            if (list_empty(conn->new_ops)) {
                errno = EAGAIN;
                FSTRACE(ASYNCHTTP_H2C_RECEIVE_REQUEST_FAIL, conn->uid);
                return NULL;
            }
    }
    h2op_t *op = (h2op_t *) list_pop_first(conn->new_ops);
    FSTRACE(ASYNCHTTP_H2C_RECEIVE_REQUEST, op->opid,
            http_env_get_method(op->recv.envelope),
            http_env_get_path(op->recv.envelope));
    *request = op->recv.envelope;
    set_api_state(op, API_ENVELOPE_PASSED);
    return op;
}

static bool alive_and_well(h2op_t *op)
{
    switch (op->state) {
        case OP_ERRORED:
            errno = op->err;
            return false;
        case OP_ZOMBIE:
            errno = EBADF;
            return false;
        default:
            ;
    }
    switch (op->conn->state) {
        case CONN_ACTIVE:
        case CONN_PASSIVE:
            return true;
        case CONN_ERRORED:
            errno = EBADF;
            return false;
        default:
            assert(false);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_RECEIVE_RESPONSE_FAIL, "OPID=%s ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2C_RECEIVE_RESPONSE, "OPID=%s STATUS=%d");

const http_env_t *h2op_receive_response(h2op_t *op)
{
    assert(op_is_client(op));
    if (!alive_and_well(op)) {
        FSTRACE(ASYNCHTTP_H2C_RECEIVE_RESPONSE_FAIL, op->opid);
        return NULL;
    }
    switch (op->recv.state) {
        case RECV_AWAITING_RESPONSE_HEADER:
        case RECV_AWAITING_CONTINUATION_HEADER:
        case RECV_AWAITING_FINAL_CONTINUATION_HEADER:
        case RECV_AWAITING_CONTINUATION_TRAILER:
            errno = EAGAIN;
            FSTRACE(ASYNCHTTP_H2C_RECEIVE_RESPONSE_FAIL, op->opid);
            return NULL;
        case RECV_AWAITING_DATA:
        case RECV_FINISHED:
            switch (op->api.state) {
                case API_AWAITING_PROMISE:
                    assert(false);
                case API_AWAITING_RESPONSE:
                    FSTRACE(ASYNCHTTP_H2C_RECEIVE_RESPONSE, op->opid,
                            http_env_get_code(op->recv.envelope));
                    set_api_state(op, API_ENVELOPE_PASSED);
                    return op->recv.envelope;
                default:
                    errno = EAGAIN;
                    FSTRACE(ASYNCHTTP_H2C_RECEIVE_RESPONSE_FAIL, op->opid);
                    return NULL;
            }
        default:
            assert(false);
    }
}

size_t cap_readable(h2op_t *op, size_t count)
{
    if (op->recv.space_remaining > op->recv.read_cursor) {
        if (op->recv.space_remaining + count > LOCAL_INITIAL_WINDOW)
            return LOCAL_INITIAL_WINDOW - op->recv.space_remaining;
        return count;
    }
    if (op->recv.read_cursor + count > LOCAL_INITIAL_WINDOW)
        return LOCAL_INITIAL_WINDOW - op->recv.read_cursor;
    return count;
}

static ssize_t _read_body_content(void *obj, void *buf, size_t count)
{
    if (count == 0)
        return 0;
    h2op_t *op = obj;
    if (!alive_and_well(op))
        return -1;
    count = cap_readable(op, count);
    switch (op->recv.state) {
        case RECV_AWAITING_DATA:
        case RECV_AWAITING_CONTINUATION_TRAILER:
            assert (op->api.state == API_CONTENT_PASSED);
            if (count == 0) {
                errno = EAGAIN;
                return -1;
            }
            break;
        case RECV_FINISHED:
            if (op->api.state == API_CONTENT_EXHAUSTED)
                return 0;
            assert (op->api.state == API_CONTENT_PASSED);
            if (count == 0) {
                set_api_state(op, API_CONTENT_EXHAUSTED);
                return 0;
            }
            break;
        default:
            assert(false);
    }
    memcpy(buf, op->recv.window + op->recv.read_cursor, count);
    op->recv.read_cursor += count;
    if (op->recv.read_cursor == LOCAL_INITIAL_WINDOW)
        op->recv.read_cursor = 0;
    op->recv.space_remaining += count;
    award_op_credit(op, count);
    return count;
}

FSTRACE_DECL(ASYNCHTTP_H2C_BODY_READ, "OPID=%s WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2C_BODY_READ_DUMP, "OPID=%s DATA=%B");

static ssize_t read_body_content(void *obj, void *buf, size_t count)
{
    h2op_t *op = obj;
    ssize_t n = _read_body_content(op, buf, count);
    FSTRACE(ASYNCHTTP_H2C_BODY_READ, op->opid, count, n);
    FSTRACE(ASYNCHTTP_H2C_BODY_READ_DUMP, op->opid, buf, n);
    return n;
}

FSTRACE_DECL(ASYNCHTTP_H2C_BODY_CLOSE, "OPID=%s");

static void close_body_content(void *obj)
{
    h2op_t *op = obj;
    FSTRACE(ASYNCHTTP_H2C_BODY_CLOSE, op->opid);
    if (op->state != OP_LIVE) {
        set_api_state(op, API_CONTENT_CLOSED);
        check_op_pulse(op);
        return;
    }
    switch (op->recv.state) {
        case RECV_AWAITING_DATA:
        case RECV_AWAITING_CONTINUATION_TRAILER:
        case RECV_FINISHED:
            set_api_state(op, API_CONTENT_CLOSED);
            do_input(op->conn);
            break;
        default:
            assert(false);
    }
}

void register_body_content_callback(void *obj, action_1 action)
{
    ((h2op_t *) obj)->recv.content_callback = action;
}

void unregister_body_content_callback(void *obj)
{
    ((h2op_t *) obj)->recv.content_callback = NULL_ACTION_1;
}

static struct bytestream_1_vt h2body_vt = {
    .read = read_body_content,
    .close = close_body_content,
    .register_callback = register_body_content_callback,
    .unregister_callback = unregister_body_content_callback,
};

FSTRACE_DECL(ASYNCHTTP_H2C_GET_CONTENT_FAIL, "OPID=%s ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2C_GET_CONTENT, "OPID=%s LENGTH=%I");

bool h2op_get_content(h2op_t *op, ssize_t content_length,
                      bytestream_1 *content)
{
    assert(op_is_client(op));
    if (!alive_and_well(op)) {
        FSTRACE(ASYNCHTTP_H2C_GET_CONTENT_FAIL, op->opid);
        return false;
    }
    switch (op->recv.state) {
        case RECV_AWAITING_RESPONSE_HEADER:
        case RECV_AWAITING_CONTINUATION_HEADER:
        case RECV_AWAITING_FINAL_CONTINUATION_HEADER:
            errno = EAGAIN;
            FSTRACE(ASYNCHTTP_H2C_GET_CONTENT_FAIL, op->opid);
            return false;
        case RECV_AWAITING_DATA:
        case RECV_AWAITING_CONTINUATION_TRAILER:
        case RECV_FINISHED:
            switch (op->api.state) {
                case API_ENVELOPE_PASSED:
                    FSTRACE(ASYNCHTTP_H2C_GET_CONTENT, op->opid,
                            trace_content_length, &content_length);
                    set_api_state(op, API_CONTENT_PASSED);
                    op->recv.content_callback = NULL_ACTION_1;
                    content->obj = op;
                    content->vt = &h2body_vt;
                    return true;
                default:
                    errno = EAGAIN;
                    FSTRACE(ASYNCHTTP_H2C_GET_CONTENT_FAIL, op->opid);
                    return false;
            }            
        default:
            assert(false);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2C_RECEIVE_PROMISE_FAIL, "UID=%64u ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2C_RECEIVE_PROMISE,
             "OPID=%s METHOD=%s PATH=%s STATUS=%d");

h2op_t *h2conn_receive_promise(h2conn_t *conn, const http_env_t **promise,
                               const http_env_t **response)
{
    assert(conn_is_client(conn));
    switch (conn->state) {
        case CONN_ERRORED:
            errno = ENOTCONN;
            FSTRACE(ASYNCHTTP_H2C_RECEIVE_PROMISE_FAIL, conn->uid);
            return NULL;
        case CONN_ZOMBIE:
            errno = EBADF;
            FSTRACE(ASYNCHTTP_H2C_RECEIVE_PROMISE_FAIL, conn->uid);
            return NULL;
        default:
            if (list_empty(conn->new_ops)) {
                errno = EAGAIN;
                FSTRACE(ASYNCHTTP_H2C_RECEIVE_PROMISE_FAIL, conn->uid);
                return NULL;
            }
    }
    h2op_t *op = (h2op_t *) list_pop_first(conn->new_ops);
    *promise = op->recv.promise_envelope;
    *response = op->recv.envelope;
    FSTRACE(ASYNCHTTP_H2C_RECEIVE_PROMISE, op->opid,
            http_env_get_method(*promise),
            http_env_get_path(*promise),
            http_env_get_code(*response));
    set_api_state(op, API_ENVELOPE_PASSED);
    return op;
}

void h2op_register_callback(h2op_t *op, action_1 action)
{
    op->recv.callback = action;
}

void h2op_unregister_callback(h2op_t *op)
{
    op->recv.callback = NULL_ACTION_1;
}

void h2conn_register_callback(h2conn_t *conn, action_1 action)
{
    conn->input.callback = action;
}

void h2conn_unregister_callback(h2conn_t *conn)
{
    conn->input.callback = NULL_ACTION_1;
}

void h2conn_register_peer_closed_callback(h2conn_t *conn, action_1 action)
{
    conn->output.peer_closed_callback = action;
}

void h2conn_unregister_peer_closed_callback(h2conn_t *conn)
{
    conn->output.peer_closed_callback = NULL_ACTION_1;
}

static void free_envelope(http_env_t *envelope)
{
    http_env_iter_t *iter = NULL;
    for (;;) {
        const char *name, *value;
        iter = http_env_get_next_header(envelope, iter, &name, &value);
        if (!iter)
            break;
        fsfree((char *) name);
        fsfree((char *) value);
    }
    destroy_http_env(envelope);
}

FSTRACE_DECL(ASYNCHTTP_H2C_OP_CLOSE, "OPID=%s");

void h2op_close(h2op_t *op)
{
    assert(op->state != OP_ZOMBIE);
    FSTRACE(ASYNCHTTP_H2C_OP_CLOSE, op->opid);
    set_op_state(op, OP_ZOMBIE);
    if (op->xmit.state != XMIT_FINISHED) {
        bytestream_1_close(op->xmit.content);
        set_xmit_state(op, XMIT_FINISHED);
    }
    if (op->api.state != API_CONTENT_CLOSED)
        reset_stream(op, H2FRAME_ERR_STREAM_CLOSED);
    if (op->recv.envelope)
        free_envelope(op->recv.envelope);
    if (op->recv.promise_envelope) {
        fsfree((char *) http_env_get_method(op->recv.promise_envelope));
        fsfree((char *) http_env_get_path(op->recv.promise_envelope));
        free_envelope(op->recv.promise_envelope);
    }
    fsfree(op->recv.window);
    destroy_async_event(op->api.event);
    hash_table_remove(op->conn->ops,
                      hash_table_get(op->conn->ops, &op->strid));
    /* Note: even zombie operations are kept in the dependency tree to
     * ensure proper priority calculation. */
    check_op_pulse(op);
}
