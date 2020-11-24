#include "http_op_jockey.h"

#include <async/drystream.h>
#include <fstrace.h>

#include <errno.h>

struct http_op_response {
    const http_env_t *envelope;
    byte_array_t *body;
};

const http_env_t *http_op_response_get_envelope(http_op_response_t *response)
{
    return response->envelope;
}

byte_array_t *http_op_response_release_body(http_op_response_t *response)
{
    byte_array_t *body = response->body;
    response->body = NULL;
    return body;
}

typedef enum {
    HTTP_OP_JOCKEY_READING_HEADERS,
    HTTP_OP_JOCKEY_READING_BODY,
    HTTP_OP_JOCKEY_DONE,
    HTTP_OP_JOCKEY_FAILED,
    HTTP_OP_JOCKEY_ZOMBIE,
} http_op_jockey_state_t;

struct http_op_jockey {
    async_t *async;
    http_op_t *op;
    uint64_t uid;
    http_op_jockey_state_t state;
    int error;
    bytestream_1 content;
    http_op_response_t response;
    action_1 callback;
};

FSTRACE_DECL(ASYNCHTTP_OP_JOCKEY_CREATE, "UID=%64u OP=%p MAX-BODY-SIZE=%z");

http_op_jockey_t *make_http_op_jockey(async_t *async,
                                      http_op_t *op,
                                      size_t max_body_size)
{
    http_op_jockey_t *jockey = fscalloc(1, sizeof *jockey);
    jockey->async = async;
    jockey->uid = fstrace_get_unique_id();
    jockey->state = HTTP_OP_JOCKEY_READING_HEADERS;
    jockey->op = op;
    jockey->content = drystream;
    jockey->response.body = make_byte_array(max_body_size);
    FSTRACE(ASYNCHTTP_OP_JOCKEY_CREATE, jockey->uid, op, max_body_size);
    return jockey;
}

FSTRACE_DECL(ASYNCHTTP_OP_JOCKEY_CLOSE, "UID=%64u");

void http_op_jockey_close(http_op_jockey_t *jockey)
{
    FSTRACE(ASYNCHTTP_OP_JOCKEY_CLOSE, jockey->uid);
    if (jockey->response.body)
        destroy_byte_array(jockey->response.body);
    bytestream_1_close(jockey->content);
    http_op_close(jockey->op);
    jockey->state = HTTP_OP_JOCKEY_ZOMBIE;
    async_wound(jockey->async, jockey);
}

FSTRACE_DECL(ASYNCHTTP_OP_JOCKEY_REGISTER, "UID=%64u OBJ=%p ACT=%p");

void http_op_jockey_register_callback(http_op_jockey_t *jockey, action_1 action)
{
    FSTRACE(ASYNCHTTP_OP_JOCKEY_REGISTER, jockey->uid, action.obj, action.act);
    jockey->callback = action;
    http_op_register_callback(jockey->op, action);
    bytestream_1_register_callback(jockey->content, action);
}

FSTRACE_DECL(ASYNCHTTP_OP_JOCKEY_UNREGISTER, "UID=%64u");

void http_op_jockey_unregister_callback(http_op_jockey_t *jockey)
{
    FSTRACE(ASYNCHTTP_OP_JOCKEY_UNREGISTER, jockey->uid);
    jockey->callback = NULL_ACTION_1;
    http_op_unregister_callback(jockey->op);
    bytestream_1_unregister_callback(jockey->content);
}

static const char *trace_state(void *state)
{
    switch (*(http_op_jockey_state_t *) state) {
        case HTTP_OP_JOCKEY_READING_HEADERS:
            return "HTTP_OP_JOCKEY_READING_HEADERS";
        case HTTP_OP_JOCKEY_READING_BODY:
            return "HTTP_OP_JOCKEY_READING_BODY";
        case HTTP_OP_JOCKEY_DONE:
            return "HTTP_OP_JOCKEY_DONE";
        case HTTP_OP_JOCKEY_FAILED:
            return "HTTP_OP_JOCKEY_FAILED";
        case HTTP_OP_JOCKEY_ZOMBIE:
            return "HTTP_OP_JOCKEY_ZOMBIE";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCHTTP_OP_JOCKEY_SET_STATE, "UID=%64u OLD=%I NEW=%I");

static void set_state(http_op_jockey_t *jockey, http_op_jockey_state_t state)
{
    FSTRACE(ASYNCHTTP_OP_JOCKEY_SET_STATE,
            jockey->uid,
            trace_state,
            &jockey->state,
            trace_state,
            &state);
    jockey->state = state;
}

static ssize_t read_frame(void *obj, void *buf, size_t count)
{
    bytestream_1 *stream = obj;
    return bytestream_1_read(*stream, buf, count);
}

static void probe_body(http_op_jockey_t *jockey)
{
    ssize_t count = byte_array_append_stream(jockey->response.body,
                                             read_frame,
                                             &jockey->content,
                                             2048);
    if (count < 0 && errno == ENOSPC) {
        char c;
        count = bytestream_1_read(jockey->content, &c, 1);
        if (count > 0) {
            jockey->error = EMSGSIZE;
            set_state(jockey, HTTP_OP_JOCKEY_FAILED);
            return;
        }
    }
    if (count < 0) {
        if (errno != EAGAIN) {
            jockey->error = errno;
            set_state(jockey, HTTP_OP_JOCKEY_FAILED);
        }
        return;
    }
    if (count == 0) {
        set_state(jockey, HTTP_OP_JOCKEY_DONE);
        return;
    }
    async_execute(jockey->async, jockey->callback);
    errno = EAGAIN;
}

FSTRACE_DECL(ASYNCHTTP_OP_JOCKEY_GOT_RESPONSE,
             "UID=%64u RESP=%d EXPLANATION=%s");

static void probe_headers(http_op_jockey_t *jockey)
{
    errno = 0;
    const http_env_t *envelope = http_op_receive_response(jockey->op);
    if (!envelope) {
        if (errno != EAGAIN) {
            jockey->error = errno;
            set_state(jockey, HTTP_OP_JOCKEY_FAILED);
        }
        return;
    }
    FSTRACE(ASYNCHTTP_OP_JOCKEY_GOT_RESPONSE,
            jockey->uid,
            http_env_get_code(envelope),
            http_env_get_explanation(envelope));
    if (http_op_get_response_content(jockey->op, &jockey->content) < 0) {
        jockey->error = errno;
        set_state(jockey, HTTP_OP_JOCKEY_FAILED);
        return;
    }
    jockey->response.envelope = envelope;
    set_state(jockey, HTTP_OP_JOCKEY_READING_BODY);
    bytestream_1_register_callback(jockey->content, jockey->callback);
    async_execute(jockey->async, jockey->callback);
    errno = EAGAIN;
}

FSTRACE_DECL(ASYNCHTTP_OP_JOCKEY_RECEIVE_RESP, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_JOCKEY_RECEIVE_RESP_FAIL, "UID=%64u ERROR=%e");

http_op_response_t *http_op_jockey_receive_response(http_op_jockey_t *jockey)
{
    switch (jockey->state) {
        case HTTP_OP_JOCKEY_READING_HEADERS:
            probe_headers(jockey);
            break;
        case HTTP_OP_JOCKEY_READING_BODY:
            probe_body(jockey);
            break;
        default:
            break;
    }
    switch (jockey->state) {
        case HTTP_OP_JOCKEY_READING_HEADERS:
        case HTTP_OP_JOCKEY_READING_BODY:
            FSTRACE(ASYNCHTTP_OP_JOCKEY_RECEIVE_RESP_FAIL, jockey->uid);
            return NULL;
        case HTTP_OP_JOCKEY_FAILED:
            errno = jockey->error;
            FSTRACE(ASYNCHTTP_OP_JOCKEY_RECEIVE_RESP_FAIL, jockey->uid);
            return NULL;
        case HTTP_OP_JOCKEY_DONE:
            FSTRACE(ASYNCHTTP_OP_JOCKEY_RECEIVE_RESP, jockey->uid);
            return &jockey->response;
        default:
            errno = EINVAL;
            return NULL;
    }
}
