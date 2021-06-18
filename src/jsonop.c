#include "jsonop.h"

#include <assert.h>
#include <errno.h>

#include <async/jsondecoder.h>
#include <async/jsonencoder.h>
#include <fsdyn/charstr.h>
#include <fsdyn/fsalloc.h>
#include <fstrace.h>

#include "asynchttp_version.h"
#include "client.h"

typedef enum {
    JSONOP_REQUESTED,
    JSONOP_READING,
    JSONOP_DONE_200,   /* received 200 OK and parsed the JSON response */
    JSONOP_DONE_OTHER, /* received something else; content stream available */
    JSONOP_FAILED,
    JSONOP_ZOMBIE
} jsonop_state_t;

struct jsonop {
    async_t *async;
    uint64_t uid;
    jsonop_state_t state;
    http_op_t *http_op;
    action_1 callback;
    jsondecoder_t *content;             /* JSONOP_READING, JSONOP_DONE_200 */
    const http_env_t *response_headers; /* JSONOP_READING, JSONOP_DONE_* */
    json_thing_t *response_body;        /* JSONOP_DONE_200 */
    /* At the moment, we don't give the application access to
     * response_stream. In the end, we can, but note that we need to
     * decide who closes the stream. */
    bytestream_1 response_stream; /* JSONOP_DONE_OTHER */
    int err;                      /* JSONOP_FAILED */
};

FSTRACE_DECL(ASYNCHTTP_JSONOP_REGISTER, "UID=%64u OBJ=%p ACT=%p");

void jsonop_register_callback(jsonop_t *op, action_1 action)
{
    FSTRACE(ASYNCHTTP_JSONOP_REGISTER, op->uid, action.obj, action.act);
    op->callback = action;
    http_op_register_callback(op->http_op, action);
    if (op->state == JSONOP_READING)
        jsondecoder_register_callback(op->content, op->callback);
}

FSTRACE_DECL(ASYNCHTTP_JSONOP_UNREGISTER, "UID=%64u");

void jsonop_unregister_callback(jsonop_t *op)
{
    FSTRACE(ASYNCHTTP_JSONOP_UNREGISTER, op->uid);
    op->callback = NULL_ACTION_1;
    http_op_unregister_callback(op->http_op);
    if (op->state == JSONOP_READING)
        jsondecoder_unregister_callback(op->content);
}

FSTRACE_DECL(ASYNCHTTP_JSONOP_CREATE,
             "UID=%64u PTR=%p ASYNC=%p CLIENT=%p URI=%s ENCODER=%p");

jsonop_t *jsonop_make_request(async_t *async, http_client_t *client,
                              const char *uri, json_thing_t *request_body)
{
    http_op_t *http_op = http_client_make_request(client, "POST", uri);
    if (!http_op)
        return NULL;
    jsonop_t *op = fsalloc(sizeof *op);
    op->async = async;
    op->uid = fstrace_get_unique_id();
    op->callback = NULL_ACTION_1;
    op->http_op = http_op;
    http_env_add_header(jsonop_get_request_envelope(op), "Content-Type",
                        "application/json");
    jsonencoder_t *encoder = json_encode(op->async, request_body);
    FSTRACE(ASYNCHTTP_JSONOP_CREATE, op->uid, op, async, client, uri, encoder);
    ssize_t size = jsonencoder_size(encoder);
    assert(size >= 0);
    http_op_set_content(op->http_op, size,
                        jsonencoder_as_bytestream_1(encoder));
    op->state = JSONOP_REQUESTED;
    return op;
}

FSTRACE_DECL(ASYNCHTTP_JSONOP_SET_TIMEOUT, "UID=%64u DURATION=%64d");

void jsonop_set_timeout(jsonop_t *op, int64_t max_duration)
{
    FSTRACE(ASYNCHTTP_JSONOP_SET_TIMEOUT, op->uid, max_duration);
    http_op_set_timeout(op->http_op, max_duration);
}

FSTRACE_DECL(ASYNCHTTP_JSONOP_CANCEL_TIMEOUT, "UID=%64u");

void jsonop_cancel_timeout(jsonop_t *op)
{
    FSTRACE(ASYNCHTTP_JSONOP_CANCEL_TIMEOUT, op->uid);
    http_op_cancel_timeout(op->http_op);
}

FSTRACE_DECL(ASYNCHTTP_JSONOP_CREATE_GET,
             "UID=%64u PTR=%p ASYNC=%p CLIENT=%p URI=%s");

jsonop_t *jsonop_make_get_request(async_t *async, http_client_t *client,
                                  const char *uri)
{
    http_op_t *http_op = http_client_make_request(client, "GET", uri);
    if (!http_op)
        return NULL;
    jsonop_t *op = fsalloc(sizeof *op);
    op->async = async;
    op->uid = fstrace_get_unique_id();
    op->callback = NULL_ACTION_1;
    op->http_op = http_op;
    FSTRACE(ASYNCHTTP_JSONOP_CREATE_GET, op->uid, op, async, client, uri);
    op->state = JSONOP_REQUESTED;
    return op;
}

http_env_t *jsonop_get_request_envelope(jsonop_t *op)
{
    return http_op_get_request_envelope(op->http_op);
}

static const char *trace_state(void *pstate)
{
    switch (*(jsonop_state_t *) pstate) {
        case JSONOP_REQUESTED:
            return "JSONOP_REQUESTED";
        case JSONOP_READING:
            return "JSONOP_READING";
        case JSONOP_DONE_200:
            return "JSONOP_DONE_200";
        case JSONOP_DONE_OTHER:
            return "JSONOP_DONE_OTHER";
        case JSONOP_FAILED:
            return "JSONOP_FAILED";
        case JSONOP_ZOMBIE:
            return "JSONOP_ZOMBIE";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCHTTP_JSONOP_SET_STATE, "UID=%64u OLD=%I NEW=%I");

static void set_op_state(jsonop_t *op, jsonop_state_t state)
{
    FSTRACE(ASYNCHTTP_JSONOP_SET_STATE, op->uid, trace_state, &op->state,
            trace_state, &state);
    op->state = state;
}

static bool jockey_requested(jsonop_t *op)
{
    op->response_headers = http_op_receive_response(op->http_op);
    if (!op->response_headers) {
        if (errno != EAGAIN) {
            op->err = errno;
            set_op_state(op, JSONOP_FAILED);
        }
        return false;
    }
    http_op_get_response_content(op->http_op, &op->response_stream);
    int response_code = http_env_get_code(op->response_headers);
    if (response_code != 200) {
        set_op_state(op, JSONOP_DONE_OTHER);
        return true;
    }
    op->content = open_jsondecoder(op->async, op->response_stream, 1000000);
    jsondecoder_register_callback(op->content, op->callback);
    set_op_state(op, JSONOP_READING);
    return true;
}

static bool jockey_reading(jsonop_t *op)
{
    op->response_body = jsondecoder_receive(op->content);
    if (!op->response_body)
        return false;
    set_op_state(op, JSONOP_DONE_200);
    return true;
}

static void jockey_request(jsonop_t *op)
{
    for (;;)
        switch (op->state) {
            case JSONOP_REQUESTED:
                if (!jockey_requested(op))
                    return;
                break;
            case JSONOP_READING:
                if (!jockey_reading(op))
                    return;
                break;
            case JSONOP_DONE_200:
            case JSONOP_DONE_OTHER:
            case JSONOP_FAILED:
                return;
            default:
                assert(false);
        }
}

FSTRACE_DECL(ASYNCHTTP_JSONOP_RESPONSE_BODY, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_JSONOP_RESPONSE_BODY_FAIL, "UID=%64u ERRNO=%e");

json_thing_t *jsonop_response_body(jsonop_t *op)
{
    jockey_request(op);
    switch (op->state) {
        case JSONOP_DONE_200:
            FSTRACE(ASYNCHTTP_JSONOP_RESPONSE_BODY, op->uid);
            return op->response_body;
        case JSONOP_FAILED:
            errno = op->err;
            FSTRACE(ASYNCHTTP_JSONOP_RESPONSE_BODY_FAIL, op->uid);
            return NULL;
        case JSONOP_DONE_OTHER:
        case JSONOP_ZOMBIE:
            assert(false);
        default:
            /* errno has been set by jockey_request() */
            FSTRACE(ASYNCHTTP_JSONOP_RESPONSE_BODY_FAIL, op->uid);
            return NULL;
    }
}

FSTRACE_DECL(ASYNCHTTP_JSONOP_RESPONSE_HEADERS, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_JSONOP_RESPONSE_HEADERS_FAIL, "UID=%64u ERRNO=%e");

const http_env_t *jsonop_response_headers(jsonop_t *op)
{
    jockey_request(op);
    switch (op->state) {
        case JSONOP_DONE_200:
        case JSONOP_DONE_OTHER:
            FSTRACE(ASYNCHTTP_JSONOP_RESPONSE_HEADERS, op->uid);
            return op->response_headers;
        case JSONOP_FAILED:
            errno = op->err;
            FSTRACE(ASYNCHTTP_JSONOP_RESPONSE_HEADERS_FAIL, op->uid);
            return NULL;
        case JSONOP_ZOMBIE:
            assert(false);
        default:
            /* errno has been set by jockey_request() */
            FSTRACE(ASYNCHTTP_JSONOP_RESPONSE_HEADERS_FAIL, op->uid);
            return NULL;
    }
}

FSTRACE_DECL(ASYNCHTTP_JSONOP_RESPONSE_CODE, "UID=%64u CODE=%d");
FSTRACE_DECL(ASYNCHTTP_JSONOP_RESPONSE_CODE_FAIL, "UID=%64u ERRNO=%e");

int jsonop_response_code(jsonop_t *op)
{
    const http_env_t *headers = jsonop_response_headers(op);
    if (!headers) {
        FSTRACE(ASYNCHTTP_JSONOP_RESPONSE_CODE_FAIL, op->uid);
        return -1;
    }
    int code = http_env_get_code(headers);
    FSTRACE(ASYNCHTTP_JSONOP_RESPONSE_CODE, op->uid, code);
    return code;
}

FSTRACE_DECL(ASYNCHTTP_JSONOP_CLOSE, "UID=%64u");

void jsonop_close(jsonop_t *op)
{
    FSTRACE(ASYNCHTTP_JSONOP_CLOSE, op->uid);
    switch (op->state) {
        case JSONOP_FAILED:
        case JSONOP_REQUESTED:
            break;
        case JSONOP_DONE_200:
            jsondecoder_close(op->content);
            json_destroy_thing(op->response_body);
            break;
        case JSONOP_DONE_OTHER:
            bytestream_1_close(op->response_stream);
            break;
        case JSONOP_READING:
            jsondecoder_close(op->content);
            break;
        default:
            assert(false);
    }
    http_op_close(op->http_op);
    set_op_state(op, JSONOP_ZOMBIE);
    async_wound(op->async, op);
}
