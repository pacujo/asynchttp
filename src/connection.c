#include "connection.h"

#include <errno.h>

#include <fsdyn/fsalloc.h>
#include <fstrace.h>

#include "asynchttp_version.h"
#include "decoder.h"
#include "framer.h"

struct http_conn {
    async_t *async;
    uint64_t uid;
    http_framer_t *framer;
    action_1 peer_closed_callback;
    http_decoder_t *decoder;
};

static void farewell_connection(http_conn_t *conn)
{
    conn->framer = NULL;
    async_execute(conn->async, conn->peer_closed_callback);
}

FSTRACE_DECL(ASYNCHTTP_CONN_CREATE,
             "UID=%64u PTR=%p ASYNC=%p INPUT=%p MAX-ENV-SIZE=%z "
             "FRAMER=%p DECODER=%p");

http_conn_t *open_http_connection(async_t *async, bytestream_1 input_stream,
                                  size_t max_envelope_size)
{
    http_conn_t *conn = fsalloc(sizeof *conn);
    conn->async = async;
    conn->uid = fstrace_get_unique_id();
    conn->framer = open_http_framer(async);
    action_1 farewell_cb = { conn, (act_1) farewell_connection };
    http_framer_register_farewell_callback(conn->framer, farewell_cb);
    conn->peer_closed_callback = NULL_ACTION_1;
    conn->decoder = open_http_decoder(async, input_stream, max_envelope_size);
    FSTRACE(ASYNCHTTP_CONN_CREATE, conn->uid, conn, async, input_stream.obj,
            max_envelope_size, conn->framer, conn->decoder);
    return conn;
}

FSTRACE_DECL(ASYNCHTTP_CONN_CLOSE, "UID=%64u");

void http_close(http_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_CONN_CLOSE, conn->uid);
    if (conn->framer)
        http_framer_unregister_farewell_callback(conn->framer);
    /* It is up to the caller to make sure the framer gets closed by
     * closing its output stream. */
    http_decoder_close(conn->decoder);
    async_wound(conn->async, conn);
    conn->framer = NULL;
    conn->async = NULL;
}

FSTRACE_DECL(ASYNCHTTP_CONN_REGISTER_PEER, "UID=%64u OBJ=%p ACT=%p");

void http_register_peer_closed_callback(http_conn_t *conn, action_1 action)
{
    FSTRACE(ASYNCHTTP_CONN_REGISTER_PEER, conn->uid, action.obj, action.act);
    conn->peer_closed_callback = action;
}

FSTRACE_DECL(ASYNCHTTP_CONN_UNREGISTER_PEER, "UID=%64u");

void http_unregister_peer_closed_callback(http_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_CONN_UNREGISTER_PEER, conn->uid);
    conn->peer_closed_callback = NULL_ACTION_1;
}

bytestream_1 http_get_output_stream(http_conn_t *conn)
{
    return http_framer_get_output_stream(conn->framer);
}

FSTRACE_DECL(ASYNCHTTP_CONN_SEND, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_CONN_SEND_DISCONNECTED, "UID=%64u");

void http_send(http_conn_t *conn, const http_env_t *envelope,
               ssize_t content_length, bytestream_1 content)
{
    if (!conn->framer) {
        FSTRACE(ASYNCHTTP_CONN_SEND_DISCONNECTED, conn->uid);
        bytestream_1_close_relaxed(conn->async, content);
        return;
    }
    FSTRACE(ASYNCHTTP_CONN_SEND, conn->uid);
    http_framer_enqueue(conn->framer, envelope, content_length, content);
}

FSTRACE_DECL(ASYNCHTTP_CONN_TERMINATE, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_CONN_TERMINATE_DISCONNECTED, "UID=%64u");

void http_terminate(http_conn_t *conn)
{
    if (!conn->framer) {
        FSTRACE(ASYNCHTTP_CONN_TERMINATE_DISCONNECTED, conn->uid);
        return;
    }
    FSTRACE(ASYNCHTTP_CONN_TERMINATE, conn->uid);
    http_framer_terminate(conn->framer);
}

FSTRACE_DECL(ASYNCHTTP_CONN_RECEIVE, "UID=%64u ENV=%p ERRNO=%e");

const http_env_t *http_receive(http_conn_t *conn, http_env_type_t type)
{
    const http_env_t *env = http_decoder_dequeue(conn->decoder, type);
    FSTRACE(ASYNCHTTP_CONN_RECEIVE, conn->uid, env);
    return env;
}

int http_get_content(http_conn_t *conn, ssize_t content_length,
                     bytestream_1 *content)
{
    return http_decoder_get_content(conn->decoder, content_length, content);
}

FSTRACE_DECL(ASYNCHTTP_CONN_REGISTER, "UID=%64u OBJ=%p ACT=%p");

void http_register_callback(http_conn_t *conn, action_1 action)
{
    FSTRACE(ASYNCHTTP_CONN_REGISTER, conn->uid, action.obj, action.act);
    http_decoder_register_callback(conn->decoder, action);
}

FSTRACE_DECL(ASYNCHTTP_CONN_UNREGISTER, "UID=%64u");

void http_unregister_callback(http_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_CONN_UNREGISTER, conn->uid);
    http_decoder_unregister_callback(conn->decoder);
}
