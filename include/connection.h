#ifndef __ASYNCHTTP_CONNECTION__
#define __ASYNCHTTP_CONNECTION__

#include <async/async.h>
#include <async/bytestream_1.h>

#include "decoder.h"
#include "envelope.h"
#include "framer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct http_conn http_conn_t;

http_conn_t *open_http_connection(async_t *async, bytestream_1 input_stream,
                                  size_t max_envelope_size);
void http_close(http_conn_t *conn);

/* The peer-closed callback is invoked when an HTTP message cannot be
 * delivered to the peer, or rather, to the kernel. */
void http_register_peer_closed_callback(http_conn_t *conn, action_1 action);
void http_unregister_peer_closed_callback(http_conn_t *conn);
bytestream_1 http_get_output_stream(http_conn_t *conn);
void http_send(http_conn_t *conn, const http_env_t *envelope,
               ssize_t content_length, bytestream_1 content);
void http_terminate(http_conn_t *conn);
const http_env_t *http_receive(http_conn_t *conn, http_env_type_t type);
int http_get_content(http_conn_t *conn, ssize_t content_length,
                     bytestream_1 *content);
void http_register_callback(http_conn_t *conn, action_1 action);
void http_unregister_callback(http_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif
