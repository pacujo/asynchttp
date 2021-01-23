#ifndef __ASYNCHTTP_H2CONNECTION__
#define __ASYNCHTTP_H2CONNECTION__

#include <async/bytestream_1.h>
#include "envelope.h"
#include "api_constants.h"

typedef struct h2conn h2conn_t;
typedef struct h2op h2op_t;

/* Open an HTTP/2 client or server connection on top of an existing
 * transport. */
h2conn_t *open_h2connection(async_t *async, bytestream_1 input_stream,
                            bool is_client, size_t max_envelope_size);

/* (Client only.) A connection starts with server push disabled. This
 * function gives the server a permission to push streams.
 *
 * Warning: Improper push promise implementations at the client, the
 * server and this library are a serious security risk. */
void h2conn_allow_push(h2conn_t *conn);

/* Return a byte stream for interlinking with the transport layer. */
bytestream_1 h2conn_get_output_stream(h2conn_t *conn);

void h2conn_close(h2conn_t *conn);

/* (Server only.) */
void h2conn_register_callback(h2conn_t *conn, action_1 action);
void h2conn_unregister_callback(h2conn_t *conn);

/* The peer-closed callback is invoked when an HTTP message cannot be
 * delivered to the peer. */
void h2conn_register_peer_closed_callback(h2conn_t *conn, action_1 action);
void h2conn_unregister_peer_closed_callback(h2conn_t *conn);

/* (Client only.) Initiate an independent HTTP operation (on a new
 * HTTP/2 stream). NULL is returned and errno is set if the connection
 * is not capable of sending a request. Notably, EAGAIN indicates that
 * too many streams are open and ENOSR indicates that the pool of
 * stream IDs has been exhausted.
 *
 * The 'content_length' parameter is interpreted as follows:
 *
 *   1. content_length >= 0:
 *      - encode a "Content-length: <n>" field to as part of the
 *        envelope header
 *      - deliver 'content' unprocessed
 *      - ignore the envelope trailer
 *   2. content_length == HTTP_ENCODE_CHUNKED:
 *      - do not add fields to the envelope header
 *      - after exhausting 'content'--but before closing it--deliver
 *        the envelope trailer (*)
 *   3. content_length == HTTP_ENCODE_RAW:
 *      - a synonym of HTTP_ENCODE_CHUNKED
 *
 * (*) The envelope trailer can be amended with http_env_add_trailer() up
 * to the point when 'content' returns an end-of-stream. You can "buy
 * time" by having 'content' return EAGAIN until the trailers have been
 * added to 'envelope'. */
h2op_t *h2conn_request(h2conn_t *conn, const http_env_t *envelope,
                       ssize_t content_length, bytestream_1 content);

/* (Client only.) Initiate a dependent HTTP operation (on a new HTTP/2
 * stream). See h2conn_request() for the possible values of
 * content_length. The weight must be a number between 1 and 256. See
 * RFC 7540 § 5.3.1 for an explanation of the exclusive flag.
 *
 * NULL is returned and errno is set if the connection is not capable
 * of sending a request. Notably, EAGAIN indicates that too many
 * streams are open and ENOSR indicates that the pool of stream IDs
 * has been exhausted. */
h2op_t *h2op_request(h2op_t *parent, const http_env_t *envelope,
                     ssize_t content_length, bytestream_1 content,
                     bool exclusive, unsigned weight);

void h2op_register_callback(h2op_t *op, action_1 action);
void h2op_unregister_callback(h2op_t *op);

/* (Server only.) Tell if the client allows push promises. The
 * callback (or h2conn_register_callback()) is invoked whenever the
 * situation changes. */
bool h2conn_can_push(h2conn_t *conn);

/* (Server only.) Issue a push promise. Give a request envelope in
 * promise and a response envelope in response. The response content
 * is given in content_length and content. See h2conn_request() for
 * the possible values of content_length. The weight must be a number
 * between 1 and 256. See RFC 7540 § 5.3.1 for an explanation of the
 * exclusive flag. */
h2op_t *h2op_push(h2op_t *parent, const http_env_t *promise,
                  const http_env_t *response,
                  ssize_t content_length, bytestream_1 content,
                  bool exclusive, unsigned weight);

/* (Server only.) Receive a request. Returns NULL and sets errno in
 * case of an error. */
h2op_t *h2conn_receive_request(h2conn_t *conn, const http_env_t **request);

void h2op_reply(h2op_t *op, const http_env_t *envelope,
                ssize_t content_length, bytestream_1 content);

/* (Client only.) Receive response headers. If the return value is
 * NULL, consult errno. After a non-NULL envelope is returned by
 * h2op_receive(), subsequent calls to the function return NULL with
 * errno == EAGAIN. The returned envelope is valid until h2op_close()
 * is called for the operation. */
const http_env_t *h2op_receive_response(h2op_t *op);

/* After a non-NULL value is returned from h2op_receive_response(), or
 * h2conn_receive_request(), the message body can be read out with
 * h2op_get_content().
 *
 * The 'content_length' parameter is interpreted as follows:
 *
 *   1. content_length >= 0:
 *      - HTTP/2 content is verified to match the given length; a
 *        mismatch results in an EPROTO error
 *   2. content_length == HTTP_DECODE_CHUNKED:
 *      - HTTP/2 content is delivered without a length check
 *   3. content_length == HTTP_DECODE_EXHAUST:
 *      - a synonym of HTTP_DECODE_CHUNKED
 *   4. content_length == HTTP_DECODE_OBEY_HEADER:
 *      - if the envelope contains a "Content-length: <n>" header,
 *        perform as though content_length == n
 *      - otherwise, perform as though
 *        content_length == HTTP_DECODE_EXHAUST
 *
 * After 'content' returns an end-of-stream, the dequeued envelope may
 * contain trailer fields.
 *
 * Normally, returns a nonnegative value. If a negative number is
 * returned, errno should be consulted. After a nonnegative value is
 * returned by h2op_get_content(), subsequent calls to the function
 * return a negative value with errno == EAGAIN. */
int h2op_get_content(h2op_t *op, ssize_t content_length,
                     bytestream_1 *content);

/* Every operation returned by h2conn_request() or h2op_request() must
 * eventually be closed. */
void h2op_close(h2op_t *op);

#endif
