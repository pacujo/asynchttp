#ifndef __ASYNCHTTP_ICAP__
#define __ASYNCHTTP_ICAP__

#include <async/async.h>
#include <async/bytestream_1.h>

#include "envelope.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct icap_conn icap_conn_t;

typedef enum {
    ICAP_REQ_BODY,
    ICAP_RES_BODY,
    ICAP_OPT_BODY,
    ICAP_NULL_BODY,
    ICAP_UNENCAPSULATED
} icap_body_type_t;

icap_conn_t *open_icap_connection(async_t *async, bytestream_1 input_stream,
                                  size_t max_envelope_size);
void icap_close(icap_conn_t *conn);

/* The peer-closed callback is invoked when an ICAP message cannot be
 * delivered to the peer, or rather, to the kernel. */
void icap_register_peer_closed_callback(icap_conn_t *conn, action_1 action);
void icap_unregister_peer_closed_callback(icap_conn_t *conn);
bytestream_1 icap_get_output_stream(icap_conn_t *conn);

/* Send an ICAP request or response. Create 'icap_envelope' with
 * make_http_env_request() or make_http_env_response() without
 * specifying the "Encapsulated" header.
 *
 * Indicate the absense of 'http_request' and/or 'http_response' by
 * setting them to NULL. If ICAP_NULL_BODY or ICAP_UNENCAPSULATED is
 * specified as 'body_type', 'body' must still be a valid (and
 * preferably empty) bytestream_1 object. Each of the http_env_t
 * arguments must be kept valid until 'body' is closed. If
 * ICAP_UNENCAPSULATED is specified as 'body_type', no "Encapsulated"
 * header is constructed.
 *
 * If 'body_type' is ICAP_REQ_BODY (ICAP_RES_BODY), the caller may keep
 * updating the trailers of 'http_request' ('http_response') up until
 * the point when 'body' returns an EOF. Trailers are ignored if
 * ICAP_OPT_BODY or ICAP_NULL_BODY is specified. */
void icap_send(icap_conn_t *conn, const http_env_t *icap_envelope,
               const http_env_t *http_request, const http_env_t *http_response,
               icap_body_type_t body_type, bytestream_1 body);

/* Send the remainder of a body in response to a "100 Continue".
 * 'icap_envelope' is consulted for the final chunk extensions. If
 * 'http_envelope' is non-NULL, it is consulted for possible trailers
 * after an EOF is read from 'remainder' (but before it is closed).
 *
 * If you reuse 'http_envelope' from a previous icap_send() call, note
 * that trailers might get sent out twice. */
void icap_continue(icap_conn_t *conn, const http_env_t *icap_envelope,
                   const http_env_t *http_envelope, bytestream_1 remainder);

void icap_terminate(icap_conn_t *conn);

/* Receive an ICAP request or response. Return its envelope structure.
 *
 * If the function returns a non-NULL value, 'http_request',
 * 'http_response', 'body_type' and 'body' are set to meaningful values:
 *
 *   - If 'http_request' is non-NULL, '*http_request' contains an HTTP
 *     request envelope or NULL.
 *   - If 'http_response' is non-NULL, '*http_response' contains an HTTP
 *    response envelope or NULL.
 *   - If 'body_type' is non-NULL, '*body_type' contains the type of
 *     'body'.
 *   - 'body' must not be NULL. It is an empty stream if '*body_type' is
 *     ICAP_NULL_BODY or ICAP_UNENCAPSULATED.
 *
 * The returned envelopes stay valid until '*body' is closed. The caller
 * must make sure to close '*body' eventually.
 *
 * If '*body_type' is ICAP_REQ_BODY (ICAP_RES_BODY), '*http_request'
 * ('*http_response') may acquire trailers. The trailers are accessible
 * starting when '*body' yields an EOF up till when '*body' is closed.
 *
 * If icap_receive() returns NULL, the caller must check 'errno' for a
 * reason (eg, EAGAIN). NULL (with EAGAIN) is returned if previous
 * message content is still open.
 *
 * If an end-of-stream is detected, NULL is returned. In case of a clean
 * end-of-stream before the first byte of a envelope, 'errno' is set to 0.
 * An unclean end-of-stream causes 'errno' to be set to EPROTO. */
const http_env_t *icap_receive(icap_conn_t *conn, http_env_type_t type,
                               const http_env_t **http_request,
                               const http_env_t **http_response,
                               icap_body_type_t *body_type, bytestream_1 *body);

/* Receive the remainder of a body in response to a "100 Continue".
 * icap_receive_continuation() must be called after reading an EOF from
 * '*body' returned by icap_receive() but before closing '*body'.
 * '*body' can be closed as soon as icap_receive_continuation() returns.
 * The envelopes returned by icap_receive() will stay valid until the
 * remainder stream is closed. Possible HTTP new trailers are available
 * after the remainder stream reaches the EOF. The final chunk
 * extensions are replaced by those of the continuation. */
bytestream_1 icap_receive_continuation(icap_conn_t *conn);

void icap_register_callback(icap_conn_t *conn, action_1 action);
void icap_unregister_callback(icap_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif
