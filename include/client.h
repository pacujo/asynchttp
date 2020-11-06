#ifndef __ASYNCHTTP_CLIENT__
#define __ASYNCHTTP_CLIENT__

#include <async/tls_connection.h>
#include <async/fsadns.h>
#include "connection.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct http_client http_client_t;
typedef struct http_op http_op_t;

/* An HTTP client is used to perform HTTP operations over a dynamic
 * pool of HTTP(S) connections. If dns is NULL, use synchronous,
 * blocking DNS resolution. */
http_client_t *open_http_client_2(async_t *async, fsadns_t *dns);

/* Equivalent to open_http_client_2(async, NULL). */
http_client_t *open_http_client(async_t *async);

/* A client can be closed before the operations are closed, but the
 * operations must be closed separately. */
void http_client_close(http_client_t *client);

/* Set the maximum size for the response headers accepted from the
 * server. If the size is exceeded on reception, errno is set to
 * EOVERFLOW. The default: 100000.
 *
 * The effect of calling this function after the first call to
 * http_client_make_request() is unspecified. */
void http_client_set_max_envelope_size(http_client_t *client, size_t size);

/* Set the explicit proxy address. Set proxy_host to NULL (the default)
 * for no proxy. The proxy_host string is only needed for the duration
 * of the call.
 *
 * The setting affects subsequent calls to http_client_make_request().
 * Previously initiated operations are unaffected. */
void http_client_set_proxy(http_client_t *client,
                           const char *proxy_host, unsigned port);

/* Set the proxy address specified in the given URI. The URI must have
 * the following format:
 *
 * ("http" | "https") "://" host [":" port] ["/"]
 *
 * The default port is 80 and 443 for "http" and "https", respectively.
 *
 * The setting affects subsequent calls to http_client_make_request().
 * Previously initiated operations are unaffected. */
bool http_client_set_proxy_from_uri(http_client_t *client, const char *uri);

/* Explicitly prevent the use of an HTTP proxy.
 *
 * The setting affects subsequent calls to http_client_make_request().
 * Previously initiated operations are unaffected. */
void http_client_set_direct(http_client_t *client);

/* Use the system-wide HTTP proxy configuration if it is available.
 * Otherwise, do not use a proxy.
 *
 * This is the default mode.
 *
 * The setting affects subsequent calls to http_client_make_request().
 * Previously initiated operations are unaffected. */
void http_client_use_system_proxy(http_client_t *client);

/* Set the TLS CA bundle. Subsequent operations initiated with
 * http_client_makerequest() use the given bundle.
 *
 * This function can be called again any time. */
void http_client_set_tls_ca_bundle(http_client_t *client,
                                   tls_ca_bundle_t *ca_bundle);

/* Create an HTTP request from a URI and a content stream. See
 * http_framer_enqueue() in framer.h for the meaning of
 * content_length. */
http_op_t *http_client_make_request(http_client_t *client,
                                    const char *method,
                                    const char *uri);

/* See http_framer_enqueue() in framer.h for the meaning of
 * content_length. */
void http_op_set_content(http_op_t *op, ssize_t content_length,
                         bytestream_1 content);

/* Set or cancel a maximum expected duration for the operation. Each
 * operation has an associated convenience timer that is not active by
 * default. The timer can be started, restarted or canceled at any
 * time, even redundantly. The duration is expressed in ASYNC_NS
 * units. Nonpositive durations expire right away.
 *
 * A timer expiry causes op's callback (see http_op_register_callback)
 * to be called if relevant. Also, the content bytestream's callback
 * is called analogously as needed.
 *
 * After a timer expiry, the operation may proceed normally with one
 * exception: instead of EAGAIN, an ETIMEDOUT response is returned.
 * After ETIMEDOUT is returned, the operation is in a permanent,
 * nonrecoverable error state. */
void http_op_set_timeout(http_op_t *op, int64_t max_duration);
void http_op_cancel_timeout(http_op_t *op);

/* Get the request envelope. It can be modified until
 * http_op_receive_response() is called on the operation for the first
 * time. */
http_env_t *http_op_get_request_envelope(http_op_t *op);

/* Check if the server has responded to the request. If the return value
 * is NULL, errno contains more information. If the response headers
 * have not been received yet, errno is set to EAGAIN. The return
 * value is NULL and errno == 0 in two situations:
 *
 *  1. The server has closed the connection without responding. This
 *     would happen in HTTP/1.0 but could also happen in HTTP/1.1.
 *
 *  2. The response has already been returned previously. This is a
 *     local application error. */
const http_env_t *http_op_receive_response(http_op_t *op);

/* After http_op_receive_response() has returned a response, the content
 * byte stream can be retrieved using http_op_get_response_content(). In
 * case of a failure, the return value is negative and errno is set. */
int http_op_get_response_content(http_op_t *op, bytestream_1 *content);

void http_op_register_callback(http_op_t *op, action_1 action);
void http_op_unregister_callback(http_op_t *op);

/* An operation can be closed before it has been received. If
 * http_op_receive_response() has returned content, it must be closed
 * separately. */
void http_op_close(http_op_t *op);

#ifdef __cplusplus
}

#include <functional>
#include <memory>

namespace fsecure {
namespace asynchttp {

// std::unique_ptr for http_client_t with custom deleter.
using HttpClientPtr =
    std::unique_ptr<http_client_t, std::function<void(http_client_t *)>>;

// Create HttpClientPtr that takes ownership of the provided http_client_t. Pass
// nullptr to create an instance which doesn't contain any http_client_t object.
inline HttpClientPtr make_http_client_ptr(http_client_t *http_client)
{
    return { http_client, http_client_close };
}

// std::unique_ptr for http_op_t with custom deleter.
using HttpOpPtr = std::unique_ptr<http_op_t, std::function<void(http_op_t *)>>;

// Create HttpOpPtr that takes ownership of the provided http_op_t. Pass
// nullptr to create an instance which doesn't contain any http_op_t object.
inline HttpOpPtr make_http_op_ptr(http_op_t *http_op)
{
    return { http_op, http_op_close };
}

} // namespace asynchttp
} // namespace fsecure

#endif

#endif
