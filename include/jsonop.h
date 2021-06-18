#ifndef __ASYNCHTTP_JSONOP__
#define __ASYNCHTTP_JSONOP__

#include <async/async.h>
#include <encjson.h>

#include "client.h"
#include "envelope.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct jsonop jsonop_t;

/* A JSON operation can be used with an http_client_t GET or POST
 * request when the response carry a JSON payload. Both uri and
 * request_body are only needed for the duration of the function
 * call. */
jsonop_t *jsonop_make_request(async_t *async, http_client_t *client,
                              const char *uri, json_thing_t *request_body);

jsonop_t *jsonop_make_get_request(async_t *async, http_client_t *client,
                                  const char *uri);

/* Set or cancel a maximum expected duration for the operation. See
 * http_op_set_timeout() and http_op_cancel_timeout() for the
 * semantics. */
void jsonop_set_timeout(jsonop_t *op, int64_t max_duration);
void jsonop_cancel_timeout(jsonop_t *op);

/* The request envelope can be amended before
 * jsonop_response_headers(), jsonop_response_code() or
 * jsonop_response_body() is called on the operation. */
http_env_t *jsonop_get_request_envelope(jsonop_t *op);

/* Return NULL and set errno in case of an error (eg, EAGAIN). */
const http_env_t *jsonop_response_headers(jsonop_t *op);

/* Return a negative number and set errno in case of an error (eg,
 * EAGAIN). A negative number with errno == 0 means the server has
 * closed the connection without a response. */
int jsonop_response_code(jsonop_t *op);

/* The response body is available only if jsonop_response_code() returns
 * 200. The returned value is for inspection only and continues to be
 * owned by the JSON operation. */
json_thing_t *jsonop_response_body(jsonop_t *op);

void jsonop_close(jsonop_t *op);
void jsonop_register_callback(jsonop_t *op, action_1 action);
void jsonop_unregister_callback(jsonop_t *op);

#ifdef __cplusplus
}

#include <functional>
#include <memory>

namespace fsecure {
namespace asynchttp {

// std::unique_ptr for jsonop_t with custom deleter.
using JsonopPtr = std::unique_ptr<jsonop_t, std::function<void(jsonop_t *)>>;

// Create JsonopPtr that takes ownership of the provided jsonop_t. Pass
// nullptr to create an instance which doesn't contain any jsonop_t object.
inline JsonopPtr make_jsonop_ptr(jsonop_t *op)
{
    return { op, jsonop_close };
}

} // namespace asynchttp
} // namespace fsecure

#endif

#endif
