#pragma once

#include <fsdyn/bytearray.h>

#include "client.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct http_op_jockey http_op_jockey_t;
typedef struct http_op_response http_op_response_t;

/*
 * An HTTP jockey takes ownership of an HTTP operation, jockeys it
 * from start to finish and returns the response. The response body is
 * buffered, up to the given size.
 */
http_op_jockey_t *make_http_op_jockey(async_t *async, http_op_t *op,
                                      size_t max_body_size);

void http_op_jockey_close(http_op_jockey_t *jockey);

void http_op_jockey_register_callback(http_op_jockey_t *jockey,
                                      action_1 action);
void http_op_jockey_unregister_callback(http_op_jockey_t *jockey);

/*
 * Return NULL and set errno in case of an error (eg, EAGAIN). If the
 * response body is larger than the maximum size, NULL is returned and
 * errno is set to EMSGSIZE. If the server closes the connection
 * before sending a response, NULL is returned and errno is set to 0.
 */
http_op_response_t *http_op_jockey_receive_response(http_op_jockey_t *jockey);

const http_env_t *http_op_response_get_envelope(http_op_response_t *response);
byte_array_t *http_op_response_release_body(http_op_response_t *response);

#ifdef __cplusplus
}

#include <functional>
#include <memory>

namespace fsecure {
namespace asynchttp {

// std::unique_ptr for http_op_jockey_t with custom deleter.
using HttpOpJockeyPtr =
    std::unique_ptr<http_op_jockey_t, std::function<void(http_op_jockey_t *)>>;

// Create HttpOpJockeyPtr that takes ownership of the provided http_op_jockey_t.
// Pass nullptr to create an instance which doesn't contain any http_op_jockey_t
// object.
inline HttpOpJockeyPtr make_http_op_jockey_ptr(http_op_jockey_t *jockey)
{
    return { jockey, http_op_jockey_close };
}

} // namespace asynchttp
} // namespace fsecure

#endif
