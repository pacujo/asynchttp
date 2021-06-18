#ifndef __ASYNCHTTP_DECODER__
#define __ASYNCHTTP_DECODER__

#include <async/async.h>
#include <async/bytestream_1.h>
#include <async/queuestream.h>

#include "envelope.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct http_decoder http_decoder_t;

/* The decoder object assumes lifetime ownership of 'input_stream' and
 * will eventually close it. */
http_decoder_t *open_http_decoder(async_t *async, bytestream_1 input_stream,
                                  size_t max_envelope_size);

void http_decoder_close(http_decoder_t *decoder);

enum {
    HTTP_DECODE_CHUNKED = -1,    /* assume chunked encoding */
    HTTP_DECODE_EXHAUST = -2,    /* content ends with end-of-stream */
    HTTP_DECODE_OBEY_HEADER = -3 /* inspect headers for content size */
};

/* Read out the headers of the next HTTP message from the decoder's
 * stream. Return its envelope structure.
 *
 * If the function returns a non-NULL value, the caller must eventually
 * call http_decoder_get_content() and, in the end, close it so the
 * decoder has an opportunity to free the resources associated with the
 * message. The returned envelope structure is for inspection only.
 *
 * If the function returns NULL, the caller must check 'errno' for a
 * reason (eg, EAGAIN). NULL (with EAGAIN) is returned if previous
 * message content is still open.
 *
 * If an end-of-stream is detected, NULL is returned. In case of a clean
 * end-of-stream before the first byte of a envelope, 'errno' is set to 0.
 * An unclean end-of-stream causes 'errno' to be set to EPROTO. */
const http_env_t *http_decoder_dequeue(http_decoder_t *decoder,
                                       http_env_type_t type);

/* After http_decoder_dequeue() returns a non-NULL envelope, the caller
 * needs to inspect the envelope headers and call
 * http_decoder_get_content() to read out the message content. The
 * caller must eventually close 'content' so the decoder has an
 * opportunity to free the resources associated with the message.
 *
 * Responses to some requests cannot carry content. An empty 'content'
 * is returned in those situations, and the application must close it
 * when the message is no longer needed.
 *
 * The 'content_length' parameter is interpreted as follows:
 *
 *   1. content_length >= 0:
 *      - the given number of bytes are delivered as-is
 *   2. content_length == HTTP_DECODE_CHUNKED:
 *      - chunked decoding is performed and the decoded bytes delivered
 *   3. content_length == HTTP_DECODE_EXHAUST:
 *      - the remainder of the stream is delivered unprocessed as
 *        content
 *   4. content_length == HTTP_DECODE_OBEY_HEADER:
 *      - if the envelope contains a "Content-length: <n>" header,
 *        perform as though content_length == n
 *      - if the envelope contains a "Transfer-encoding: chunked"
 *        header, perform as though content_length ==
 *        HTTP_ENCODE_CHUNKED
 *      - otherwise, perform as though
 *        content_length == HTTP_DECODE_EXHAUST
 *
 * After 'content' returns an end-of-stream, the dequeued envelope may
 * contain trailer fields.
 *
 * Normally, returns a nnonnegative value. If HTTP_DECODE_OBEY_HEADER is
 * specified, http_decoder_get_content() may return a negative number
 * (with errno == EPROTO) as a sign of a fatal protocol error. */
int http_decoder_get_content(http_decoder_t *decoder, ssize_t content_length,
                             bytestream_1 *content);

/* Temporarily take over underlying content stream. Called instead of
 * http_decoder_get_content() to implement other content-encoding
 * schemes. The caller must eventually call
 * http_decoder_restore_content(). */
queuestream_t *http_decoder_grab_content(http_decoder_t *decoder);

/* This function must be called eventually after calling
 * http_decoder_grab_stream(). */
void http_decoder_restore_content(http_decoder_t *decoder,
                                  queuestream_t *content);

/* The callback concerns both http_decoder_dequeue() and
 * bytestream_1_read() for the content returned by
 * http_decoder_dequeue(). There is no ambiguity: after
 * http_decoder_dequeue() retunrs content, no new HTTP message can be
 * dequeued before the content is closed. */
void http_decoder_register_callback(http_decoder_t *decoder, action_1 action);
void http_decoder_unregister_callback(http_decoder_t *decoder);

#ifdef __cplusplus
}
#endif

#endif
