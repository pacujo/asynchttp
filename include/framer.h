#ifndef __ASYNCHTTP_FRAMER__
#define __ASYNCHTTP_FRAMER__

#include <async/async.h>
#include <async/bytestream_1.h>

#include "envelope.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct http_framer http_framer_t;

/* An HTTP framer inputs HTTP messages encodes them into a bytestream_1.
 * The farewell action is invoked when the framer's output stream is
 * closed. */
http_framer_t *open_http_framer(async_t *async);

void http_framer_register_farewell_callback(http_framer_t *framer,
                                            action_1 action);
void http_framer_unregister_farewell_callback(http_framer_t *framer);

/* Return the encoded byte stream.
 *
 * When the stream is closed,
 *
 *  - the framer's farewell action is invoked immediately,
 *
 *  - all outstanding bodies of enqueued messages are scheduled to be
 *    closed nonpreemptively, and
 *
 *  - the framer object is discarded. */
bytestream_1 http_framer_get_output_stream(http_framer_t *framer);

/* Terminating causes an end-of-file to be read out of the stream after
 * all currently pending bytes have been read out. */
void http_framer_terminate(http_framer_t *framer);

enum {
    HTTP_ENCODE_CHUNKED = -1, /* declare and encode chunked */
    HTTP_ENCODE_RAW = -2      /* no envelope or content processing */
};

/* Submit an HTTP message for sending, ie, an HTTP envelope plus a
 * content stream.
 *
 * The ownership of the content is taken over by the framer. The
 * envelope stays owned by the caller and must not be disposed of until
 * the content is closed by the framer.
 *
 * The 'content_length' parameter is interpreted as follows:
 *
 *   1. content_length >= 0:
 *      - encode a "Content-length: <n>" field to as part of the
 *        envelope header
 *      - deliver 'content' unprocessed
 *      - ignore the envelope trailer
 *   2. content_length == HTTP_ENCODE_CHUNKED:
 *      - encode a "Transfer-encoding: chunked" field as part of the
 *        envelope header
 *      - perform chunked encoding on 'content'
 *      - after exhausting 'content'--but before closing it--deliver
 *        the envelope trailer (*)
 *   3. content_length == HTTP_ENCODE_RAW:
 *      - do not add fields to the envelope header
 *      - deliver 'content' unprocessed
 *      - ignore the envelope trailer
 *
 * Note that it is possible to generate an illegal HTTP message.
 *
 * (*) The envelope trailer can be amended with http_env_add_trailer() up
 * to the point when 'content' returns an end-of-stream. You can "buy
 * time" by having 'content' return EAGAIN until the trailers have been
 * added to 'envelope'. */
void http_framer_enqueue(http_framer_t *framer, const http_env_t *envelope,
                         ssize_t content_length, bytestream_1 content);

#ifdef __cplusplus
}
#endif

#endif
