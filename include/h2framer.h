#ifndef __ASYNCHTTP_H2FRAMER__
#define __ASYNCHTTP_H2FRAMER__

#include <async/yield_1.h>
#include "framer_1.h"

typedef struct h2frame_encoder h2frame_encoder_t;

/* An H2 frame encoder inputs HTTP/2 messages and encodes them into a
 * bytestream_1. The farewell action is invoked when the framer's
 * output yield is closed. */
h2frame_encoder_t *open_h2frame_encoder(async_t *async);

/* An h2frame encoder yields h2frame_t objects. */
yield_1 h2frame_encoder_get_output_yield(h2frame_encoder_t *encoder);

void h2frame_encoder_terminate(h2frame_encoder_t *encoder);

/* In HTTP/2, HTTP_ENCODE_CHUNKED does not cause a chunked
 * transfer-encoding header to be inserted to the envelope. */
void h2frame_encoder_enqueue(h2frame_encoder_t *encoder,
                             const http_env_t *envelope,
                             ssize_t content_length, bytestream_1 content);
void h2frame_encoder_register_farewell_callback(h2frame_encoder_t *encoder,
                                                action_1 action);
void h2frame_encoder_unregister_farewell_callback(h2frame_encoder_t *encoder);

http_framer_1 h2frame_encoder_as_http_encoder_1(h2frame_encoder_t *encoder);

#endif
