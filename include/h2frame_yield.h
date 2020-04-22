#ifndef __ASYNCHTTP_H2FRAME_YIELD__
#define __ASYNCHTTP_H2FRAME_YIELD__

#include <async/async.h>
#include <async/bytestream_1.h>
#include <async/yield_1.h>
#include "h2frame_raw.h"

typedef struct h2frame_yield h2frame_yield_t;

/* Yield raw HTTP/2 frames out of a byte stream. */
h2frame_yield_t *open_h2frame_yield(async_t *async, bytestream_1 source);

yield_1 h2frame_yield_as_yield_1(h2frame_yield_t *yield);

/* The caller is responsible for disposing of the returned frame by
 * calling h2frame_raw_close(frame). */
h2frame_raw_t *h2frame_yield_receive(h2frame_yield_t *yield);

/* Closing the h2frame yield closes the source stream as well. */
void h2frame_yield_close(h2frame_yield_t *yield);
void h2frame_yield_register_callback(h2frame_yield_t *yield, action_1 action);
void h2frame_yield_unregister_callback(h2frame_yield_t *yield);

/* Return the 8-bit type of the frame. */
unsigned h2frame_raw_get_type(h2frame_raw_t *frame);

/* Return the 8-bit flags field of the frame. */
unsigned h2frame_raw_get_flags(h2frame_raw_t *frame);

/* Return the 31-bit stream ID of the frame. */
uint32_t h2frame_raw_get_stream_id(h2frame_raw_t *frame);

/* Return the length of the frame payload. */
size_t h2frame_raw_get_payload_length(h2frame_raw_t *frame);

/* These two functions are synonymous. */
bytestream_1 h2frame_raw_get_payload(h2frame_raw_t *frame);
bytestream_1 h2frame_raw_as_bytestream_1(h2frame_raw_t *frame);

ssize_t h2frame_raw_read(h2frame_raw_t *frame, void *buf, size_t count);
void h2frame_raw_close(h2frame_raw_t *frame);
void h2frame_raw_register_callback(h2frame_raw_t *frame, action_1 action);
void h2frame_raw_unregister_callback(h2frame_raw_t *frame);

#endif
