#ifndef __ASYNCHTTP_H2FRAME_YIELD__
#define __ASYNCHTTP_H2FRAME_YIELD__

#include <async/async.h>
#include <async/bytestream_1.h>
#include <async/yield_1.h>
#include "h2frame_raw.h"

typedef struct h2frame_yield h2frame_yield_t;

/* Yield raw HTTP/2 frames out of a byte stream. Skip the given
 * NUL-terminated character string prefix from the beginning of the
 * byte stream. The prefix is expected to be available for the
 * lifetime of the yield. */
h2frame_yield_t *open_h2frame_yield(async_t *async, bytestream_1 source,
                                    const char *prefix);

yield_1 h2frame_yield_as_yield_1(h2frame_yield_t *yield);

/* The caller is responsible for disposing of the returned frame by
 * calling h2frame_raw_close(frame). */
h2frame_raw_t *h2frame_yield_receive(h2frame_yield_t *yield);

/* Closing the h2frame yield closes the source stream as well. */
void h2frame_yield_close(h2frame_yield_t *yield);
void h2frame_yield_register_callback(h2frame_yield_t *yield, action_1 action);
void h2frame_yield_unregister_callback(h2frame_yield_t *yield);

#endif
