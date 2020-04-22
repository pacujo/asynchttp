#ifndef __ASYNCHTTP_H2FRAME_DECODER__
#define __ASYNCHTTP_H2FRAME_DECODER__

#include <fsdyn/list.h>
#include <async/async.h>
#include <async/yield_1.h>
#include <async/bytestream_1.h>
#include "hpack.h"
#include "h2frame.h"

typedef struct h2frame_decoder h2frame_decoder_t;

h2frame_decoder_t *open_h2frame_decoder(async_t *async, yield_1 source,
                                        size_t max_nondata_length);
void h2frame_decoder_close(h2frame_decoder_t *decoder);
void h2frame_decoder_register_callback(h2frame_decoder_t *decoder,
                                       action_1 action);
void h2frame_decoder_unregister_callback(h2frame_decoder_t *decoder);
yield_1 h2frame_decoder_as_yield_1(h2frame_decoder_t *decoder);

/* Use h2frame_free() to free the returned frame. In case the frame is
 * of type H2FRAME_TYPE_DATA, you must close its data bytestream in
 * addition to closing the frame. */
h2frame_t *h2frame_decoder_receive(h2frame_decoder_t *decoder);

#endif
