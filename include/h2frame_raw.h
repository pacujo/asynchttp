#ifndef __ASYNCHTTP_H2FRAME_RAW__
#define __ASYNCHTTP_H2FRAME_RAW__

#include <async/async.h>
#include <async/bytestream_1.h>

typedef struct {
    unsigned type;
    unsigned flags;
    uint32_t stream_id;
    size_t payload_length;
    bytestream_1 payload;
} h2frame_raw_t;

const char *trace_frame_type(void *ptype);

/* Return a bytestream that is the HTTP/2 frame encoding of the given
 * raw frame. The caller must ensure that payload has the given
 * length. */
bytestream_1 h2frame_raw_encode(async_t *async, h2frame_raw_t *frame);

#endif
