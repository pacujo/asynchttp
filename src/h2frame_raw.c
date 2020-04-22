#include <fstrace.h>
#include <assert.h>
#include <async/blobstream.h>
#include <async/concatstream.h>
#include "h2frame_raw.h"
#include "h2frame_constants.h"

const char *trace_frame_type(void *ptype)
{
    switch (*(uint8_t *) ptype) {
        case H2FRAME_TYPE_DATA:
            return "H2FRAME_TYPE_DATA";
        case H2FRAME_TYPE_HEADERS:
            return "H2FRAME_TYPE_HEADERS";
        case H2FRAME_TYPE_PRIORITY:
            return "H2FRAME_TYPE_PRIORITY";
        case H2FRAME_TYPE_RST_STREAM:
            return "H2FRAME_TYPE_RST_STREAM";
        case H2FRAME_TYPE_SETTINGS:
            return "H2FRAME_TYPE_SETTINGS";
        case H2FRAME_TYPE_PUSH_PROMISE:
            return "H2FRAME_TYPE_PUSH_PROMISE";
        case H2FRAME_TYPE_PING:
            return "H2FRAME_TYPE_PING";
        case H2FRAME_TYPE_GOAWAY:
            return "H2FRAME_TYPE_GOAWAY";
        case H2FRAME_TYPE_WINDOW_UPDATE:
            return "H2FRAME_TYPE_WINDOW_UPDATE";
        case H2FRAME_TYPE_CONTINUATION:
            return "H2FRAME_TYPE_CONTINUATION";
        default: {
            return fstrace_unsigned_repr(*(uint8_t *) ptype);
        }
    }
}

FSTRACE_DECL(ASYNCHTTP_H2FRAME_RAW_ENCODE,
             "UID=%64u PTR=%p LENGTH=%z TYPE=%I FLAGS=%u STREAM-ID=%64u");

bytestream_1 h2frame_raw_encode(async_t *async, h2frame_raw_t *frame)
{
    assert(!(frame->payload_length & ~0x00ffffff));
    assert(!(frame->stream_id & ~0x7fffffff));
    uint8_t header[9] = {
        frame->payload_length >> 16 & 0xff,
        frame->payload_length >> 8 & 0xff,
        frame->payload_length & 0xff,
        frame->type,
        frame->flags,
        frame->stream_id >> 24 & 0x7f, /* sic */
        frame->stream_id >> 16 & 0xff,
        frame->stream_id >> 8 & 0xff,
        frame->stream_id & 0xff,
    };
    blobstream_t *hdrstr = copy_blobstream(async, header, sizeof header);
    concatstream_t *conc =
        concatenate_two_streams(async, blobstream_as_bytestream_1(hdrstr),
                                frame->payload);
    /* The UID carries no information value at the moment. */
    FSTRACE(ASYNCHTTP_H2FRAME_RAW_ENCODE, fstrace_get_unique_id(), conc,
            frame->payload_length, trace_frame_type, &frame->type,
            (unsigned) frame->flags, (uint64_t) frame->stream_id);
    return concatstream_as_bytestream_1(conc);
}
