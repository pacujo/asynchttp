#include <assert.h>
#include <fstrace.h>
#include <fsdyn/fsalloc.h>
#include <async/blobstream.h>
#include <async/concatstream.h>
#include "hpack.h"
#include "h2frame.h"
#include "h2frame_raw.h"
#include "h2frame_constants.h"

static void destroy_headers(list_t *headers)
{
    list_foreach(headers, (void *) hpack_free_header_field, NULL);
    destroy_list(headers);
}

FSTRACE_DECL(ASYNCHTTP_H2F_FREE, "FRAME=%p");

void h2frame_free(h2frame_t *frame)
{
    FSTRACE(ASYNCHTTP_H2F_FREE, frame);
    switch (frame->frame_type) {
        case H2FRAME_TYPE_HEADERS:
            destroy_headers(frame->headers.headers);
            break;
        case H2FRAME_TYPE_SETTINGS:
            list_foreach(frame->settings.settings, (void *) fsfree, NULL);
            destroy_list(frame->settings.settings);
            break;
        case H2FRAME_TYPE_PUSH_PROMISE:
            destroy_headers(frame->push_promise.headers);
        case H2FRAME_TYPE_GOAWAY:
            fsfree(frame->goaway.debug_data);
            break;
        case H2FRAME_TYPE_CONTINUATION:
            destroy_headers(frame->continuation.headers);
        default:
            assert(true);
    }
    fsfree(frame);
}

static void encode_data_frame(async_t *async, h2frame_t *frame,
                              h2frame_raw_t *raw_frame)
{
    if (frame->data.end_stream)
        raw_frame->flags |= H2FRAME_FLAG_END_STREAM;
    raw_frame->payload_length = frame->data.data_length;
    raw_frame->payload = frame->data.data;
}

static size_t encode_headers(async_t *async, list_t *headers,
                             bytestream_1 *pstream)
{
    size_t total_size = 0;
    list_elem_t *e;
    for (e = list_get_first(headers); e; e = list_next(e))
        total_size +=
            hpack_encode_header_field(list_elem_get_value(e), NULL, 0);
    uint8_t *buffer = fsalloc(total_size);
    uint8_t *p = buffer, *end = buffer + total_size;
    for (e = list_get_first(headers); e; e = list_next(e))
        p += hpack_encode_header_field(list_elem_get_value(e), p, end - p);
    action_1 free_cb = { buffer, (act_1) fsfree };
    blobstream_t *blobstr =
        adopt_blobstream(async, buffer, total_size, free_cb);
    *pstream = blobstream_as_bytestream_1(blobstr);
    return total_size;
}

static void encode_headers_frame(async_t *async, h2frame_t *frame,
                                 h2frame_raw_t *raw_frame)
{
    bytestream_1 headers_encoding;
    size_t headers_length =
        encode_headers(async, frame->headers.headers, &headers_encoding);
    if (frame->headers.end_stream)
        raw_frame->flags |= H2FRAME_FLAG_END_STREAM;
    if (frame->headers.end_headers)
        raw_frame->flags |= H2FRAME_FLAG_END_HEADERS;
    if (!frame->headers.priority) {
        raw_frame->payload_length = headers_length;
        raw_frame->payload = headers_encoding;
        return;
    }
    raw_frame->flags |= H2FRAME_FLAG_PRIORITY;
    uint8_t buffer[5];
    buffer[0] = frame->headers.dependency >> 24 & 0x7f;
    if (frame->headers.exclusive)
        buffer[0] |= 0x80;
    buffer[1] = frame->headers.dependency >> 16 & 0xff;
    buffer[2] = frame->headers.dependency >> 8 & 0xff;
    buffer[3] = frame->headers.dependency & 0xff;
    buffer[4] = frame->headers.weight & 0xff;
    blobstream_t *blobstr = copy_blobstream(async, buffer, sizeof buffer);
    concatstream_t *conc =
        concatenate_two_streams(async, blobstream_as_bytestream_1(blobstr),
                                headers_encoding);
    raw_frame->payload_length = sizeof buffer + headers_length;
    raw_frame->payload = concatstream_as_bytestream_1(conc);
}

static void encode_priority_frame(async_t *async, h2frame_t *frame,
                                  h2frame_raw_t *raw_frame)
{
    uint8_t buffer[5];
    buffer[0] = frame->priority.dependency >> 24 & 0x7f;
    if (frame->priority.exclusive)
        buffer[0] |= 0x80;
    buffer[1] = frame->priority.dependency >> 16 & 0xff;
    buffer[2] = frame->priority.dependency >> 8 & 0xff;
    buffer[3] = frame->priority.dependency & 0xff;
    buffer[4] = frame->priority.weight & 0xff;
    blobstream_t *blobstr = copy_blobstream(async, buffer, sizeof buffer);
    raw_frame->payload_length = sizeof buffer;
    raw_frame->payload = blobstream_as_bytestream_1(blobstr);
}

static void encode_rst_stream_frame(async_t *async, h2frame_t *frame,
                                    h2frame_raw_t *raw_frame)
{
    uint8_t buffer[4];
    buffer[0] = frame->rst_stream.error_code >> 24 & 0xff;
    buffer[1] = frame->rst_stream.error_code >> 16 & 0xff;
    buffer[2] = frame->rst_stream.error_code >> 8 & 0xff;
    buffer[3] = frame->rst_stream.error_code & 0xff;
    blobstream_t *blobstr = copy_blobstream(async, buffer, sizeof buffer);
    raw_frame->payload_length = sizeof buffer;
    raw_frame->payload = blobstream_as_bytestream_1(blobstr);
}

static void encode_settings_frame(async_t *async, h2frame_t *frame,
                                  h2frame_raw_t *raw_frame)
{
    enum {
        SETTING_ENCODING_SIZE = 6
    };
    if (frame->settings.ack)
        raw_frame->flags |= H2FRAME_FLAG_ACK;
    size_t count = list_size(frame->settings.settings);
    size_t buffer_size = count * SETTING_ENCODING_SIZE;
    uint8_t *buffer = fsalloc(buffer_size);
    uint8_t *p = buffer;
    list_elem_t *e;
    for (e = list_get_first(frame->settings.settings); e; e = list_next(e)) {
        const h2frame_setting_t *setting = list_elem_get_value(e);
        *p++ = setting->parameter >> 8 & 0xff;
        *p++ = setting->parameter & 0xff;
        *p++ = setting->value >> 24 & 0xff;
        *p++ = setting->value >> 16 & 0xff;
        *p++ = setting->value >> 8 & 0xff;
        *p++ = setting->value & 0xff;
    }
    blobstream_t *blobstr =
        adopt_blobstream(async, buffer, buffer_size,
                         (action_1) { buffer, (act_1) fsfree });
    raw_frame->payload_length = buffer_size;
    raw_frame->payload = blobstream_as_bytestream_1(blobstr);
}

static void encode_push_promise_frame(async_t *async, h2frame_t *frame,
                                      h2frame_raw_t *raw_frame)
{
    if (frame->push_promise.end_headers)
        raw_frame->flags |= H2FRAME_FLAG_END_HEADERS;
    uint8_t buffer[4];
    buffer[0] = frame->push_promise.promised >> 24 & 0x7f;
    buffer[1] = frame->push_promise.promised >> 16 & 0xff;
    buffer[2] = frame->push_promise.promised >> 8 & 0xff;
    buffer[3] = frame->push_promise.promised & 0xff;
    blobstream_t *blobstr = copy_blobstream(async, buffer, sizeof buffer);
    bytestream_1 headers_encoding;
    size_t headers_length =
        encode_headers(async, frame->push_promise.headers, &headers_encoding);
    concatstream_t *conc =
        concatenate_two_streams(async, blobstream_as_bytestream_1(blobstr),
                                headers_encoding);
    raw_frame->payload_length = sizeof buffer + headers_length;
    raw_frame->payload = concatstream_as_bytestream_1(conc);
}

static void encode_ping_frame(async_t *async, h2frame_t *frame,
                              h2frame_raw_t *raw_frame)
{
    if (frame->settings.ack)
        raw_frame->flags |= H2FRAME_FLAG_ACK;
    blobstream_t *blobstr =
        copy_blobstream(async, frame->ping.data, sizeof frame->ping.data);
    raw_frame->payload_length = sizeof frame->ping.data;
    raw_frame->payload = blobstream_as_bytestream_1(blobstr);
}

static void encode_goaway_frame(async_t *async, h2frame_t *frame,
                                h2frame_raw_t *raw_frame)
{
    uint8_t buffer[8] = {
        frame->goaway.last_stream_id >> 24 & 0xff,
        frame->goaway.last_stream_id >> 16 & 0xff,
        frame->goaway.last_stream_id >> 8 & 0xff,
        frame->goaway.last_stream_id & 0xff,
        frame->goaway.error_code >> 24 & 0xff,
        frame->goaway.error_code >> 16 & 0xff,
        frame->goaway.error_code >> 8 & 0xff,
        frame->goaway.error_code & 0xff,
    };
    blobstream_t *blobstr1 = copy_blobstream(async, buffer, sizeof buffer);
    blobstream_t *blobstr2 =
        copy_blobstream(async, frame->goaway.debug_data,
                        frame->goaway.debug_data_length);
    concatstream_t *conc =
        concatenate_two_streams(async, blobstream_as_bytestream_1(blobstr1),
                                blobstream_as_bytestream_1(blobstr2));
    raw_frame->payload_length = sizeof buffer + frame->goaway.debug_data_length;
    raw_frame->payload = concatstream_as_bytestream_1(conc);
}

static void encode_window_update_frame(async_t *async, h2frame_t *frame,
                                       h2frame_raw_t *raw_frame)
{
    uint8_t buffer[4];
    buffer[0] = frame->window_update.increment >> 24 & 0x7f; /* sic */
    buffer[1] = frame->window_update.increment >> 16 & 0xff;
    buffer[2] = frame->window_update.increment >> 8 & 0xff;
    buffer[3] = frame->window_update.increment & 0xff;
    blobstream_t *blobstr = copy_blobstream(async, buffer, sizeof buffer);
    raw_frame->payload_length = sizeof buffer;
    raw_frame->payload = blobstream_as_bytestream_1(blobstr);
}

static void encode_continuation_frame(async_t *async, h2frame_t *frame,
                                      h2frame_raw_t *raw_frame)
{
    if (frame->continuation.end_headers)
        raw_frame->flags |= H2FRAME_FLAG_END_HEADERS;
    raw_frame->payload_length =
        encode_headers(async, frame->continuation.headers, &raw_frame->payload);
}

bytestream_1 h2frame_encode(async_t *async, h2frame_t *frame)
{
    h2frame_raw_t raw_frame;
    raw_frame.type = frame->frame_type;
    raw_frame.flags = 0;
    raw_frame.stream_id = frame->stream_id;
    switch (frame->frame_type) {
        case H2FRAME_TYPE_DATA:
            encode_data_frame(async, frame, &raw_frame);
            break;
        case H2FRAME_TYPE_HEADERS:
            encode_headers_frame(async, frame, &raw_frame);
            break;
        case H2FRAME_TYPE_PRIORITY:
            encode_priority_frame(async, frame, &raw_frame);
            break;
        case H2FRAME_TYPE_RST_STREAM:
            encode_rst_stream_frame(async, frame, &raw_frame);
            break;
        case H2FRAME_TYPE_SETTINGS:
            encode_settings_frame(async, frame, &raw_frame);
            break;
        case H2FRAME_TYPE_PUSH_PROMISE:
            encode_push_promise_frame(async, frame, &raw_frame);
            break;
        case H2FRAME_TYPE_PING:
            encode_ping_frame(async, frame, &raw_frame);
            break;
        case H2FRAME_TYPE_GOAWAY:
            encode_goaway_frame(async, frame, &raw_frame);
            break;
        case H2FRAME_TYPE_WINDOW_UPDATE:
            encode_window_update_frame(async, frame, &raw_frame);
            break;
        case H2FRAME_TYPE_CONTINUATION:
            encode_continuation_frame(async, frame, &raw_frame);
            break;
        default:
            assert(false);
    }
    return h2frame_raw_encode(async, &raw_frame);
}

h2frame_setting_t *h2frame_make_setting(unsigned parameter, uint32_t value)
{
    h2frame_setting_t *setting = fsalloc(sizeof *setting);
    setting->parameter = parameter;
    setting->value = value;
    return setting;
}

const char *h2frame_trace_error_code(void *p)
{
    switch (*(uint32_t *) p) {
        case H2FRAME_ERR_NO_ERROR:
            return "H2FRAME_ERR_NO_ERROR";
        case H2FRAME_ERR_PROTOCOL_ERROR:
            return "H2FRAME_ERR_PROTOCOL_ERROR";
        case H2FRAME_ERR_INTERNAL_ERROR:
            return "H2FRAME_ERR_INTERNAL_ERROR";
        case H2FRAME_ERR_FLOW_CONTROL_ERROR:
            return "H2FRAME_ERR_FLOW_CONTROL_ERROR";
        case H2FRAME_ERR_SETTINGS_TIMEOUT:
            return "H2FRAME_ERR_SETTINGS_TIMEOUT";
        case H2FRAME_ERR_STREAM_CLOSED:
            return "H2FRAME_ERR_STREAM_CLOSED";
        case H2FRAME_ERR_FRAME_SIZE_ERROR:
            return "H2FRAME_ERR_FRAME_SIZE_ERROR";
        case H2FRAME_ERR_REFUSED_STREAM:
            return "H2FRAME_ERR_REFUSED_STREAM";
        case H2FRAME_ERR_CANCEL:
            return "H2FRAME_ERR_CANCEL";
        case H2FRAME_ERR_COMPRESSION_ERROR:
            return "H2FRAME_ERR_COMPRESSION_ERROR";
        case H2FRAME_ERR_CONNECT_ERROR:
            return "H2FRAME_ERR_CONNECT_ERROR";
        case H2FRAME_ERR_ENHANCE_YOUR_CALM:
            return "H2FRAME_ERR_ENHANCE_YOUR_CALM";
        case H2FRAME_ERR_INADEQUATE_SECURITY:
            return "H2FRAME_ERR_INADEQUATE_SECURITY";
        case H2FRAME_ERR_HTTP_1_1_REQUIRED:
            return "H2FRAME_ERR_HTTP_1_1_REQUIRED";
        default:
            return fstrace_unsigned_repr(*(uint32_t *) p);
    }
}

