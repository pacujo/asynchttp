#include <string.h>
#include <errno.h>
#include <assert.h>
#include <fsdyn/fsalloc.h>
#include <async/substream.h>
#include <async/farewellstream.h>
#include <fstrace.h>
#include "h2frame_decoder.h"
#include "h2frame_yield.h"
#include "h2frame_constants.h"
#include "asynchttp_version.h"

typedef enum {
    DECODER_RECEIVING,
    DECODER_DECODING,
    DECODER_READING_DATA_PAYLOAD,
    DECODER_ERRORED,
    DECODER_ZOMBIE
} decoder_state_t;

struct h2frame_decoder {
    async_t *async;
    uint64_t uid;
    decoder_state_t state;
    yield_1 source;
    action_1 callback;
    size_t max_nondata_length;
    union {
        struct {
            h2frame_raw_t *raw_frame;
            size_t cursor, need;
            uint8_t *buffer;
        } decoding;
        struct {
        } reading_data_payload;
        struct {
            int error;
        } errored;
    };
};

enum {
    STREAM_ID_MASK = 0x7fffffff
};

static const char *trace_decoder_state(void *pstate)
{
    switch (*(decoder_state_t *) pstate) {
        case DECODER_RECEIVING:
            return "DECODER_RECEIVING";
        case DECODER_DECODING:
            return "DECODER_DECODING";
        case DECODER_READING_DATA_PAYLOAD:
            return "DECODER_READING_DATA_PAYLOAD";
        case DECODER_ERRORED:
            return "DECODER_ERRORED";
        case DECODER_ZOMBIE:
            return "DECODER_ZOMBIE";
        default:
            return fstrace_unsigned_repr(*(decoder_state_t *) pstate);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_SET_STATE, "UID=%64u OLD=%I NEW=%I");

static void set_decoder_state(h2frame_decoder_t *decoder, decoder_state_t state)
{
    FSTRACE(ASYNCHTTP_H2F_DECODER_SET_STATE, decoder->uid,
            trace_decoder_state, &decoder->state,
            trace_decoder_state, &state);
    decoder->state = state;
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_CREATE,
             "UID=%64u PTR=%p ASYNC=%p SOURCE=%p MAX-NONDATA-LENGTH=%z");

h2frame_decoder_t *open_h2frame_decoder(async_t *async, yield_1 source,
                                        size_t max_nondata_length)
{
    h2frame_decoder_t *decoder = fsalloc(sizeof *decoder);
    decoder->async = async;
    decoder->uid = fstrace_get_unique_id();
    FSTRACE(ASYNCHTTP_H2F_DECODER_CREATE,
            decoder->uid, decoder, async, source.obj, max_nondata_length);
    decoder->state = DECODER_RECEIVING;
    decoder->source = source;
    decoder->callback = NULL_ACTION_1;
    decoder->max_nondata_length = max_nondata_length;
    return decoder;
}

static void clear_payload(h2frame_decoder_t *decoder)
{
    assert(decoder->state == DECODER_DECODING);
    fsfree(decoder->decoding.buffer);
    bytestream_1_close(decoder->decoding.raw_frame->payload);
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_DECODING_ERROR, "UID=%64u");

static h2frame_t *decoding_error(h2frame_decoder_t *decoder)
{
    FSTRACE(ASYNCHTTP_H2F_DECODER_DECODING_ERROR, decoder->uid);
    clear_payload(decoder);
    set_decoder_state(decoder, DECODER_ERRORED);
    errno = decoder->errored.error = EPROTO;
    return NULL;
}

static uint32_t get_stream_id(h2frame_decoder_t *decoder)
{
    return decoder->decoding.raw_frame->stream_id;
}

static bool get_flag(h2frame_decoder_t *decoder, unsigned flag)
{
    return !!(decoder->decoding.raw_frame->flags & flag);
}

static size_t get_payload_length(h2frame_decoder_t *decoder)
{
    return decoder->decoding.raw_frame->payload_length;
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_DATA_PAYLOAD_CLOSED, "UID=%64u");

static void data_payload_closed(h2frame_decoder_t *decoder)
{
    FSTRACE(ASYNCHTTP_H2F_DECODER_DATA_PAYLOAD_CLOSED, decoder->uid);
    assert(decoder->state == DECODER_READING_DATA_PAYLOAD);
    set_decoder_state(decoder, DECODER_RECEIVING);
    action_1_perf(decoder->callback);
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_GOT_DATA,
             "UID=%64u FRAME=%p STRID=%64u ENDS=%b LENGTH=%z");

static h2frame_t *decode_data(h2frame_decoder_t *decoder)
{
    bytestream_1 data = decoder->decoding.raw_frame->payload;
    size_t payload_length = get_payload_length(decoder);
    size_t data_length = payload_length;
    if (get_flag(decoder, H2FRAME_FLAG_PADDED)) {
        size_t padding = decoder->decoding.buffer[0];
        if (payload_length < padding - 1)
            return decoding_error(decoder);
        data_length -= padding + 1;
    }
    substream_t *substr =
        make_substream(decoder->async, data, SUBSTREAM_FAST_FORWARD,
                       0, data_length);
    action_1 data_payload_cb = { decoder, (act_1) data_payload_closed };
    farewellstream_t *fwstr =
        open_relaxed_farewellstream(decoder->async,
                                    substream_as_bytestream_1(substr),
                                    data_payload_cb);
    data = farewellstream_as_bytestream_1(fwstr);
    fsfree(decoder->decoding.buffer);
    uint32_t stream_id = get_stream_id(decoder);
    bool end_stream = get_flag(decoder, H2FRAME_FLAG_END_STREAM);
    set_decoder_state(decoder, DECODER_READING_DATA_PAYLOAD);
    h2frame_t *frame = fsalloc(sizeof *frame);
    frame->frame_type = H2FRAME_TYPE_DATA;
    frame->stream_id = stream_id;
    frame->data.end_stream = end_stream;
    frame->data.data_length = data_length;
    frame->data.data = data;
    FSTRACE(ASYNCHTTP_H2F_DECODER_GOT_DATA, decoder->uid, frame,
            (uint64_t) frame->stream_id, frame->data.end_stream,
            frame->data.data_length);
    return frame;
}

static const uint8_t *get_uint8(const uint8_t *p, uint8_t *value)
{
    *value = *p++;
    return p;
}

static const uint8_t *get_uint16(const uint8_t *p, uint16_t *value)
{
    uint8_t hi, lo;
    p = get_uint8(p, &hi);
    p = get_uint8(p, &lo);
    *value = hi << 8 | lo;
    return p;
}

static const uint8_t *get_uint32(const uint8_t *p, uint32_t *value)
{
    uint16_t hi, lo;
    p = get_uint16(p, &hi);
    p = get_uint16(p, &lo);
    *value = hi << 16 | lo;
    return p;
}

static const uint8_t *bound(h2frame_decoder_t *decoder, const uint8_t **end)
{
    *end = decoder->decoding.buffer + get_payload_length(decoder);
    return decoder->decoding.buffer;
}

static const uint8_t *unpad(h2frame_decoder_t *decoder, const uint8_t **end)
{
    size_t payload_length = get_payload_length(decoder);
    if (!get_flag(decoder, H2FRAME_FLAG_PADDED))
        return bound(decoder, end);
    size_t padding = decoder->decoding.buffer[0];
    if (padding >= payload_length)
        return NULL;
    *end = decoder->decoding.buffer + payload_length - padding - 1;
    return decoder->decoding.buffer + 1;
}

static list_t *get_header_block_fragment(h2frame_decoder_t *decoder,
                                         const uint8_t *start,
                                         const uint8_t *end)
{
    list_t *headers = make_list();
    while (start < end) {
        hpack_header_field_t *header;
        ssize_t count =
            hpack_decode_header_field(start, end - start, &header, 10000);
        if (count < 0) {
            list_foreach(headers, (void *) hpack_free_header_field, NULL);
            destroy_list(headers);
            return NULL;
        }
        list_append(headers, header);
        start += count;
    }
    return headers;
}

static const char *trace_representation(const void *prepr)
{
    switch (*(hpack_repr_t *) prepr) {
        case HPACK_NO_LITERAL:
            return "HPACK_NO_LITERAL";
        case HPACK_UPDATE:
            return "HPACK_UPDATE";
        case HPACK_NO_UPDATE:
            return "HPACK_NO_UPDATE";
        case HPACK_NEVER_UPDATE:
            return "HPACK_NEVER_UPDATE";
        default:
            return fstrace_unsigned_repr(*(hpack_repr_t *) prepr);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_HEADER_FIELD,
             "UID=%64u REPR=%I NEW=%b INDEX=%64u NAME=%s VALUE=%s");

static void trace_headers(h2frame_decoder_t *decoder, list_t *headers)
{
    if (FSTRACE_ENABLED(ASYNCHTTP_H2F_DECODER_HEADER_FIELD)) {
        list_elem_t *e;
        for (e = list_get_first(headers); e; e = list_next(e)) {
            const hpack_header_field_t *header = list_elem_get_value(e);
            uint64_t index = 0;
            const char *name = NULL, *value = NULL;
            if (header->representation == HPACK_NO_LITERAL)
                index = header->no_literal.index;
            else if (header->new_name) {
                name = header->new.name;
                value = header->new.value;
            } else {
                index = header->indexed.index;
                value = header->indexed.value;
            }
            FSTRACE(ASYNCHTTP_H2F_DECODER_HEADER_FIELD, decoder->uid,
                    trace_representation, &header->representation,
                    header->new_name, index, name, value);
        }
    }
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_GOT_HEADERS,
             "UID=%64u FRAME=%p STRID=%64u ENDS=%b ENDH=%b PRIOR=%b EXCL=%b "
             "DEP-STRID=%64u WEIGHT=%u");

static h2frame_t *decode_headers(h2frame_decoder_t *decoder)
{
    const uint8_t *end;
    const uint8_t *p = unpad(decoder, &end);
    if (!p)
        return decoding_error(decoder);
    bool end_stream = get_flag(decoder, H2FRAME_FLAG_END_STREAM);
    bool end_headers = get_flag(decoder, H2FRAME_FLAG_END_HEADERS);
    bool priority = get_flag(decoder, H2FRAME_FLAG_PRIORITY);
    uint32_t dependency = 0;
    uint8_t weight = 0;
    if (priority) {
        if (end < p + 5)
            return decoding_error(decoder);
        p = get_uint32(p, &dependency);
        p = get_uint8(p, &weight);
    }
    list_t *headers = get_header_block_fragment(decoder, p, end);
    if (!headers)
        return decoding_error(decoder);
    uint32_t stream_id = get_stream_id(decoder);
    clear_payload(decoder);
    set_decoder_state(decoder, DECODER_RECEIVING);
    h2frame_t *frame = fsalloc(sizeof *frame);
    frame->frame_type = H2FRAME_TYPE_HEADERS;
    frame->stream_id = stream_id;
    frame->headers.end_stream = end_stream;
    frame->headers.end_headers = end_headers;
    frame->headers.priority = priority;
    frame->headers.exclusive = !!(dependency & ~STREAM_ID_MASK);
    frame->headers.dependency = dependency & STREAM_ID_MASK;
    frame->headers.weight = weight + 1;
    frame->headers.headers = headers;
    FSTRACE(ASYNCHTTP_H2F_DECODER_GOT_HEADERS, decoder->uid, frame,
            (uint64_t) frame->stream_id, frame->headers.end_stream,
            frame->headers.end_headers, frame->headers.priority,
            frame->headers.exclusive, (uint64_t) frame->headers.dependency,
            frame->headers.weight);
    trace_headers(decoder, headers);
    return frame;
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_GOT_PRIORITY,
             "UID=%64u FRAME=%p STRID=%64u EXCL=%b DEP-STRID=%64u");

static h2frame_t *decode_priority(h2frame_decoder_t *decoder)
{
    if (get_payload_length(decoder) != 5)
        return decoding_error(decoder);
    uint32_t dependency;
    uint8_t weight;
    const uint8_t *p = decoder->decoding.buffer;
    p = get_uint32(p, &dependency);
    p = get_uint8(p, &weight);
    uint32_t stream_id = get_stream_id(decoder);
    clear_payload(decoder);
    set_decoder_state(decoder, DECODER_RECEIVING);
    h2frame_t *frame = fsalloc(sizeof *frame);
    frame->frame_type = H2FRAME_TYPE_PRIORITY;
    frame->stream_id = stream_id;
    frame->priority.exclusive = !!(dependency & ~STREAM_ID_MASK);
    frame->priority.dependency = dependency & STREAM_ID_MASK;
    frame->priority.weight = weight + 1;
    FSTRACE(ASYNCHTTP_H2F_DECODER_GOT_PRIORITY, decoder->uid, frame,
            (uint64_t) frame->stream_id, frame->priority.exclusive,
            (uint64_t) frame->priority.dependency);
    return frame;
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_GOT_RST_STREAM,
             "UID=%64u FRAME=%p STRID=%64u ERR=%64u");

static h2frame_t *decode_rst_stream(h2frame_decoder_t *decoder)
{
    if (get_payload_length(decoder) != 4)
        return decoding_error(decoder);
    uint32_t error_code;
    const uint8_t *p = decoder->decoding.buffer;
    p = get_uint32(p, &error_code);
    uint32_t stream_id = get_stream_id(decoder);
    clear_payload(decoder);
    set_decoder_state(decoder, DECODER_RECEIVING);
    h2frame_t *frame = fsalloc(sizeof *frame);
    frame->frame_type = H2FRAME_TYPE_RST_STREAM;
    frame->stream_id = stream_id;
    frame->rst_stream.error_code = error_code;
    FSTRACE(ASYNCHTTP_H2F_DECODER_GOT_RST_STREAM, decoder->uid, frame,
            (uint64_t) frame->stream_id,
            (uint64_t) frame->rst_stream.error_code);
    return frame;
}

static const char *trace_setting(void *pstate)
{
    unsigned param = *(unsigned *) pstate;
    switch (param) {
        case H2FRAME_SETTINGS_HEADER_TABLE_SIZE:
            return "H2FRAME_SETTINGS_HEADER_TABLE_SIZE";
        case H2FRAME_SETTINGS_ENABLE_PUSH:
            return "H2FRAME_SETTINGS_ENABLE_PUSH";
        case H2FRAME_SETTINGS_MAX_CONCURRENT_STREAMS:
            return "H2FRAME_SETTINGS_MAX_CONCURRENT_STREAMS";
        case H2FRAME_SETTINGS_INITIAL_WINDOW_SIZE:
            return "H2FRAME_SETTINGS_INITIAL_WINDOW_SIZE";
        case H2FRAME_SETTINGS_MAX_FRAME_SIZE:
            return "H2FRAME_SETTINGS_MAX_FRAME_SIZE";
        case H2FRAME_SETTINGS_MAX_HEADER_LIST_SIZE:
            return "H2FRAME_SETTINGS_MAX_HEADER_LIST_SIZE";
        default: {
            static char buffer[20];
            snprintf(buffer, sizeof buffer, "%u", param);
            return buffer;
        }
    }
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_GOT_SETTINGS,
             "UID=%64u FRAME=%p STRID=%64u ACK=%b SETTING-COUNT=%z");
FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_SETTING, "UID=%64u PARAM=%I VALUE=%64u");

static h2frame_t *decode_settings(h2frame_decoder_t *decoder)
{
    size_t payload_length = get_payload_length(decoder);
    if (payload_length % 6)
        return decoding_error(decoder);
    unsigned setting_count = payload_length / 6;
    list_t *settings = make_list();
    const uint8_t *end;
    const uint8_t *p = bound(decoder, &end);
    unsigned i;
    for (i = 0; i < setting_count; i++) {
        uint16_t identifier;
        uint32_t value;
        p = get_uint16(p, &identifier);
        p = get_uint32(p, &value);
        list_append(settings, h2frame_make_setting(identifier, value));
    }
    bool ack = get_flag(decoder, H2FRAME_FLAG_ACK);
    uint32_t stream_id = get_stream_id(decoder);
    clear_payload(decoder);
    set_decoder_state(decoder, DECODER_RECEIVING);
    h2frame_t *frame = fsalloc(sizeof *frame);
    frame->frame_type = H2FRAME_TYPE_SETTINGS;
    frame->stream_id = stream_id;
    frame->settings.ack = ack;
    frame->settings.settings = settings;
    FSTRACE(ASYNCHTTP_H2F_DECODER_GOT_SETTINGS, decoder->uid, frame,
            (uint64_t) frame->stream_id, frame->settings.ack,
            list_size(frame->settings.settings));
    if (FSTRACE_ENABLED(ASYNCHTTP_H2F_DECODER_SETTING)) {
        list_elem_t *e;
        for (e = list_get_first(settings); e; e = list_next(e)) {
            const h2frame_setting_t *setting = list_elem_get_value(e);
            FSTRACE(ASYNCHTTP_H2F_DECODER_SETTING, decoder->uid,
                    trace_setting, &setting->parameter,
                    (uint64_t) setting->value);
        }
    }
    return frame;
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_GOT_PUSH_PROMISE,
             "UID=%64u FRAME=%p STRID=%64u ENDH=%b PROM-STRID=%64u");

static h2frame_t *decode_push_promise(h2frame_decoder_t *decoder)
{
    const uint8_t *end;
    const uint8_t *p = unpad(decoder, &end);
    if (!p || end < p + 4)
        return decoding_error(decoder);
    bool end_headers = get_flag(decoder, H2FRAME_FLAG_END_HEADERS);
    uint32_t promised;
    p = get_uint32(p, &promised);
    list_t *headers = get_header_block_fragment(decoder, p, end);
    if (!headers)
        return decoding_error(decoder);
    uint32_t stream_id = get_stream_id(decoder);
    clear_payload(decoder);
    set_decoder_state(decoder, DECODER_RECEIVING);
    h2frame_t *frame = fsalloc(sizeof *frame);
    frame->frame_type = H2FRAME_TYPE_PUSH_PROMISE;
    frame->stream_id = stream_id;
    frame->push_promise.end_headers = end_headers;
    frame->push_promise.promised = promised & STREAM_ID_MASK;
    frame->push_promise.headers = headers;
    FSTRACE(ASYNCHTTP_H2F_DECODER_GOT_PUSH_PROMISE, decoder->uid, frame,
            (uint64_t) frame->stream_id, frame->push_promise.end_headers,
            (uint64_t) frame->push_promise.promised);
    trace_headers(decoder, headers);
    return frame;
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_GOT_PING,
             "UID=%64u FRAME=%p STRID=%64u ACK=%b DATA=%A");

static h2frame_t *decode_ping(h2frame_decoder_t *decoder)
{
    if (get_payload_length(decoder) != 8)
        return decoding_error(decoder);
    bool ack = get_flag(decoder, H2FRAME_FLAG_ACK);

    h2frame_t *frame = fsalloc(sizeof *frame);
    frame->frame_type = H2FRAME_TYPE_PING;
    frame->stream_id = get_stream_id(decoder);
    frame->ping.ack = ack;
    memcpy(frame->ping.data, decoder->decoding.buffer, 8);
    clear_payload(decoder);
    set_decoder_state(decoder, DECODER_RECEIVING);
    FSTRACE(ASYNCHTTP_H2F_DECODER_GOT_PING, decoder->uid, frame,
            (uint64_t) frame->stream_id, frame->ping.ack,
            frame->ping.data, sizeof frame->ping.data);
    return frame;
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_GOT_GOAWAY,
             "UID=%64u FRAME=%p STRID=%64u LAST-STRID=%64u ERR=%64u DEBUG=%A");

static h2frame_t *decode_goaway(h2frame_decoder_t *decoder)
{
    size_t payload_length = get_payload_length(decoder);
    if (payload_length < 8)
        return decoding_error(decoder);
    uint32_t last_stream_id, error_code;
    const uint8_t *p = decoder->decoding.buffer;
    p = get_uint32(p, &last_stream_id);
    p = get_uint32(p, &error_code);
    uint8_t *debug_data = decoder->decoding.buffer;
    decoder->decoding.buffer = NULL;
    memmove(debug_data, p, payload_length - 8);
    uint32_t stream_id = get_stream_id(decoder);
    clear_payload(decoder);
    set_decoder_state(decoder, DECODER_RECEIVING);
    h2frame_t *frame = fsalloc(sizeof *frame);
    frame->frame_type = H2FRAME_TYPE_GOAWAY;
    frame->stream_id = stream_id;
    frame->goaway.last_stream_id = last_stream_id & STREAM_ID_MASK;
    frame->goaway.error_code = error_code;
    frame->goaway.debug_data = debug_data;
    frame->goaway.debug_data_length = payload_length - 8;
    FSTRACE(ASYNCHTTP_H2F_DECODER_GOT_GOAWAY, decoder->uid, frame,
            (uint64_t) frame->stream_id,
            (uint64_t) frame->goaway.last_stream_id,
            (uint64_t) frame->goaway.error_code,
            frame->goaway.debug_data, frame->goaway.debug_data_length);
    return frame;
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_GOT_WINDOW_UPDATE,
             "UID=%64u FRAME=%p STRID=%64u INCREMENT=%64u");

static h2frame_t *decode_window_update(h2frame_decoder_t *decoder)
{
    if (get_payload_length(decoder) != 4)
        return decoding_error(decoder);
    uint32_t increment;
    const uint8_t *p = decoder->decoding.buffer;
    p = get_uint32(p, &increment);
    uint32_t stream_id = get_stream_id(decoder);
    clear_payload(decoder);
    set_decoder_state(decoder, DECODER_RECEIVING);
    h2frame_t *frame = fsalloc(sizeof *frame);
    frame->frame_type = H2FRAME_TYPE_WINDOW_UPDATE;
    frame->stream_id = stream_id;
    frame->window_update.increment = increment & STREAM_ID_MASK;
    FSTRACE(ASYNCHTTP_H2F_DECODER_GOT_WINDOW_UPDATE, decoder->uid, frame,
            (uint64_t) frame->stream_id,
            (uint64_t) frame->window_update.increment);
    return frame;
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_GOT_CONTINUATION,
             "UID=%64u FRAME=%p STRID=%64u ENDH=%b");

static h2frame_t *decode_continuation(h2frame_decoder_t *decoder)
{
    const uint8_t *end;
    const uint8_t *p = bound(decoder, &end);
    list_t *headers = get_header_block_fragment(decoder, p, end);
    if (!headers)
        return decoding_error(decoder);
    bool end_headers = get_flag(decoder, H2FRAME_FLAG_END_HEADERS);
    uint32_t stream_id = get_stream_id(decoder);
    clear_payload(decoder);
    set_decoder_state(decoder, DECODER_RECEIVING);
    h2frame_t *frame = fsalloc(sizeof *frame);
    frame->frame_type = H2FRAME_TYPE_CONTINUATION;
    frame->stream_id = stream_id;
    frame->continuation.end_headers = end_headers;
    frame->continuation.headers = headers;
    FSTRACE(ASYNCHTTP_H2F_DECODER_GOT_CONTINUATION, decoder->uid, frame,
            (uint64_t) frame->stream_id, frame->continuation.end_headers);
    trace_headers(decoder, headers);
    return frame;
}

static h2frame_t *decode(h2frame_decoder_t *decoder)
{
    switch (decoder->decoding.raw_frame->type) {
        case H2FRAME_TYPE_DATA:
            return decode_data(decoder);
        case H2FRAME_TYPE_HEADERS:
            return decode_headers(decoder);
        case H2FRAME_TYPE_PRIORITY:
            return decode_priority(decoder);
        case H2FRAME_TYPE_RST_STREAM:
            return decode_rst_stream(decoder);
        case H2FRAME_TYPE_SETTINGS:
            return decode_settings(decoder);
        case H2FRAME_TYPE_PUSH_PROMISE:
            return decode_push_promise(decoder);
        case H2FRAME_TYPE_PING:
            return decode_ping(decoder);
        case H2FRAME_TYPE_GOAWAY:
            return decode_goaway(decoder);
        case H2FRAME_TYPE_WINDOW_UPDATE:
            return decode_window_update(decoder);
        case H2FRAME_TYPE_CONTINUATION:
            return decode_continuation(decoder);
        default:
            assert(false);      /* unreachable */
    }
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_RECEIVE_PREAMBLE, "UID=%64u");

static h2frame_t *receive_decoding(h2frame_decoder_t *decoder)
{
    FSTRACE(ASYNCHTTP_H2F_DECODER_RECEIVE_PREAMBLE, decoder->uid);
    for (;;) {
        size_t remaining = decoder->decoding.need - decoder->decoding.cursor;
        if (!remaining)
            return decode(decoder);
        uint8_t *p = decoder->decoding.buffer + decoder->decoding.cursor;
        ssize_t count =
            bytestream_1_read(decoder->decoding.raw_frame->payload,
                              p, remaining);
        if (count < 0)
            return NULL;
        if (count == 0)
            return decoding_error(decoder);
        decoder->decoding.cursor += count;
    }
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_PROBE_PREAMBLE, "UID=%64u");

static void probe_preamble(h2frame_decoder_t *decoder)
{
    FSTRACE(ASYNCHTTP_H2F_DECODER_PROBE_PREAMBLE, decoder->uid);
    action_1_perf(decoder->callback);
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_RECEIVE_FAIL, "UID=%64u ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_RECEIVE_TYPE, "UID=%64u FRAME-TYPE=%I");
FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_RECEIVE_SKIP, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_RECEIVE_TOO_BIG, "UID=%64u");

static h2frame_t *receive_receiving(h2frame_decoder_t *decoder)
{
    for (;;) {
        h2frame_raw_t *raw_frame = yield_1_receive(decoder->source);
        if (!raw_frame) {
            FSTRACE(ASYNCHTTP_H2F_DECODER_RECEIVE_FAIL, decoder->uid);
            return NULL;
        }
        uint8_t frame_type = raw_frame->type;
        FSTRACE(ASYNCHTTP_H2F_DECODER_RECEIVE_TYPE, decoder->uid,
                trace_frame_type, &frame_type);
        size_t need;
        switch (frame_type) {
            case H2FRAME_TYPE_DATA:
                if (raw_frame->flags & H2FRAME_FLAG_PADDED)
                    need = 1;
                else need = 0;
                break;
            case H2FRAME_TYPE_HEADERS:
            case H2FRAME_TYPE_PRIORITY:
            case H2FRAME_TYPE_RST_STREAM:
            case H2FRAME_TYPE_SETTINGS:
            case H2FRAME_TYPE_PUSH_PROMISE:
            case H2FRAME_TYPE_PING:
            case H2FRAME_TYPE_GOAWAY:
            case H2FRAME_TYPE_WINDOW_UPDATE:
            case H2FRAME_TYPE_CONTINUATION:
                need = raw_frame->payload_length;
                break;
            default:
                FSTRACE(ASYNCHTTP_H2F_DECODER_RECEIVE_SKIP, decoder->uid);
                bytestream_1_close(raw_frame->payload);
                continue;
        }
        if (need > decoder->max_nondata_length) {
            FSTRACE(ASYNCHTTP_H2F_DECODER_RECEIVE_TOO_BIG, decoder->uid);
            bytestream_1_close(raw_frame->payload);
            set_decoder_state(decoder, DECODER_ERRORED);
            errno = decoder->errored.error = EMSGSIZE;
            return NULL;
        }
        set_decoder_state(decoder, DECODER_DECODING);
        action_1 preamble_callback = { decoder, (act_1) probe_preamble };
        bytestream_1_register_callback(raw_frame->payload, preamble_callback);
        decoder->decoding.raw_frame = raw_frame;
        decoder->decoding.cursor = 0;
        decoder->decoding.need = need;
        decoder->decoding.buffer = fsalloc(need);
        return receive_decoding(decoder);
    }
}

static h2frame_t *receive(h2frame_decoder_t *decoder)
{
    switch (decoder->state) {
        case DECODER_RECEIVING:
            return receive_receiving(decoder);
        case DECODER_DECODING:
            return receive_decoding(decoder);
        case DECODER_READING_DATA_PAYLOAD:
            errno = EAGAIN;
            return NULL;
        case DECODER_ERRORED:
            errno = decoder->errored.error;
            return NULL;
        default:
            assert(false);
    }
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_RECEIVE, "UID=%64u FRAME=%p ERRNO=%e");

h2frame_t *h2frame_decoder_receive(h2frame_decoder_t *decoder)
{
    h2frame_t *frame = receive(decoder);
    FSTRACE(ASYNCHTTP_H2F_DECODER_RECEIVE, decoder->uid, frame);
    return frame;
}

FSTRACE_DECL(ASYNCHTTP_H2F_DECODER_CLOSE, "UID=%64u");

void h2frame_decoder_close(h2frame_decoder_t *decoder)
{
    FSTRACE(ASYNCHTTP_H2F_DECODER_CLOSE, decoder->uid);
    if (decoder->state == DECODER_DECODING)
        clear_payload(decoder);
    yield_1_close(decoder->source);
    set_decoder_state(decoder, DECODER_ZOMBIE);
    async_wound(decoder->async, decoder);
}

void h2frame_decoder_register_callback(h2frame_decoder_t *decoder,
                                       action_1 action)
{
    decoder->callback = action;
    yield_1_register_callback(decoder->source, action);
}

void h2frame_decoder_unregister_callback(h2frame_decoder_t *decoder)
{
    decoder->callback = NULL_ACTION_1;
    yield_1_unregister_callback(decoder->source);
}

static void *_receive(void *obj)
{
    return h2frame_decoder_receive(obj);
}

static void _close(void *obj)
{
    h2frame_decoder_close(obj);
}

static void _register_callback(void *obj, action_1 action)
{
    h2frame_decoder_register_callback(obj, action);
}

static void _unregister_callback(void *obj)
{
    h2frame_decoder_unregister_callback(obj);
}

static const struct yield_1_vt h2frame_decoder_vt = {
    .receive = _receive,
    .close = _close,
    .register_callback = _register_callback,
    .unregister_callback = _unregister_callback
};
    
yield_1 h2frame_decoder_as_yield_1(h2frame_decoder_t *decoder)
{
    return (yield_1) { decoder, &h2frame_decoder_vt };
}
