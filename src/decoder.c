#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#include <fstrace.h>
#include <fsdyn/list.h>
#include <fsdyn/fsalloc.h>
#include <async/queuestream.h>
#include <async/chunkdecoder.h>
#include <async/nicestream.h>
#include <async/emptystream.h>
#include <async/blobstream.h>
#include "decoder.h"
#include "field_reader.h"
#include "asynchttp_version.h"

static void __attribute__ ((noinline)) protocol_violation(void)
{
    /* set your breakpoint here*/
    errno = EPROTO;
}

typedef enum {
    HTTP_DECODER_READING_HEADERS,
    HTTP_DECODER_HEADERS_DEQUEUED,
    HTTP_DECODER_READING_CONTENT,
    HTTP_DECODER_CLOSED_READING_CONTENT,
    HTTP_DECODER_SKIPPING_CHUNKED,
    HTTP_DECODER_SKIPPING_TRAILER,
    HTTP_DECODER_SKIPPING_BOUNDED,
    HTTP_DECODER_DISCONNECTED,
    HTTP_DECODER_ERRORED,
    HTTP_DECODER_ZOMBIE
} http_decoder_state_t;

enum {
    HTTP_DECODE_UNKNOWN = -99
};

struct http_decoder {
    async_t *async;
    uint64_t uid;
    queuestream_t *input_stream;
    http_decoder_state_t state;
    union {
        struct {
            /* HTTP_DECODER_READING_HEADERS */
            field_reader_t *reader;
        } reading_headers;
        struct {
            /* HTTP_DECODER_HEADERS_DEQUEUED or HTTP_DECODER_READING_CONTENT */
            http_env_t *envelope;
            char *header_buffer;
            char *trailer_buffer; /* may be NULL */
            size_t max_trailer_size;
            bytestream_1 output_stream; /* HTTP_DECODER_READING_CONTENT only */
            action_1 callback;
        } reading_content;
        struct {
            /* HTTP_DECODER_SKIPPING_CHUNKED */
            chunkdecoder_t *chunk_decoder;
            size_t max_trailer_size;
        } skipping_chunked;
        struct {
            /* HTTP_DECODER_SKIPPING_TRAILER */
            field_reader_t *reader;
        } skipping_trailer;
        struct {
            /* HTTP_DECODER_SKIPPING_BOUNDED */
            size_t remaining;
        } skipping_bounded;
    };
    action_1 callback;
    size_t max_envelope_size;
};

typedef enum {
    CHUNKED_WRAPPER_READING_CONTENT,
    CHUNKED_WRAPPER_READING_TRAILER,
    CHUNKED_WRAPPER_DONE,
    CHUNKED_WRAPPER_ERRORED
} chunked_wrapper_state_t;

typedef struct {
    http_decoder_t *decoder;
    uint64_t uid;
    chunkdecoder_t *chunk_decoder;
    chunked_wrapper_state_t state;
    field_reader_t *reader;     /* CHUNKED_WRAPPER_READING_TRAILER */
} chunked_wrapper_t;

typedef struct {
    http_decoder_t *decoder;
    uint64_t uid;
} exhaust_wrapper_t;

typedef struct {
    http_decoder_t *decoder;
    uint64_t uid;
    size_t remaining;
    int errored;
} bounded_wrapper_t;

FSTRACE_DECL(ASYNCHTTP_DECODER_HEADER_NOTIFICATION, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_DECODER_CONTENT_NOTIFICATION, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_DECODER_NO_NOTIFICATION, "UID=%64u");

static void input_notification(http_decoder_t *decoder)
{
    switch (decoder->state) {
        case HTTP_DECODER_READING_HEADERS:
        case HTTP_DECODER_SKIPPING_CHUNKED:
        case HTTP_DECODER_SKIPPING_BOUNDED:
            FSTRACE(ASYNCHTTP_DECODER_HEADER_NOTIFICATION, decoder->uid);
            action_1_perf(decoder->callback);
            break;
        case HTTP_DECODER_READING_CONTENT:
            FSTRACE(ASYNCHTTP_DECODER_CONTENT_NOTIFICATION, decoder->uid);
            action_1_perf(decoder->reading_content.callback);
            break;
        case HTTP_DECODER_HEADERS_DEQUEUED:
        case HTTP_DECODER_DISCONNECTED:
        case HTTP_DECODER_ERRORED:
        case HTTP_DECODER_ZOMBIE:
            FSTRACE(ASYNCHTTP_DECODER_NO_NOTIFICATION, decoder->uid);
            break;
        default:
            abort();
    }
}

static const char *trace_state(void *pstate)
{
    switch (*(http_decoder_state_t *) pstate) {
        case HTTP_DECODER_READING_HEADERS:
            return "HTTP_DECODER_READING_HEADERS";
        case HTTP_DECODER_HEADERS_DEQUEUED:
            return "HTTP_DECODER_HEADERS_DEQUEUED";
        case HTTP_DECODER_READING_CONTENT:
            return "HTTP_DECODER_READING_CONTENT";
        case HTTP_DECODER_CLOSED_READING_CONTENT:
            return "HTTP_DECODER_CLOSED_READING_CONTENT";
        case HTTP_DECODER_SKIPPING_CHUNKED:
            return "HTTP_DECODER_SKIPPING_CHUNKED";
        case HTTP_DECODER_SKIPPING_TRAILER:
            return "HTTP_DECODER_SKIPPING_TRAILER";
        case HTTP_DECODER_SKIPPING_BOUNDED:
            return "HTTP_DECODER_SKIPPING_BOUNDED";
        case HTTP_DECODER_DISCONNECTED:
            return "HTTP_DECODER_DISCONNECTED";
        case HTTP_DECODER_ERRORED:
            return "HTTP_DECODER_ERRORED";
        case HTTP_DECODER_ZOMBIE:
            return "HTTP_DECODER_ZOMBIE";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCHTTP_DECODER_SET_STATE, "UID=%64u OLD=%I NEW=%I");

static void set_decoder_state(http_decoder_t *decoder,
                              http_decoder_state_t state)
{
    FSTRACE(ASYNCHTTP_DECODER_SET_STATE, decoder->uid,
            trace_state, &decoder->state, trace_state, &state);
    decoder->state = state;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_START, "UID=%64u");

static void start_reading(http_decoder_t *decoder)
{
    FSTRACE(ASYNCHTTP_DECODER_START, decoder->uid);
    decoder->reading_headers.reader =
        make_field_reader(queuestream_as_bytestream_1(decoder->input_stream),
                          decoder->max_envelope_size);
    set_decoder_state(decoder, HTTP_DECODER_READING_HEADERS);
}

FSTRACE_DECL(ASYNCHTTP_DECODER_CREATE,
             "UID=%64u PTR=%p ASYNC=%p INPUT=%p Q=%p MAX-SIZE=%z");

http_decoder_t *open_http_decoder(async_t *async, bytestream_1 input_stream,
                                  size_t max_envelope_size)
{
    http_decoder_t *decoder = fsalloc(sizeof *decoder);
    decoder->async = async;
    decoder->uid = fstrace_get_unique_id();
    decoder->input_stream = make_queuestream(async);
    nicestream_t *nice_input = make_nice(async, input_stream, 100000);
    queuestream_enqueue(decoder->input_stream,
                        nicestream_as_bytestream_1(nice_input));
    queuestream_terminate(decoder->input_stream);
    FSTRACE(ASYNCHTTP_DECODER_CREATE, decoder->uid, decoder, async,
            input_stream.obj, decoder->input_stream, max_envelope_size);
    action_1 input_cb = { decoder, (act_1) input_notification };
    queuestream_register_callback(decoder->input_stream, input_cb);
    decoder->callback = NULL_ACTION_1;
    decoder->max_envelope_size = max_envelope_size;
    /* Set decoder->state redundantly to accommodate tracing in
     * set_decoder_state() in start_reading(). */
    decoder->state = HTTP_DECODER_READING_HEADERS;
    start_reading(decoder);
    return decoder;
}

static void destroy_reading_content(http_decoder_t *decoder)
{
    destroy_http_env(decoder->reading_content.envelope);
    fsfree(decoder->reading_content.header_buffer);
    if (decoder->reading_content.trailer_buffer)
        fsfree(decoder->reading_content.trailer_buffer);
}

static void close_decoder(http_decoder_t *decoder)
{
    switch (decoder->state) {
        case HTTP_DECODER_READING_HEADERS:
            field_reader_close(decoder->reading_headers.reader);
            break;
        case HTTP_DECODER_HEADERS_DEQUEUED:
            destroy_reading_content(decoder);
            break;
        case HTTP_DECODER_CLOSED_READING_CONTENT:
            break;
        case HTTP_DECODER_SKIPPING_CHUNKED:
            chunkdecoder_close(decoder->skipping_chunked.chunk_decoder);
            break;
        case HTTP_DECODER_SKIPPING_TRAILER:
            field_reader_close(decoder->skipping_trailer.reader);
            break;
        case HTTP_DECODER_ERRORED:
        case HTTP_DECODER_DISCONNECTED:
        case HTTP_DECODER_SKIPPING_BOUNDED:
            break;
        default:
            abort();
    };
    if (decoder->input_stream)
        queuestream_close(decoder->input_stream);
    set_decoder_state(decoder, HTTP_DECODER_ZOMBIE);
    async_wound(decoder->async, decoder);
}

FSTRACE_DECL(ASYNCHTTP_DECODER_CLOSE, "UID=%64u");

void http_decoder_close(http_decoder_t *decoder)
{
    FSTRACE(ASYNCHTTP_DECODER_CLOSE, decoder->uid);
    switch (decoder->state) {
        case HTTP_DECODER_READING_CONTENT:
            set_decoder_state(decoder, HTTP_DECODER_CLOSED_READING_CONTENT);
            break;
        default:
            close_decoder(decoder);
    };
}

static bool reading_content(http_decoder_t *decoder)
{
    switch (decoder->state) {
        case HTTP_DECODER_READING_CONTENT:
        case HTTP_DECODER_CLOSED_READING_CONTENT:
            return true;
        default:
            return false;
    }
}

static void stop_reading_content(http_decoder_t *decoder)
{
    switch (decoder->state) {
        case HTTP_DECODER_READING_CONTENT:
            destroy_reading_content(decoder);
            break;
        case HTTP_DECODER_CLOSED_READING_CONTENT:
            destroy_reading_content(decoder);
            close_decoder(decoder);
            break;
        default:
            assert(false);
    }
}

static void register_content_callback(http_decoder_t *decoder, action_1 action)
{
    assert(decoder->state == HTTP_DECODER_READING_CONTENT);
    decoder->reading_content.callback = action;
}

static void unregister_content_callback(http_decoder_t *decoder)
{
    assert(decoder->state == HTTP_DECODER_READING_CONTENT);
    decoder->reading_content.callback = NULL_ACTION_1;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_CREATE,
             "UID=%64u PTR=%p DECODER=%64u ASSEMBLER=%p");

static chunked_wrapper_t *open_chunked_wrapper(http_decoder_t *decoder)
{
    assert(decoder->state == HTTP_DECODER_HEADERS_DEQUEUED);
    chunked_wrapper_t *wrapper = fsalloc(sizeof *wrapper);
    wrapper->decoder = decoder;
    wrapper->uid = fstrace_get_unique_id();
    wrapper->chunk_decoder =
        chunk_decode(decoder->async,
                     queuestream_as_bytestream_1(decoder->input_stream),
                     CHUNKDECODER_DETACH_AT_TRAILER);
    FSTRACE(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_CREATE,
            wrapper->uid, wrapper, decoder->uid, wrapper->chunk_decoder);
    // TODO: final extensions
    wrapper->state = CHUNKED_WRAPPER_READING_CONTENT;
    wrapper->reader = NULL;
    return wrapper;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_CLOSE_READER, "UID=%64u");

static void close_reader(http_decoder_t *decoder, field_reader_t *reader)
{
    FSTRACE(ASYNCHTTP_DECODER_CLOSE_READER, decoder->uid);
    blobstream_t *prefix =
        copy_blobstream(decoder->async,
                        field_reader_leftover_bytes(reader),
                        field_reader_leftover_size(reader));
    queuestream_push(decoder->input_stream,
                     blobstream_as_bytestream_1(prefix));
    field_reader_close(reader);
}

static const char *trace_chunked_wrapper_state(void *pstate)
{
    switch (*(chunked_wrapper_state_t *) pstate) {
        case CHUNKED_WRAPPER_READING_CONTENT:
            return "CHUNKED_WRAPPER_READING_CONTENT";
        case CHUNKED_WRAPPER_READING_TRAILER:
            return "CHUNKED_WRAPPER_READING_TRAILER";
        case CHUNKED_WRAPPER_DONE:
            return "CHUNKED_WRAPPER_DONE";
        case CHUNKED_WRAPPER_ERRORED:
            return "CHUNKED_WRAPPER_ERRORED";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_SET_STATE,
             "UID=%64u DECODER=%64u OLD=%I NEW=%I");

static void chunked_wrapper_set_state(chunked_wrapper_t *wrapper,
                                      chunked_wrapper_state_t state)
{
    FSTRACE(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_SET_STATE,
            wrapper->uid, wrapper->decoder->uid,
            trace_chunked_wrapper_state, &wrapper->state,
            trace_chunked_wrapper_state, &state);
    wrapper->state = state;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_TRAILER_READ_FAIL,
             "UID=%64u DECODER=%64u ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_TRAILER_EXHAUSTED,
             "UID=%64u DECODER=%64u");
FSTRACE_DECL(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_TRAILER_SYNTAX_ERROR,
             "UID=%64u DECODER=%64u");
FSTRACE_DECL(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_TRAILER_READ,
             "UID=%64u DECODER=%64u");

static ssize_t chunked_wrapper_read_trailer(chunked_wrapper_t *wrapper)
{
    http_decoder_t *decoder = wrapper->decoder;
    assert(reading_content(decoder));
    assert(wrapper->state == CHUNKED_WRAPPER_READING_TRAILER);
    assert(wrapper->reader);
    int status = field_reader_read(wrapper->reader);
    if (status < 0) {
        if (errno == EPROTO) {
            field_reader_close(wrapper->reader);
            chunked_wrapper_set_state(wrapper, CHUNKED_WRAPPER_ERRORED);
            protocol_violation();
        }
        FSTRACE(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_TRAILER_READ_FAIL,
                wrapper->uid, decoder->uid);
        return -1;
    }
    if (status == 0) {
        FSTRACE(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_TRAILER_EXHAUSTED,
                wrapper->uid, decoder->uid);
        field_reader_close(wrapper->reader);
        chunked_wrapper_set_state(wrapper, CHUNKED_WRAPPER_ERRORED);
        protocol_violation();
        return -1;
    }
    const char *end;
    char *trailer_buffer = field_reader_combine(wrapper->reader, &end);
    if (!http_env_parse_trailers(decoder->reading_content.envelope,
                                 trailer_buffer, end)) {
        FSTRACE(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_TRAILER_SYNTAX_ERROR,
                wrapper->uid, decoder->uid);
        fsfree(trailer_buffer);
        field_reader_close(wrapper->reader);
        chunked_wrapper_set_state(wrapper, CHUNKED_WRAPPER_ERRORED);
        protocol_violation();
        return -1;
    }
    FSTRACE(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_TRAILER_READ,
            wrapper->uid, decoder->uid);
    close_reader(decoder, wrapper->reader);
    decoder->reading_content.trailer_buffer = trailer_buffer;
    chunked_wrapper_set_state(wrapper, CHUNKED_WRAPPER_DONE);
    return 0;
}

static void push_leftovers(http_decoder_t *decoder,
                           chunkdecoder_t *chunk_decoder)
{
    blobstream_t *leftover =
        copy_blobstream(decoder->async,
                        chunkdecoder_leftover_bytes(chunk_decoder),
                        chunkdecoder_leftover_size(chunk_decoder));
    queuestream_push(decoder->input_stream,
                     blobstream_as_bytestream_1(leftover));
}

static ssize_t do_chunked_wrapper_read(chunked_wrapper_t *wrapper,
                                       void *buf, size_t count)
{
    http_decoder_t *decoder = wrapper->decoder;
    assert(reading_content(decoder));
    switch (wrapper->state) {
        case CHUNKED_WRAPPER_READING_CONTENT:
            break;
        case CHUNKED_WRAPPER_READING_TRAILER:
            return chunked_wrapper_read_trailer(wrapper);
        case CHUNKED_WRAPPER_DONE:
            return 0;
        case CHUNKED_WRAPPER_ERRORED:
            protocol_violation();
            return -1;
        default:
            abort();
    }
    if (count == 0)
        return 0;
    ssize_t n = chunkdecoder_read(wrapper->chunk_decoder, buf, count);
    if (n < 0) {
        if (errno == EPROTO)
            chunked_wrapper_set_state(wrapper, CHUNKED_WRAPPER_ERRORED);
        return -1;
    }
    if (n == 0) {
        push_leftovers(decoder, wrapper->chunk_decoder);
        bytestream_1 input_stream =
            queuestream_as_bytestream_1(decoder->input_stream);
        wrapper->reader =
            make_field_reader(input_stream,
                              decoder->reading_content.max_trailer_size);
        chunked_wrapper_set_state(wrapper, CHUNKED_WRAPPER_READING_TRAILER);
        return chunked_wrapper_read_trailer(wrapper);
    }
    return n;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_READ,
             "UID=%64u DECODER=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_READ_DUMP,
             "UID=%64u DECODER=%64u DATA=%B");

static ssize_t chunked_wrapper_read(chunked_wrapper_t *wrapper,
                                    void *buf, size_t count)
{
    ssize_t n = do_chunked_wrapper_read(wrapper, buf, count);
    FSTRACE(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_READ,
            wrapper->uid, wrapper->decoder->uid, count, n);
    FSTRACE(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_READ_DUMP,
            wrapper->uid, wrapper->decoder->uid, buf, n);
    return n;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_CLOSE, "UID=%64u DECODER=%64u");

static void chunked_wrapper_close(chunked_wrapper_t *wrapper)
{
    http_decoder_t *decoder = wrapper->decoder;
    FSTRACE(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_CLOSE,
            wrapper->uid, decoder->uid);
    stop_reading_content(decoder);
    async_wound(decoder->async, wrapper);
    if (decoder->state == HTTP_DECODER_ZOMBIE) {
        chunkdecoder_close(wrapper->chunk_decoder);
        return;
    }
    switch (wrapper->state) {
        case CHUNKED_WRAPPER_READING_CONTENT:
            decoder->skipping_chunked.chunk_decoder =
                wrapper->chunk_decoder;
            set_decoder_state(decoder, HTTP_DECODER_SKIPPING_CHUNKED);
            break;
        case CHUNKED_WRAPPER_READING_TRAILER:
            chunkdecoder_close(wrapper->chunk_decoder);
            decoder->skipping_trailer.reader = wrapper->reader;
            set_decoder_state(decoder, HTTP_DECODER_SKIPPING_TRAILER);
            break;
        case CHUNKED_WRAPPER_DONE:
            chunkdecoder_close(wrapper->chunk_decoder);
            start_reading(decoder);
            break;
        case CHUNKED_WRAPPER_ERRORED:
            chunkdecoder_close(wrapper->chunk_decoder);
            set_decoder_state(decoder, HTTP_DECODER_ERRORED);
            break;
        default:
            abort();
    }
}

FSTRACE_DECL(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_REGISTER,
             "UID=%64u DECODER=%64u OBJ=%p ACT=%p");

static void chunked_wrapper_register_callback(chunked_wrapper_t *wrapper,
                                              action_1 action)
{
    FSTRACE(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_REGISTER,
            wrapper->uid, wrapper->decoder->uid, action.obj, action.act);
    register_content_callback(wrapper->decoder, action);
}

FSTRACE_DECL(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_UNREGISTER,
             "UID=%64u DECODER=%64u");

static void chunked_wrapper_unregister_callback(chunked_wrapper_t *wrapper)
{
    FSTRACE(ASYNCHTTP_DECODER_CHUNKED_WRAPPER_UNREGISTER,
            wrapper->uid, wrapper->decoder->uid);
    unregister_content_callback(wrapper->decoder);
}

static const struct bytestream_1_vt chunked_wrapper_vt = {
    .read = (void *) chunked_wrapper_read,
    .close = (void *) chunked_wrapper_close,
    .register_callback = (void *) chunked_wrapper_register_callback,
    .unregister_callback = (void *) chunked_wrapper_unregister_callback
};

static bytestream_1 chunked_wrapper_as_bytestream_1(chunked_wrapper_t *wrapper)
{
    return (bytestream_1) { wrapper, &chunked_wrapper_vt };
}

FSTRACE_DECL(ASYNCHTTP_DECODER_EXHAUST_WRAPPER_CREATE,
             "UID=%64u PTR=%p DECODER=%64u");

static exhaust_wrapper_t *open_exhaust_wrapper(http_decoder_t *decoder)
{
    assert(decoder->state == HTTP_DECODER_HEADERS_DEQUEUED);
    exhaust_wrapper_t *wrapper = fsalloc(sizeof *wrapper);
    wrapper->decoder = decoder;
    wrapper->uid = fstrace_get_unique_id();
    FSTRACE(ASYNCHTTP_DECODER_EXHAUST_WRAPPER_CREATE,
            wrapper->uid, wrapper, decoder->uid);
    return wrapper;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_EXHAUST_WRAPPER_READ,
             "UID=%64u DECODER=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_DECODER_EXHAUST_WRAPPER_READ_DUMP,
             "UID=%64u DECODER=%64u DATA=%B");

static ssize_t exhaust_wrapper_read(exhaust_wrapper_t *wrapper,
                                    void *buf, size_t count)
{
    assert(reading_content(wrapper->decoder));
    size_t n = queuestream_read(wrapper->decoder->input_stream, buf, count);
    FSTRACE(ASYNCHTTP_DECODER_EXHAUST_WRAPPER_READ,
            wrapper->uid, wrapper->decoder->uid, count, n);
    FSTRACE(ASYNCHTTP_DECODER_EXHAUST_WRAPPER_READ_DUMP,
            wrapper->uid, wrapper->decoder->uid, buf, n);
    return n;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_EXHAUST_WRAPPER_CLOSE, "UID=%64u DECODER=%64u");

static void exhaust_wrapper_close(exhaust_wrapper_t *wrapper)
{
    http_decoder_t *decoder = wrapper->decoder;
    FSTRACE(ASYNCHTTP_DECODER_EXHAUST_WRAPPER_CLOSE,
            wrapper->uid, decoder->uid);
    stop_reading_content(decoder);
    async_wound(decoder->async, wrapper);
    if (decoder->state == HTTP_DECODER_ZOMBIE)
        return;
    start_reading(decoder);
}

FSTRACE_DECL(ASYNCHTTP_DECODER_EXHAUST_WRAPPER_REGISTER,
             "UID=%64u DECODER=%64u OBJ=%p ACT=%p");

static void exhaust_wrapper_register_callback(exhaust_wrapper_t *wrapper,
                                              action_1 action)
{
    FSTRACE(ASYNCHTTP_DECODER_EXHAUST_WRAPPER_REGISTER,
            wrapper->uid, wrapper->decoder->uid, action.obj, action.act);
    register_content_callback(wrapper->decoder, action);
}

FSTRACE_DECL(ASYNCHTTP_DECODER_EXHAUST_WRAPPER_UNREGISTER,
             "UID=%64u DECODER=%64u");

static void exhaust_wrapper_unregister_callback(exhaust_wrapper_t *wrapper)
{
    FSTRACE(ASYNCHTTP_DECODER_EXHAUST_WRAPPER_UNREGISTER,
            wrapper->uid, wrapper->decoder->uid);
    unregister_content_callback(wrapper->decoder);
}

static const struct bytestream_1_vt exhaust_wrapper_vt = {
    .read = (void *) exhaust_wrapper_read,
    .close = (void *) exhaust_wrapper_close,
    .register_callback = (void *) exhaust_wrapper_register_callback,
    .unregister_callback = (void *) exhaust_wrapper_unregister_callback
};

static bytestream_1 exhaust_wrapper_as_bytestream_1(exhaust_wrapper_t *wrapper)
{
    return (bytestream_1) { wrapper, &exhaust_wrapper_vt };
}

FSTRACE_DECL(ASYNCHTTP_DECODER_BOUNDED_WRAPPER_CREATE,
             "UID=%64u PTR=%p DECODER=%64u CLEN=%z");

static bounded_wrapper_t *open_bounded_wrapper(http_decoder_t *decoder,
                                               size_t content_length)
{
    assert(decoder->state == HTTP_DECODER_HEADERS_DEQUEUED);
    bounded_wrapper_t *wrapper = fsalloc(sizeof *wrapper);
    wrapper->decoder = decoder;
    wrapper->uid = fstrace_get_unique_id();
    FSTRACE(ASYNCHTTP_DECODER_BOUNDED_WRAPPER_CREATE,
            wrapper->uid, wrapper, decoder->uid, content_length);
    wrapper->remaining = content_length;
    wrapper->errored = 0;
    return wrapper;
}

static ssize_t do_bounded_wrapper_read(bounded_wrapper_t *wrapper,
                                       void *buf, size_t count)
{
    assert(reading_content(wrapper->decoder));
    if (wrapper->errored) {
        protocol_violation();
        return -1;
    }
    if (count == 0 || wrapper->remaining == 0)
        return 0;
    if (count > wrapper->remaining)
        count = wrapper->remaining;
    ssize_t n = queuestream_read(wrapper->decoder->input_stream, buf, count);
    if (n < 0)
        return -1;
    if (n == 0) {
        /* Premature EOF */
        wrapper->errored = 1;
        protocol_violation();
        return -1;
    }
    wrapper->remaining -= n;
    return n;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_BOUNDED_WRAPPER_READ,
             "UID=%64u DECODER=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_DECODER_BOUNDED_WRAPPER_READ_DUMP,
             "UID=%64u DECODER=%64u DATA=%B");

static ssize_t bounded_wrapper_read(bounded_wrapper_t *wrapper,
                                    void *buf, size_t count)
{
    size_t n = do_bounded_wrapper_read(wrapper, buf, count);
    FSTRACE(ASYNCHTTP_DECODER_BOUNDED_WRAPPER_READ,
            wrapper->uid, wrapper->decoder->uid, count, n);
    FSTRACE(ASYNCHTTP_DECODER_BOUNDED_WRAPPER_READ_DUMP,
            wrapper->uid, wrapper->decoder->uid, buf, n);
    return n;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_BOUNDED_WRAPPER_CLOSE, "UID=%64u DECODER=%64u");

static void bounded_wrapper_close(bounded_wrapper_t *wrapper)
{
    http_decoder_t *decoder = wrapper->decoder;
    FSTRACE(ASYNCHTTP_DECODER_BOUNDED_WRAPPER_CLOSE,
            wrapper->uid, decoder->uid);
    stop_reading_content(decoder);
    async_wound(decoder->async, wrapper);
    if (decoder->state == HTTP_DECODER_ZOMBIE)
        return;
    if (wrapper->errored) {
        set_decoder_state(decoder, HTTP_DECODER_ERRORED);
        return;
    }
    decoder->skipping_bounded.remaining = wrapper->remaining;
    set_decoder_state(decoder, HTTP_DECODER_SKIPPING_BOUNDED);
}

FSTRACE_DECL(ASYNCHTTP_DECODER_BOUNDED_WRAPPER_REGISTER,
             "UID=%64u DECODER=%64u OBJ=%p ACT=%p");

static void bounded_wrapper_register_callback(bounded_wrapper_t *wrapper,
                                              action_1 action)
{
    FSTRACE(ASYNCHTTP_DECODER_BOUNDED_WRAPPER_REGISTER,
            wrapper->uid, wrapper->decoder->uid, action.obj, action.act);
    register_content_callback(wrapper->decoder, action);
}

FSTRACE_DECL(ASYNCHTTP_DECODER_BOUNDED_WRAPPER_UNREGISTER,
             "UID=%64u DECODER=%64u");

static void bounded_wrapper_unregister_callback(bounded_wrapper_t *wrapper)
{
    FSTRACE(ASYNCHTTP_DECODER_BOUNDED_WRAPPER_UNREGISTER,
            wrapper->uid, wrapper->decoder->uid);
    unregister_content_callback(wrapper->decoder);
}

static const struct bytestream_1_vt bounded_wrapper_vt = {
    .read = (void *) bounded_wrapper_read,
    .close = (void *) bounded_wrapper_close,
    .register_callback = (void *) bounded_wrapper_register_callback,
    .unregister_callback = (void *) bounded_wrapper_unregister_callback
};

static bytestream_1 bounded_wrapper_as_bytestream_1(bounded_wrapper_t *wrapper)
{
    return (bytestream_1) { wrapper, &bounded_wrapper_vt };
}

static ssize_t scan_size(const char *p)
{
    ssize_t size = 0;
    for (;;) {
        char c = *p++;
        if (c >= '0' && c <= '9') {
            if (size > SSIZE_MAX / 10)
                return -1;      /* overflow */
            size *= 10;
            int digit = c - '0';
            if (digit > SSIZE_MAX - size)
                return -1;      /* overflow */
            size += digit;
        }
        else if (!c)
            return size;
        else return -1;         /* illegal character */
    }
}

static ssize_t discover_content_length(const http_env_t *envelope)
{
    http_env_iter_t *iter = NULL;
    for (;;) {
        const char *field, *value;
        iter = http_env_get_next_header(envelope, iter, &field, &value);
        if (!iter)
            return HTTP_DECODE_EXHAUST;
        if (compare_case_insensitively(field, "transfer-encoding") == 0) {
            if (compare_case_insensitively(value, "chunked") == 0)
                return HTTP_DECODE_CHUNKED;
            return HTTP_DECODE_UNKNOWN;
        }
        if (compare_case_insensitively(field, "content-length") == 0) {
            ssize_t size = scan_size(value);
            if (size < 0)
                return HTTP_DECODE_UNKNOWN;
            return size;
        }
    }
}

static bool prepare_content(http_decoder_t *decoder, ssize_t content_length,
                            bytestream_1 *content)
{
    if (content_length == HTTP_DECODE_OBEY_HEADER)
        content_length =
            discover_content_length(decoder->reading_content.envelope);
    switch (content_length) {
        case HTTP_DECODE_CHUNKED:
            {
                chunked_wrapper_t *wrapper = open_chunked_wrapper(decoder);
                *content = chunked_wrapper_as_bytestream_1(wrapper);
            }
            return true;
        case HTTP_DECODE_EXHAUST:
            {
                exhaust_wrapper_t *wrapper = open_exhaust_wrapper(decoder);
                *content = exhaust_wrapper_as_bytestream_1(wrapper);
            }
            return true;
        case HTTP_DECODE_UNKNOWN:
            return false;
        default:
            assert(content_length >= 0);
            {
                bounded_wrapper_t *wrapper =
                    open_bounded_wrapper(decoder, content_length);
                *content = bounded_wrapper_as_bytestream_1(wrapper);
            }
            return true;
    }
}

static bool can_dequeue_skipping_trailer(http_decoder_t *decoder)
{
    field_reader_t *reader = decoder->skipping_trailer.reader;
    int status = field_reader_read(reader);
    if (status < 0) {
        if (errno == EPROTO) {
            field_reader_close(reader);
            set_decoder_state(decoder, HTTP_DECODER_ERRORED);
        }
        return false;
    }
    if (status == 0) {
        protocol_violation();
        field_reader_close(reader);
        set_decoder_state(decoder, HTTP_DECODER_ERRORED);
        return false;
    }
    const char *end;
    char *trailer_buffer = field_reader_combine(reader, &end);
    http_env_t *dummy_envelope = make_http_env_request("", "", "");
    if (!http_env_parse_trailers(dummy_envelope, trailer_buffer, end)) {
        destroy_http_env(dummy_envelope);
        fsfree(trailer_buffer);
        protocol_violation();
        field_reader_close(reader);
        set_decoder_state(decoder, HTTP_DECODER_ERRORED);
        return false;
    }
    close_reader(decoder, reader);
    destroy_http_env(dummy_envelope);
    fsfree(trailer_buffer);
    start_reading(decoder);
    return true;
}

static bool can_dequeue_skipping_chunked(http_decoder_t *decoder)
{
    chunkdecoder_t *chunk_decoder = decoder->skipping_chunked.chunk_decoder;
    for (;;) {
        char buf[2000];
        ssize_t count = chunkdecoder_read(chunk_decoder, buf, sizeof buf);
        if (count < 0) {
            if (errno == EPROTO) {
                chunkdecoder_close(chunk_decoder);
                set_decoder_state(decoder, HTTP_DECODER_ERRORED);
            }
            return false;
        }
        if (count == 0) {
            push_leftovers(decoder, chunk_decoder);
            chunkdecoder_close(chunk_decoder);
            bytestream_1 input_stream =
                queuestream_as_bytestream_1(decoder->input_stream);
            decoder->skipping_trailer.reader =
                make_field_reader(input_stream,
                                  decoder->skipping_chunked.max_trailer_size);
            set_decoder_state(decoder, HTTP_DECODER_SKIPPING_TRAILER);
            return can_dequeue_skipping_trailer(decoder);
        }
    }
}

static bool can_dequeue_skipping_bounded(http_decoder_t *decoder)
{
    while (decoder->skipping_bounded.remaining > 0) {
        char buf[2000];
        ssize_t count =
            queuestream_read(decoder->input_stream, buf, sizeof buf);
        if (count < 0)
            return false;
        if (count == 0) {
            set_decoder_state(decoder, HTTP_DECODER_ERRORED);
            protocol_violation();
            return false;
        }
        decoder->skipping_bounded.remaining -= count;
    }
    start_reading(decoder);
    return true;
}

static bool can_dequeue(http_decoder_t *decoder)
{
    switch (decoder->state) {
        case HTTP_DECODER_READING_HEADERS:
            return true;
        case HTTP_DECODER_ZOMBIE:
            errno = EBADF;
            return false;
        case HTTP_DECODER_HEADERS_DEQUEUED:
        case HTTP_DECODER_READING_CONTENT:
            errno = EAGAIN;
            return false;
        case HTTP_DECODER_SKIPPING_CHUNKED:
            return can_dequeue_skipping_chunked(decoder);
        case HTTP_DECODER_SKIPPING_TRAILER:
            return can_dequeue_skipping_trailer(decoder);
        case HTTP_DECODER_SKIPPING_BOUNDED:
            return can_dequeue_skipping_bounded(decoder);
        case HTTP_DECODER_ERRORED:
            protocol_violation();
            return false;
        case HTTP_DECODER_DISCONNECTED:
            errno = 0;
            return false;
        default:
            abort();
    }
}

static const http_env_t *do_dequeue(http_decoder_t *decoder,
                                    http_env_type_t type)
{
    if (!can_dequeue(decoder))
        return NULL;
    assert(decoder->state == HTTP_DECODER_READING_HEADERS);
    field_reader_t *reader = decoder->reading_headers.reader;
    int status = field_reader_read(reader);
    if (status < 0) {
        if (errno == EPROTO) {
            field_reader_close(reader);
            set_decoder_state(decoder, HTTP_DECODER_ERRORED);
        }
        return NULL;
    }
    if (status == 0) {
        field_reader_close(reader);
        set_decoder_state(decoder, HTTP_DECODER_DISCONNECTED);
        errno = 0;
        return NULL;
    }
    const char *end;
    char *header_buffer = field_reader_combine(reader, &end);
    http_env_t *envelope = http_env_parse_headers(type, header_buffer, end);
    if (!envelope) {
        field_reader_close(reader);
        fsfree(header_buffer);
        protocol_violation();
        set_decoder_state(decoder, HTTP_DECODER_ERRORED);
        return NULL;
    }
    close_reader(decoder, reader);
    decoder->reading_content.envelope = envelope;
    decoder->reading_content.header_buffer = header_buffer;
    decoder->reading_content.max_trailer_size =
        decoder->max_envelope_size - (end - header_buffer);
    decoder->reading_content.trailer_buffer = NULL;
    decoder->reading_content.callback = NULL_ACTION_1;
    set_decoder_state(decoder, HTTP_DECODER_HEADERS_DEQUEUED);
    return envelope;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_DEQUEUE, "UID=%64u ENV=%p ERRNO=%e");

const http_env_t *http_decoder_dequeue(http_decoder_t *decoder,
                                       http_env_type_t type)
{
    const http_env_t *env = do_dequeue(decoder, type);
    FSTRACE(ASYNCHTTP_DECODER_DEQUEUE, decoder->uid, env);
    return env;
}

static const char *trace_content_length(void *pclen)
{
    switch (*(ssize_t *) pclen) {
        case HTTP_DECODE_CHUNKED:
            return "HTTP_DECODE_CHUNKED";
        case HTTP_DECODE_EXHAUST:
            return "HTTP_DECODE_EXHAUST";
        case HTTP_DECODE_UNKNOWN:
            return "HTTP_DECODE_UNKNOWN";
        default:
            return "HTTP_DECODE_CONTENT_LENGTH";
    }
}

FSTRACE_DECL(ASYNCHTTP_DECODER_GET_CONTENT_FAIL,
             "UID=%64u CLEN-TYPE=%I CLEN=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_DECODER_GET_CONTENT,
             "UID=%64u CLEN-TYPE=%I CLEN=%z CONTENT=%p");

int http_decoder_get_content(http_decoder_t *decoder, ssize_t content_length,
                             bytestream_1 *content)
{
    assert(decoder->state == HTTP_DECODER_HEADERS_DEQUEUED);
    if (!prepare_content(decoder, content_length, content)) {
        destroy_http_env(decoder->reading_content.envelope);
        fsfree(decoder->reading_content.header_buffer);
        set_decoder_state(decoder, HTTP_DECODER_ERRORED);
        protocol_violation();
        FSTRACE(ASYNCHTTP_DECODER_GET_CONTENT_FAIL, decoder->uid,
                trace_content_length, &content_length, content_length);
        return -1;
    }
    FSTRACE(ASYNCHTTP_DECODER_GET_CONTENT, decoder->uid,
            trace_content_length, &content_length, content_length, content->obj);
    decoder->reading_content.output_stream = *content;
    set_decoder_state(decoder, HTTP_DECODER_READING_CONTENT);
    return 0;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_GRAB, "UID=%64u Q=%p");

queuestream_t *http_decoder_grab_content(http_decoder_t *decoder)
{
    FSTRACE(ASYNCHTTP_DECODER_GRAB, decoder->uid, decoder->input_stream);
    assert(decoder->state == HTTP_DECODER_HEADERS_DEQUEUED);
    queuestream_t *content = decoder->input_stream;
    decoder->input_stream = NULL;
    queuestream_unregister_callback(content);
    decoder->reading_content.output_stream = emptystream;
    set_decoder_state(decoder, HTTP_DECODER_READING_CONTENT);
    return content;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_RESTORE, "UID=%64u Q=%p");

void http_decoder_restore_content(http_decoder_t *decoder,
                                  queuestream_t *content)
{
    FSTRACE(ASYNCHTTP_DECODER_RESTORE, decoder->uid, content);
    assert(decoder->state == HTTP_DECODER_READING_CONTENT);
    assert(!decoder->input_stream);
    stop_reading_content(decoder);
    decoder->input_stream = content;
    start_reading(decoder);
    action_1 input_cb = { decoder, (act_1) input_notification };
    queuestream_register_callback(decoder->input_stream, input_cb);
}

FSTRACE_DECL(ASYNCHTTP_DECODER_REGISTER, "UID=%64u OBJ=%p ACT=%p");

void http_decoder_register_callback(http_decoder_t *decoder, action_1 action)
{
    FSTRACE(ASYNCHTTP_DECODER_REGISTER, decoder->uid, action.obj, action.act);
    decoder->callback = action;
}

FSTRACE_DECL(ASYNCHTTP_DECODER_UNREGISTER, "UID=%64u");

void http_decoder_unregister_callback(http_decoder_t *decoder)
{
    FSTRACE(ASYNCHTTP_DECODER_UNREGISTER, decoder->uid);
    decoder->callback = NULL_ACTION_1;
}
