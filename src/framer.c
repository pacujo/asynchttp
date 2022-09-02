#include "framer.h"

#include <assert.h>
#include <stdio.h>

#include <async/chunkencoder.h>
#include <async/farewellstream.h>
#include <async/probestream.h>
#include <async/queuestream.h>
#include <async/stringstream.h>
#include <fsdyn/fsalloc.h>
#include <fsdyn/list.h>
#include <fstrace.h>

#include "asynchttp_version.h"

typedef enum {
    CHUNKED_NONE,
    CHUNKED_BODY,
    CHUNKED_TRAILER,
    CHUNKED_EOF,
    CHUNKED_CLOSED
} chunked_state_t;

struct http_framer {
    async_t *async;
    uint64_t uid;
    queuestream_t *outq;
    bytestream_1 output_stream;
    action_1 farewell_action;
    chunked_state_t chunked_state;
    const http_env_t *envelope;
    chunkencoder_t *chunker;  /* CHUNKED_BODY */
    action_1 chunks_callback; /* CHUNKED_BODY */
    queuestream_t *trailerq;  /* CHUNKED_TRAILER */
};

FSTRACE_DECL(ASYNCHTTP_FRAMER_CLOSE, "UID=%64u");

static void farewell_framer(http_framer_t *framer)
{
    FSTRACE(ASYNCHTTP_FRAMER_CLOSE, framer->uid);
    async_wound(framer->async, framer);
    framer->async = NULL;
    action_1_perf(framer->farewell_action);
}

FSTRACE_DECL(ASYNCHTTP_FRAMER_CREATE, "UID=%64u PTR=%p ASYNC=%p Q=%p");

http_framer_t *open_http_framer(async_t *async)
{
    http_framer_t *framer = fsalloc(sizeof *framer);
    framer->async = async;
    framer->uid = fstrace_get_unique_id();
    framer->outq = make_queuestream(async);
    FSTRACE(ASYNCHTTP_FRAMER_CREATE, framer->uid, framer, async, framer->outq);
    action_1 farewell_cb = { framer, (act_1) farewell_framer };
    farewellstream_t *fws =
        open_farewellstream(async, queuestream_as_bytestream_1(framer->outq),
                            farewell_cb);
    framer->output_stream = farewellstream_as_bytestream_1(fws);
    framer->farewell_action = NULL_ACTION_1;
    framer->chunked_state = CHUNKED_NONE;
    return framer;
}

void http_framer_register_farewell_callback(http_framer_t *framer,
                                            action_1 action)
{
    framer->farewell_action = action;
}

void http_framer_unregister_farewell_callback(http_framer_t *framer)
{
    framer->farewell_action = NULL_ACTION_1;
}

bytestream_1 http_framer_get_output_stream(http_framer_t *framer)
{
    return framer->output_stream;
}

void http_framer_terminate(http_framer_t *framer)
{
    queuestream_terminate(framer->outq);
}

static void enqstream(queuestream_t *q, stringstream_t *sstr)
{
    queuestream_enqueue(q, stringstream_as_bytestream_1(sstr));
}

static void enqstr(http_framer_t *framer, queuestream_t *q, const char *s)
{
    enqstream(q, open_stringstream(framer->async, s));
}

static void enqcode(http_framer_t *framer, queuestream_t *q, unsigned code)
{
    char buf[10];
    sprintf(buf, "%03u", code % 1000);
    enqstream(q, copy_stringstream(framer->async, buf));
}

static void enqsize(http_framer_t *framer, queuestream_t *q, unsigned long size)
{
    char buf[50];
    sprintf(buf, "%lu", size);
    enqstream(q, copy_stringstream(framer->async, buf));
}

static void enqfield(http_framer_t *framer, queuestream_t *q, const char *field,
                     const char *value)
{
    enqstr(framer, q, field);
    enqstr(framer, q, ": ");
    enqstr(framer, q, value);
    enqstr(framer, q, "\r\n");
}

static void enqtrailers(http_framer_t *framer, queuestream_t *q,
                        const http_env_t *envelope)
{
    const char *field, *value;
    http_env_iter_t *iter = NULL;
    while ((iter = http_env_get_next_trailer(envelope, iter, &field, &value)))
        enqfield(framer, q, field, value);
}

static void encode_trailer(http_framer_t *framer)
{
    assert(framer->chunked_state == CHUNKED_BODY);
    framer->trailerq = make_queuestream(framer->async);
    queuestream_register_callback(framer->trailerq, framer->chunks_callback);
    enqstr(framer, framer->trailerq,
           http_env_get_final_extensions(framer->envelope));
    enqstr(framer, framer->trailerq, "\r\n");
    enqtrailers(framer, framer->trailerq, framer->envelope);
    enqstr(framer, framer->trailerq, "\r\n");
    queuestream_terminate(framer->trailerq);
}

static const char *trace_chunked_state(void *pstate)
{
    switch (*(chunked_state_t *) pstate) {
        case CHUNKED_NONE:
            return "CHUNKED_NONE";
        case CHUNKED_BODY:
            return "CHUNKED_BODY";
        case CHUNKED_TRAILER:
            return "CHUNKED_TRAILER";
        case CHUNKED_EOF:
            return "CHUNKED_EOF";
        case CHUNKED_CLOSED:
            return "CHUNKED_CLOSED";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCHTTP_FRAMER_SET_CHUNKED_STATE, "UID=%64u OLD=%I NEW=%I");

static void set_chunked_state(http_framer_t *framer, chunked_state_t state)
{
    FSTRACE(ASYNCHTTP_FRAMER_SET_CHUNKED_STATE, framer->uid,
            trace_chunked_state, &framer->chunked_state, trace_chunked_state,
            &state);
    framer->chunked_state = state;
}

static ssize_t do_chunks_read(http_framer_t *framer, void *buf, size_t count)
{
    ssize_t n;
    switch (framer->chunked_state) {
        case CHUNKED_BODY:
            n = chunkencoder_read(framer->chunker, buf, count);
            if (n == 0) {
                encode_trailer(framer);
                chunkencoder_close(framer->chunker);
                set_chunked_state(framer, CHUNKED_TRAILER);
                return do_chunks_read(framer, buf, count);
            }
            return n;
        case CHUNKED_TRAILER:
            n = queuestream_read(framer->trailerq, buf, count);
            if (n == 0) {
                queuestream_close(framer->trailerq);
                set_chunked_state(framer, CHUNKED_EOF);
                return do_chunks_read(framer, buf, count);
            }
            return n;
        case CHUNKED_EOF:
            return 0;
        default:
            assert(false);
    }
}

FSTRACE_DECL(ASYNCHTTP_FRAMER_CHUNKS_READ, "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_FRAMER_CHUNKS_READ_DUMP, "UID=%64u DATA=%A");

static ssize_t chunks_read(void *obj, void *buf, size_t count)
{
    http_framer_t *framer = obj;
    ssize_t n = do_chunks_read(framer, buf, count);
    FSTRACE(ASYNCHTTP_FRAMER_CHUNKS_READ, framer->uid, count, n);
    FSTRACE(ASYNCHTTP_FRAMER_CHUNKS_READ_DUMP, framer->uid, buf, n);
    return n;
}

FSTRACE_DECL(ASYNCHTTP_FRAMER_CHUNKS_CLOSE, "UID=%64u");

static void chunks_close(void *obj)
{
    http_framer_t *framer = obj;
    FSTRACE(ASYNCHTTP_FRAMER_CHUNKS_CLOSE, framer->uid);
    switch (framer->chunked_state) {
        case CHUNKED_BODY:
            chunkencoder_close(framer->chunker);
            break;
        case CHUNKED_TRAILER:
            queuestream_close(framer->trailerq);
            break;
        case CHUNKED_EOF:
            break;
        default:
            assert(false);
    }
    set_chunked_state(framer, CHUNKED_CLOSED);
}

FSTRACE_DECL(ASYNCHTTP_FRAMER_CHUNKS_REGISTER, "UID=%64u OBJ=%p ACT=%p");

static void chunks_register_callback(void *obj, action_1 action)
{
    http_framer_t *framer = obj;
    FSTRACE(ASYNCHTTP_FRAMER_CHUNKS_REGISTER, framer->uid, action.obj,
            action.act);
    switch (framer->chunked_state) {
        case CHUNKED_BODY:
            framer->chunks_callback = action;
            chunkencoder_register_callback(framer->chunker, action);
            break;
        case CHUNKED_TRAILER:
            queuestream_register_callback(framer->trailerq, action);
            break;
        default:;
    }
}

FSTRACE_DECL(ASYNCHTTP_FRAMER_CHUNKS_UNREGISTER, "UID=%64u");

static void chunks_unregister_callback(void *obj)
{
    http_framer_t *framer = obj;
    FSTRACE(ASYNCHTTP_FRAMER_CHUNKS_UNREGISTER, framer->uid);
    switch (framer->chunked_state) {
        case CHUNKED_BODY:
            framer->chunks_callback = NULL_ACTION_1;
            chunkencoder_unregister_callback(framer->chunker);
            break;
        case CHUNKED_TRAILER:
            queuestream_unregister_callback(framer->trailerq);
            break;
        default:;
    }
}

static struct bytestream_1_vt chunks_vt = {
    .read = chunks_read,
    .close = chunks_close,
    .register_callback = chunks_register_callback,
    .unregister_callback = chunks_unregister_callback,
};

static void encode_chunked(http_framer_t *framer, queuestream_t *q,
                           bytestream_1 content)
{
    enqstr(framer, q, "Transfer-encoding: chunked\r\n\r\n");
    framer->chunker = chunk_encode_2(framer->async, content, 2000,
                                     CHUNKENCODER_STOP_AT_FINAL_EXTENSIONS);
    framer->chunks_callback = NULL_ACTION_1;
    queuestream_enqueue(q, (bytestream_1) { framer, &chunks_vt });
    set_chunked_state(framer, CHUNKED_BODY);
}

static const char *trace_content_length(void *pclen)
{
    switch (*(ssize_t *) pclen) {
        case HTTP_ENCODE_CHUNKED:
            return "HTTP_ENCODE_CHUNKED";
        case HTTP_ENCODE_RAW:
            return "HTTP_ENCODE_RAW";
        default:
            return "HTTP_ENCODE_CONTENT_LENGTH";
    }
}

FSTRACE_DECL(ASYNCHTTP_FRAMER_ENV_READ, "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_FRAMER_ENV_READ_DUMP, "UID=%64u DATA=%A");

static void probe_env_read(void *obj, const void *buf, size_t size, ssize_t n)
{
    http_framer_t *framer = obj;
    FSTRACE(ASYNCHTTP_FRAMER_ENV_READ, framer->uid, size, n);
    FSTRACE(ASYNCHTTP_FRAMER_ENV_READ_DUMP, framer->uid, buf, n);
}

FSTRACE_DECL(ASYNCHTTP_FRAMER_ENV_CLOSE, "UID=%64u");

static void probe_env_close(void *obj)
{
    http_framer_t *framer = obj;
    FSTRACE(ASYNCHTTP_FRAMER_ENV_CLOSE, framer->uid);
}

static queuestream_t *enq_envelope_stream(http_framer_t *framer)
{
    queuestream_t *q = make_queuestream(framer->async);
    probestream_t *probe =
        open_probestream(framer->async, framer, queuestream_as_bytestream_1(q),
                         probe_env_close, probe_env_read);
    queuestream_enqueue(framer->outq, probestream_as_bytestream_1(probe));
    return q;
}

FSTRACE_DECL(ASYNCHTTP_FRAMER_BODY_READ, "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_FRAMER_BODY_READ_DUMP, "UID=%64u DATA=%A");

static void probe_body_read(void *obj, const void *buf, size_t size, ssize_t n)
{
    http_framer_t *framer = obj;
    FSTRACE(ASYNCHTTP_FRAMER_BODY_READ, framer->uid, size, n);
    FSTRACE(ASYNCHTTP_FRAMER_BODY_READ_DUMP, framer->uid, buf, n);
}

FSTRACE_DECL(ASYNCHTTP_FRAMER_BODY_CLOSE, "UID=%64u");

static void probe_body_close(void *obj)
{
    http_framer_t *framer = obj;
    FSTRACE(ASYNCHTTP_FRAMER_BODY_CLOSE, framer->uid);
}

static queuestream_t *enq_body_stream(http_framer_t *framer)
{
    queuestream_t *q = make_queuestream(framer->async);
    probestream_t *probe =
        open_probestream(framer->async, framer, queuestream_as_bytestream_1(q),
                         probe_body_close, probe_body_read);
    queuestream_enqueue(framer->outq, probestream_as_bytestream_1(probe));
    return q;
}

FSTRACE_DECL(ASYNCHTTP_FRAMER_ENQUEUE,
             "UID=%64u ENV=%p CLEN-TYPE=%I CLEN=%z CONTENT=%p");

void http_framer_enqueue(http_framer_t *framer, const http_env_t *envelope,
                         ssize_t content_length, bytestream_1 content)
{
    FSTRACE(ASYNCHTTP_FRAMER_ENQUEUE, framer->uid, envelope,
            trace_content_length, &content_length, content_length, content.obj);
    queuestream_t *q = enq_envelope_stream(framer);
    switch (http_env_get_type(envelope)) {
        case HTTP_ENV_REQUEST:
            enqstr(framer, q, http_env_get_method(envelope));
            enqstr(framer, q, " ");
            enqstr(framer, q, http_env_get_path(envelope));
            enqstr(framer, q, " ");
            enqstr(framer, q, http_env_get_protocol(envelope));
            enqstr(framer, q, "\r\n");
            break;
        case HTTP_ENV_RESPONSE:
            enqstr(framer, q, http_env_get_protocol(envelope));
            enqstr(framer, q, " ");
            enqcode(framer, q, http_env_get_code(envelope));
            enqstr(framer, q, " ");
            enqstr(framer, q, http_env_get_explanation(envelope));
            enqstr(framer, q, "\r\n");
            break;
        default:
            abort();
    }
    const char *field, *value;
    http_env_iter_t *iter = NULL;
    while ((iter = http_env_get_next_header(envelope, iter, &field, &value)))
        enqfield(framer, q, field, value);
    queuestream_terminate(q);
    q = enq_body_stream(framer);
    switch (content_length) {
        case HTTP_ENCODE_CHUNKED:
            framer->envelope = envelope;
            encode_chunked(framer, q, content);
            break;
        case HTTP_ENCODE_RAW:
            enqstr(framer, q, "\r\n");
            queuestream_enqueue(q, content);
            break;
        default:
            assert(content_length >= 0);
            enqstr(framer, q, "Content-length: ");
            enqsize(framer, q, content_length);
            enqstr(framer, q, "\r\n\r\n");
            queuestream_enqueue(q, content);
    }
    queuestream_terminate(q);
}
