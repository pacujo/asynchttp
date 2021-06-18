#include "icap.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#include <async/blobstream.h>
#include <async/chunkdecoder.h>
#include <async/chunkencoder.h>
#include <async/emptystream.h>
#include <async/farewellstream.h>
#include <async/queuestream.h>
#include <async/stringstream.h>
#include <fsdyn/fsalloc.h>
#include <fsdyn/list.h>
#include <fstrace.h>

#include "asynchttp_version.h"
#include "decoder.h"
#include "field_reader.h"

static void __attribute__((noinline)) protocol_violation(void)
{
    /* set your breakpoint here*/
    errno = EPROTO;
}

typedef enum {
    ICAP_INPUT_AWAITING_ICAP_ENVELOPE,
    ICAP_INPUT_READING_HTTP_ENVELOPES,
    ICAP_INPUT_PASSING_BODY,
    ICAP_INPUT_SKIPPING_BODY,
    ICAP_INPUT_READING_FINAL_EXTENSIONS,
    ICAP_INPUT_SKIPPING_FINAL_EXTENSIONS,
    ICAP_INPUT_READING_TRAILERS,
    ICAP_INPUT_SKIPPING_TRAILERS,
    ICAP_INPUT_AWAITING_BODY_CLOSE,
    ICAP_INPUT_AWAITING_UNENCAPSULATED_CLOSE,
    ICAP_INPUT_DISCONNECTED,
    ICAP_INPUT_ERRORED,
    ICAP_INPUT_CLOSED
} icap_input_state_t;

typedef enum {
    ICAP_OUTPUT_OPEN,
    ICAP_OUTPUT_TERMINATED,
    ICAP_OUTPUT_CLOSED
} icap_output_state_t;

typedef struct {
    const http_env_t *icap_envelope;
    const http_env_t *http_envelope; /* one of the two HTTP envelopes */
    queuestream_t *q;                /* where to send the trailers */
} transfer_t;

enum {
    MAX_EXTENSIONS_SIZE = 1000,
};

struct icap_conn {
    async_t *async;
    uint64_t uid;
    regex_t encapsulated_pattern;
    icap_input_state_t input_state;
    size_t max_envelope_size;
    action_1 callback;

    /* ICAP_INPUT_READING_HTTP_ENVELOPES..ICAP_INPUT_AWAITING_BODY_CLOSE */
    http_env_t *icap_envelope;
    ssize_t req_hdr_offset, res_hdr_offset, body_offset;
    icap_body_type_t body_type;
    queuestream_t *underlying_stream;
    char *http_buffer;
    size_t http_buffer_cursor;
    action_1 body_callback, continuation_callback;

    /* ICAP_INPUT_PASSING_BODY..ICAP_INPUT_AWAITING_BODY_CLOSE */
    bool first_leg_open, second_leg_open;
    http_env_t *http_request;
    http_env_t *http_response;
    http_env_t *dummy_envelope;
    http_env_t *trailer_envelope;
    size_t max_trailer_size;
    chunkdecoder_t *chunk_decoder;

    /* ICAP_INPUT_READING_FINAL_EXTENSIONS..ICAP_INPUT_AWAITING_BODY_CLOSE */
    char final_extensions[MAX_EXTENSIONS_SIZE];
    size_t final_extensions_cursor;

    /* ICAP_INPUT_READING_TRAILERS..ICAP_INPUT_AWAITING_BODY_CLOSE */
    field_reader_t *reader;

    /* ICAP_INPUT_AWAITING_BODY_CLOSE */
    char *trailer_buffer;

    icap_output_state_t output_state;
    bytestream_1 output_stream;
    http_decoder_t *decoder;
    action_1 peer_closed_callback;
    queuestream_t *outq;

    /* ICAP_OUTPUT_OPEN */
    list_t *pending_transfers; /* of transfer_t */
};

static const char *RE_ENCAPSULATED =
    "^(req-hdr=([0-9]+), )?"
    "(res-hdr=([0-9]+), )?"
    "(((req)|(res)|(opt)|(null))-body=([0-9]+))$";

enum {
    ENCAPSULATED_REQ_HDR_OFFSET = 2,
    ENCAPSULATED_RES_HDR_OFFSET = 4,
    ENCAPSULATED_REQ_BODY = 7,
    ENCAPSULATED_RES_BODY = 8,
    ENCAPSULATED_OPT_BODY = 9,
    ENCAPSULATED_NULL_BODY = 10,
    ENCAPSULATED_BODY_OFFSET = 11,
    ENCAPSULATED_MATCH_COUNT = 12
};

static transfer_t *open_transfer(const http_env_t *icap_envelope,
                                 const http_env_t *http_envelope,
                                 queuestream_t *q)
{
    transfer_t *transfer = fsalloc(sizeof *transfer);
    transfer->icap_envelope = icap_envelope;
    transfer->http_envelope = http_envelope;
    transfer->q = q;
    return transfer;
}

static void close_transfer(transfer_t *transfer)
{
    fsfree(transfer);
}

static const char *trace_output_state(void *pstate)
{
    switch (*(icap_output_state_t *) pstate) {
        case ICAP_OUTPUT_OPEN:
            return "ICAP_OUTPUT_OPEN";
        case ICAP_OUTPUT_TERMINATED:
            return "ICAP_OUTPUT_TERMINATED";
        case ICAP_OUTPUT_CLOSED:
            return "ICAP_OUTPUT_CLOSED";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCHTTP_ICAP_SET_OUTPUT_STATE, "UID=%64u OLD=%I NEW=%I");

static void set_output_state(icap_conn_t *conn, icap_output_state_t state)
{
    FSTRACE(ASYNCHTTP_ICAP_SET_OUTPUT_STATE, conn->uid, trace_output_state,
            &conn->output_state, trace_output_state, &state);
    conn->output_state = state;
}

FSTRACE_DECL(ASYNCHTTP_ICAP_FAREWELL, "UID=%64u");

static void farewell_connection(icap_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_ICAP_FAREWELL, conn->uid);
    assert(conn->output_state != ICAP_OUTPUT_CLOSED);
    while (!list_empty(conn->pending_transfers))
        close_transfer((transfer_t *) list_pop_first(conn->pending_transfers));
    destroy_list(conn->pending_transfers);
    set_output_state(conn, ICAP_OUTPUT_CLOSED);
    switch (conn->input_state) {
        case ICAP_INPUT_CLOSED:
            async_wound(conn->async, conn);
            break;
        default:
            async_execute(conn->async, conn->peer_closed_callback);
    }
}

FSTRACE_DECL(ASYNCHTTP_ICAP_CREATE,
             "UID=%64u PTR=%p ASYNC=%p INPUT=%p MAX-ENV-SIZE=%z Q=%p "
             "DECODER=%p");

icap_conn_t *open_icap_connection(async_t *async, bytestream_1 input_stream,
                                  size_t max_envelope_size)
{
    icap_conn_t *conn = fsalloc(sizeof *conn);
    conn->async = async;
    conn->uid = fstrace_get_unique_id();
    int status =
        regcomp(&conn->encapsulated_pattern, RE_ENCAPSULATED, REG_EXTENDED);
    assert(status == 0);
    conn->input_state = ICAP_INPUT_AWAITING_ICAP_ENVELOPE;
    conn->callback = NULL_ACTION_1;
    conn->output_state = ICAP_OUTPUT_OPEN;
    action_1 farewell_cb = { conn, (act_1) farewell_connection };
    conn->peer_closed_callback = NULL_ACTION_1;
    conn->outq = make_queuestream(async);
    farewellstream_t *fws =
        open_farewellstream(async, queuestream_as_bytestream_1(conn->outq),
                            farewell_cb);
    conn->pending_transfers = make_list();
    conn->output_stream = farewellstream_as_bytestream_1(fws);
    conn->max_envelope_size = max_envelope_size;
    conn->decoder = open_http_decoder(async, input_stream, max_envelope_size);
    FSTRACE(ASYNCHTTP_ICAP_CREATE, conn->uid, conn, async, input_stream.obj,
            max_envelope_size, conn->outq, conn->decoder);
    return conn;
}

static void push_leftovers(icap_conn_t *conn, const void *bytes, size_t size)
{
    blobstream_t *leftover = copy_blobstream(conn->async, bytes, size);
    queuestream_push(conn->underlying_stream,
                     blobstream_as_bytestream_1(leftover));
}

static void clear_input(icap_conn_t *conn)
{
    switch (conn->input_state) {
        case ICAP_INPUT_AWAITING_BODY_CLOSE:
            fsfree(conn->trailer_buffer);
            push_leftovers(conn, field_reader_leftover_bytes(conn->reader),
                           field_reader_leftover_size(conn->reader));
            /* flow through */
        case ICAP_INPUT_READING_FINAL_EXTENSIONS:
        case ICAP_INPUT_SKIPPING_FINAL_EXTENSIONS:
        case ICAP_INPUT_READING_TRAILERS:
        case ICAP_INPUT_SKIPPING_TRAILERS:
            field_reader_close(conn->reader);
            /* flow through */
        case ICAP_INPUT_PASSING_BODY:
        case ICAP_INPUT_SKIPPING_BODY:
            http_decoder_restore_content(conn->decoder,
                                         conn->underlying_stream);
            if (conn->http_request)
                destroy_http_env(conn->http_request);
            if (conn->http_response)
                destroy_http_env(conn->http_response);
            if (conn->dummy_envelope)
                destroy_http_env(conn->dummy_envelope);
            chunkdecoder_close(conn->chunk_decoder);
            /* flow through */
        case ICAP_INPUT_READING_HTTP_ENVELOPES:
            destroy_http_env(conn->icap_envelope);
            fsfree(conn->http_buffer);
            /* flow through */
        case ICAP_INPUT_AWAITING_ICAP_ENVELOPE:
        case ICAP_INPUT_DISCONNECTED:
        case ICAP_INPUT_ERRORED:
            break;
        case ICAP_INPUT_AWAITING_UNENCAPSULATED_CLOSE:
            destroy_http_env(conn->icap_envelope);
            fsfree(conn->http_buffer);
            if (conn->dummy_envelope)
                destroy_http_env(conn->dummy_envelope);
            http_decoder_restore_content(conn->decoder,
                                         conn->underlying_stream);
            break;
        default:
            abort();
    }
}

static const char *trace_input_state(void *pstate)
{
    switch (*(icap_input_state_t *) pstate) {
        case ICAP_INPUT_AWAITING_ICAP_ENVELOPE:
            return "ICAP_INPUT_AWAITING_ICAP_ENVELOPE";
        case ICAP_INPUT_READING_HTTP_ENVELOPES:
            return "ICAP_INPUT_READING_HTTP_ENVELOPES";
        case ICAP_INPUT_PASSING_BODY:
            return "ICAP_INPUT_PASSING_BODY";
        case ICAP_INPUT_SKIPPING_BODY:
            return "ICAP_INPUT_SKIPPING_BODY";
        case ICAP_INPUT_READING_FINAL_EXTENSIONS:
            return "ICAP_INPUT_READING_FINAL_EXTENSIONS";
        case ICAP_INPUT_SKIPPING_FINAL_EXTENSIONS:
            return "ICAP_INPUT_SKIPPING_FINAL_EXTENSIONS";
        case ICAP_INPUT_READING_TRAILERS:
            return "ICAP_INPUT_READING_TRAILERS";
        case ICAP_INPUT_SKIPPING_TRAILERS:
            return "ICAP_INPUT_SKIPPING_TRAILERS";
        case ICAP_INPUT_AWAITING_BODY_CLOSE:
            return "ICAP_INPUT_AWAITING_BODY_CLOSE";
        case ICAP_INPUT_AWAITING_UNENCAPSULATED_CLOSE:
            return "ICAP_INPUT_AWAITING_UNENCAPSULATED_CLOSE";
        case ICAP_INPUT_DISCONNECTED:
            return "ICAP_INPUT_DISCONNECTED";
        case ICAP_INPUT_ERRORED:
            return "ICAP_INPUT_ERRORED";
        case ICAP_INPUT_CLOSED:
            return "ICAP_INPUT_CLOSED";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCHTTP_ICAP_SET_INPUT_STATE, "UID=%64u OLD=%I NEW=%I");

static void set_input_state(icap_conn_t *conn, icap_input_state_t state)
{
    FSTRACE(ASYNCHTTP_ICAP_SET_INPUT_STATE, conn->uid, trace_input_state,
            &conn->input_state, trace_input_state, &state);
    conn->input_state = state;
}

FSTRACE_DECL(ASYNCHTTP_ICAP_CLOSE, "UID=%64u");

void icap_close(icap_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_ICAP_CLOSE, conn->uid);
    assert(conn->input_state != ICAP_INPUT_CLOSED);
    clear_input(conn);
    http_decoder_close(conn->decoder);
    set_input_state(conn, ICAP_INPUT_CLOSED);
    regfree(&conn->encapsulated_pattern);
    if (conn->output_state == ICAP_OUTPUT_CLOSED)
        async_wound(conn->async, conn);
}

FSTRACE_DECL(ASYNCHTTP_ICAP_REGISTER_PEER, "UID=%64u OBJ=%p ACT=%p");

void icap_register_peer_closed_callback(icap_conn_t *conn, action_1 action)
{
    FSTRACE(ASYNCHTTP_ICAP_REGISTER_PEER, conn->uid, action.obj, action.act);
    conn->peer_closed_callback = action;
}

FSTRACE_DECL(ASYNCHTTP_ICAP_UNREGISTER_PEER, "UID=%64u");

void icap_unregister_peer_closed_callback(icap_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_ICAP_UNREGISTER_PEER, conn->uid);
    conn->peer_closed_callback = NULL_ACTION_1;
}

bytestream_1 icap_get_output_stream(icap_conn_t *conn)
{
    return conn->output_stream;
}

static void enqstream(queuestream_t *q, stringstream_t *sstr)
{
    queuestream_enqueue(q, stringstream_as_bytestream_1(sstr));
}

static void enqstr(icap_conn_t *conn, queuestream_t *q, const char *s)
{
    enqstream(q, open_stringstream(conn->async, s));
}

static void enqcode(icap_conn_t *conn, queuestream_t *q, unsigned code)
{
    char buf[10];
    sprintf(buf, "%03u", code % 1000);
    enqstream(q, copy_stringstream(conn->async, buf));
}

static void enqsize(icap_conn_t *conn, queuestream_t *q, unsigned long size)
{
    char buf[50];
    sprintf(buf, "%lu", size);
    enqstream(q, copy_stringstream(conn->async, buf));
}

static void enqfield(icap_conn_t *conn, queuestream_t *q, const char *field,
                     const char *value)
{
    enqstr(conn, q, field);
    enqstr(conn, q, ": ");
    enqstr(conn, q, value);
    enqstr(conn, q, "\r\n");
}

static void enqheaders(icap_conn_t *conn, queuestream_t *q,
                       const http_env_t *envelope)
{
    switch (http_env_get_type(envelope)) {
        case HTTP_ENV_REQUEST:
            enqstr(conn, q, http_env_get_method(envelope));
            enqstr(conn, q, " ");
            enqstr(conn, q, http_env_get_path(envelope));
            enqstr(conn, q, " ");
            enqstr(conn, q, http_env_get_protocol(envelope));
            enqstr(conn, q, "\r\n");
            break;
        case HTTP_ENV_RESPONSE:
            enqstr(conn, q, http_env_get_protocol(envelope));
            enqstr(conn, q, " ");
            enqcode(conn, q, http_env_get_code(envelope));
            enqstr(conn, q, " ");
            enqstr(conn, q, http_env_get_explanation(envelope));
            enqstr(conn, q, "\r\n");
            break;
        default:
            abort();
    }
    const char *field, *value;
    http_env_iter_t *iter = NULL;
    while ((iter = http_env_get_next_header(envelope, iter, &field, &value)))
        enqfield(conn, q, field, value);
}

static size_t calc_header_size(icap_conn_t *conn, const http_env_t *envelope)
{
    queuestream_t *q = make_queuestream(conn->async);
    enqheaders(conn, q, envelope);
    enqstr(conn, q, "\r\n");
    queuestream_terminate(q);
    size_t size = 0;
    for (;;) {
        uint8_t buf[2000];
        ssize_t count = queuestream_read(q, buf, sizeof buf);
        assert(count >= 0);
        if (count == 0)
            break;
        size += count;
    }
    queuestream_close(q);
    return size;
}

static void enqtrailers(icap_conn_t *conn, queuestream_t *q,
                        const http_env_t *envelope)
{
    const char *field, *value;
    http_env_iter_t *iter = NULL;
    while ((iter = http_env_get_next_trailer(envelope, iter, &field, &value)))
        enqfield(conn, q, field, value);
}

static void encode_trailer(icap_conn_t *conn)
{
    if (conn->output_state == ICAP_OUTPUT_CLOSED)
        return;
    transfer_t *transfer =
        (transfer_t *) list_pop_first(conn->pending_transfers);
    enqstr(conn, transfer->q,
           http_env_get_final_extensions(transfer->icap_envelope));
    enqstr(conn, transfer->q, "\r\n");
    if (transfer->http_envelope)
        enqtrailers(conn, transfer->q, transfer->http_envelope);
    queuestream_terminate(transfer->q);
    close_transfer(transfer);
}

static void deliver_content(icap_conn_t *conn, const http_env_t *icap_envelope,
                            const http_env_t *trailer_env, bytestream_1 body)
{
    chunkencoder_t *chunker =
        chunk_encode_2(conn->async, body, 2000,
                       CHUNKENCODER_STOP_AT_FINAL_EXTENSIONS);
    queuestream_enqueue(conn->outq, chunkencoder_as_bytestream_1(chunker));
    action_1 at_trailer = { conn, (act_1) encode_trailer };
    farewellstream_t *fws =
        open_relaxed_farewellstream(conn->async, emptystream, at_trailer);
    queuestream_enqueue(conn->outq, farewellstream_as_bytestream_1(fws));
    queuestream_t *trailerq = make_queuestream(conn->async);
    queuestream_enqueue(conn->outq, queuestream_as_bytestream_1(trailerq));
    list_append(conn->pending_transfers,
                open_transfer(icap_envelope, trailer_env, trailerq));
    enqstr(conn, conn->outq, "\r\n");
}

static const char *trace_body_type(void *ptype)
{
    switch (*(icap_body_type_t *) ptype) {
        case ICAP_REQ_BODY:
            return "ICAP_REQ_BODY";
        case ICAP_RES_BODY:
            return "ICAP_RES_BODY";
        case ICAP_OPT_BODY:
            return "ICAP_OPT_BODY";
        case ICAP_NULL_BODY:
            return "ICAP_NULL_BODY";
        case ICAP_UNENCAPSULATED:
            return "ICAP_UNENCAPSULATED";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCHTTP_ICAP_SEND_DISCONNECTED,
             "UID=%64u REQ=%p HTTP-REQ=%p HTTP-RESP=%p BODY-TYPE=%I BODY=%p");
FSTRACE_DECL(ASYNCHTTP_ICAP_SEND,
             "UID=%64u REQ=%p HTTP-REQ=%p HTTP-RESP=%p BODY-TYPE=%I BODY=%p");

void icap_send(icap_conn_t *conn, const http_env_t *icap_envelope,
               const http_env_t *http_request, const http_env_t *http_response,
               icap_body_type_t body_type, bytestream_1 body)
{
    if (conn->output_state != ICAP_OUTPUT_OPEN) {
        FSTRACE(ASYNCHTTP_ICAP_SEND_DISCONNECTED, conn->uid, icap_envelope,
                http_request, http_response, trace_body_type, &body_type,
                body.obj);
        bytestream_1_close_relaxed(conn->async, body);
        return;
    }
    FSTRACE(ASYNCHTTP_ICAP_SEND, conn->uid, icap_envelope, http_request,
            http_response, trace_body_type, &body_type, body.obj);
    enqheaders(conn, conn->outq, icap_envelope);
    if (body_type == ICAP_UNENCAPSULATED) {
        enqstr(conn, conn->outq, "\r\n");
        queuestream_enqueue(conn->outq, body);
        return;
    }
    enqstr(conn, conn->outq, "Encapsulated: ");
    size_t offset = 0;
    if (http_request) {
        enqstr(conn, conn->outq, "req-hdr=");
        enqsize(conn, conn->outq, offset);
        offset += calc_header_size(conn, http_request);
        enqstr(conn, conn->outq, ", ");
    }
    if (http_response) {
        enqstr(conn, conn->outq, "res-hdr=");
        enqsize(conn, conn->outq, offset);
        offset += calc_header_size(conn, http_response);
        enqstr(conn, conn->outq, ", ");
    }
    const http_env_t *trailer_env;
    switch (body_type) {
        case ICAP_REQ_BODY:
            trailer_env = http_request;
            enqstr(conn, conn->outq, "req-body=");
            break;
        case ICAP_RES_BODY:
            trailer_env = http_response;
            enqstr(conn, conn->outq, "res-body=");
            break;
        case ICAP_OPT_BODY:
            trailer_env = NULL;
            enqstr(conn, conn->outq, "opt-body=");
            break;
        case ICAP_NULL_BODY:
            trailer_env = NULL;
            enqstr(conn, conn->outq, "null-body=");
            break;
        default:
            abort();
    }
    enqsize(conn, conn->outq, offset);
    enqstr(conn, conn->outq, "\r\n\r\n");
    if (body_type == ICAP_NULL_BODY) {
        queuestream_enqueue(conn->outq, body);
        return;
    }
    deliver_content(conn, icap_envelope, trailer_env, body);
}

FSTRACE_DECL(ASYNCHTTP_ICAP_CONTINUE_DISCONNECTED,
             "UID=%64u ENV=%p HTTP-ENV=%p REMAINDER=%p");
FSTRACE_DECL(ASYNCHTTP_ICAP_CONTINUE,
             "UID=%64u ENV=%p HTTP-ENV=%p REMAINDER=%p");

void icap_continue(icap_conn_t *conn, const http_env_t *icap_envelope,
                   const http_env_t *http_envelope, bytestream_1 remainder)
{
    if (conn->output_state != ICAP_OUTPUT_OPEN) {
        FSTRACE(ASYNCHTTP_ICAP_CONTINUE_DISCONNECTED, conn->uid, icap_envelope,
                http_envelope, remainder.obj);
        bytestream_1_close_relaxed(conn->async, remainder);
        return;
    }
    FSTRACE(ASYNCHTTP_ICAP_CONTINUE, conn->uid, icap_envelope, http_envelope,
            remainder.obj);
    deliver_content(conn, icap_envelope, http_envelope, remainder);
}

FSTRACE_DECL(ASYNCHTTP_ICAP_TERMINATE_DISCONNECTED, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_ICAP_TERMINATE, "UID=%64u");

void icap_terminate(icap_conn_t *conn)
{
    if (conn->output_state != ICAP_OUTPUT_OPEN) {
        FSTRACE(ASYNCHTTP_ICAP_TERMINATE_DISCONNECTED, conn->uid);
        return;
    }
    FSTRACE(ASYNCHTTP_ICAP_TERMINATE, conn->uid);
    queuestream_terminate(conn->outq);
    set_output_state(conn, ICAP_OUTPUT_TERMINATED);
}

static ssize_t scan_offset(const char *s, regmatch_t *pm)
{
    int i;
    ssize_t value = 0;
    for (i = pm->rm_so; i < pm->rm_eo; i++) {
        if (value > SSIZE_MAX / 10)
            return -1; /* overflow */
        value *= 10;
        int digit = s[i] - '0';
        if (digit > SSIZE_MAX - value)
            return -1; /* overflow */
        value += digit;
    }
    return value;
}

static bool good_offset(icap_conn_t *conn, ssize_t cursor, ssize_t offset)
{
    if (cursor < 0)
        return offset == 0;
    return offset >= cursor && offset - cursor <= conn->max_envelope_size;
}

static bool parse_encapsulated(icap_conn_t *conn, const char *encapsulated,
                               ssize_t *req_hdr, ssize_t *res_hdr,
                               icap_body_type_t *body_type, ssize_t *body)
{
    regmatch_t match[ENCAPSULATED_MATCH_COUNT];
    if (regexec(&conn->encapsulated_pattern, encapsulated,
                ENCAPSULATED_MATCH_COUNT, match, 0))
        return false;
    ssize_t cursor = -1;
    if (match[ENCAPSULATED_REQ_HDR_OFFSET].rm_so < 0)
        *req_hdr = -1;
    else {
        *req_hdr =
            scan_offset(encapsulated, &match[ENCAPSULATED_REQ_HDR_OFFSET]);
        if (!good_offset(conn, cursor, *req_hdr))
            return false;
        cursor = *req_hdr;
    }
    if (match[ENCAPSULATED_RES_HDR_OFFSET].rm_so < 0)
        *res_hdr = -1;
    else {
        *res_hdr =
            scan_offset(encapsulated, &match[ENCAPSULATED_RES_HDR_OFFSET]);
        if (!good_offset(conn, cursor, *res_hdr))
            return false;
        cursor = *res_hdr;
    }
    if (body_type) {
        if (match[ENCAPSULATED_REQ_BODY].rm_so >= 0)
            *body_type = ICAP_REQ_BODY;
        else if (match[ENCAPSULATED_RES_BODY].rm_so >= 0)
            *body_type = ICAP_RES_BODY;
        else if (match[ENCAPSULATED_OPT_BODY].rm_so >= 0)
            *body_type = ICAP_OPT_BODY;
        else {
            assert(match[ENCAPSULATED_NULL_BODY].rm_so >= 0);
            *body_type = ICAP_NULL_BODY;
        }
    }
    *body = scan_offset(encapsulated, &match[ENCAPSULATED_BODY_OFFSET]);
    return good_offset(conn, cursor, *body);
}

static ssize_t body_read_trailers(icap_conn_t *conn)
{
    assert(conn->input_state == ICAP_INPUT_READING_TRAILERS);
    int status = field_reader_read(conn->reader);
    if (status < 0) {
        if (errno == EPROTO) {
            clear_input(conn);
            protocol_violation();
            set_input_state(conn, ICAP_INPUT_ERRORED);
        }
        return -1;
    }
    if (status == 0) {
        clear_input(conn);
        protocol_violation();
        set_input_state(conn, ICAP_INPUT_ERRORED);
        return -1;
    }
    const char *end;
    conn->trailer_buffer = field_reader_combine(conn->reader, &end);
    set_input_state(conn, ICAP_INPUT_AWAITING_BODY_CLOSE);
    if (!http_env_parse_trailers(conn->trailer_envelope, conn->trailer_buffer,
                                 end)) {
        clear_input(conn);
        protocol_violation();
        set_input_state(conn, ICAP_INPUT_ERRORED);
        return -1;
    }
    return 0;
}

static ssize_t body_read_final_extensions(icap_conn_t *conn)
{
    assert(conn->input_state == ICAP_INPUT_READING_FINAL_EXTENSIONS);
    for (;;) {
        char *p = conn->final_extensions + conn->final_extensions_cursor;
        size_t size =
            sizeof conn->final_extensions - conn->final_extensions_cursor;
        ssize_t n = queuestream_read(conn->underlying_stream, p, size);
        if (n < 0)
            return -1;
        if (n == 0) {
            /* Covers the case where size == 0, as well. */
            clear_input(conn);
            protocol_violation();
            set_input_state(conn, ICAP_INPUT_ERRORED);
            return -1;
        }
        size_t i;
        for (i = 0; i < n; i++)
            if (p[i] == '\n') {
                if (conn->final_extensions_cursor + i > 0 && p[i - 1] == '\r')
                    p[i - 1] = '\0';
                else
                    p[i] = '\0';
                http_env_set_final_extensions(conn->icap_envelope,
                                              conn->final_extensions);
                i++;
                push_leftovers(conn, p + i, n - i);
                bytestream_1 reader_stream =
                    queuestream_as_bytestream_1(conn->underlying_stream);
                conn->reader =
                    make_field_reader(reader_stream, conn->max_trailer_size);
                set_input_state(conn, ICAP_INPUT_READING_TRAILERS);
                return body_read_trailers(conn);
            }
        conn->final_extensions_cursor += n;
    }
}

static ssize_t do_read(icap_conn_t *conn, void *buf, size_t count)
{
    switch (conn->input_state) {
        case ICAP_INPUT_PASSING_BODY:
            break;
        case ICAP_INPUT_READING_FINAL_EXTENSIONS:
            return body_read_final_extensions(conn);
        case ICAP_INPUT_READING_TRAILERS:
            return body_read_trailers(conn);
        case ICAP_INPUT_AWAITING_BODY_CLOSE:
        case ICAP_INPUT_AWAITING_UNENCAPSULATED_CLOSE:
            return 0;
        case ICAP_INPUT_ERRORED:
            protocol_violation();
            return -1;
        default:
            abort();
    }
    if (count == 0)
        return 0;
    ssize_t n = chunkdecoder_read(conn->chunk_decoder, buf, count);
    if (n < 0) {
        if (errno == EPROTO) {
            clear_input(conn);
            protocol_violation();
            set_input_state(conn, ICAP_INPUT_ERRORED);
        }
        return -1;
    }
    if (n == 0) {
        push_leftovers(conn, chunkdecoder_leftover_bytes(conn->chunk_decoder),
                       chunkdecoder_leftover_size(conn->chunk_decoder));
        conn->final_extensions_cursor = 0;
        set_input_state(conn, ICAP_INPUT_READING_FINAL_EXTENSIONS);
        return body_read_final_extensions(conn);
    }
    return n;
}

FSTRACE_DECL(ASYNCHTTP_ICAP_CONTENT_READ, "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_ICAP_CONTENT_READ_DUMP, "UID=%64u DATA=%B");

static ssize_t content_read(icap_conn_t *conn, void *buf, size_t count)
{
    ssize_t n = do_read(conn, buf, count);
    FSTRACE(ASYNCHTTP_ICAP_CONTENT_READ, conn->uid, count, n);
    FSTRACE(ASYNCHTTP_ICAP_CONTENT_READ_DUMP, conn->uid, buf, n);
    return n;
}

FSTRACE_DECL(ASYNCHTTP_ICAP_BODY_READ, "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_ICAP_BODY_READ_DUMP, "UID=%64u DATA=%B");

static ssize_t body_read(icap_conn_t *conn, void *buf, size_t count)
{
    assert(conn->first_leg_open);
    ssize_t n = do_read(conn, buf, count);
    FSTRACE(ASYNCHTTP_ICAP_BODY_READ, conn->uid, count, n);
    FSTRACE(ASYNCHTTP_ICAP_BODY_READ_DUMP, conn->uid, buf, n);
    return n;
}

static void skip_trailers(icap_conn_t *conn)
{
    assert(conn->input_state == ICAP_INPUT_SKIPPING_TRAILERS);
    int status = field_reader_read(conn->reader);
    if (status <= 0) {
        if (status < 0 && errno == EAGAIN)
            return;
        clear_input(conn);
        protocol_violation();
        set_input_state(conn, ICAP_INPUT_ERRORED);
        async_execute(conn->async, conn->callback);
        return;
    }
    const char *end;
    conn->trailer_buffer = field_reader_combine(conn->reader, &end);
    /* Change state here so clear_input() cleans up trailer_buffer */
    set_input_state(conn, ICAP_INPUT_AWAITING_BODY_CLOSE);
    if (!http_env_parse_trailers(conn->trailer_envelope, conn->trailer_buffer,
                                 end)) {
        clear_input(conn);
        protocol_violation();
        set_input_state(conn, ICAP_INPUT_ERRORED);
        async_execute(conn->async, conn->callback);
        return;
    }
    if (conn->first_leg_open)
        return;
    clear_input(conn);
    set_input_state(conn, ICAP_INPUT_AWAITING_ICAP_ENVELOPE);
    async_execute(conn->async, conn->callback);
}

static void skip_final_extensions(icap_conn_t *conn)
{
    assert(conn->input_state == ICAP_INPUT_SKIPPING_FINAL_EXTENSIONS);
    for (;;) {
        ssize_t n =
            queuestream_read(conn->underlying_stream, conn->final_extensions,
                             sizeof conn->final_extensions);
        if (n <= 0) {
            if (n < 0 && errno == EAGAIN)
                return;
            clear_input(conn);
            protocol_violation();
            set_input_state(conn, ICAP_INPUT_ERRORED);
            async_execute(conn->async, conn->callback);
            return;
        }
        size_t i = 0;
        while (i < n)
            if (conn->final_extensions[i++] == '\n') {
                push_leftovers(conn, conn->final_extensions + i, n - i);
                bytestream_1 reader_stream =
                    queuestream_as_bytestream_1(conn->underlying_stream);
                conn->reader =
                    make_field_reader(reader_stream, conn->max_trailer_size);
                set_input_state(conn, ICAP_INPUT_SKIPPING_TRAILERS);
                skip_trailers(conn);
                return;
            }
    }
}

static void skip_body(icap_conn_t *conn)
{
    assert(conn->input_state == ICAP_INPUT_SKIPPING_BODY);
    for (;;) {
        uint8_t buf[2000];
        ssize_t n = chunkdecoder_read(conn->chunk_decoder, buf, sizeof buf);
        if (n < 0) {
            if (errno == EAGAIN)
                return;
            clear_input(conn);
            protocol_violation();
            set_input_state(conn, ICAP_INPUT_ERRORED);
            async_execute(conn->async, conn->callback);
            return;
        }
        if (n == 0) {
            push_leftovers(conn,
                           chunkdecoder_leftover_bytes(conn->chunk_decoder),
                           chunkdecoder_leftover_size(conn->chunk_decoder));
            set_input_state(conn, ICAP_INPUT_SKIPPING_FINAL_EXTENSIONS);
            skip_final_extensions(conn);
            return;
        }
    }
}

FSTRACE_DECL(ASYNCHTTP_ICAP_BODY_PROBE, "UID=%64u");

static void body_probe(icap_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_ICAP_BODY_PROBE, conn->uid);
    switch (conn->input_state) {
        case ICAP_INPUT_PASSING_BODY:
        case ICAP_INPUT_READING_TRAILERS:
            if (conn->second_leg_open)
                action_1_perf(conn->continuation_callback);
            else
                action_1_perf(conn->body_callback);
            break;
        case ICAP_INPUT_SKIPPING_BODY:
            skip_body(conn);
            break;
        case ICAP_INPUT_SKIPPING_FINAL_EXTENSIONS:
            skip_final_extensions(conn);
            break;
        case ICAP_INPUT_SKIPPING_TRAILERS:
            skip_trailers(conn);
            break;
        default:
            abort();
    }
}

FSTRACE_DECL(ASYNCHTTP_ICAP_CLOSE_TRANSACTION, "UID=%64u");

static void close_transaction(icap_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_ICAP_CLOSE_TRANSACTION, conn->uid);
    switch (conn->input_state) {
        case ICAP_INPUT_PASSING_BODY: {
            set_input_state(conn, ICAP_INPUT_SKIPPING_BODY);
            action_1 probe_cb = { conn, (act_1) body_probe };
            async_execute(conn->async, probe_cb);
        } break;
        case ICAP_INPUT_READING_TRAILERS: {
            set_input_state(conn, ICAP_INPUT_SKIPPING_TRAILERS);
            action_1 probe_cb = { conn, (act_1) body_probe };
            async_execute(conn->async, probe_cb);
        } break;
        case ICAP_INPUT_AWAITING_BODY_CLOSE:
        case ICAP_INPUT_AWAITING_UNENCAPSULATED_CLOSE:
            clear_input(conn);
            set_input_state(conn, ICAP_INPUT_AWAITING_ICAP_ENVELOPE);
            break;
        case ICAP_INPUT_ERRORED:
            break;
        default:
            abort();
    }
}

FSTRACE_DECL(ASYNCHTTP_ICAP_BODY_CLOSE, "UID=%64u");

static void body_close(icap_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_ICAP_BODY_CLOSE, conn->uid);
    assert(conn->first_leg_open);
    conn->first_leg_open = false;
    if (!conn->second_leg_open)
        close_transaction(conn);
}

FSTRACE_DECL(ASYNCHTTP_ICAP_BODY_REGISTER, "UID=%64u OBJ=%p ACT=%p");

static void body_register_callback(icap_conn_t *conn, action_1 action)
{
    FSTRACE(ASYNCHTTP_ICAP_BODY_REGISTER, conn->uid, action.obj, action.act);
    conn->body_callback = action;
}

FSTRACE_DECL(ASYNCHTTP_ICAP_BODY_UNREGISTER, "UID=%64u");

static void body_unregister_callback(icap_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_ICAP_BODY_UNREGISTER, conn->uid);
    conn->body_callback = NULL_ACTION_1;
}

static const struct bytestream_1_vt body_stream_vt = {
    .read = (void *) body_read,
    .close = (void *) body_close,
    .register_callback = (void *) body_register_callback,
    .unregister_callback = (void *) body_unregister_callback
};

static const struct bytestream_1_vt unencapsulated_stream_vt = {
    .read = (void *) content_read,
    .close = (void *) close_transaction,
    .register_callback = (void *) body_register_callback,
    .unregister_callback = (void *) body_unregister_callback
};

static bool parse_http_envelopes(icap_conn_t *conn, ssize_t *http_req_size,
                                 ssize_t *http_resp_size)
{
    *http_req_size = *http_resp_size = 0;
    conn->http_request = conn->http_response = conn->dummy_envelope = NULL;
    if (!conn->body_offset) {
        conn->dummy_envelope = make_http_env_request(NULL, NULL, NULL);
        return true;
    }
    if (conn->res_hdr_offset > 0) {
        *http_req_size = conn->res_hdr_offset;
        *http_resp_size = conn->body_offset - conn->res_hdr_offset;
        conn->http_request =
            http_env_parse_request(conn->http_buffer,
                                   conn->http_buffer + conn->res_hdr_offset);
        if (!conn->http_request)
            return false;
        conn->http_response =
            http_env_parse_response(conn->http_buffer + conn->res_hdr_offset,
                                    conn->http_buffer + conn->body_offset);
        if (!conn->http_response) {
            destroy_http_env(conn->http_request);
            return false;
        }
        return true;
    }
    if (conn->req_hdr_offset >= 0) {
        *http_req_size = conn->body_offset;
        conn->http_request =
            http_env_parse_request(conn->http_buffer,
                                   conn->http_buffer + conn->body_offset);
        return conn->http_request != NULL;
    }
    *http_resp_size = conn->body_offset;
    conn->http_response =
        http_env_parse_response(conn->http_buffer,
                                conn->http_buffer + conn->body_offset);
    return conn->http_response != NULL;
}

static void input_notification(icap_conn_t *conn)
{
    action_1_perf(conn->callback);
}

static const http_env_t *receive_http_envelopes(
    icap_conn_t *conn, http_env_type_t type, const http_env_t **http_request,
    const http_env_t **http_response, icap_body_type_t *body_type,
    bytestream_1 *body)
{
    assert(conn->input_state == ICAP_INPUT_READING_HTTP_ENVELOPES);
    for (;;) {
        char *p = conn->http_buffer + conn->http_buffer_cursor;
        size_t size = conn->body_offset - conn->http_buffer_cursor;
        if (!size)
            break;
        ssize_t count = queuestream_read(conn->underlying_stream, p, size);
        if (count < 0)
            return NULL;
        if (count == 0) {
            clear_input(conn);
            protocol_violation();
            set_input_state(conn, ICAP_INPUT_ERRORED);
            return NULL;
        }
        conn->http_buffer_cursor += count;
    }
    queuestream_unregister_callback(conn->underlying_stream);
    ssize_t http_req_size, http_resp_size;
    if (!parse_http_envelopes(conn, &http_req_size, &http_resp_size)) {
        clear_input(conn);
        protocol_violation();
        set_input_state(conn, ICAP_INPUT_ERRORED);
        return NULL;
    }
    if (http_request)
        *http_request = conn->http_request;
    if (http_response)
        *http_response = conn->http_response;
    *body_type = conn->body_type;
    switch (conn->body_type) {
        case ICAP_REQ_BODY:
            conn->trailer_envelope = conn->http_request;
            conn->max_trailer_size = conn->max_envelope_size - http_req_size;
            *body = (bytestream_1) { conn, &body_stream_vt };
            break;
        case ICAP_RES_BODY:
            conn->trailer_envelope = conn->http_response;
            conn->max_trailer_size = conn->max_envelope_size - http_resp_size;
            *body = (bytestream_1) { conn, &body_stream_vt };
            break;
        case ICAP_NULL_BODY:
            conn->trailer_envelope = conn->dummy_envelope;
            conn->max_trailer_size = conn->max_envelope_size;
            *body = (bytestream_1) { conn, &unencapsulated_stream_vt };
            break;
        default:
            abort();
    }
    if (conn->body_type == ICAP_NULL_BODY)
        set_input_state(conn, ICAP_INPUT_AWAITING_UNENCAPSULATED_CLOSE);
    else {
        conn->chunk_decoder =
            chunk_decode(conn->async,
                         queuestream_as_bytestream_1(conn->underlying_stream),
                         CHUNKDECODER_DETACH_AT_FINAL_EXTENSIONS);
        action_1 body_cb = { conn, (act_1) body_probe };
        chunkdecoder_register_callback(conn->chunk_decoder, body_cb);
        conn->body_callback = conn->continuation_callback = NULL_ACTION_1;
        conn->first_leg_open = true;
        conn->second_leg_open = false;
        set_input_state(conn, ICAP_INPUT_PASSING_BODY);
    }
    return conn->icap_envelope;
}

static const http_env_t *receive_icap_envelope(icap_conn_t *conn,
                                               http_env_type_t type,
                                               const http_env_t **http_request,
                                               const http_env_t **http_response,
                                               icap_body_type_t *body_type,
                                               bytestream_1 *body)
{
    assert(conn->input_state == ICAP_INPUT_AWAITING_ICAP_ENVELOPE);
    const http_env_t *envelope = http_decoder_dequeue(conn->decoder, type);
    if (!envelope)
        return NULL;
    conn->icap_envelope = copy_http_env(envelope);
    const char *encapsulated =
        http_env_get_matching_header(conn->icap_envelope, "encapsulated");
    if (!encapsulated) {
        if (http_request)
            *http_request = NULL;
        if (http_response)
            *http_response = NULL;
        if (body_type)
            *body_type = ICAP_UNENCAPSULATED;
        *body = (bytestream_1) { conn, &unencapsulated_stream_vt };
        conn->underlying_stream = http_decoder_grab_content(conn->decoder);
        set_input_state(conn, ICAP_INPUT_AWAITING_UNENCAPSULATED_CLOSE);
        conn->http_buffer = NULL;
        conn->dummy_envelope = NULL;
        return conn->icap_envelope;
    }
    if (!parse_encapsulated(conn, encapsulated, &conn->req_hdr_offset,
                            &conn->res_hdr_offset, &conn->body_type,
                            &conn->body_offset)) {
        clear_input(conn);
        protocol_violation();
        set_input_state(conn, ICAP_INPUT_ERRORED);
        return NULL;
    }
    conn->underlying_stream = http_decoder_grab_content(conn->decoder);
    conn->http_buffer = fsalloc(conn->body_offset);
    conn->http_buffer_cursor = 0;
    set_input_state(conn, ICAP_INPUT_READING_HTTP_ENVELOPES);
    action_1 input_cb = { conn, (act_1) input_notification };
    queuestream_register_callback(conn->underlying_stream, input_cb);
    return receive_http_envelopes(conn, type, http_request, http_response,
                                  body_type, body);
}

static const http_env_t *do_receive(icap_conn_t *conn, http_env_type_t type,
                                    const http_env_t **http_request,
                                    const http_env_t **http_response,
                                    icap_body_type_t *body_type,
                                    bytestream_1 *body)
{
    switch (conn->input_state) {
        case ICAP_INPUT_AWAITING_ICAP_ENVELOPE:
            return receive_icap_envelope(conn, type, http_request,
                                         http_response, body_type, body);
        case ICAP_INPUT_READING_HTTP_ENVELOPES:
            return receive_http_envelopes(conn, type, http_request,
                                          http_response, body_type, body);
        case ICAP_INPUT_PASSING_BODY:
        case ICAP_INPUT_SKIPPING_BODY:
        case ICAP_INPUT_READING_FINAL_EXTENSIONS:
        case ICAP_INPUT_SKIPPING_FINAL_EXTENSIONS:
        case ICAP_INPUT_READING_TRAILERS:
        case ICAP_INPUT_SKIPPING_TRAILERS:
        case ICAP_INPUT_AWAITING_BODY_CLOSE:
        case ICAP_INPUT_AWAITING_UNENCAPSULATED_CLOSE:
            errno = EAGAIN;
            return NULL;
        case ICAP_INPUT_DISCONNECTED:
            errno = 0;
            return NULL;
        case ICAP_INPUT_ERRORED:
            protocol_violation();
            return NULL;
        case ICAP_INPUT_CLOSED:
            errno = EBADF;
            return NULL;
        default:
            abort();
    }
}

FSTRACE_DECL(ASYNCHTTP_ICAP_RECEIVE,
             "UID=%64u RESP=%p HTTP-REQ=%p HTTP-RESP=%p BODY-TYPE=%I BODY=%p");
FSTRACE_DECL(ASYNCHTTP_ICAP_RECEIVE_EOF, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_ICAP_RECEIVE_FAIL, "UID=%64u ERRNO=%e");

const http_env_t *icap_receive(icap_conn_t *conn, http_env_type_t type,
                               const http_env_t **http_request,
                               const http_env_t **http_response,
                               icap_body_type_t *body_type, bytestream_1 *body)
{
    const http_env_t *resp =
        do_receive(conn, type, http_request, http_response, body_type, body);
    if (resp) {
        const http_env_t *http_req = http_request ? *http_request : NULL;
        const http_env_t *http_resp = http_response ? *http_response : NULL;
        FSTRACE(ASYNCHTTP_ICAP_RECEIVE, conn->uid, resp, http_req, http_resp,
                trace_body_type, body_type, body->obj);
    } else {
        if (errno == 0)
            FSTRACE(ASYNCHTTP_ICAP_RECEIVE_EOF, conn->uid);
        else
            FSTRACE(ASYNCHTTP_ICAP_RECEIVE_FAIL, conn->uid);
    }
    return resp;
}

FSTRACE_DECL(ASYNCHTTP_ICAP_CONTINUATION_READ,
             "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_ICAP_CONTINUATION_READ_DUMP, "UID=%64u DATA=%B");

static ssize_t continuation_read(icap_conn_t *conn, void *buf, size_t count)
{
    assert(conn->second_leg_open);
    ssize_t n = do_read(conn, buf, count);
    FSTRACE(ASYNCHTTP_ICAP_CONTINUATION_READ, conn->uid, count, n);
    FSTRACE(ASYNCHTTP_ICAP_CONTINUATION_READ_DUMP, conn->uid, buf, n);
    return n;
}

FSTRACE_DECL(ASYNCHTTP_ICAP_CONTINUATION_CLOSE, "UID=%64u");

static void continuation_close(icap_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_ICAP_CONTINUATION_CLOSE, conn->uid);
    assert(conn->second_leg_open);
    conn->second_leg_open = false;
    if (!conn->first_leg_open)
        close_transaction(conn);
}

FSTRACE_DECL(ASYNCHTTP_ICAP_CONTINUATION_REGISTER, "UID=%64u OBJ=%p ACT=%p");

static void continuation_register_callback(icap_conn_t *conn, action_1 action)
{
    FSTRACE(ASYNCHTTP_ICAP_CONTINUATION_REGISTER, conn->uid, action.obj,
            action.act);
    conn->continuation_callback = action;
}

FSTRACE_DECL(ASYNCHTTP_ICAP_CONTINUATION_UNREGISTER, "UID=%64u");

static void continuation_unregister_callback(icap_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_ICAP_CONTINUATION_UNREGISTER, conn->uid);
    conn->continuation_callback = NULL_ACTION_1;
}

static const struct bytestream_1_vt continuation_stream_vt = {
    .read = (void *) continuation_read,
    .close = (void *) continuation_close,
    .register_callback = (void *) continuation_register_callback,
    .unregister_callback = (void *) continuation_unregister_callback
};

FSTRACE_DECL(ASYNCHTTP_ICAP_RECEIVE_CONTINUATION, "UID=%64u");

bytestream_1 icap_receive_continuation(icap_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_ICAP_RECEIVE_CONTINUATION, conn->uid);
    assert(conn->first_leg_open);
    assert(conn->input_state == ICAP_INPUT_AWAITING_BODY_CLOSE);
    assert(!conn->second_leg_open);
    fsfree(conn->trailer_buffer);
    push_leftovers(conn, field_reader_leftover_bytes(conn->reader),
                   field_reader_leftover_size(conn->reader));
    field_reader_close(conn->reader);
    chunkdecoder_close(conn->chunk_decoder);
    conn->chunk_decoder =
        chunk_decode(conn->async,
                     queuestream_as_bytestream_1(conn->underlying_stream),
                     CHUNKDECODER_DETACH_AT_FINAL_EXTENSIONS);
    action_1 body_cb = { conn, (act_1) body_probe };
    chunkdecoder_register_callback(conn->chunk_decoder, body_cb);
    conn->continuation_callback = NULL_ACTION_1;
    conn->second_leg_open = true;
    set_input_state(conn, ICAP_INPUT_PASSING_BODY);
    return (bytestream_1) { conn, &continuation_stream_vt };
}

FSTRACE_DECL(ASYNCHTTP_ICAP_REGISTER, "UID=%64u OBJ=%p ACT=%p");

void icap_register_callback(icap_conn_t *conn, action_1 action)
{
    FSTRACE(ASYNCHTTP_ICAP_REGISTER, conn->uid, action.obj, action.act);
    conn->callback = action;
    http_decoder_register_callback(conn->decoder, action);
}

FSTRACE_DECL(ASYNCHTTP_ICAP_UNREGISTER, "UID=%64u");

void icap_unregister_callback(icap_conn_t *conn)
{
    FSTRACE(ASYNCHTTP_ICAP_UNREGISTER, conn->uid);
    conn->callback = NULL_ACTION_1;
    http_decoder_unregister_callback(conn->decoder);
}
