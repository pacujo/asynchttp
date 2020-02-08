#include <fstrace.h>
#include <fsdyn/list.h>
#include <fsdyn/fsalloc.h>
#include "envelope.h"
#include "asynchttp_version.h"

typedef struct {
    const char *field, *value;
} httpassoc_t;

struct http_env {
    http_env_type_t type;
    uint64_t uid;
    union {
        struct {
            const char *method, *path;
        } request;
        struct {
            unsigned code;
            const char *explanation;
        } response;
    };
    const char *protocol;
    list_t *headers;            /* of httpassoc_t */
    list_t *trailers;           /* of httpassoc_t */
    const char *final_extensions;
};

FSTRACE_DECL(ASYNCHTTP_ENV_REQ_CREATE,
             "UID=%64u PTR=%p METHOD=%s PATH=%s PROTOCOL=%s");

http_env_t *make_http_env_request(const char *method, const char *path,
                                  const char *protocol)
{
    http_env_t *envelope = fsalloc(sizeof *envelope);
    envelope->uid = fstrace_get_unique_id();
    FSTRACE(ASYNCHTTP_ENV_REQ_CREATE, envelope->uid, envelope,
            method, path, protocol);
    envelope->type = HTTP_ENV_REQUEST;
    envelope->request.method = method;
    envelope->request.path = path;
    envelope->protocol = protocol;
    envelope->headers = make_list();
    envelope->trailers = make_list();
    envelope->final_extensions = "";
    return envelope;
}

FSTRACE_DECL(ASYNCHTTP_ENV_RESP_CREATE,
             "UID=%64u PTR=%p PROTOCOL=%s CODE=%u EXPLANATION=%s");

http_env_t *make_http_env_response(const char *protocol, unsigned code,
                                   const char *explanation)
{
    http_env_t *envelope = fsalloc(sizeof *envelope);
    envelope->uid = fstrace_get_unique_id();
    FSTRACE(ASYNCHTTP_ENV_RESP_CREATE, envelope->uid, envelope,
            protocol, code, explanation);
    envelope->type = HTTP_ENV_RESPONSE;
    envelope->response.code = code;
    envelope->response.explanation = explanation;
    envelope->protocol = protocol;
    envelope->headers = make_list();
    envelope->trailers = make_list();
    envelope->final_extensions = "";
    return envelope;
}

static void destroy_fields(list_t *fields)
{
    while (!list_empty(fields)) {
        httpassoc_t *field = (httpassoc_t *) list_pop_first(fields);
        fsfree(field);
    }
    destroy_list(fields);
}

FSTRACE_DECL(ASYNCHTTP_ENV_DESTROY, "UID=%64u");

void destroy_http_env(http_env_t *envelope)
{
    FSTRACE(ASYNCHTTP_ENV_DESTROY, envelope->uid);
    destroy_fields(envelope->headers);
    destroy_fields(envelope->trailers);
    fsfree(envelope);
}

static void add_field(list_t *fields, const char *field, const char *value)
{
    httpassoc_t *assoc = fsalloc(sizeof *assoc);
    assoc->field = field;
    assoc->value = value;
    list_append(fields, assoc);
}

FSTRACE_DECL(ASYNCHTTP_ENV_ADD_HEADER, "UID=%64u FIELD=%s VALUE=%s");

void http_env_add_header(http_env_t *envelope, const char *field,
                         const char *value)
{
    FSTRACE(ASYNCHTTP_ENV_ADD_HEADER, envelope->uid, field, value);
    add_field(envelope->headers, field, value);
}

FSTRACE_DECL(ASYNCHTTP_ENV_ADD_TRAILER, "UID=%64u FIELD=%s VALUE=%s");

void http_env_add_trailer(http_env_t *envelope, const char *field,
                          const char *value)
{
    FSTRACE(ASYNCHTTP_ENV_ADD_TRAILER, envelope->uid, field, value);
    add_field(envelope->trailers, field, value);
}

FSTRACE_DECL(ASYNCHTTP_ENV_SET_FINAL_EXT, "UID=%64u FINAL-EXT=%s");

void http_env_set_final_extensions(http_env_t *envelope,
                                   const char *final_extensions)
{
    FSTRACE(ASYNCHTTP_ENV_SET_FINAL_EXT, envelope->uid, final_extensions);
    envelope->final_extensions = final_extensions;
}

http_env_type_t http_env_get_type(const http_env_t *envelope)
{
    return envelope->type;
}

const char *http_env_get_protocol(const http_env_t *envelope)
{
    return envelope->protocol;
}

const char *http_env_get_method(const http_env_t *envelope)
{
    if (envelope->type != HTTP_ENV_REQUEST)
        return NULL;
    return envelope->request.method;
}

const char *http_env_get_path(const http_env_t *envelope)
{
    if (envelope->type != HTTP_ENV_REQUEST)
        return NULL;
    return envelope->request.path;
}

int http_env_get_code(const http_env_t *envelope)
{
    if (envelope->type != HTTP_ENV_RESPONSE)
        return -1;
    return envelope->response.code;
}

const char *http_env_get_explanation(const http_env_t *envelope)
{
    if (envelope->type != HTTP_ENV_RESPONSE)
        return NULL;
    return envelope->response.explanation;
}

static http_env_iter_t *get_next_field(list_t *fields, http_env_iter_t *iter,
                                       const char **field, const char **value)
{
    list_elem_t *e;
    if (iter)
        e = list_next((list_elem_t *) iter);
    else e = list_get_first(fields);
    if (!e)
        return NULL;
    httpassoc_t *assoc = (httpassoc_t *) list_elem_get_value(e);
    *field = assoc->field;
    *value = assoc->value;
    return (http_env_iter_t *) e;
}

http_env_iter_t *http_env_get_next_header(const http_env_t *envelope,
                                          http_env_iter_t *iter,
                                          const char **field,
                                          const char **value)
{
    return get_next_field(envelope->headers, iter, field, value);
}

http_env_iter_t *http_env_get_next_trailer(const http_env_t *envelope,
                                           http_env_iter_t *iter,
                                           const char **field,
                                           const char **value)
{
    return get_next_field(envelope->trailers, iter, field, value);
}

FSTRACE_DECL(ASYNCHTTP_ENV_COPY, "UID=%64u ORIG=%64u");

http_env_t *copy_http_env(const http_env_t *envelope)
{
    http_env_t *copy;
    if (envelope->type == HTTP_ENV_REQUEST)
        copy = make_http_env_request(http_env_get_method(envelope),
                                     http_env_get_path(envelope),
                                     http_env_get_protocol(envelope));
    else copy = make_http_env_response(http_env_get_protocol(envelope),
                                       http_env_get_code(envelope),
                                       http_env_get_explanation(envelope));
    const char *field, *value;
    http_env_iter_t *iter = NULL;
    while ((iter = http_env_get_next_header(envelope, iter, &field, &value)))
        http_env_add_header(copy, field, value);
    while ((iter = http_env_get_next_trailer(envelope, iter, &field, &value)))
        http_env_add_trailer(copy, field, value);
    http_env_set_final_extensions(copy,
                                  http_env_get_final_extensions(envelope));
    FSTRACE(ASYNCHTTP_ENV_COPY, copy->uid, envelope->uid);
    return copy;
}

static char lcase[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

int compare_case_insensitively(const char *a, const char *b)
{
    /* Don't use strcasecmp() because of locale nonsense. */
    while (*a) {
        unsigned char ac = lcase[*(unsigned char *) a++];
        unsigned char bc = lcase[*(unsigned char *) b++];
        if (ac < bc)
            return -1;
        if (ac > bc)
            return 1;
    }
    return 0;
}

static http_env_iter_t *get_next_matching_field(list_t *fields,
                                                http_env_iter_t *iter,
                                                const char *field,
                                                const char **value)
{
    const char *next;
    do {
        iter = get_next_field(fields, iter, &next, value);
    } while (iter && compare_case_insensitively(field, next));
    return iter;
}

http_env_iter_t *http_env_get_next_matching_header(const http_env_t *envelope,
                                                   http_env_iter_t *iter,
                                                   const char *field,
                                                   const char **value)
{
    return get_next_matching_field(envelope->headers, iter, field, value);
}

http_env_iter_t *http_env_get_next_matching_trailer(const http_env_t *envelope,
                                                    http_env_iter_t *iter,
                                                    const char *field,
                                                    const char **value)
{
    return get_next_matching_field(envelope->trailers, iter, field, value);
}

static const char *get_matching_field(list_t *fields, const char *name)
{
    const char *value;
    if (!get_next_matching_field(fields, NULL, name, &value))
        return NULL;
    return value;
}

const char *http_env_get_matching_header(const http_env_t *envelope,
                                         const char *name)
{
    return get_matching_field(envelope->headers, name);
}

const char *http_env_get_matching_trailer(const http_env_t *envelope,
                                          const char *name)
{
    return get_matching_field(envelope->trailers, name);
}

const char *http_env_get_final_extensions(const http_env_t *envelope)
{
    return envelope->final_extensions;
}

static char *skip_token(char *p, const char *end)
{
    if (!p || p >= end)
        return NULL;
    switch (*p++) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
        case ':':
            return NULL;
        default:
            ;
    }
    while (p && p < end)
        switch (*p) {
            case ' ':
            case '\t':
            case '\r':
            case '\n':
            case ':':
                return p;
            default:
                p++;
        }
    return p;
}

static char *skip_char(char *p, const char *end, char c)
{
    if (!p || p >= end || *p != c)
        return NULL;
    return p + 1;
}

static char *skip_crlf(char *p, const char *end)
{
    if (!p || p >= end)
        return NULL;
    switch (*p++) {
        case '\n':
            return p;
        case '\r':
            if (p >= end || *p++ != '\n')
                return NULL;
            return p;
        default:
            return NULL;
    }
}

static char *skip_till_end_of_line(char *p, const char *end)
{
    while (p && p < end)
        switch (*p) {
            case '\r':
            case '\n':
                return p;
            default:
                p++;
        }
    return NULL;
}

static char *skip_ws(char *p, const char *end)
{
    if (!p)
        return NULL;
    while (p < end && (*p == '\t' || *p == ' '))
        p++;
    return p;
}

static char *backskip_ws(char *p, const char *start)
{
    if (!p)
        return NULL;
    while (p > start && (*p == '\t' || *p == ' '))
        p--;
    return p;
}

/* Remove folding sequences. Return a pointer to the beginning of the
 * next line. */
static char *unfold_value(char *p, const char *end, char **value_end)
{
    char *q = p;
    while (p < end)
        switch (*p) {
            case '\r':
                p++;
                if (p >= end || *p != '\n') {
                    *q++ = '\r';
                    break;
                }
                /* flow through */
            case '\n':
                p++;
                if (p >= end)
                    return NULL;
                switch (*p) {
                    case ' ':
                    case '\t':
                        p++;
                        /* In accordance with RFC 2616 (even if
                         * deprecated by RFC 7230) and in slight
                         * violation of RFC 2822: skip all LWS
                         * and replace with a single SP. */
                        p = skip_ws(p, end);
                        *q++ = ' ';
                        break;
                    default:
                        *value_end = q;
                        return p;
                }
                break;
            default:
                *q++ = *p++;
        }
    return NULL;
}

/* Return a negative number in case of an error. */
static int evaluate_status_code(const char *status)
{
    if (status[0] < '0' || status[0] > '9' ||
        status[1] < '0' || status[1] > '9' ||
        status[2] < '0' || status[2] > '9' ||
        status[3])
        return -1;
    return status[0] * 100 + status[1] * 10 + status[2] - '0' * 111;
}

static char *chop_first_header_line(char *p, const char *end,
                                    const char **f0,
                                    const char **f1,
                                    const char **f2)
{
    char *f_begin0, *f_begin1, *f_begin2;
    char *f_end0, *f_end1, *f_end2;
    f_begin0 = p;
    f_end0 = skip_token(f_begin0, end);
    f_begin1 = skip_char(f_end0, end, ' ');
    f_end1 = skip_token(f_begin1, end);
    f_begin2 = skip_char(f_end1, end, ' ');
    f_end2 = skip_till_end_of_line(f_begin2, end);
    char *next_line = skip_crlf(f_end2, end);
    if (!next_line)
        return NULL;
    *f_end0 = *f_end1 = *f_end2 = '\0';
    *f0 = f_begin0;
    *f1 = f_begin1;
    *f2 = f_begin2;
    return next_line;
}

static char *chop_field(char *p, const char *end,
                        const char **field, const char **value)
{
    char *field_end, *value_end;
    *field = p;
    field_end = p = skip_token(p, end);
    p = skip_ws(p, end);
    p = skip_char(p, end, ':');
    if (!p)
        return NULL;
    char *value_start = p;
    p = unfold_value(p, end, &value_end);
    if (!p)
        return NULL;
    *value = value_start = skip_ws(value_start, value_end);
    value_end = backskip_ws(value_end, value_start);
    *field_end = *value_end = '\0';
    return p;
}

http_env_t *http_env_parse_request(char *buffer, const char *end)
{
    const char *method, *path, *protocol;
    char *p = chop_first_header_line(buffer, end, &method, &path, &protocol);
    if (!p)
        return NULL;
    http_env_t *envelope = make_http_env_request(method, path, protocol);
    while (p < end && (*p != '\r' && *p != '\n')) {
        const char *field, *value;
        p = chop_field(p, end, &field, &value);
        if (!p) {
            destroy_http_env(envelope);
            return NULL;
        }
        http_env_add_header(envelope, field, value);
    }
    return envelope;
}

http_env_t *http_env_parse_response(char *buffer, const char *end)
{
    const char *protocol, *status, *explanation;
    char *p =
        chop_first_header_line(buffer, end, &protocol, &status, &explanation);
    if (!p)
        return NULL;
    int code = evaluate_status_code(status);
    if (code < 0)
        return NULL;
    http_env_t *envelope = make_http_env_response(protocol, code, explanation);
    while (p < end && (*p != '\r' && *p != '\n')) {
        const char *field, *value;
        p = chop_field(p, end, &field, &value);
        if (!p) {
            destroy_http_env(envelope);
            return NULL;
        }
        http_env_add_header(envelope, field, value);
    }
    return envelope;
}

http_env_t *http_env_parse_headers(http_env_type_t type,
                                   char *header_buffer, const char *end)
{
    switch (type) {
        case HTTP_ENV_REQUEST:
            return http_env_parse_request(header_buffer, end);
        case HTTP_ENV_RESPONSE:
            return http_env_parse_response(header_buffer, end);
        default:
            abort();
    }
}

bool http_env_parse_trailers(http_env_t *envelope,
                             char *buffer, const char *end)
{
    char *p = buffer;
    while (p < end && (*p != '\r' && *p != '\n')) {
        const char *field, *value;
        p = chop_field(p, end, &field, &value);
        if (!p)
            return false;
        http_env_add_trailer(envelope, field, value);
    }
    return true;
}
