#include "client.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <async/emptystream.h>
#include <async/farewellstream.h>
#include <async/switchstream.h>
#include <async/tcp_client.h>
#include <async/tls_connection.h>
#include <fsdyn/base64.h>
#include <fsdyn/charstr.h>
#include <fsdyn/fsalloc.h>
#include <fsdyn/list.h>
#include <fstrace.h>
#include <nwutil.h>

#include "asynchttp_version.h"

enum {
    STALE_CONNECTION_TIMEOUT = 10, /* seconds */
    DEFAULT_PORT_HTTPS = 443,
    DEFAULT_PORT_HTTP = 80,
};

typedef enum {
    PROXY_SYSTEM,
    PROXY_DIRECT,
    PROXY_EXPLICIT,
} proxy_mode_t;

struct http_client {
    bool closed;
    async_t *async;
    uint64_t uid;
    fsadns_t *dns;
    list_t *operations;     /* of http_op_t */
    list_t *free_conn_pool; /* of pool_elem_t */
    size_t max_envelope_size;
    proxy_mode_t proxy_mode;
    char *proxy_host; /* NULL if no proxy */
    unsigned proxy_port;
    char *proxy_authorization; /* no proxy authorization if NULL */
    tls_ca_bundle_t *ca_bundle;
    action_1 callback;
};

typedef struct {
    http_conn_t *http_conn;
    tls_conn_t *tls_conn;
    tcp_conn_t *tcp_conn;
} protocol_stack_t;

typedef struct {
    http_client_t *client;
    uint64_t uid;
    tls_ca_bundle_t *ca_bundle;
    list_elem_t *loc;
    char *host;
    unsigned port;
    bool https;
    async_timer_t *timer;
    protocol_stack_t stack;
} pool_elem_t;

typedef enum {
    HTTP_OP_IDLE,
    HTTP_OP_CONNECTING_DIRECTLY,
    HTTP_OP_CONNECTING_TO_PROXY,
    HTTP_OP_TUNNELING,
    HTTP_OP_SENT,
    HTTP_OP_RECEIVED,
    HTTP_OP_STREAMING,
    HTTP_OP_STREAM_CLOSED,
    HTTP_OP_CLOSED_STREAMING,
    HTTP_OP_CLOSED
} http_op_state_t;

/*
 * http_op_t state machine
 * =======================
 *
 *
 *          +------- IDLE --------+
 *          |                     |
 *          v                     v
 *   CONNECTING_TO_PROXY  CONNECTING_DIRECTLY
 *          |         |           |
 *          v         |           |
 *      TUNNELING     |           |
 *          |         v           |
 *          +------> SENT <-------+
 *                    |
 *                    v
 *                 RECEIVED
 *                    |
 *                    v
 *                STREAMING ----> CLOSED_STREAMING
 *                    |                   |
 *                    v                   v
 *              STREAM_CLOSED -------> CLOSED
 */

typedef enum {
    HTTP_OP_TIMER_CANCELED,
    HTTP_OP_TIMER_RUNNING,
    HTTP_OP_TIMER_EXPIRED,
    HTTP_OP_TIMER_REPORTED
} http_op_timer_state_t;

struct http_op {
    http_client_t *client;
    uint64_t uid;
    tls_ca_bundle_t *ca_bundle;
    list_elem_t *loc; /* in client->operations */
    http_op_state_t state;
    bool https;
    char *proxy_host; /* no proxy if NULL */
    unsigned proxy_port;
    char *proxy_authorization; /* no proxy authorization if NULL */
    char *host;
    unsigned port;
    char *host_entry;    /* host[:port] */
    char *connect_entry; /* host:port or NULL*/
    char *method;
    char *path;
    http_env_t *request;
    ssize_t content_length;
    action_1 callback;
    bool recycle_connection;
    http_op_timer_state_t timer_state;
    async_timer_t *timer; /* HTTP_OP_TIMER_RUNNING */

    /* HTTP_OP_IDLE, HTTP_OP_CONNECTING_DIRECTLY,
     * HTTP_OP_CONNECTING_TO_PROXY, HTTP_OP_TUNNELING */
    bytestream_1 request_content;

    /* HTTP_OP_CONNECTING_DIRECTLY, HTTP_OP_CONNECTING_TO_PROXY */
    tcp_client_t *tcp_client;

    /* HTTP_OP_TUNNELING */
    switchstream_t *input_swstr;
    switchstream_t *output_swstr;

    /* HTTP_OP_TUNNELING, HTTP_OP_SENT, HTTP_OP_RECEIVED,
     * HTTP_OP_STREAMING, HTTP_OP_CLOSED_STREAMING */
    protocol_stack_t stack;

    /* HTTP_OP_RECEIVED */
    size_t response_content_length;

    /* HTTP_OP_STREAMING, HTTP_OP_CLOSED_STREAMING */
    bytestream_1 response_content;
    action_1 response_content_callback;
};

FSTRACE_DECL(ASYNCHTTP_CLIENT_CREATE, "UID=%64u PTR=%p ASYNC=%p");

http_client_t *open_http_client_2(async_t *async, fsadns_t *dns)
{
    http_client_t *client = fsalloc(sizeof *client);
    client->closed = false;
    client->async = async;
    client->dns = dns;
    client->uid = fstrace_get_unique_id();
    FSTRACE(ASYNCHTTP_CLIENT_CREATE, client->uid, client, async);
    client->operations = make_list();
    client->free_conn_pool = make_list();
    client->max_envelope_size = 100000;
    client->proxy_mode = PROXY_SYSTEM;
    client->proxy_host = client->proxy_authorization = NULL;
    client->ca_bundle = share_tls_ca_bundle(TLS_SYSTEM_CA_BUNDLE);
    client->callback = NULL_ACTION_1;
    return client;
}

http_client_t *open_http_client(async_t *async)
{
    return open_http_client_2(async, NULL);
}

static protocol_stack_t peel_pool_element(pool_elem_t *pe)
{
    /* assert: pe->timer is no longer running */
    list_remove(pe->client->free_conn_pool, pe->loc);
    protocol_stack_t stack = pe->stack;
    destroy_tls_ca_bundle(pe->ca_bundle);
    fsfree(pe->host);
    fsfree(pe);
    return stack;
}

static void close_stack(protocol_stack_t stack)
{
    tcp_close(stack.tcp_conn);
    if (stack.tls_conn)
        tls_close(stack.tls_conn);
    http_close(stack.http_conn);
}

static void flush_free_conn_pool(http_client_t *client)
{
    while (!list_empty(client->free_conn_pool)) {
        pool_elem_t *pe = (pool_elem_t *) list_elem_get_value(
            list_get_first(client->free_conn_pool));
        async_timer_cancel(client->async, pe->timer);
        close_stack(peel_pool_element(pe));
    }
}

static void prevent_recycling_of_ops_in_flight(http_client_t *client)
{
    list_elem_t *e;
    for (e = list_get_first(client->operations); e; e = list_next(e)) {
        http_op_t *op = (http_op_t *) list_elem_get_value(e);
        op->recycle_connection = false;
    }
}

static void check_pulse(http_client_t *client)
{
    if (!client->closed)
        return;
    if (!list_empty(client->operations))
        return;
    destroy_list(client->operations);
    flush_free_conn_pool(client);
    destroy_list(client->free_conn_pool);
    fsfree(client->proxy_host);
    fsfree(client->proxy_authorization);
    destroy_tls_ca_bundle(client->ca_bundle);
    async_wound(client->async, client);
}

FSTRACE_DECL(ASYNCHTTP_CLIENT_CLOSE, "UID=%64u");

void http_client_close(http_client_t *client)
{
    FSTRACE(ASYNCHTTP_CLIENT_CLOSE, client->uid);
    assert(!client->closed);
    client->closed = true;
    check_pulse(client);
}

FSTRACE_DECL(ASYNCHTTP_CLIENT_SET_MAX_ENVELOPE_SIZE, "UID=%64u SIZE=%z");

void http_client_set_max_envelope_size(http_client_t *client, size_t size)
{
    FSTRACE(ASYNCHTTP_CLIENT_SET_MAX_ENVELOPE_SIZE, client->uid, size);
    client->max_envelope_size = size;
}

static char *make_proxy_authorization(const char *username,
                                      const char *password)
{
    if (!username || !password)
        return NULL;
    char *credentials = charstr_printf("%s:%s", username, password);
    char *encoding = base64_encode_simple(credentials, strlen(credentials));
    fsfree(credentials);
    char *auth = charstr_printf("Basic %s", encoding);
    fsfree(encoding);
    return auth;
}

/* proxy_host is moved; username and password are not */
static void set_proxy(http_client_t *client, char *proxy_host, unsigned port,
                      const char *username, const char *password)
{
    fsfree(client->proxy_host);
    fsfree(client->proxy_authorization);
    client->proxy_mode = PROXY_EXPLICIT;
    client->proxy_host = proxy_host;
    client->proxy_port = port;
    client->proxy_authorization = make_proxy_authorization(username, password);
    flush_free_conn_pool(client);
    prevent_recycling_of_ops_in_flight(client);
}

FSTRACE_DECL(ASYNCHTTP_CLIENT_SET_PROXY,
             "UID=%64u HOST=%s PORT=%u USER=%s PASSWORD=%s");
FSTRACE_DECL(ASYNCHTTP_CLIENT_NON_IDNA_PROXY_HOST, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_CLIENT_IDNA_PROXY_HOST, "UID=%64u IDNA=%s");

bool http_client_set_proxy_2(http_client_t *client, const char *proxy_host,
                             unsigned port, const char *username,
                             const char *password)
{
    FSTRACE(ASYNCHTTP_CLIENT_SET_PROXY, client->uid, proxy_host, port, username,
            password);
    char *idna = NULL;
    if (proxy_host) {
        idna = charstr_idna_encode(proxy_host);
        if (!idna) {
            FSTRACE(ASYNCHTTP_CLIENT_NON_IDNA_PROXY_HOST, client->uid);
            return false;
        }
        FSTRACE(ASYNCHTTP_CLIENT_IDNA_PROXY_HOST, client->uid, idna);
    }
    set_proxy(client, idna, port, username, password);
    return true;
}

bool http_client_set_proxy(http_client_t *client, const char *proxy_host,
                           unsigned port)
{
    return http_client_set_proxy_2(client, proxy_host, port, NULL, NULL);
}

FSTRACE_DECL(ASYNCHTTP_CLIENT_SET_DIRECT, "UID=%64u");

void http_client_set_direct(http_client_t *client)
{
    FSTRACE(ASYNCHTTP_CLIENT_SET_DIRECT, client->uid);
    fsfree(client->proxy_host);
    fsfree(client->proxy_authorization);
    client->proxy_host = client->proxy_authorization = NULL;
    client->proxy_mode = PROXY_DIRECT;
    flush_free_conn_pool(client);
    prevent_recycling_of_ops_in_flight(client);
}

FSTRACE_DECL(ASYNCHTTP_CLIENT_USE_SYSTEM_PROXY, "UID=%64u");

void http_client_use_system_proxy(http_client_t *client)
{
    FSTRACE(ASYNCHTTP_CLIENT_USE_SYSTEM_PROXY, client->uid);
    fsfree(client->proxy_host);
    fsfree(client->proxy_authorization);
    client->proxy_host = client->proxy_authorization = NULL;
    client->proxy_mode = PROXY_SYSTEM;
    flush_free_conn_pool(client);
    prevent_recycling_of_ops_in_flight(client);
}

FSTRACE_DECL(ASYNCHTTP_CLIENT_SET_CA_BUNDLE, "UID=%64u CA-BUNDLE=%p");

void http_client_set_tls_ca_bundle(http_client_t *client,
                                   tls_ca_bundle_t *ca_bundle)
{
    FSTRACE(ASYNCHTTP_CLIENT_SET_CA_BUNDLE, client->uid, ca_bundle);
    destroy_tls_ca_bundle(client->ca_bundle);
    client->ca_bundle = share_tls_ca_bundle(ca_bundle);
}

static bool percent_decode(const char *encoding, char **decoding)
{
    if (!encoding) {
        *decoding = NULL;
        return true;
    }
    size_t size;
    *decoding = charstr_url_decode(encoding, false, &size);
    if (!*decoding)
        return false;
    if (strlen(*decoding) != size) { /* treat %00 as an error */
        fsfree(*decoding);
        return false;
    }
    return true;
}

FSTRACE_DECL(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI, "UID=%64u URI=%s");
FSTRACE_DECL(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_SYNTAX_ERROR,
             "UID=%64u URI=%s");
FSTRACE_DECL(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_BAD_SCHEME, "UID=%64u URI=%s");
FSTRACE_DECL(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_BAD_USERNAME,
             "UID=%64u URI=%s");
FSTRACE_DECL(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_BAD_PASSWORD,
             "UID=%64u URI=%s");

bool http_client_set_proxy_from_uri(http_client_t *client, const char *uri)
{
    nwutil_url_t *url = nwutil_parse_url(uri, strlen(uri), NULL);
    if (!url) {
        FSTRACE(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_SYNTAX_ERROR, client->uid,
                uri);
        return false;
    }
    const char *scheme = nwutil_url_get_scheme(url);
    unsigned port;
    if (!strcmp(scheme, "http"))
        port = DEFAULT_PORT_HTTP;
    else if (!strcmp(scheme, "https"))
        port = DEFAULT_PORT_HTTPS;
    else {
        FSTRACE(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_BAD_SCHEME, client->uid,
                uri);
        nwutil_url_destroy(url);
        return false;
    }
    (void) nwutil_url_get_port(url, &port);
    FSTRACE(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI, client->uid, uri);
    const char *host = nwutil_url_get_host(url);
    char *username;
    if (!percent_decode(nwutil_url_get_username(url), &username)) {
        FSTRACE(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_BAD_USERNAME, client->uid,
                uri);
        nwutil_url_destroy(url);
        return false;
    }
    char *password;
    if (!percent_decode(nwutil_url_get_password(url), &password)) {
        FSTRACE(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_BAD_PASSWORD, client->uid,
                uri);
        fsfree(username);
        nwutil_url_destroy(url);
        return false;
    }
    set_proxy(client, charstr_dupstr(host), port, username, password);
    fsfree(password);
    fsfree(username);
    nwutil_url_destroy(url);
    return true;
}

static const char *trace_state(void *pstate)
{
    switch (*(http_op_state_t *) pstate) {
        case HTTP_OP_IDLE:
            return "HTTP_OP_IDLE";
        case HTTP_OP_CONNECTING_DIRECTLY:
            return "HTTP_OP_CONNECTING_DIRECTLY";
        case HTTP_OP_CONNECTING_TO_PROXY:
            return "HTTP_OP_CONNECTING_TO_PROXY";
        case HTTP_OP_TUNNELING:
            return "HTTP_OP_TUNNELING";
        case HTTP_OP_SENT:
            return "HTTP_OP_SENT";
        case HTTP_OP_RECEIVED:
            return "HTTP_OP_RECEIVED";
        case HTTP_OP_STREAMING:
            return "HTTP_OP_STREAMING";
        case HTTP_OP_STREAM_CLOSED:
            return "HTTP_OP_STREAM_CLOSED";
        case HTTP_OP_CLOSED_STREAMING:
            return "HTTP_OP_CLOSED_STREAMING";
        case HTTP_OP_CLOSED:
            return "HTTP_OP_CLOSED";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCHTTP_OP_SET_STATE, "UID=%64u OLD=%I NEW=%I");

static void set_op_state(http_op_t *op, http_op_state_t state)
{
    FSTRACE(ASYNCHTTP_OP_SET_STATE, op->uid, trace_state, &op->state,
            trace_state, &state);
    op->state = state;
}

FSTRACE_DECL(ASYNCHTTP_OP_LEARN_PROXY,
             "CLIENT=%64u PROXY-HOST=%s PROXY-PORT=%u AUTH=%s");
FSTRACE_DECL(ASYNCHTTP_OP_LEARN_GLOBAL_PROXY,
             "CLIENT=%64u PROXY-HOST=%s PROXY-PORT=%u AUTH=%s");
FSTRACE_DECL(ASYNCHTTP_OP_LEARN_PROXY_FAIL, "CLIENT=%64u ERRNO=%e");

static bool learn_op_proxy(http_op_t *op, const char *uri)
{
    op->proxy_host = op->proxy_authorization = NULL;
    http_client_t *client = op->client;
    switch (client->proxy_mode) {
        case PROXY_DIRECT:
            return true;
        case PROXY_EXPLICIT:
            op->proxy_host = charstr_dupstr(client->proxy_host);
            op->proxy_port = client->proxy_port;
            op->proxy_authorization =
                charstr_dupstr(client->proxy_authorization);
            FSTRACE(ASYNCHTTP_OP_LEARN_PROXY, client->uid, op->proxy_host,
                    op->proxy_port, op->proxy_authorization);
            return true;
        default:
            assert(false);
        case PROXY_SYSTEM:;
    }
    nwutil_http_proxy_settings_t *settings =
        nwutil_get_global_http_proxy_settings_1(uri);
    if (!settings) {
        FSTRACE(ASYNCHTTP_OP_LEARN_PROXY_FAIL, client->uid);
        return false;
    }
    if (nwutil_use_http_proxy(settings)) {
        op->proxy_host = charstr_dupstr(nwutil_http_proxy_host(settings));
        op->proxy_port = nwutil_http_proxy_port(settings);
        op->proxy_authorization =
            make_proxy_authorization(nwutil_http_proxy_user(settings),
                                     nwutil_http_proxy_password(settings));
        FSTRACE(ASYNCHTTP_OP_LEARN_GLOBAL_PROXY, client->uid, op->proxy_host,
                op->proxy_port, op->proxy_authorization);
    }
    nwutil_release_http_proxy_settings(settings);
    return true;
}

FSTRACE_DECL(ASYNCHTTP_OP_URI_SYNTAX_ERROR, "CLIENT=%64u URI=%s");
FSTRACE_DECL(ASYNCHTTP_OP_BAD_URI_SCHEME, "CLIENT=%64u URI=%s");

static bool parse_uri(http_op_t *op, const char *uri)
{
    if (!learn_op_proxy(op, uri))
        return false;
    nwutil_url_t *url = nwutil_parse_url(uri, strlen(uri), NULL);
    if (!url) {
        FSTRACE(ASYNCHTTP_OP_URI_SYNTAX_ERROR, op->client->uid, uri);
        return false;
    }
    const char *scheme = nwutil_url_get_scheme(url);
    if (!strcmp(scheme, "http")) {
        op->https = false;
        op->port = DEFAULT_PORT_HTTP;
    } else if (!strcmp(scheme, "https")) {
        op->https = true;
        op->port = DEFAULT_PORT_HTTPS;
    } else {
        FSTRACE(ASYNCHTTP_OP_BAD_URI_SCHEME, op->client->uid, uri);
        nwutil_url_destroy(url);
        return false;
    }
    (void) nwutil_url_get_port(url, &op->port);
    /* As allowed by RFC 3986 § 3.2.1, we ignore
     * nwutil_url_get_username() and nwutil_url_get_password(). */
    op->host = charstr_dupstr(nwutil_url_get_host(url));
    op->host_entry = charstr_dupstr(nwutil_url_get_host_header(url));
    if (op->proxy_host && !op->https)
        op->path = charstr_dupstr(uri);
    else {
        const char *q = "?", *query = nwutil_url_get_query(url);
        if (!query)
            q = query = "";
        const char *f = "#", *fragment = nwutil_url_get_fragment(url);
        if (!fragment)
            f = fragment = "";
        op->path = charstr_printf("%s%s%s%s%s", nwutil_url_get_path(url), q,
                                  query, f, fragment);
    }
    nwutil_url_destroy(url);
    return true;
}

FSTRACE_DECL(ASYNCHTTP_OP_CREATE_FAIL, "CLIENT=%64u METHOD=%s URI=%s");
FSTRACE_DECL(ASYNCHTTP_OP_CREATE,
             "UID=%64u PTR=%p CLIENT=%64u METHOD=%s URI=%s");

http_op_t *http_client_make_request(http_client_t *client, const char *method,
                                    const char *uri)
{
    http_op_t *op = fsalloc(sizeof *op);
    op->client = client;
    op->uid = fstrace_get_unique_id();
    op->state = HTTP_OP_IDLE;
    op->timer_state = HTTP_OP_TIMER_CANCELED;
    if (!parse_uri(op, uri)) {
        FSTRACE(ASYNCHTTP_OP_CREATE_FAIL, client->uid, method, uri);
        fsfree(op->proxy_host);
        fsfree(op->proxy_authorization);
        fsfree(op);
        return NULL;
    }
    FSTRACE(ASYNCHTTP_OP_CREATE, op->uid, op, client->uid, method, uri);
    op->ca_bundle = share_tls_ca_bundle(client->ca_bundle);
    op->method = charstr_dupstr(method);
    op->loc = list_append(client->operations, op);
    op->request = make_http_env_request(op->method, op->path, "HTTP/1.1");
    http_env_add_header(op->request, "Host", op->host_entry);
    if (op->proxy_authorization && !op->https)
        http_env_add_header(op->request, "Proxy-Authorization",
                            op->proxy_authorization);
    op->request_content = emptystream;
    op->content_length = HTTP_ENCODE_RAW;
    op->callback = NULL_ACTION_1;
    op->recycle_connection = true;
    op->connect_entry = NULL;
    return op;
}

FSTRACE_DECL(ASYNCHTTP_OP_SET_CONTENT, "UID=%64u CONTENT=%p");

void http_op_set_content(http_op_t *op, ssize_t size, bytestream_1 content)
{
    FSTRACE(ASYNCHTTP_OP_SET_CONTENT, op->uid, content.obj);
    op->request_content = content;
    op->content_length = size;
}

static const char *trace_timer_state(void *pstate)
{
    switch (*(http_op_timer_state_t *) pstate) {
        case HTTP_OP_TIMER_CANCELED:
            return "HTTP_OP_TIMER_CANCELED";
        case HTTP_OP_TIMER_RUNNING:
            return "HTTP_OP_TIMER_RUNNING";
        case HTTP_OP_TIMER_EXPIRED:
            return "HTTP_OP_TIMER_EXPIRED";
        case HTTP_OP_TIMER_REPORTED:
            return "HTTP_OP_TIMER_REPORTED";
        default:
            return fstrace_unsigned_repr(*(unsigned *) pstate);
    }
}

FSTRACE_DECL(ASYNCHTTP_OP_SET_TIMER_STATE, "UID=%64u OLD=%I NEW=%I");

static void set_timer_state(http_op_t *op, http_op_timer_state_t timer_state)
{
    FSTRACE(ASYNCHTTP_OP_SET_TIMER_STATE, op->uid, trace_timer_state,
            &op->timer_state, trace_timer_state, &timer_state);
    op->timer_state = timer_state;
}

static int again_or_timeout(http_op_t *op, int err)
{
    if (err != EAGAIN)
        return err;
    switch (op->timer_state) {
        case HTTP_OP_TIMER_EXPIRED:
            set_timer_state(op, HTTP_OP_TIMER_REPORTED);
            return ETIMEDOUT;
        case HTTP_OP_TIMER_REPORTED:
            return ETIMEDOUT;
        default:
            return EAGAIN;
    }
}

static void op_probe(http_op_t *op)
{
    action_1_perf(op->callback);
}

FSTRACE_DECL(ASYNCHTTP_OP_TIMEOUT_NOTIFY_OP, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_TIMEOUT_NOTIFY_STREAM, "UID=%64u");

static void op_timeout(http_op_t *op)
{
    assert(op->timer_state == HTTP_OP_TIMER_RUNNING);
    set_timer_state(op, HTTP_OP_TIMER_EXPIRED);
    switch (op->state) {
        case HTTP_OP_CONNECTING_DIRECTLY:
        case HTTP_OP_CONNECTING_TO_PROXY:
        case HTTP_OP_TUNNELING:
        case HTTP_OP_SENT:
            FSTRACE(ASYNCHTTP_OP_TIMEOUT_NOTIFY_OP, op->uid);
            op_probe(op);
            break;
        case HTTP_OP_STREAMING:
            FSTRACE(ASYNCHTTP_OP_TIMEOUT_NOTIFY_STREAM, op->uid);
            action_1_perf(op->response_content_callback);
            break;
        default:;
    }
}

static void op_cancel_timeout(http_op_t *op)
{
    assert(op->state != HTTP_OP_CLOSED);
    switch (op->timer_state) {
        case HTTP_OP_TIMER_RUNNING:
            async_timer_cancel(op->client->async, op->timer);
            set_timer_state(op, HTTP_OP_TIMER_CANCELED);
            break;
        case HTTP_OP_TIMER_EXPIRED:
            set_timer_state(op, HTTP_OP_TIMER_CANCELED);
            break;
        default:;
    }
}

FSTRACE_DECL(ASYNCHTTP_OP_SET_TIMEOUT, "UID=%64u DURATION=%64d");

void http_op_set_timeout(http_op_t *op, int64_t max_duration)
{
    FSTRACE(ASYNCHTTP_OP_SET_TIMEOUT, op->uid, max_duration);
    op_cancel_timeout(op);
    if (op->timer_state != HTTP_OP_TIMER_CANCELED)
        return;
    set_timer_state(op, HTTP_OP_TIMER_RUNNING);
    op->timer = async_timer_start(op->client->async,
                                  async_now(op->client->async) + max_duration,
                                  (action_1) { op, (act_1) op_timeout });
}

FSTRACE_DECL(ASYNCHTTP_OP_CANCEL_TIMEOUT, "UID=%64u");

void http_op_cancel_timeout(http_op_t *op)
{
    FSTRACE(ASYNCHTTP_OP_CANCEL_TIMEOUT, op->uid);
    op_cancel_timeout(op);
}

http_env_t *http_op_get_request_envelope(http_op_t *op)
{
    return op->request;
}

FSTRACE_DECL(ASYNCHTTP_OP_REUSE,
             "UID=%64u HOST=%s PORT=%u PROTO=%s POOL-ID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_CANNOT_REUSE, "UID=%64u HOST=%s PORT=%u PROTO=%s");

static bool reuse_connection(http_op_t *op, const char *host, unsigned port,
                             bool https)
{
    list_elem_t *e, *next;
    for (e = list_get_first(op->client->free_conn_pool); e; e = next) {
        next = list_next(e);
        pool_elem_t *pe = (pool_elem_t *) list_elem_get_value(e);
        if (!strcmp(pe->host, host) && pe->port == port && pe->https == https &&
            tls_ca_bundle_equal(pe->ca_bundle, op->ca_bundle)) {
            async_timer_cancel(pe->client->async, pe->timer);
            FSTRACE(ASYNCHTTP_OP_REUSE, op->uid, host, port,
                    https ? "HTTPS" : "HTTP", pe->uid);
            op->stack = peel_pool_element(pe);
            http_register_callback(op->stack.http_conn, op->callback);
            return true;
        }
    }
    FSTRACE(ASYNCHTTP_OP_CANNOT_REUSE, op->uid, host, port,
            https ? "HTTPS" : "HTTP");
    return false;
}

static void op_dispatch(http_op_t *op)
{
    action_1 request_closed_cb = { op->request, (act_1) destroy_http_env };
    farewellstream_t *fwstr =
        open_relaxed_farewellstream(op->client->async, op->request_content,
                                    request_closed_cb);
    bytestream_1 content = farewellstream_as_bytestream_1(fwstr);
    http_send(op->stack.http_conn, op->request, op->content_length, content);
    set_op_state(op, HTTP_OP_SENT);
}

static void op_send_http_connect(http_op_t *op)
{
    assert(!op->connect_entry);
    op->connect_entry = charstr_printf("%s:%u", op->host, op->port);
    http_env_t *connect_request =
        make_http_env_request("CONNECT", op->connect_entry, "HTTP/1.1");
    http_env_add_header(connect_request, "Host", op->connect_entry);
    if (op->proxy_authorization)
        http_env_add_header(connect_request, "Proxy-Authorization",
                            op->proxy_authorization);
    action_1 request_closed_cb = { connect_request, (act_1) destroy_http_env };
    farewellstream_t *fwstr =
        open_relaxed_farewellstream(op->client->async, emptystream,
                                    request_closed_cb);
    bytestream_1 content = farewellstream_as_bytestream_1(fwstr);
    http_send(op->stack.http_conn, connect_request, HTTP_ENCODE_RAW, content);
    set_op_state(op, HTTP_OP_TUNNELING);
}

FSTRACE_DECL(ASYNCHTTP_OP_SEND_VIA_PROXY_REUSE_HTTPS, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_SEND_VIA_PROXY_REUSING, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_SEND_VIA_PROXY, "UID=%64u");

static void op_send_request_via_proxy(http_op_t *op)
{
    if (op->https && reuse_connection(op, op->host, op->port, op->https)) {
        FSTRACE(ASYNCHTTP_OP_SEND_VIA_PROXY_REUSE_HTTPS, op->uid);
        op_dispatch(op);
        return;
    }
    if (reuse_connection(op, op->proxy_host, op->proxy_port, false)) {
        FSTRACE(ASYNCHTTP_OP_SEND_VIA_PROXY_REUSING, op->uid);
        if (op->https)
            op_send_http_connect(op);
        else
            op_dispatch(op);
        return;
    }
    FSTRACE(ASYNCHTTP_OP_SEND_VIA_PROXY, op->uid);
    op->tcp_client = open_tcp_client_2(op->client->async, op->proxy_host,
                                       op->proxy_port, op->client->dns);
    action_1 probe_cb = { op, (act_1) op_probe };
    tcp_client_register_callback(op->tcp_client, probe_cb);
    set_op_state(op, HTTP_OP_CONNECTING_TO_PROXY);
}

FSTRACE_DECL(ASYNCHTTP_OP_SEND_REUSING, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_SEND_DIRECTLY, "UID=%64u");

static void op_send_request(http_op_t *op)
{
    assert(op->state == HTTP_OP_IDLE);
    if (op->proxy_host) {
        op_send_request_via_proxy(op);
        return;
    }
    if (reuse_connection(op, op->host, op->port, op->https)) {
        FSTRACE(ASYNCHTTP_OP_SEND_REUSING, op->uid);
        op_dispatch(op);
        return;
    }
    FSTRACE(ASYNCHTTP_OP_SEND_DIRECTLY, op->uid);
    op->tcp_client = open_tcp_client_2(op->client->async, op->host, op->port,
                                       op->client->dns);
    action_1 probe_cb = { op, (act_1) op_probe };
    tcp_client_register_callback(op->tcp_client, probe_cb);
    set_op_state(op, HTTP_OP_CONNECTING_DIRECTLY);
}

FSTRACE_DECL(ASYNCHTTP_OP_ESTABLISH_FAIL, "UID=%64u ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_OP_ESTABLISH, "UID=%64u TCP-CONN=%p CONN=%p");

static bool op_build_http_stack(http_op_t *op)
{
    op->stack.tcp_conn = tcp_client_establish(op->tcp_client);
    if (!op->stack.tcp_conn) {
        FSTRACE(ASYNCHTTP_OP_ESTABLISH_FAIL, op->uid);
        return false;
    }
    tcp_client_close(op->tcp_client);
    op->input_swstr =
        open_switch_stream(op->client->async,
                           tcp_get_input_stream(op->stack.tcp_conn));
    bytestream_1 http_input = switchstream_as_bytestream_1(op->input_swstr);
    op->stack.tls_conn = NULL;
    op->stack.http_conn = open_http_connection(op->client->async, http_input,
                                               op->client->max_envelope_size);
    action_1 probe_cb = { op, (act_1) op_probe };
    http_register_callback(op->stack.http_conn, probe_cb);
    op->output_swstr =
        open_switch_stream(op->client->async,
                           http_get_output_stream(op->stack.http_conn));
    bytestream_1 tcp_output = switchstream_as_bytestream_1(op->output_swstr);
    tcp_set_output_stream(op->stack.tcp_conn, tcp_output);
    FSTRACE(ASYNCHTTP_OP_ESTABLISH, op->uid, op->stack.tcp_conn,
            op->stack.http_conn);
    return true;
}

static const http_env_t *op_receive_via_proxy(http_op_t *op)
{
    if (!op_build_http_stack(op))
        return NULL;
    if (op->https)
        op_send_http_connect(op);
    else
        op_dispatch(op);
    return http_op_receive_response(op);
}

static void op_wrap_tls(http_op_t *op)
{
    op->stack.tls_conn =
        open_tls_client_2(op->client->async,
                          tcp_get_input_stream(op->stack.tcp_conn),
                          op->ca_bundle, op->host);
    tls_suppress_ragged_eofs(op->stack.tls_conn);
    tls_set_plain_output_stream(op->stack.tls_conn,
                                http_get_output_stream(op->stack.http_conn));
    switchstream_reattach(op->output_swstr,
                          tls_get_encrypted_output_stream(op->stack.tls_conn));
    switchstream_reattach(op->input_swstr,
                          tls_get_plain_input_stream(op->stack.tls_conn));
}

FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_RECYCLE, "UID=%64u RECYCLE=%b");

static void response_received(http_op_t *op, const http_env_t *response)
{
    set_op_state(op, HTTP_OP_RECEIVED);
    const char *field = http_env_get_matching_header(response, "connection");
    op->recycle_connection = op->recycle_connection &&
        charstr_case_cmp(http_env_get_protocol(response), "HTTP/1.1") >= 0 &&
        (!field || strcmp(field, "close"));
    FSTRACE(ASYNCHTTP_OP_RECEIVE_RECYCLE, op->uid, op->recycle_connection);
}

static const http_env_t *op_receive_tunnel(http_op_t *op)
{
    assert(op->https);
    const http_env_t *response =
        http_receive(op->stack.http_conn, HTTP_ENV_RESPONSE);
    if (!response)
        return NULL;
    int code = http_env_get_code(response);
    if (code < 200 || code > 299) {
        response_received(op, response);
        return response;
    }
    bytestream_1 stream;
    int status = http_get_content(op->stack.http_conn, 0, &stream);
    assert(status >= 0);
    bytestream_1_close(stream);
    op_wrap_tls(op);
    op_dispatch(op);
    return http_op_receive_response(op);
}

static const http_env_t *op_receive_from_server(http_op_t *op)
{
    if (!op_build_http_stack(op))
        return NULL;
    if (op->https)
        op_wrap_tls(op);
    op_dispatch(op);
    return http_op_receive_response(op);
}

static const http_env_t *op_receive_response(http_op_t *op)
{
    const http_env_t *response =
        http_receive(op->stack.http_conn, HTTP_ENV_RESPONSE);
    if (response) {
        response_received(op, response);
        int code = http_env_get_code(response);
        if (code == 204 || (code >= 100 && code <= 199) || code == 304 ||
            !charstr_case_cmp(op->method, "head"))
            op->response_content_length = 0;
        else
            op->response_content_length = HTTP_DECODE_OBEY_HEADER;
    }
    return response;
}

FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_TIMED_OUT, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_DIRECTLY, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_VIA_PROXY, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_TUNNELING, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_SENT, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_EOF, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_RECEIVED, "UID=%64u RESPONSE=%p ERRNO=%e");

const http_env_t *http_op_receive_response(http_op_t *op)
{
    if (op->timer_state == HTTP_OP_TIMER_REPORTED) {
        FSTRACE(ASYNCHTTP_OP_RECEIVE_TIMED_OUT, op->uid);
        errno = ETIMEDOUT;
        return NULL;
    }
    const http_env_t *response;
    switch (op->state) {
        case HTTP_OP_IDLE:
            /* FSTRACE omitted intentionally */
            op_send_request(op);
            response = http_op_receive_response(op);
            break;
        case HTTP_OP_CONNECTING_DIRECTLY:
            FSTRACE(ASYNCHTTP_OP_RECEIVE_DIRECTLY, op->uid);
            response = op_receive_from_server(op);
            break;
        case HTTP_OP_CONNECTING_TO_PROXY:
            FSTRACE(ASYNCHTTP_OP_RECEIVE_VIA_PROXY, op->uid);
            response = op_receive_via_proxy(op);
            break;
        case HTTP_OP_TUNNELING:
            FSTRACE(ASYNCHTTP_OP_RECEIVE_TUNNELING, op->uid);
            response = op_receive_tunnel(op);
            break;
        case HTTP_OP_SENT:
            FSTRACE(ASYNCHTTP_OP_RECEIVE_SENT, op->uid);
            response = op_receive_response(op);
            break;
        default:
            FSTRACE(ASYNCHTTP_OP_RECEIVE_EOF, op->uid);
            errno = 0; /* pseudo-EOF */
            response = NULL;
    }
    errno = again_or_timeout(op, errno);
    FSTRACE(ASYNCHTTP_OP_RECEIVED, op->uid, response);
    return response;
}

FSTRACE_DECL(ASYNCHTTP_POOL_TIMEOUT, "UID=%64u");

static void pool_elem_timeout(pool_elem_t *pe)
{
    FSTRACE(ASYNCHTTP_POOL_TIMEOUT, pe->uid);
    close_stack(peel_pool_element(pe));
}

FSTRACE_DECL(ASYNCHTTP_MOVE_TO_POOL, "UID=%64u OP=%64u CLIENT=%64u");

static void move_connection_to_pool(http_op_t *op)
{
    http_client_t *client = op->client;
    pool_elem_t *pe = fsalloc(sizeof *pe);
    pe->client = client;
    pe->ca_bundle = share_tls_ca_bundle(op->ca_bundle);
    pe->uid = fstrace_get_unique_id();
    FSTRACE(ASYNCHTTP_MOVE_TO_POOL, pe->uid, op->uid, client->uid);
    pe->host = op->host;
    op->host = NULL;
    pe->port = op->port;
    pe->https = op->https;
    pe->stack = op->stack;
    action_1 pe_cb = { pe, (act_1) pool_elem_timeout };
    uint64_t expiry =
        async_now(client->async) + STALE_CONNECTION_TIMEOUT * ASYNC_S;
    pe->timer = async_timer_start(client->async, expiry, pe_cb);
    pe->loc = list_append(client->free_conn_pool, pe);
}

FSTRACE_DECL(ASYNCHTTP_OP_RESPONSE_CLOSED, "UID=%64u");

static void do_close(http_op_t *op);

static void response_closed(http_op_t *op)
{
    if (op->state == HTTP_OP_CLOSED)
        return;
    FSTRACE(ASYNCHTTP_OP_RESPONSE_CLOSED, op->uid);
    switch (op->state) {
        case HTTP_OP_STREAMING:
            if (op->recycle_connection)
                move_connection_to_pool(op);
            else
                close_stack(op->stack);
            set_op_state(op, HTTP_OP_STREAM_CLOSED);
            break;
        case HTTP_OP_CLOSED_STREAMING:
            if (op->recycle_connection)
                move_connection_to_pool(op);
            else
                close_stack(op->stack);
            set_op_state(op, HTTP_OP_STREAM_CLOSED);
            do_close(op);
            break;
        default:
            assert(false);
    }
}

FSTRACE_DECL(ASYNCHTTP_OP_WRAPPER_READ_TIMED_OUT, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_WRAPPER_READ, "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_OP_WRAPPER_READ_DUMP, "UID=%64u DATA=%A");

static ssize_t content_wrapper_read(void *obj, void *buf, size_t count)
{
    http_op_t *op = obj;
    if (op->timer_state == HTTP_OP_TIMER_REPORTED) {
        FSTRACE(ASYNCHTTP_OP_WRAPPER_READ_TIMED_OUT, op->uid);
        errno = ETIMEDOUT;
        return -1;
    }
    ssize_t n = bytestream_1_read(op->response_content, buf, count);
    if (n < 0)
        errno = again_or_timeout(op, errno);
    FSTRACE(ASYNCHTTP_OP_WRAPPER_READ, op->uid, count, n);
    FSTRACE(ASYNCHTTP_OP_WRAPPER_READ_DUMP, op->uid, buf, n);
    return n;
}

FSTRACE_DECL(ASYNCHTTP_OP_WRAPPER_CLOSE, "UID=%64u");

static void content_wrapper_close(void *obj)
{
    http_op_t *op = obj;
    FSTRACE(ASYNCHTTP_OP_WRAPPER_CLOSE, op->uid);
    bytestream_1_close(op->response_content);
    action_1 farewell_cb = { op, (act_1) response_closed };
    async_execute(op->client->async, farewell_cb);
}

FSTRACE_DECL(ASYNCHTTP_OP_WRAPPER_REGISTER, "UID=%64u OBJ=%p ACT=%p");

static void content_wrapper_register_callback(void *obj, action_1 action)
{
    http_op_t *op = obj;
    FSTRACE(ASYNCHTTP_OP_WRAPPER_REGISTER, op->uid, action.obj, action.act);
    bytestream_1_register_callback(op->response_content, action);
    op->response_content_callback = action;
}

FSTRACE_DECL(ASYNCHTTP_OP_WRAPPER_UNREGISTER, "UID=%64u");

static void content_wrapper_unregister_callback(void *obj)
{
    http_op_t *op = obj;
    FSTRACE(ASYNCHTTP_OP_WRAPPER_UNREGISTER, op->uid);
    bytestream_1_unregister_callback(op->response_content);
    op->response_content_callback = NULL_ACTION_1;
}

static struct bytestream_1_vt content_wrapper_vt = {
    .read = content_wrapper_read,
    .close = content_wrapper_close,
    .register_callback = content_wrapper_register_callback,
    .unregister_callback = content_wrapper_unregister_callback
};

FSTRACE_DECL(ASYNCHTTP_OP_GET_RESPONSE_CONTENT_TIMED_OUT, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_GET_RESPONSE_CONTENT_FAIL, "UID=%64u ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_OP_GET_RESPONSE_CONTENT, "UID=%64u CONTENT=%p");

int http_op_get_response_content(http_op_t *op, bytestream_1 *content)
{
    if (op->timer_state == HTTP_OP_TIMER_REPORTED) {
        FSTRACE(ASYNCHTTP_OP_GET_RESPONSE_CONTENT_TIMED_OUT, op->uid);
        errno = ETIMEDOUT;
        return -1;
    }
    switch (op->state) {
        case HTTP_OP_CONNECTING_DIRECTLY:
        case HTTP_OP_CONNECTING_TO_PROXY:
        case HTTP_OP_TUNNELING:
        case HTTP_OP_SENT:
            FSTRACE(ASYNCHTTP_OP_GET_RESPONSE_CONTENT_FAIL, op->uid);
            errno = again_or_timeout(op, EAGAIN);
            return -1;
        default:
            FSTRACE(ASYNCHTTP_OP_GET_RESPONSE_CONTENT_FAIL, op->uid);
            errno = 0; /* pseudo-EOF */
            return -1;
        case HTTP_OP_RECEIVED:;
    }
    bytestream_1 stream;
    if (http_get_content(op->stack.http_conn, op->response_content_length,
                         &stream) < 0) {
        errno = again_or_timeout(op, errno);
        FSTRACE(ASYNCHTTP_OP_GET_RESPONSE_CONTENT_FAIL, op->uid);
        return -1;
    }
    op->response_content = stream;
    *content = (bytestream_1) { op, &content_wrapper_vt };
    op->response_content_callback = NULL_ACTION_1;
    FSTRACE(ASYNCHTTP_OP_GET_RESPONSE_CONTENT, op->uid, content->obj);
    set_op_state(op, HTTP_OP_STREAMING);
    return 0;
}

FSTRACE_DECL(ASYNCHTTP_HTTP_OP_REGISTER, "UID=%64u OBJ=%p ACT=%p");

void http_op_register_callback(http_op_t *op, action_1 action)
{
    FSTRACE(ASYNCHTTP_HTTP_OP_REGISTER, op->uid, action.obj, action.act);
    op->callback = action;
}

FSTRACE_DECL(ASYNCHTTP_HTTP_OP_UNREGISTER, "UID=%64u");

void http_op_unregister_callback(http_op_t *op)
{
    FSTRACE(ASYNCHTTP_HTTP_OP_UNREGISTER, op->uid);
    op->callback = NULL_ACTION_1;
}

static void clear_request(http_op_t *op)
{
    destroy_http_env(op->request);
    bytestream_1_close(op->request_content);
}

static void do_close(http_op_t *op)
{
    list_remove(op->client->operations, op->loc);
    fsfree(op->proxy_host);
    fsfree(op->proxy_authorization);
    fsfree(op->host_entry);
    fsfree(op->connect_entry);
    fsfree(op->method);
    fsfree(op->path);
    fsfree(op->host);
    switch (op->state) {
        case HTTP_OP_IDLE:
            clear_request(op);
            break;
        case HTTP_OP_CONNECTING_DIRECTLY:
        case HTTP_OP_CONNECTING_TO_PROXY:
            clear_request(op);
            tcp_client_close(op->tcp_client);
            break;
        case HTTP_OP_TUNNELING:
            clear_request(op);
            close_stack(op->stack);
            break;
        case HTTP_OP_SENT:
        case HTTP_OP_RECEIVED:
            close_stack(op->stack);
            break;
        case HTTP_OP_STREAM_CLOSED:
            break;
        default:
            assert(false);
    }
    if (op->timer_state == HTTP_OP_TIMER_RUNNING)
        async_timer_cancel(op->client->async, op->timer);
    destroy_tls_ca_bundle(op->ca_bundle);
    set_op_state(op, HTTP_OP_CLOSED);
    async_wound(op->client->async, op);
    check_pulse(op->client);
}

FSTRACE_DECL(ASYNCHTTP_OP_CLOSE, "UID=%64u");

void http_op_close(http_op_t *op)
{
    FSTRACE(ASYNCHTTP_OP_CLOSE, op->uid);
    switch (op->state) {
        case HTTP_OP_CLOSED:
        case HTTP_OP_CLOSED_STREAMING:
            assert(false);
        case HTTP_OP_STREAMING:
            set_op_state(op, HTTP_OP_CLOSED_STREAMING);
            return;
        default:
            do_close(op);
    }
}
