#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <fstrace.h>
#include <fsdyn/fsalloc.h>
#include <fsdyn/charstr.h>
#include <fsdyn/list.h>
#include <fsdyn/base64.h>
#include <fsdyn/avltree.h>
#include <async/drystream.h>
#include <async/emptystream.h>
#include <async/farewellstream.h>
#include <async/switchstream.h>
#include <async/tcp_client.h>
#include <async/tls_connection.h>
#include <nwutil.h>
#include "client.h"
#include "h2connection.h"
#include "asynchttp_version.h"

enum {
    STALE_CONNECTION_TIMEOUT = 10, /* seconds */
    DEFAULT_PORT_HTTPS = 443,
    DEFAULT_PORT_HTTP = 80,
};

typedef enum {
    PROXY_SYSTEM,
    PROXY_DIRECT,
    PROXY_EXPLICIT
} proxy_mode_t;

struct http_client {
    bool closed;
    async_t *async;
    uint64_t uid;
    fsadns_t *dns;
    avl_tree_t *conn_pool;      /* of pool_elem_t */
    size_t max_envelope_size;
    proxy_mode_t proxy_mode;
    char *proxy_host;           /* NULL if no proxy */
    unsigned proxy_port;
    char *proxy_authorization;  /* no proxy authorization if NULL */
    tls_ca_bundle_t *ca_bundle;
    action_1 callback;
};

typedef struct {
    const char *host;
    unsigned port;
    bool https;
    uint64_t uid;
} pool_key_t;

typedef enum {
    POOL_ELEM_LOOSE,            /* outside conn_pool */
    POOL_ELEM_IDLE,             /* inside conn pool */
    POOL_ELEM_SHARED,           /* inside conn pool */
    POOL_ELEM_SHARED_TAINTED,   /* outside conn pool */
    POOL_ELEM_TAKEN,            /* inside conn pool */
    POOL_ELEM_TAKEN_TAINTED,    /* outside conn pool */
} pool_elem_state_t;

typedef struct {
    http_client_t *client;
    pool_key_t key;
    tls_ca_bundle_t *ca_bundle;
    pool_elem_state_t state;
    union {
        struct {
            async_timer_t *timer;
        } idle;
        struct {
            unsigned ref_count;
        } shared;
    };
    http_conn_t *http_conn;
    switchstream_t *swstr;
    h2conn_t *h2conn;
    tls_conn_t *tls_conn;
    tcp_conn_t *tcp_conn;
} pool_elem_t;

typedef enum {
    HTTP_OP_IDLE,
    HTTP_OP_CONNECTING_DIRECTLY, /* establishing TCP connection to server */
    HTTP_OP_CONNECTING_TO_PROXY, /* establishing TCP connection to proxy */
    HTTP_OP_TUNNELING,           /* HTTPS via proxy; CONNECT sent */
    HTTP_OP_NEGOTIATING,         /* HTTPS protocol version negotiation */
    HTTP_OP_SENT,
    HTTP_OP_RECEIVED,
    HTTP_OP_STREAMING,
    HTTP_OP_STREAM_CLOSED,
    HTTP_OP_CLOSED_STREAMING,
    HTTP_OP_CLOSED,
    HTTP_OP_ERRORED
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
 *          |         |     |     |
 *          |         V     |     |
 *          |     TUNNELING |     |
 *          |         |     |     |
 *          |         v     v     |
 *          |       NEGOTIATING   |
 *          |         |           |
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
    http_op_state_t state;
    bool https;
    char *proxy_host;           /* no proxy if NULL */
    unsigned proxy_port;
    char *proxy_authorization;  /* no proxy authorization if NULL */
    char *host;
    unsigned port;
    char *host_entry;           /* host:port */
    bool reusing;
    char *method;
    char *path;
    http_env_t *request;
    ssize_t content_length;
    action_1 callback;
    http_op_timer_state_t timer_state;
    async_timer_t *timer; /* HTTP_OP_TIMER_RUNNING */

    /* HTTP_OP_IDLE, HTTP_OP_CONNECTING_DIRECTLY,
     * HTTP_OP_CONNECTING_TO_PROXY, HTTP_OP_TUNNELING, HTTP_OP_NEGOTIATING */
    bytestream_1 request_content;
    switchstream_t *request_swstr;

    /* HTTP_OP_CONNECTING_DIRECTLY, HTTP_OP_CONNECTING_TO_PROXY */
    tcp_client_t *tcp_client;

    /* HTTP_OP_TUNNELING, HTTP_OP_NEGOTIATING, HTTP_OP_SENT, HTTP_OP_RECEIVED,
     * HTTP_OP_STREAMING, HTTP_OP_CLOSED_STREAMING */
    pool_elem_t *pe;

    /* HTTP_OP_SENT, HTTP_OP_RECEIVED */
    h2op_t *h2op;

    /* HTTP_OP_RECEIVED */
    size_t response_content_length;

    /* HTTP_OP_STREAMING, HTTP_OP_CLOSED_STREAMING */
    bytestream_1 response_content;
    action_1 response_content_callback;

    /* HTTP_OP_ERRORED */
    int err;
};

static const char *trace_pe_state(void *p)
{
    switch (*(pool_elem_state_t *) p) {
        case POOL_ELEM_IDLE:
            return "POOL_ELEM_IDLE";
        case POOL_ELEM_SHARED:
            return "POOL_ELEM_SHARED";
        case POOL_ELEM_SHARED_TAINTED:
            return "POOL_ELEM_SHARED_TAINTED";
        case POOL_ELEM_TAKEN:
            return "POOL_ELEM_TAKEN";
        case POOL_ELEM_TAKEN_TAINTED:
            return "POOL_ELEM_TAKEN_TAINTED";
        default:
            return fstrace_unsigned_repr(*(pool_elem_state_t *) p);
    }
}

FSTRACE_DECL(ASYNCHTTP_PE_SET_STATE, "UID=%64u OLD=%I NEW=%I");

static void set_pe_state(pool_elem_t *pe, pool_elem_state_t state)
{
    FSTRACE(ASYNCHTTP_PE_SET_STATE, pe->key.uid, trace_pe_state, &pe->state,
            trace_pe_state, &state);
    pe->state = state;
}

static int pool_key_cmp(pool_key_t *a, pool_key_t *b)
{
    int c = strcmp(a->host, b->host);
    if (c)
        return c;
    if (a->port < b->port)
        return -1;
    if (a->port > b->port)
        return 1;
    if (!a->https) {
        if (b->https)
            return -1;
    } else if (!b->https)
        return 1;
    if (a->uid < b->uid)
        return -1;
    if (a->uid > b->uid)
        return 1;
    return 0;
}

FSTRACE_DECL(ASYNCHTTP_CLIENT_CREATE, "UID=%64u PTR=%p ASYNC=%p");

http_client_t *open_http_client_2(async_t *async, fsadns_t *dns)
{
    http_client_t *client = fsalloc(sizeof *client);
    client->closed = false;
    client->async = async;
    client->dns = dns;
    client->uid = fstrace_get_unique_id();
    FSTRACE(ASYNCHTTP_CLIENT_CREATE, client->uid, client, async);
    client->conn_pool = make_avl_tree((void *) pool_key_cmp);
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

static void destroy_pool_element(pool_elem_t *pe)
{
    switch (pe->state) {
        case POOL_ELEM_LOOSE:
            break;
        case POOL_ELEM_IDLE:
            async_timer_cancel(pe->client->async, pe->idle.timer);
            break;
        default:
            assert(false);
    }
    fsfree((char *) pe->key.host);
    destroy_tls_ca_bundle(pe->ca_bundle);
    tcp_close(pe->tcp_conn);
    if (pe->tls_conn)
        tls_close(pe->tls_conn);
    if (pe->h2conn)
        h2conn_close(pe->h2conn);
    if (pe->http_conn)
        http_close(pe->http_conn);
    fsfree(pe);
}

static void detach_pool_element(pool_elem_t *pe)
{
    destroy_avl_element(avl_tree_pop(pe->client->conn_pool, &pe->key));
}

static void abandon_pool_element(pool_elem_t *pe)
{
    detach_pool_element(pe);
    set_pe_state(pe, POOL_ELEM_LOOSE);
    destroy_pool_element(pe);
}

static void taint_pool_element(pool_elem_t *pe)
{
    switch (pe->state) {
        case POOL_ELEM_SHARED:
            detach_pool_element(pe);
            set_pe_state(pe, POOL_ELEM_SHARED_TAINTED);
            break;
        case POOL_ELEM_TAKEN:
            detach_pool_element(pe);
            set_pe_state(pe, POOL_ELEM_TAKEN_TAINTED);
            break;
        case POOL_ELEM_LOOSE:
        case POOL_ELEM_SHARED_TAINTED:
        case POOL_ELEM_TAKEN_TAINTED:
            break;
        default:
            assert(false);
    }
}

static void taint_conn_pool(http_client_t *client)
{
    while (!avl_tree_empty(client->conn_pool)) {
        pool_elem_t *pe = (pool_elem_t *)
            avl_elem_get_value(avl_tree_get_first(client->conn_pool));
        taint_pool_element(pe);
    }
}

static bool tainted_pool_element(pool_elem_t *pe)
{
    switch (pe->state) {
        case POOL_ELEM_SHARED_TAINTED:
        case POOL_ELEM_TAKEN_TAINTED:
            return true;
        default:
            return false;
    }
}

static void flush_conn_pool(http_client_t *client)
{
    list_t *idle = make_list();
    list_t *in_flight = make_list();
    avl_elem_t *e;
    for (e = avl_tree_get_first(client->conn_pool); e; e = avl_tree_next(e)) {
        pool_elem_t *pe = (pool_elem_t *) avl_elem_get_value(e);
        switch (pe->state) {
            case POOL_ELEM_IDLE:
                list_append(idle, pe);
                break;
            case POOL_ELEM_SHARED:
            case POOL_ELEM_TAKEN:
                break;
            default:
                assert(false);
        }
    }
    list_foreach(idle, (void *) abandon_pool_element, NULL);
    destroy_list(idle);
    list_foreach(in_flight, (void *) taint_pool_element, NULL);
    destroy_list(in_flight);
}

static void check_pulse(http_client_t *client)
{
    if (!client->closed)
        return;
    flush_conn_pool(client);
    if (!avl_tree_empty(client->conn_pool))
        return;
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
    char *encoding =
        base64_encode_simple(credentials, strlen(credentials));
    fsfree(credentials);
    char *auth = charstr_printf("Basic %s", encoding);
    fsfree(encoding);
    return auth;
}

/* proxy_host is moved; username and password are not */
static void set_proxy(http_client_t *client,
                      char *proxy_host, unsigned port,
                      const char *username, const char *password)
{
    fsfree(client->proxy_host);
    fsfree(client->proxy_authorization);
    client->proxy_mode = PROXY_EXPLICIT;
    client->proxy_host = proxy_host;
    client->proxy_port = port;
    client->proxy_authorization = make_proxy_authorization(username, password);
    flush_conn_pool(client);
    taint_conn_pool(client);
}

FSTRACE_DECL(ASYNCHTTP_CLIENT_SET_PROXY,
             "UID=%64u HOST=%s PORT=%u USER=%s PASSWORD=%s");
FSTRACE_DECL(ASYNCHTTP_CLIENT_NON_IDNA_PROXY_HOST, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_CLIENT_IDNA_PROXY_HOST, "UID=%64u IDNA=%s");

bool http_client_set_proxy_2(http_client_t *client,
                             const char *proxy_host, unsigned port,
                             const char *username, const char *password)
{
    FSTRACE(ASYNCHTTP_CLIENT_SET_PROXY, client->uid, proxy_host, port,
            username, password);
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

bool http_client_set_proxy(http_client_t *client,
                           const char *proxy_host, unsigned port)
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
    flush_conn_pool(client);
    taint_conn_pool(client);
}

FSTRACE_DECL(ASYNCHTTP_CLIENT_USE_SYSTEM_PROXY, "UID=%64u");

void http_client_use_system_proxy(http_client_t *client)
{
    FSTRACE(ASYNCHTTP_CLIENT_USE_SYSTEM_PROXY, client->uid);
    fsfree(client->proxy_host);
    fsfree(client->proxy_authorization);
    client->proxy_host = client->proxy_authorization = NULL;
    client->proxy_mode = PROXY_SYSTEM;
    flush_conn_pool(client);
    taint_conn_pool(client);
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
FSTRACE_DECL(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_BAD_SCHEME,
             "UID=%64u URI=%s");
FSTRACE_DECL(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_BAD_USERNAME,
             "UID=%64u URI=%s");
FSTRACE_DECL(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_BAD_PASSWORD,
             "UID=%64u URI=%s");

bool http_client_set_proxy_from_uri(http_client_t *client, const char *uri)
{
    nwutil_url_t *url = nwutil_parse_url(uri, strlen(uri), NULL);
    if (!url) {
        FSTRACE(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_SYNTAX_ERROR,
                client->uid, uri);
        return false;
    }
    const char *scheme = nwutil_url_get_scheme(url);
    unsigned port;
    if (!strcmp(scheme, "http"))
        port = DEFAULT_PORT_HTTP;
    else if (!strcmp(scheme, "https"))
        port = DEFAULT_PORT_HTTPS;
    else {
        FSTRACE(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_BAD_SCHEME,
                client->uid, uri);
        nwutil_url_destroy(url);
        return false;
    }
    (void) nwutil_url_get_port(url, &port);
    FSTRACE(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI, client->uid, uri);
    const char *host = nwutil_url_get_host(url);
    char *username;
    if (!percent_decode(nwutil_url_get_username(url), &username)) {
        FSTRACE(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_BAD_USERNAME,
                client->uid, uri);
        nwutil_url_destroy(url);
        return false;
    }
    char *password;
    if (!percent_decode(nwutil_url_get_password(url), &password)) {
        FSTRACE(ASYNCHTTP_CLIENT_SET_PROXY_FROM_URI_BAD_PASSWORD,
                client->uid, uri);
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
        case HTTP_OP_NEGOTIATING:
            return "HTTP_OP_NEGOTIATING";
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
        case HTTP_OP_ERRORED:
            return "HTTP_OP_ERRORED";
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
        case PROXY_SYSTEM:
            ;
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
        FSTRACE(ASYNCHTTP_OP_LEARN_GLOBAL_PROXY,
                client->uid, op->proxy_host,
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
    if (op->proxy_host && !op->https)
        op->path = charstr_dupstr(uri);
    else {
        const char *q = "?", *query = nwutil_url_get_query(url);
        if (!query)
            q = query = "";
        const char *f = "#", *fragment = nwutil_url_get_fragment(url);
        if (!fragment)
            f = fragment = "";
        op->path =
            charstr_printf("%s%s%s%s%s",
                           nwutil_url_get_path(url), q, query, f, fragment);
    }
    nwutil_url_destroy(url);
    return true;
}

FSTRACE_DECL(ASYNCHTTP_OP_CREATE_FAIL, "CLIENT=%64u METHOD=%s URI=%s");
FSTRACE_DECL(ASYNCHTTP_OP_CREATE,
             "UID=%64u PTR=%p CLIENT=%64u METHOD=%s URI=%s");

http_op_t *http_client_make_request(http_client_t *client,
                                    const char *method, const char *uri)
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
    if (op->port == (op->https ? DEFAULT_PORT_HTTPS : DEFAULT_PORT_HTTP))
        op->host_entry = charstr_dupstr(op->host);
    else op->host_entry = charstr_printf("%s:%u", op->host, op->port);
    op->reusing = false;
    op->request = make_http_env_request(op->method, op->path, "HTTP/1.1");
    http_env_add_header(op->request, "Host", op->host_entry);
    if (op->proxy_authorization && !op->https)
        http_env_add_header(op->request, "Proxy-Authorization",
                            op->proxy_authorization);
    op->request_swstr = open_switch_stream(op->client->async, emptystream);
    bytestream_1 swbytes = switchstream_as_bytestream_1(op->request_swstr);
    action_1 request_closed_cb = { op->request, (act_1) destroy_http_env };
    farewellstream_t *fwstr =
        open_relaxed_farewellstream(op->client->async, swbytes,
                                    request_closed_cb);
    op->request_content = farewellstream_as_bytestream_1(fwstr);
    op->content_length = HTTP_ENCODE_RAW;
    op->callback = NULL_ACTION_1;
    return op;
}

FSTRACE_DECL(ASYNCHTTP_OP_SET_CONTENT, "UID=%64u CONTENT=%p");

void http_op_set_content(http_op_t *op, ssize_t size, bytestream_1 content)
{
    FSTRACE(ASYNCHTTP_OP_SET_CONTENT, op->uid, content.obj);
    bytestream_1_close(switchstream_reattach(op->request_swstr, content));
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
    FSTRACE(ASYNCHTTP_OP_SET_TIMER_STATE, op->uid,
            trace_timer_state, &op->timer_state,
            trace_timer_state, &timer_state);
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

FSTRACE_DECL(ASYNCHTTP_OP_PROBE, "UID=%64u");

static void op_probe(http_op_t *op)
{
    FSTRACE(ASYNCHTTP_OP_PROBE, op->uid);
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
        default:
            ;
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
        default:
            ;
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
    pool_key_t key = {
        .host = host,
        .port = port,
        .https = https,
        .uid = 0,
    };
    avl_elem_t *e;
    for (e = avl_tree_get_on_or_after(op->client->conn_pool, &key);
         e;
         e = avl_tree_next(e)) {
        pool_elem_t *pe = (pool_elem_t *) avl_elem_get_value(e);
        if (strcmp(pe->key.host, host) || pe->key.port != port ||
            pe->key.https != https)
            continue;
        switch (pe->state) {
            case POOL_ELEM_IDLE:
                if (tls_ca_bundle_equal(pe->ca_bundle, op->ca_bundle)) {
                    async_timer_cancel(op->client->async, pe->idle.timer);
                    if (pe->h2conn) {
                        set_pe_state(pe, POOL_ELEM_SHARED);
                        pe->shared.ref_count = 1;
                    } else set_pe_state(pe, POOL_ELEM_TAKEN);
                    FSTRACE(ASYNCHTTP_OP_REUSE, op->uid, host, port,
                            https ? "HTTPS" : "HTTP", pe->key.uid);
                    op->pe = pe;
                    return true;
                }
                break;
            case POOL_ELEM_SHARED:
                if (tls_ca_bundle_equal(pe->ca_bundle, op->ca_bundle)) {
                    pe->shared.ref_count++;
                    FSTRACE(ASYNCHTTP_OP_REUSE, op->uid, host, port,
                            https ? "HTTPS" : "HTTP", pe->key.uid);
                    op->pe = pe;
                    return true;
                }
                break;
            case POOL_ELEM_TAKEN:
                break;
            default:
                assert(false);
        }
    }
    FSTRACE(ASYNCHTTP_OP_CANNOT_REUSE, op->uid, host, port,
            https ? "HTTPS" : "HTTP");
    return false;
}

static action_1 get_op_cb(http_op_t *op)
{
    return (action_1) { op, (act_1) op_probe };
}

static void op_dispatch(http_op_t *op)
{
    /* op->pe has been set by the caller */
    if (op->pe->h2conn) {
        op->h2op = h2conn_request(op->pe->h2conn, op->request,
                                  op->content_length, op->request_content);
        if (!op->h2op) {
            taint_pool_element(op->pe);
            if (op->reusing) {
                op->reusing = false;
                set_op_state(op, HTTP_OP_IDLE);
                return;
            }
            /* We were trying a brand new connection and failed; it's
             * a lost cause. */
            op->err = errno;
            set_op_state(op, HTTP_OP_ERRORED);
            return;
        }
        h2op_register_callback(op->h2op, get_op_cb(op));
    } else {
        http_send(op->pe->http_conn, op->request, op->content_length,
                  op->request_content);
        http_register_callback(op->pe->http_conn, get_op_cb(op));
    }
    set_op_state(op, HTTP_OP_SENT);
}

static void op_send_http_connect(http_op_t *op)
{
    /* op->pe has been set by the caller */
    http_env_t *connect_request =
        make_http_env_request("CONNECT", op->host_entry, "HTTP/1.1");
    http_env_add_header(connect_request, "Host", op->host_entry);
    if (op->proxy_authorization)
        http_env_add_header(connect_request, "Proxy-Authorization",
                            op->proxy_authorization);
    action_1 request_closed_cb = { connect_request, (act_1) destroy_http_env };
    farewellstream_t *fwstr =
        open_relaxed_farewellstream(op->client->async, emptystream,
                                    request_closed_cb);
    bytestream_1 content = farewellstream_as_bytestream_1(fwstr);
    http_send(op->pe->http_conn, connect_request, HTTP_ENCODE_RAW, content);
    http_register_callback(op->pe->http_conn, get_op_cb(op));
    set_op_state(op, HTTP_OP_TUNNELING);
}

FSTRACE_DECL(ASYNCHTTP_OP_SEND_VIA_PROXY_REUSE_HTTPS, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_SEND_VIA_PROXY_REUSING, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_SEND_VIA_PROXY, "UID=%64u");

static void op_send_request_via_proxy(http_op_t *op)
{
    if (op->https && reuse_connection(op, op->host, op->port, op->https)) {
        FSTRACE(ASYNCHTTP_OP_SEND_VIA_PROXY_REUSE_HTTPS, op->uid);
        op->reusing = true;
        op_dispatch(op);
        return;
    }
    if (reuse_connection(op, op->proxy_host, op->proxy_port, false)) {
        FSTRACE(ASYNCHTTP_OP_SEND_VIA_PROXY_REUSING, op->uid);
        op->reusing = true;
        if (op->https)
            op_send_http_connect(op);
        else op_dispatch(op);
        return;
    }
    FSTRACE(ASYNCHTTP_OP_SEND_VIA_PROXY, op->uid);
    op->tcp_client =
        open_tcp_client_2(op->client->async, op->proxy_host, op->proxy_port,
                          op->client->dns);
    tcp_client_register_callback(op->tcp_client, get_op_cb(op));
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
        op->reusing = true;
        op_dispatch(op);
        return;
    }
    FSTRACE(ASYNCHTTP_OP_SEND_DIRECTLY, op->uid);
    op->tcp_client =
        open_tcp_client_2(op->client->async, op->host, op->port,
                          op->client->dns);
    tcp_client_register_callback(op->tcp_client, get_op_cb(op));
    set_op_state(op, HTTP_OP_CONNECTING_DIRECTLY);
}

FSTRACE_DECL(ASYNCHTTP_ADD_TO_POOL, "UID=%64u PE=%64u");

static void add_connection_to_pool(http_op_t *op, bool shared)
{
    pool_elem_t *pe = op->pe;
    assert(pe->state == POOL_ELEM_LOOSE);
    FSTRACE(ASYNCHTTP_ADD_TO_POOL, op->uid, pe->key.uid);
    fsfree((char *) pe->key.host);
    pe->key.host = charstr_dupstr(op->host);
    pe->key.port = op->port;
    pe->key.https = op->https;
    avl_tree_put(op->client->conn_pool, &pe->key, pe);
    if (shared)
        set_pe_state(pe, POOL_ELEM_SHARED);
    else set_pe_state(pe, POOL_ELEM_TAKEN);
}

FSTRACE_DECL(ASYNCHTTP_NEW_POOL_ELEMENT,
             "UID=%64u OP=%64u CLIENT=%64u TCP_CONN=%p");

static pool_elem_t *make_pool_element(http_op_t *op, const char *host,
                                      unsigned port, bool https,
                                      tcp_conn_t *tcp_conn)
{
    pool_elem_t *pe = fsalloc(sizeof *pe);
    pe->client = op->client;
    pe->key.host = charstr_dupstr(host);
    pe->key.port = port;
    pe->key.https = https;
    pe->key.uid = fstrace_get_unique_id();
    FSTRACE(ASYNCHTTP_NEW_POOL_ELEMENT, pe->key.uid, op->uid, op->client->uid,
            tcp_conn);
    pe->ca_bundle = share_tls_ca_bundle(op->ca_bundle);
    pe->state = POOL_ELEM_LOOSE;
    pe->http_conn = NULL;
    pe->swstr = NULL;
    pe->h2conn = NULL;
    pe->tls_conn = NULL;
    pe->tcp_conn = tcp_conn;
    return pe;
}

FSTRACE_DECL(ASYNCHTTP_OP_ESTABLISH_FAIL, "UID=%64u ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_OP_ESTABLISH, "UID=%64u PE=%64u");

static bool op_init_protocol_stack(http_op_t *op, const char *host,
                                   unsigned port, bool https)
{
    tcp_conn_t *tcp_conn = tcp_client_establish(op->tcp_client);
    if (!tcp_conn) {
        FSTRACE(ASYNCHTTP_OP_ESTABLISH_FAIL, op->uid);
        return false;
    }
    tcp_client_close(op->tcp_client);
    op->pe = make_pool_element(op, host, port, https, tcp_conn);
    FSTRACE(ASYNCHTTP_OP_ESTABLISH, op->uid, op->pe->key.uid);
    return true;
}

static const http_env_t *op_receive_via_proxy(http_op_t *op)
{
    if (!op_init_protocol_stack(op, op->proxy_host, op->proxy_port, false))
        return NULL;
    pool_elem_t *pe = op->pe;
    pe->swstr = open_switch_stream(op->client->async,
                                   tcp_get_input_stream(pe->tcp_conn));
    bytestream_1 http_input = switchstream_as_bytestream_1(pe->swstr);
    pe->http_conn = open_http_connection(op->client->async, http_input,
                                         op->client->max_envelope_size);
    bytestream_1 http_output = http_get_output_stream(pe->http_conn);
    tcp_set_output_stream(pe->tcp_conn, http_output);
    http_register_callback(pe->http_conn, get_op_cb(op));
    if (op->https)
        op_send_http_connect(op);
    else op_dispatch(op);
    return http_op_receive_response(op);
}

FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_RECYCLE, "UID=%64u RECYCLE=%b");

static void response_received(http_op_t *op, const http_env_t *response)
{
    set_op_state(op, HTTP_OP_RECEIVED);
    const char *field =
        http_env_get_matching_header(response, "connection");
    if ((field && !strcmp(field, "close")) ||
        charstr_case_cmp(http_env_get_protocol(response), "HTTP/1.1") < 0)
        taint_pool_element(op->pe);
    FSTRACE(ASYNCHTTP_OP_RECEIVE_RECYCLE, op->uid,
            tainted_pool_element(op->pe));
}

static void op_push_tls(http_op_t *op)
{
    pool_elem_t *pe = op->pe;
    assert(!pe->http_conn && !pe->h2conn && !pe->tls_conn);
    pe->tls_conn =
        open_tls_client_2(pe->client->async,
                          tcp_get_input_stream(pe->tcp_conn),
                          pe->ca_bundle, op->host);
    tcp_set_output_stream(pe->tcp_conn,
                          tls_get_encrypted_output_stream(pe->tls_conn));
    tls_allow_protocols(pe->tls_conn, "h2", "http/1.1", (const char *) NULL);
    tls_register_callback(pe->tls_conn, get_op_cb(op));
}

static const http_env_t *op_receive_tunnel(http_op_t *op)
{
    assert(op->https);
    pool_elem_t *pe = op->pe;
    const http_env_t *response =
        http_receive(pe->http_conn, HTTP_ENV_RESPONSE);
    if (!response)
        return NULL;
    int code = http_env_get_code(response);
    if (code < 200 || code > 299) {
        response_received(op, response);
        return response;
    }
    bytestream_1 stream;
    int status = http_get_content(pe->http_conn, 0, &stream);
    assert(status >= 0);
    bytestream_1_close(stream);
    switchstream_reattach(pe->swstr, emptystream);
    http_close(pe->http_conn);
    pe->swstr = NULL;
    pe->http_conn = NULL;
    tcp_set_output_stream(pe->tcp_conn, drystream);
    op_push_tls(op);
    detach_pool_element(pe);
    set_pe_state(pe, POOL_ELEM_LOOSE);
    set_op_state(op, HTTP_OP_NEGOTIATING);
    return http_op_receive_response(op);
}

FSTRACE_DECL(ASYNCHTTP_OP_PUSH_HTTPS_LAYER, "UID=%64u HTTP-CONN=%p");

static void op_push_http_over_tls(http_op_t *op)
{
    pool_elem_t *pe = op->pe;
    assert(!pe->http_conn && !pe->h2conn);
    bytestream_1 http_input = tls_get_plain_input_stream(pe->tls_conn);
    pe->http_conn = open_http_connection(op->client->async, http_input,
                                         op->client->max_envelope_size);
    bytestream_1 http_output = http_get_output_stream(pe->http_conn);
    tls_set_plain_output_stream(pe->tls_conn, http_output);
    http_register_callback(pe->http_conn, get_op_cb(op));
    add_connection_to_pool(op, false);
    FSTRACE(ASYNCHTTP_OP_PUSH_HTTPS_LAYER, op->uid, pe->http_conn);
}

FSTRACE_DECL(ASYNCHTTP_OP_PUSH_H2LAYER, "UID=%64u H2CONN=%p");

static void op_push_h2_over_tls(http_op_t *op)
{
    pool_elem_t *pe = op->pe;
    assert(!pe->http_conn && !pe->h2conn);
    bytestream_1 h2input = tls_get_plain_input_stream(pe->tls_conn);
    pe->h2conn = open_h2connection(op->client->async, h2input, true,
                                   op->client->max_envelope_size);
    bytestream_1 h2output = h2conn_get_output_stream(pe->h2conn);
    tls_set_plain_output_stream(pe->tls_conn, h2output);
    add_connection_to_pool(op, true);
    FSTRACE(ASYNCHTTP_OP_PUSH_H2LAYER, op->uid, pe->h2conn);
}

FSTRACE_DECL(ASYNCHTTP_OP_NO_PROTO_CHOSEN, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_HTTP_1_1_CHOSEN, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_H2_CHOSEN, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_UNKNOWN_PROTO_CHOSEN, "UID=%64u PROTO=%s");

static const http_env_t *op_receive_negotiate(http_op_t *op)
{
    assert(op->https);
    if (tls_read(op->pe->tls_conn, NULL, 0) < 0)
        return NULL;
    const char *chosen = tls_get_chosen_protocol(op->pe->tls_conn);
    if (!chosen) {
        FSTRACE(ASYNCHTTP_OP_NO_PROTO_CHOSEN, op->uid);
        op_push_http_over_tls(op);
    } else if (!strcmp(chosen, "http/1.1")) {
        FSTRACE(ASYNCHTTP_OP_HTTP_1_1_CHOSEN, op->uid);
        op_push_http_over_tls(op);
    } else if (!strcmp(chosen, "h2")) {
        FSTRACE(ASYNCHTTP_OP_H2_CHOSEN, op->uid);
        op_push_h2_over_tls(op);
    } else {
        FSTRACE(ASYNCHTTP_OP_UNKNOWN_PROTO_CHOSEN, op->uid, chosen);
        op_push_http_over_tls(op);
    }
    op_dispatch(op);
    return http_op_receive_response(op);
}

FSTRACE_DECL(ASYNCHTTP_OP_PUSH_HTTP_LAYER, "UID=%64u HTTP-CONN=%p");

static const http_env_t *op_receive_from_server(http_op_t *op)
{
    if (!op_init_protocol_stack(op, op->host, op->port, op->https))
        return NULL;
    if (op->https) {
        op_push_tls(op);
        set_op_state(op, HTTP_OP_NEGOTIATING);
    } else {
        pool_elem_t *pe = op->pe;
        bytestream_1 http_input = tcp_get_input_stream(pe->tcp_conn);
        pe->http_conn =
            open_http_connection(op->client->async, http_input,
                                 op->client->max_envelope_size);
        bytestream_1 http_output = http_get_output_stream(pe->http_conn);
        tcp_set_output_stream(pe->tcp_conn, http_output);
        http_register_callback(pe->http_conn, get_op_cb(op));
        add_connection_to_pool(op, false);
        FSTRACE(ASYNCHTTP_OP_PUSH_HTTP_LAYER, op->uid, pe->http_conn);
        op_dispatch(op);
    }
    return http_op_receive_response(op);
}

static const http_env_t *op_receive_response(http_op_t *op)
{
    const http_env_t *response;
    if (op->pe->h2conn) {
        response = h2op_receive_response(op->h2op);
        if (response)
            response_received(op, response);
    } else {
        response = http_receive(op->pe->http_conn, HTTP_ENV_RESPONSE);
        if (response) {
            response_received(op, response);
            int code = http_env_get_code(response);
            if (code == 204 || (code >= 100 && code <= 199) || code == 304 ||
                !charstr_case_cmp(op->method, "head"))
                op->response_content_length = 0;
            else op->response_content_length = HTTP_DECODE_OBEY_HEADER;
        }
    }
    return response;
}

static void taint_maybe(http_op_t *op)
{
    switch (errno) {
        case 0:
        case EAGAIN:
            return;
        default:
            ;
    }
    int err = errno;
    taint_pool_element(op->pe);
    errno = err;
}

FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_TIMED_OUT, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_DIRECTLY, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_VIA_PROXY, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_TUNNELING, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_NEGOTIATING, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_SENT, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_RECEIVE_ERRORED, "UID=%64u");
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
        case HTTP_OP_NEGOTIATING:
            FSTRACE(ASYNCHTTP_OP_RECEIVE_NEGOTIATING, op->uid);
            response = op_receive_negotiate(op);
            break;
        case HTTP_OP_SENT:
            FSTRACE(ASYNCHTTP_OP_RECEIVE_SENT, op->uid);
            response = op_receive_response(op);
            break;
        case HTTP_OP_ERRORED:
            FSTRACE(ASYNCHTTP_OP_RECEIVE_ERRORED, op->uid);
            errno = op->err;
            response = NULL;
            break;
        default:
            FSTRACE(ASYNCHTTP_OP_RECEIVE_EOF, op->uid);
            errno = 0;          /* pseudo-EOF */
            response = NULL;
    }
    errno = again_or_timeout(op, errno);
    FSTRACE(ASYNCHTTP_OP_RECEIVED, op->uid, response);
    if (!response)
        taint_maybe(op);
    return response;
}

FSTRACE_DECL(ASYNCHTTP_POOL_TIMEOUT, "UID=%64u");

static void pool_elem_timeout(pool_elem_t *pe)
{
    FSTRACE(ASYNCHTTP_POOL_TIMEOUT, pe->key.uid);
    abandon_pool_element(pe);
}

static void pool_elem_make_idle(pool_elem_t *pe)
{
    set_pe_state(pe, POOL_ELEM_IDLE);
    uint64_t expiry = async_now(pe->client->async) +
        STALE_CONNECTION_TIMEOUT * ASYNC_S;
    action_1 pe_cb = { pe, (act_1) pool_elem_timeout };
    pe->idle.timer = async_timer_start(pe->client->async, expiry, pe_cb);
}

FSTRACE_DECL(ASYNCHTTP_MOVE_TO_POOL, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_POOL_ELEMENT_IN_USE, "UID=%64u OP=%64u");

static void move_connection_to_pool(http_op_t *op)
{
    FSTRACE(ASYNCHTTP_MOVE_TO_POOL, op->uid);
    pool_elem_t *pe = op->pe;
    switch (pe->state) {
        case POOL_ELEM_SHARED:
            if (--pe->shared.ref_count) {
                FSTRACE(ASYNCHTTP_POOL_ELEMENT_IN_USE, pe->key.uid, op->uid);
                return;
            }
            pool_elem_make_idle(pe);
            break;
        case POOL_ELEM_TAKEN:
            http_unregister_callback(pe->http_conn);
            pool_elem_make_idle(pe);
            break;
        case POOL_ELEM_SHARED_TAINTED:
            if (--pe->shared.ref_count) {
                FSTRACE(ASYNCHTTP_POOL_ELEMENT_IN_USE, pe->key.uid, op->uid);
                return;
            }
            abandon_pool_element(pe);
            break;
        case POOL_ELEM_TAKEN_TAINTED:
            abandon_pool_element(pe);
            break;
        default:
            assert(false);
    }
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
            move_connection_to_pool(op);
            set_op_state(op, HTTP_OP_STREAM_CLOSED);
            break;
        case HTTP_OP_CLOSED_STREAMING:
            move_connection_to_pool(op);
            do_close(op);
            break;
        default:
            assert(false);
    }
}

FSTRACE_DECL(ASYNCHTTP_OP_WRAPPER_READ_TIMED_OUT, "UID=%64u");
FSTRACE_DECL(ASYNCHTTP_OP_WRAPPER_READ, "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_OP_WRAPPER_READ_DUMP, "UID=%64u DATA=%B");

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
        case HTTP_OP_NEGOTIATING:
        case HTTP_OP_SENT:
            errno = again_or_timeout(op, EAGAIN);
            FSTRACE(ASYNCHTTP_OP_GET_RESPONSE_CONTENT_FAIL, op->uid);
            return -1;
        default:
            errno = 0;          /* pseudo-EOF */
            FSTRACE(ASYNCHTTP_OP_GET_RESPONSE_CONTENT_FAIL, op->uid);
            return -1;
        case HTTP_OP_RECEIVED:
            ;
    }
    bytestream_1 stream;
    if (op->pe->h2conn) {
        if (h2op_get_content(op->h2op,
                             HTTP_DECODE_OBEY_HEADER, &stream) < 0) {
            errno = again_or_timeout(op, errno);
            FSTRACE(ASYNCHTTP_OP_GET_RESPONSE_CONTENT_FAIL, op->uid);
            taint_maybe(op);
            return -1;
        }
    } else if (http_get_content(op->pe->http_conn,
                                op->response_content_length, &stream) < 0) {
        errno = again_or_timeout(op, errno);
        FSTRACE(ASYNCHTTP_OP_GET_RESPONSE_CONTENT_FAIL, op->uid);
        taint_maybe(op);
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
    fsfree(op->proxy_host);
    fsfree(op->proxy_authorization);
    fsfree(op->host_entry);
    fsfree(op->method);
    fsfree(op->path);
    fsfree(op->host);
    switch (op->state) {
        case HTTP_OP_IDLE:
        case HTTP_OP_ERRORED:
            clear_request(op);
            break;
        case HTTP_OP_CONNECTING_DIRECTLY:
        case HTTP_OP_CONNECTING_TO_PROXY:
            clear_request(op);
            tcp_client_close(op->tcp_client);
            break;
        case HTTP_OP_TUNNELING:
        case HTTP_OP_NEGOTIATING:
            clear_request(op);
            move_connection_to_pool(op);
            break;
        case HTTP_OP_SENT:
        case HTTP_OP_RECEIVED:
            move_connection_to_pool(op);
            break;
        case HTTP_OP_STREAM_CLOSED:
        case HTTP_OP_CLOSED_STREAMING:
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
