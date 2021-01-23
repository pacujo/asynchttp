#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <assert.h>
#include <fsdyn/fsalloc.h>
#include <fstrace.h>
#include <async/async.h>
#include <async/fsadns.h>
#include <async/tls_connection.h>
#include <async/tcp_connection.h>
#include <asynchttp/h2connection.h>

typedef enum {
    PERFORMING_HANDSHAKE,
    ESTABLISHED,
    READING,
    DONE,
    ZOMBIE
} conn_state_t;

typedef struct {
    async_t *async;
    fsadns_t *dns;
    fsadns_query_t *dns_query;
    tcp_server_t *server;
    list_t *connections;
    tls_credentials_t *credentials;
} globals_t;

typedef struct {
    globals_t *g;
    conn_state_t state;
    tcp_conn_t *tcp;
    tls_conn_t *tls;
    h2conn_t *h2;
    list_elem_t *loc;
    bytestream_1 req_body;      /* while READING */
} conn_t;

static bool probe_established(conn_t *conn)
{
    const http_env_t *request;
    h2op_t *op = h2conn_receive_request(conn->h2, &request);
    if (!op) {
        if (errno == EAGAIN)
            return false;
        perror("h2error");
        assert(false);
        return false;
    }
    fprintf(stderr, "METHOD: %s\n", http_env_get_method(request));
    fprintf(stderr, "PATH: %s\n", http_env_get_path(request));
    if (h2op_get_content(op, HTTP_DECODE_OBEY_HEADER, &conn->req_body) < 0) {
        perror("h2error");
        assert(false);
        return false;
    }
    conn->state = READING;
    return true;
}

static bool probe_reading(conn_t *conn)
{
    char buffer[1000];
    ssize_t count =
        bytestream_1_read(conn->req_body, buffer, sizeof buffer);;
    if (count < 0) {
        if (errno == EAGAIN)
            return false;
        perror("h2server");
        assert(false);
        return false;
    }
    if (count == 0) {
        fprintf(stderr, "Got request body EOF\n");
        exit(0);
    }
    fprintf(stderr, "Got %d request body bytes\n", (int) count);
    return true;
}

static void probe_h2(conn_t *conn)
{
    for (;;) {
        switch (conn->state) {
            case ESTABLISHED:
                if (!probe_established(conn))
                    return;
                break;
            case READING:
                if (!probe_reading(conn))
                    return;
                break;
            default:
                return;
        }
    }
}

static void probe_conn(conn_t *conn)
{
    if (conn->state != PERFORMING_HANDSHAKE)
        return;
    if (tls_read(conn->tls, NULL, 0) < 0) {
        if (errno == EAGAIN)
            return;
        perror("h2server");
        assert(false);
        return;
    }
    assert(!strcmp(tls_get_chosen_protocol(conn->tls), "h2"));
    conn->state = ESTABLISHED;
    fprintf(stderr, "ESTABLISHED\n");
    conn->h2 = open_h2connection(conn->g->async,
                                 tls_get_plain_input_stream(conn->tls),
                                 false, 100000);
    tls_set_plain_output_stream(conn->tls, 
                                h2conn_get_output_stream(conn->h2));
    action_1 h2_probe_cb = { conn, (act_1) probe_h2 };
    h2conn_register_callback(conn->h2, h2_probe_cb);
    async_execute(conn->g->async, h2_probe_cb);
}

static void probe_accept(globals_t *g)
{
    tcp_conn_t *tcp_conn = tcp_accept(g->server, NULL, NULL);
    if (!tcp_conn) {
        if (errno == EAGAIN)
            return;
        perror("h2server");
        assert(false);
        return;
    }
    conn_t *conn = fsalloc(sizeof *conn);
    conn->g = g;
    conn->state = PERFORMING_HANDSHAKE;
    conn->tcp = tcp_conn;
    conn->tls =
        open_tls_server_2(g->async, tcp_get_input_stream(conn->tcp),
                          g->credentials);
    tcp_set_output_stream(conn->tcp,
                          tls_get_encrypted_output_stream(conn->tls));
    conn->loc = list_append(g->connections, conn);
    action_1 probe_cb = { conn, (act_1) probe_conn };
    tls_register_callback(conn->tls, probe_cb);
    async_execute(g->async, probe_cb);
}

static fstrace_t *set_up_tracing(const char *trace_include,
                                 const char *trace_exclude)
{
    fstrace_t *trace = fstrace_direct(stderr);
    fstrace_declare_globals(trace);
    if (!fstrace_select_regex(trace, trace_include, trace_exclude)) {
        fstrace_close(trace);
        return NULL;
    }
    return trace;
}

static void bad_usage()
{
    fprintf(stderr, "Usage: h2server [ OPTIONS ] host port cert key\n");
    exit(1);
}

static void parse_cmdline(int argc, const char *const argv[],
                          const char **cert_path, const char **key_path,
                          const char **trace_include,
                          const char **trace_exclude,
                          const char **host, const char **port)
{
    *cert_path = NULL;
    *key_path = NULL;
    *trace_include = NULL;
    *trace_exclude = NULL;
    int i = 1;
    while (i < argc && argv[i][0] == '-') {
        if (!strcmp(argv[i], "--trace-include")) {
            if (++i >= argc)
                bad_usage();
            *trace_include = argv[i++];
            continue;
        }
        if (!strcmp(argv[i], "--trace-exclude")) {
            if (++i >= argc)
                bad_usage();
            *trace_exclude = argv[i++];
            continue;
        }
        bad_usage();
    }
    if (i > argc - 4)
        bad_usage();
    *host = argv[i++];
    *port = argv[i++];
    *cert_path = argv[i++];
    *key_path = argv[i++];
}

static void resolved(globals_t *g)
{
    struct addrinfo *res;
    int result = fsadns_check(g->dns_query, &res);
    switch (result) {
        case EAI_SYSTEM:
            if (errno == EAGAIN)
                return;
            perror("h2server");
            assert(false);
            return;
        default:
            fprintf(stderr, "h2server: can't resolve host\n");
            assert(false);
            return;
        case 0:
            ;
    }
    while (res && !g->server) {
        g->server = tcp_listen(g->async, res->ai_addr, res->ai_addrlen);
        res = res->ai_next;
    }
    fsadns_freeaddrinfo(res);
    assert(g->server);
    action_1 accept_cb = { g, (act_1) probe_accept };
    tcp_register_server_callback(g->server, accept_cb);
    async_execute(g->async, accept_cb);
}

int main(int argc, const char *const *argv)
{
    globals_t g;
    const char *cert_path, *key_path;
    const char *trace_include, *trace_exclude;
    const char *host, *port;
    parse_cmdline(argc, argv, &cert_path, &key_path,
                  &trace_include, &trace_exclude, &host, &port);
    fstrace_t *trace = set_up_tracing(trace_include, trace_exclude);
    if (!trace)
        return EXIT_FAILURE;
    g.async = make_async();
    action_1 post_fork_cb = { trace, (act_1) fstrace_reopen };
    g.dns = fsadns_make_resolver(g.async, 10, post_fork_cb);
    action_1 resolution_cb = { &g, (act_1) resolved };
    g.dns_query = fsadns_resolve(g.dns, host, port, NULL, resolution_cb);
    async_execute(g.async, resolution_cb);
    g.server = NULL;
    g.connections = make_list();
    g.credentials = make_tls_credentials(cert_path, key_path);
    tls_set_protocol_priority(g.credentials, "h2", (const char *) NULL);
    while (async_loop(g.async) < 0)
        if (errno != EINTR) {
            perror("h2server");
            destroy_async(g.async);
            fstrace_close(trace);
            return EXIT_FAILURE;
        }
    tcp_close_server(g.server);
    destroy_async(g.async);
    fstrace_close(trace);
    return EXIT_SUCCESS;
}
