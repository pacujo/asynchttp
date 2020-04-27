#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <fsdyn/fsalloc.h>
#include <fstrace.h>
#include <async/async.h>
#include <async/emptystream.h>
#include <async/tls_connection.h>
#include <async/tcp_connection.h>
#include <asynchttp/h2connection.h>

typedef enum {
    PERFORMING_HANDSHAKE,
    QUERYING,
    READING,
    DONE,
    ZOMBIE
} state_t;

typedef struct {
    async_t *async;
    const char *server_hostname;
    bool print_it;
    tcp_conn_t *tcp_conn;
    tls_conn_t *tls_conn;
    h2conn_t *h2conn;
    h2op_t *op;
    state_t state;
    const http_env_t *resp_env;
    bytestream_1 resp_data;
} globals_t;

static void perrmsg(const char *name)
{
    fprintf(stderr, "h2test: %s\n", name);
}

static int resolve_ipv4(struct addrinfo *res, int port,
                        struct sockaddr **address, socklen_t *addrlen)
{
    if (res->ai_addrlen < sizeof(struct sockaddr_in)) {
        perrmsg("resolved address too short");
        return 0;
    }
    *addrlen = res->ai_addrlen;
    *address = malloc(*addrlen);
    memcpy(*address, res->ai_addr, *addrlen);
    ((struct sockaddr_in *) *address)->sin_port = htons(port);
    return 1;
}

static int resolve_ipv6(struct addrinfo *res, int port,
                        struct sockaddr **address, socklen_t *addrlen)
{
    if (res->ai_addrlen < sizeof(struct sockaddr_in6)) {
        perrmsg("resolved address too short");
        return 0;
    }
    *addrlen = res->ai_addrlen;
    *address = malloc(*addrlen);
    memcpy(*address, res->ai_addr, *addrlen);
    ((struct sockaddr_in6 *) *address)->sin6_port = htons(port);
    return 1;
}

static int resolve_address(const char *host, int port,
                           struct sockaddr **address, socklen_t *addrlen)
{
    struct addrinfo *res;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    int status = getaddrinfo(host, NULL, &hints, &res);
    if (status) {
        perrmsg(gai_strerror(status));
        return 0;
    }
    int ret = 0;
    switch (res->ai_family) {
        case AF_INET:
            ret = resolve_ipv4(res, port, address, addrlen);
            break;
        case AF_INET6:
            ret = resolve_ipv6(res, port, address, addrlen);
            break;
        default:
            perrmsg("unsupported hostname resolution");
            break;
    }
    freeaddrinfo(res);
    return ret;
}

static void finish(globals_t *g)
{
    switch (g->state) {
        case PERFORMING_HANDSHAKE:
            tls_close(g->tls_conn);
            break;
        case DONE:
            break;
        case ZOMBIE:
            return;
        default:
            assert(false);
    }
    tcp_close(g->tcp_conn);
    action_1 quit = { g->async, (act_1) async_quit_loop };
    async_execute(g->async, quit);
    g->state = ZOMBIE;
}

static void myprobe(globals_t *g);

static bool handshake(globals_t *g)
{
    if (tls_read(g->tls_conn, NULL, 0) < 0) {
        if (errno == EAGAIN)
            return false;
        perror("h2test");
        async_execute(g->async, (action_1) { g, (act_1) finish });
        return false;
    }
    g->state = QUERYING;
    fprintf(stderr, "h2test: chosen protocol: \"%s\"\n",
            tls_get_chosen_protocol(g->tls_conn));
    action_1 probe_cb = { g, (act_1) myprobe };
    g->h2conn = open_h2connection(g->async,
                                  tls_get_plain_input_stream(g->tls_conn),
                                  true, 100000);
    //h2conn_register_callback(g->op, probe_cb);
    tls_set_plain_output_stream(g->tls_conn,
                                h2conn_get_output_stream(g->h2conn));
    http_env_t *env = make_http_env_request("GET", "/", "");
    http_env_add_header(env, "host", g->server_hostname);
    http_env_add_header(env, "user-agent", "h2test");
    g->op = h2conn_request(g->h2conn, env, HTTP_ENCODE_RAW, emptystream);
    h2op_register_callback(g->op, probe_cb);
    return true;
}

static bool query(globals_t *g)
{
    g->resp_env = h2op_receive_response(g->op);
    if (!g->resp_env) {
        if (errno != EAGAIN)
            perror("h2test");
        return false;
    }
    if (h2op_get_content(g->op, HTTP_DECODE_OBEY_HEADER, &g->resp_data) < 0) {
        perror("h2test");
        return false;
    }
    action_1 probe_cb = { g, (act_1) myprobe };
    bytestream_1_register_callback(g->resp_data, probe_cb);
    g->state = READING;
    return true;
}

static bool myread(globals_t *g)
{
    uint8_t buffer[5000];
    ssize_t count = bytestream_1_read(g->resp_data, buffer, sizeof buffer);
    if (count < 0) {
        if (errno != EAGAIN)
            perror("h2test");
        return false;
    }
    if (count == 0) {
        bytestream_1_close(g->resp_data);
        h2op_close(g->op);
        h2conn_close(g->h2conn);
        tls_close(g->tls_conn);
        g->state = DONE;
        return true;
    }
    if (g->print_it)
        write(1, buffer, count);
    else printf("----> %d\n", (int) count);
    return true;
}

static void myprobe(globals_t *g)
{
    for (;;) {
        switch (g->state) {
            case PERFORMING_HANDSHAKE:
                if (!handshake(g))
                    return;
                break;
            case QUERYING:
                if (!query(g))
                    return;
                break;
            case READING:
                if (!myread(g))
                    return;
                break;
            case DONE:
                async_execute(g->async, (action_1) { g, (act_1) finish });
                return;
            default:
                return;
        }
    }
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
    fprintf(stderr, "Usage: h2test [ OPTIONS ] host port\n");
    exit(1);
}

static void parse_cmdline(int argc, const char *const argv[],
                          const char **pem_file, const char **pem_dir,
                          bool *print_it,
                          const char **trace_include,
                          const char **trace_exclude,
                          const char **host, int *port)
{
    *pem_file = NULL;
    *pem_dir = NULL;
    *print_it = false;
    *trace_include = NULL;
    *trace_exclude = NULL;
    int i = 1;
    while (i < argc && argv[i][0] == '-') {
        if (!strcmp(argv[i], "--pem-file")) {
            if (++i >= argc)
                bad_usage();
            *pem_file = argv[i++];
            continue;
        }
        if (!strcmp(argv[i], "--pem-dir")) {
            if (++i >= argc)
                bad_usage();
            *pem_dir = argv[i++];
            continue;
        }
        if (!strcmp(argv[i], "--print")) {
            *print_it = true;
            i++;
            continue;
        }
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
    if (i > argc - 2)
        bad_usage();
    *host = argv[i++];
    *port = atoi(argv[i++]);
}

int main(int argc, const char *const *argv)
{
    globals_t g;
    const char *pem_file, *pem_dir, *trace_include, *trace_exclude;
    int port;
    parse_cmdline(argc, argv, &pem_file, &pem_dir, &g.print_it,
                  &trace_include, &trace_exclude, &g.server_hostname, &port);
    fstrace_t *trace = set_up_tracing(trace_include, trace_exclude);
    if (!trace)
        return EXIT_FAILURE;
    struct sockaddr *address;
    socklen_t addrlen;
    if (!resolve_address(g.server_hostname, port, &address, &addrlen)) {
        fstrace_close(trace);
        return EXIT_FAILURE;
    }
    g.async = make_async();
    g.state = PERFORMING_HANDSHAKE;
    g.tcp_conn = tcp_connect(g.async, NULL, address, addrlen);
    free(address);
    if (!g.tcp_conn) {
        perror("h2test");
        destroy_async(g.async);
        fstrace_close(trace);
        return EXIT_FAILURE;
    }
    g.tls_conn = open_tls_client(g.async, tcp_get_input_stream(g.tcp_conn),
                                 pem_file, pem_dir, g.server_hostname);
    tls_allow_protocols(g.tls_conn, "h2", "http/1.1", (const char *) NULL);
    tcp_set_output_stream(g.tcp_conn,
                          tls_get_encrypted_output_stream(g.tls_conn));
    action_1 probe_cb = { &g, (act_1) myprobe };
    tls_register_callback(g.tls_conn, probe_cb);
    async_execute(g.async, probe_cb);
    while (async_loop(g.async) < 0)
        if (errno != EINTR) {
            perror("h2test");
            destroy_async(g.async);
            fstrace_close(trace);
            return EXIT_FAILURE;
        }
    destroy_async(g.async);
    fstrace_close(trace);
    switch (g.state) {
        case ZOMBIE:
            return EXIT_SUCCESS;
        default:
            return EXIT_FAILURE;
    }
}
