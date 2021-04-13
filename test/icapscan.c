#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <fsdyn/charstr.h>
#include <fsdyn/fsalloc.h>
#include <async/async.h>
#include <async/tcp_connection.h>
#include <async/emptystream.h>
#include <async/blockingstream.h>
#include <asynchttp/icap.h>

static void perrmsg(const char *msg)
{
    fprintf(stderr, "icapscan: %s\n", msg);
}

static char *make_re_snippet(const char *s, regmatch_t *match)
{
    if (match->rm_eo < 0)
        return NULL;
    size_t size = match->rm_eo - match->rm_so;
    char *dup = fsalloc(size + 1);
    memcpy(dup, s + match->rm_so, size);
    dup[size] = '\0';
    return dup;
}

static int resolve_ipv4(struct addrinfo *res, int port,
                        struct sockaddr **address, socklen_t *addrlen)
{
    if (res->ai_addrlen < sizeof(struct sockaddr_in)) {
        freeaddrinfo(res);
        perrmsg("resolved address too short");
        return 0;
    }
    *addrlen = res->ai_addrlen;
    *address = malloc(*addrlen);
    memcpy(*address, res->ai_addr, *addrlen);
    ((struct sockaddr_in *) *address)->sin_port = htons(port);
    freeaddrinfo(res);
    return 1;
}

static int resolve_ipv6(struct addrinfo *res, int port,
                        struct sockaddr **address, socklen_t *addrlen)
{
    if (res->ai_addrlen < sizeof(struct sockaddr_in6)) {
        freeaddrinfo(res);
        perrmsg("resolved address too short");
        return 0;
    }
    *addrlen = res->ai_addrlen;
    *address = malloc(*addrlen);
    memcpy(*address, res->ai_addr, *addrlen);
    ((struct sockaddr_in6 *) *address)->sin6_port = htons(port);
    freeaddrinfo(res);
    return 1;
}

static int resolve_address(const char *host, int port,
                           struct sockaddr **address, socklen_t *addrlen)
{
    struct addrinfo *res;
    int status = getaddrinfo(host, NULL, NULL, &res);
    if (status) {
        perrmsg(gai_strerror(status));
        return 0;
    }
    switch (res->ai_family) {
        case AF_INET:
            return resolve_ipv4(res, port, address, addrlen);
        case AF_INET6:
            return resolve_ipv6(res, port, address, addrlen);
        default:
            perrmsg("unsupported hostname resolution");
            freeaddrinfo(res);
            return 0;
    }
}

static int parse_uri(const char *uri, char **host, int *port, char **path,
                     struct sockaddr **address, socklen_t *addrlen)
{
    regex_t re;
    const char *uripattern =
        "^icap://"
        "(([-.a-zA-Z0-9]+)|"     /* hostname or IPv4 address [2] */
        "\\[([:a-fA-F0-9]+)\\])" /* IPv6 address [3] */
        "(:([0-9]+))?"           /* port [5] */
        "/.*$";
    int status = regcomp(&re, uripattern, REG_EXTENDED);
    regmatch_t match[6];
    if (!status)
        status = regexec(&re, uri, 6, match, 0);
    if (status) {
        char errbuf[200];
        regerror(status, &re, errbuf, sizeof errbuf);
        perrmsg(errbuf);
        regfree(&re);
        return 0;
    }
    *host = make_re_snippet(uri, &match[2]);
    if (!*host)
        *host = make_re_snippet(uri, &match[3]);
    char *port_string = make_re_snippet(uri, &match[5]);
    if (port_string) {
        *port = atoi(port_string);
        fsfree(port_string);
    } else *port = 1344;
    *path = make_re_snippet(uri, &match[0]);
    regfree(&re);
    if (!resolve_address(*host, *port, address, addrlen)) {
        fsfree(*host);
        fsfree(*path);
        return 0;
    }
    return 1;
}

typedef struct {
    async_t *async;
    bool allow204;
    tcp_conn_t *tcp_conn;
    icap_conn_t *icap_conn;
    char *host;
    http_env_t *request;
    bytestream_1 content;
} globals_t;

static void start_transaction(globals_t *g, const char *host, int port,
                              const char *path, int fd)
{
    g->request = make_http_env_request("RESPMOD", path, "ICAP/1.0");
    if (port == 1344)
        g->host = charstr_dupstr(host);
    else
        g->host = charstr_printf("%s:%d", host, port);
    http_env_add_header(g->request, "Host", g->host);
    if (g->allow204)
        http_env_add_header(g->request, "Allow", "204");
    bytestream_1 body =
        blockingstream_as_bytestream_1(open_blockingstream(g->async, fd));
    icap_send(g->icap_conn, g->request, NULL, NULL, ICAP_RES_BODY, body);
    icap_terminate(g->icap_conn);
}

static void farewell_notification(globals_t *g)
{
    fprintf(stderr, "farewell\n");
    destroy_http_env(g->request);
}

static void probe_content(globals_t *g)
{
    for (;;) {
        char buf[2000];
        ssize_t count = bytestream_1_read(g->content, buf, sizeof buf);
        if (count < 0) {
            if (errno == EAGAIN)
                return;
            perror("icapscan");
            break;
        }
        if (count == 0) {
            fprintf(stderr, "Done!\n");
            bytestream_1_close(g->content);
            tcp_close(g->tcp_conn);
            break;
        }
        if (write(1, buf, count) != count) {
            /* Not quite accurate, but oh well... */
            perrmsg("write failed");
            break;
        }
    }
    icap_close(g->icap_conn);
    async_quit_loop(g->async);
}

static void probe_receive(globals_t *g)
{
    icap_body_type_t body_type;
    const http_env_t *envelope =
        icap_receive(g->icap_conn, HTTP_ENV_RESPONSE, NULL, NULL,
                     &body_type, &g->content);
    if (!envelope) {
        if (errno) {
            if (errno == EAGAIN)
                return;
            perror("icapscan");
        }
        else fprintf(stderr, "server closed\n");
        icap_close(g->icap_conn);
        async_quit_loop(g->async);
        return;
    }
    fprintf(stderr,
            "Response:\n"
            "Protocol: %s\n"
            "Code: %03d\n"
            "Explanation: %s\n",
            http_env_get_protocol(envelope),
            http_env_get_code(envelope),
            http_env_get_explanation(envelope));
    switch (body_type) {
        case ICAP_REQ_BODY:
            fprintf(stderr, "Body type: req-body\n");
            break;
        case ICAP_RES_BODY:
            fprintf(stderr, "Body type: res-body\n");
            break;
        case ICAP_OPT_BODY:
            fprintf(stderr, "Body type: opt-body\n");
            break;
        case ICAP_NULL_BODY:
            fprintf(stderr, "Body type: null-body\n");
            break;
        case ICAP_UNENCAPSULATED:
            fprintf(stderr, "Body type: unencapsulated\n");
            break;
        default:
            abort();
    }
    action_1 probe_content_cb = { g, (act_1) probe_content };
    bytestream_1_register_callback(g->content, probe_content_cb);
    async_execute(g->async, probe_content_cb);
}

int main(int argc, const char *const *argv)
{
    globals_t g;
    g.allow204 = false;
    if (argc >= 2 && !strcmp(argv[1], "--allow204")) {
        g.allow204 = true;
        argc--;
        argv++;
    }
    if (argc != 2 || argv[1][0] == '-') {
        fprintf(stderr, "Usage: icapscan [ --allow204 ] <uri>\n");
        return EXIT_FAILURE;
    }
    char *host, *path;
    int port;
    struct sockaddr *address;
    socklen_t addrlen;
    if (!parse_uri(argv[1], &host, &port, &path, &address, &addrlen))
        return EXIT_FAILURE;
    g.async = make_async();
    g.tcp_conn = tcp_connect(g.async, NULL, address, addrlen);
    free(address);
    if (!g.tcp_conn) {
        perror("icapscan");
        return EXIT_FAILURE;
    }
    bytestream_1 icap_input;
    icap_input = tcp_get_input_stream(g.tcp_conn);
    g.icap_conn = open_icap_connection(g.async, icap_input, 100000);
    action_1 farewell_cb = { &g, (act_1) farewell_notification };
    icap_register_peer_closed_callback(g.icap_conn, farewell_cb);
    bytestream_1 http_output = icap_get_output_stream(g.icap_conn);
    tcp_set_output_stream(g.tcp_conn, http_output);
    action_1 probe_cb = { &g, (act_1) probe_receive };
    icap_register_callback(g.icap_conn, probe_cb);
    async_execute(g.async, probe_cb);
    start_transaction(&g, host, port, path, 0);
    while (async_loop(g.async) < 0)
        if (errno != EINTR) {
            perror("icapscan");
            return EXIT_FAILURE;
        }
    destroy_async(g.async);
    fsfree(g.host);
    fsfree(host);
    fsfree(path);
    return EXIT_SUCCESS;
}
