#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fsdyn/charstr.h>
#include <fsdyn/fsalloc.h>
#include <async/async.h>
#include <async/tls_connection.h>
#include <async/tcp_connection.h>
#include <async/emptystream.h>
#include <asynchttp/connection.h>

static void perrmsg(const char *msg)
{
    fprintf(stderr, "webget: %s\n", msg);
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

static int parse_uri(const char *uri, bool *https,
                     char **host, int *port, char **path,
                     struct sockaddr **address, socklen_t *addrlen)
{
    regex_t re;
    const char *uripattern =
        "^http(s)?://"           /* scheme ([1] for HTTPS)  */
        "(([-.a-zA-Z0-9]+)|"     /* hostname or IPv4 address [3] */
        "\\[([:a-fA-F0-9]+)\\])" /* IPv6 address [4] */
        "(:([0-9]+))?"           /* port [6] */
        "(/.*)$";                /* path [7] */
    int status = regcomp(&re, uripattern, REG_EXTENDED);
    regmatch_t match[8];
    if (!status)
        status = regexec(&re, uri, 8, match, 0);
    if (status) {
        char errbuf[200];
        regerror(status, &re, errbuf, sizeof errbuf);
        perrmsg(errbuf);
        regfree(&re);
        return 0;
    }
    *https = match[1].rm_so >= 0;
    *host = make_re_snippet(uri, &match[3]);
    if (!*host)
        *host = make_re_snippet(uri, &match[4]);
    char *port_string = make_re_snippet(uri, &match[6]);
    if (port_string) {
        *port = atoi(port_string);
        fsfree(port_string);
    } else if (*https)
        *port = 443;
    else *port = 80;
    *path = make_re_snippet(uri, &match[7]);
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
    tls_conn_t *tls_conn;
    tcp_conn_t *tcp_conn;
    http_conn_t *http_conn;
    char *host;
    http_env_t *request;
    bytestream_1 content;
    int response_code;
    bool success;
} globals_t;

static void start_transaction(globals_t *g, const char *host, int port,
                              const char *path)
{
    g->request = make_http_env_request("GET", path, "HTTP/1.1");
    if (port == 80)
        g->host = charstr_dupstr(host);
    else
        g->host = charstr_printf("%s:%d", host, port);
    http_env_add_header(g->request, "Host", g->host);
    http_send(g->http_conn, g->request, HTTP_ENCODE_RAW, emptystream);
    http_terminate(g->http_conn);
}

static void farewell_notification(globals_t *g)
{
    fprintf(stderr, "farewell\n");
    destroy_http_env(g->request);
}

static void close_and_exit(globals_t *g)
{
    http_close(g->http_conn);
    if (g->tls_conn)
        tls_close(g->tls_conn);
    tcp_close(g->tcp_conn);
    async_quit_loop(g->async);
}

static void probe_content(globals_t *g)
{
    for (;;) {
        char buf[2000];
        ssize_t count = bytestream_1_read(g->content, buf, sizeof buf);
        if (count < 0) {
            if (errno == EAGAIN)
                return;
            perror("webget");
            break;
        }
        if (count == 0) {
            if (g->response_code >= 200 && g->response_code <= 399) {
                g->success = true;
                fprintf(stderr, "Done!\n");
            } else fprintf(stderr, "Done (with an error response)!\n");
            break;
        }
        if (write(STDOUT_FILENO, buf, count) != count) {
            /* Not quite accurate, but oh well... */
            perrmsg("write failed");
            break;
        }
    }
    bytestream_1_close(g->content);
    close_and_exit(g);
}

static void probe_receive(globals_t *g)
{
    const http_env_t *envelope =
        http_receive(g->http_conn, HTTP_ENV_RESPONSE);
    if (!envelope) {
        if (errno) {
            if (errno == EAGAIN)
                return;
            perror("webget");
        }
        else fprintf(stderr, "server closed\n");
        close_and_exit(g);
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
    g->response_code = http_env_get_code(envelope);
    if (http_get_content(g->http_conn, HTTP_DECODE_OBEY_HEADER,
                         &g->content) < 0) {
        perror("webget");
        close_and_exit(g);
        return;
    }
    action_1 probe_content_cb = { g, (act_1) probe_content };
    bytestream_1_register_callback(g->content, probe_content_cb);
    async_execute(g->async, probe_content_cb);
}

static void get_it(globals_t *g,
                   const struct sockaddr *address, socklen_t addrlen,
                   bool https, const char *host, int port,
                   const char *path,
                   const char *pem_path)
{
    g->tcp_conn = tcp_connect(g->async, NULL, address, addrlen);
    if (!g->tcp_conn) {
        perror("webget");
        return;
    }
    bytestream_1 http_input;
    if (https) {
        g->tls_conn =
            open_tls_client(g->async, tcp_get_input_stream(g->tcp_conn),
                            pem_path, NULL, host);
        tcp_set_output_stream(g->tcp_conn,
                              tls_get_encrypted_output_stream(g->tls_conn));
        http_input = tls_get_plain_input_stream(g->tls_conn);
    } else {
        g->tls_conn = NULL;
        http_input = tcp_get_input_stream(g->tcp_conn);
    }
    g->http_conn = open_http_connection(g->async, http_input, 100000);
    action_1 farewell_cb = { g, (act_1) farewell_notification };
    http_register_peer_closed_callback(g->http_conn, farewell_cb);
    bytestream_1 http_output = http_get_output_stream(g->http_conn);
    if (https)
        tls_set_plain_output_stream(g->tls_conn, http_output);
    else tcp_set_output_stream(g->tcp_conn, http_output);
    action_1 probe_cb = { g, (act_1) probe_receive };
    http_register_callback(g->http_conn, probe_cb);
    async_execute(g->async, probe_cb);
    start_transaction(g, host, port, path);
    while (async_loop(g->async) < 0)
        if (errno != EINTR) {
            perror("webget");
            fsfree(g->host);
            return;
        }
    async_flush(g->async, async_now(g->async) + 5 * ASYNC_S);
    fsfree(g->host);
}

int main(int argc, const char *const *argv)
{
    if (argc < 2 || argc > 3 || argv[1][0] == '-') {
        fprintf(stderr, "Usage: webget <uri> [ <pem-file> ]\n");
        return EXIT_FAILURE;
    }
    globals_t g = {
        .response_code = -1,
        .success = false
    };
    bool https;
    char *host, *path;
    int port;
    struct sockaddr *address;
    socklen_t addrlen;
    if (!parse_uri(argv[1], &https, &host, &port, &path, &address, &addrlen))
        return EXIT_FAILURE;
    if (https && argc != 3) {
        perrmsg("PEM file needed for HTTPS");
        free(address);
        fsfree(host);
        fsfree(path);
        return EXIT_FAILURE;
    }
    const char *pem_path = https ? argv[2] : NULL;
    g.async = make_async();
    get_it(&g, address, addrlen, https, host, port, path, pem_path);
    free(address);
    destroy_async(g.async);
    fsfree(host);
    fsfree(path);
    return g.success ? EXIT_SUCCESS : EXIT_FAILURE;
}
