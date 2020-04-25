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
#include <fstrace.h>
#include <fsdyn/fsalloc.h>
#include <async/async.h>
#include <async/tls_connection.h>
#include <async/tcp_connection.h>
#include <async/emptystream.h>
#include <asynchttp/client.h>

static const char *PROGRAM = "webclient";

static void perrmsg(const char *msg)
{
    fprintf(stderr, "%s: %s\n", PROGRAM, msg);
}

typedef struct {
    async_t *async;
    fsadns_t *dns;
    const char *uri;
    const char *proxy;
    const char *pem_path;
    tls_ca_bundle_t *ca_bundle;
    http_client_t *client;
    http_op_t *request;
    bytestream_1 content;
    int response_code;
    bool success;
    int64_t spam;
    bool unverified, pinned;
} globals_t;

static void get_next(globals_t *g);

static void close_and_exit(globals_t *g)
{
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
            perror(PROGRAM);
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
    http_op_close(g->request);
    if (g->success && g->spam >= 0)
        async_timer_start(g->async, async_now(g->async) + g->spam,
                          (action_1) { g, (act_1) get_next });
    else close_and_exit(g);
}

static void probe_receive(globals_t *g)
{
    const http_env_t *envelope = http_op_receive_response(g->request);
    if (!envelope) {
        if (errno == EAGAIN)
            return;
        perror(PROGRAM);
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
    if (http_op_get_response_content(g->request, &g->content) < 0) {
        perror(PROGRAM);
        close_and_exit(g);
        return;
    }
    action_1 probe_content_cb = { g, (act_1) probe_content };
    bytestream_1_register_callback(g->content, probe_content_cb);
    async_execute(g->async, probe_content_cb);
}

static void get_next(globals_t *g)
{
    g->response_code = -1;
    g->success = false;
    g->request = http_client_make_request(g->client, "GET", g->uri);
    action_1 probe_cb = { g, (act_1) probe_receive };
    http_op_register_callback(g->request, probe_cb);
    async_execute(g->async, probe_cb);
}

static void get_it(globals_t *g)
{
    g->client = open_http_client_2(g->async, g->dns);
    if (g->proxy)
        http_client_set_proxy_from_uri(g->client, g->proxy);
    if (g->unverified) {
        g->ca_bundle = make_unverified_tls_ca_bundle();
        http_client_set_tls_ca_bundle(g->client, g->ca_bundle);
    } else if (g->pinned) {
        g->ca_bundle = make_pinned_tls_ca_bundle(g->pem_path, NULL);
        http_client_set_tls_ca_bundle(g->client, g->ca_bundle);
    } else if (g->pem_path) {
        g->ca_bundle = make_tls_ca_bundle(g->pem_path, NULL);
        http_client_set_tls_ca_bundle(g->client, g->ca_bundle);
    }
    get_next(g);
    while (async_loop(g->async) < 0)
        if (errno != EINTR) {
            perror(PROGRAM);
            return;
        }
    http_client_close(g->client);
    async_flush(g->async, async_now(g->async) + 5 * ASYNC_S);
    if (g->ca_bundle)
        destroy_tls_ca_bundle(g->ca_bundle);
}

static bool set_up_tracing(fstrace_t *trace, const char *trace_include,
                           const char *trace_exclude)
{
    if (!trace_include)
        return true;
    fstrace_declare_globals(trace);
    return fstrace_select_regex(trace, trace_include, trace_exclude);
}

static void print_usage(FILE *f)
{
    fprintf(f, "Usage: %s [ <options> ] <uri> [ <pem-file> ]\n", PROGRAM);
    fprintf(f, "\n");
    fprintf(f, "Options:\n");
    fprintf(f, "    --proxy <uri>\n");
    fprintf(f, "    --trace-include <regex>\n");
    fprintf(f, "    --trace-exclude <regex>\n");
    fprintf(f, "    --spam <interval>\n");
    fprintf(f, "    --unverified\n");
    fprintf(f, "    --pinned\n");
    fprintf(f, "    -h,--help\n");
}

static void bad_usage()
{
    print_usage(stderr);
    exit(1);
}

static int parse_cmdline(int argc, const char *const argv[],
                         const char **proxy,
                         const char **trace_include, const char **trace_exclude,
                         int64_t *spam,
                         bool *unverified, bool *pinned,
                         const char **uri, const char **pem_path)
{
    *proxy = NULL;
    *trace_include = NULL;
    *trace_exclude = NULL;
    *spam = -1;
    *unverified = false;
    *pinned = false;
    int i = 1;
    while (i < argc && argv[i][0] == '-') {
        if (!strcmp(argv[i], "--proxy")) {
            if (++i >= argc)
                bad_usage();
            *proxy = argv[i++];
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
        if (!strcmp(argv[i], "--spam")) {
            if (++i >= argc)
                bad_usage();
            const char *start = argv[i++];
            char *end;
            double interval = strtod(start, &end);
            if (start == end || interval < 0 || interval > INT64_MAX)
                bad_usage();
            *spam = (int64_t) (interval * ASYNC_S);
            continue;
        }
        if (!strcmp(argv[i], "--unverified")) {
            i++;
            *unverified = true;
            continue;
        }
        if (!strcmp(argv[i], "--pinned")) {
            i++;
            *pinned = true;
            continue;
        }
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            print_usage(stdout);
            exit(0);
        }
        bad_usage();
    }
    if (i == argc)
        bad_usage();
    *uri = argv[i++];
    *pem_path = i < argc ? argv[i++] : NULL;
    return i;
}

int main(int argc, const char *const *argv)
{
    const char *proxy;
    const char *trace_include;
    const char *trace_exclude;
    int64_t spam;
    bool unverified, pinned;
    const char *uri;
    const char *pem_path;
    int i = parse_cmdline(argc, argv, &proxy, &trace_include,
                          &trace_exclude, &spam, &unverified, &pinned,
                          &uri, &pem_path);
    if (!proxy)
        proxy = getenv("http_proxy");
    if (i != argc) {
        print_usage(stderr);
        return EXIT_FAILURE;
    }
    if (unverified && pinned) {
        fprintf(stderr, "%s: --unverified and --pinned may not be "
                "specified at the same time\n", PROGRAM);
        return EXIT_FAILURE;
    }
    if (pinned && !pem_path) {
        fprintf(stderr, "%s: --pinned requires you to specify a pem-file\n",
                PROGRAM);
        return EXIT_FAILURE;
    }
    fstrace_t *trace = fstrace_direct(stderr);
    if (!set_up_tracing(trace, trace_include, trace_exclude)) {
        fprintf(stderr, "%s: bad regular expression\n", PROGRAM);
        return EXIT_FAILURE;
    }
    globals_t g = {
        .async = make_async(),
        .uri = uri,
        .proxy = proxy,
        .pem_path = pem_path,
        .spam = spam,
        .unverified = unverified,
        .pinned = pinned
    };
    g.dns = fsadns_make_resolver(g.async, 10,
                                 (action_1) { trace, (act_1) fstrace_reopen });
    get_it(&g);
    fsadns_destroy_resolver(g.dns);
    async_flush(g.async, async_now(g.async) + 5 * ASYNC_S);
    destroy_async(g.async);
    fstrace_close(trace);
    return g.success ? EXIT_SUCCESS : EXIT_FAILURE;
}
