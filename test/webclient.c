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
#include <asynchttp/http_op_jockey.h>
#include <asynchttp/jsonop.h>

static const char *PROGRAM = "webclient";

typedef struct {
    bool json;
    const char *proxy;
    long timeout;
    const char *trace_include;
    const char *trace_exclude;
    int64_t spam;
    bool unverified;
    bool pinned;
    const char *uri;
    const char *pem_path;
} args_t;

typedef struct {
    args_t *args;
    async_t *async;
    fsadns_t *dns;
    tls_ca_bundle_t *ca_bundle;
    http_client_t *client;
    http_op_jockey_t *jockey;
    jsonop_t *json_request;
    bool success;
} globals_t;

static void get_next(globals_t *g);

static void close_and_exit(globals_t *g)
{
    async_quit_loop(g->async);
}

static void probe_receive(globals_t *g)
{
    if (!g->jockey)
        return;
    http_op_response_t *response = http_op_jockey_receive_response(g->jockey);
    if (!response) {
        if (errno == EAGAIN)
            return;
        perror(PROGRAM);
        close_and_exit(g);
        return;
    }
    byte_array_t *body = http_op_response_release_body(response);
    fputs(byte_array_data(body), stdout);
    destroy_byte_array(body);
    const http_env_t *envelope = http_op_response_get_envelope(response);
    fprintf(stderr,
            "Response:\n"
            "Protocol: %s\n"
            "Code: %03d\n"
            "Explanation: %s\n",
            http_env_get_protocol(envelope),
            http_env_get_code(envelope),
            http_env_get_explanation(envelope));
    int response_code = http_env_get_code(envelope);
    if (response_code >= 200 && response_code <= 399) {
        g->success = true;
        fprintf(stderr, "Done!\n");
    } else fprintf(stderr, "Done (with an error response)!\n");
    http_op_jockey_close(g->jockey);
    g->jockey = NULL;
    if (g->success && g->args->spam >= 0)
        async_timer_start(g->async, async_now(g->async) + g->args->spam,
                          (action_1) { g, (act_1) get_next });
    else close_and_exit(g);
}

static void get_next_raw(globals_t *g)
{
    http_op_t *op = http_client_make_request(g->client, "GET", g->args->uri);
    if (g->args->timeout >= 0)
        http_op_set_timeout(op, g->args->timeout * ASYNC_MS);
    g->jockey = make_http_op_jockey(g->async, op, -1);
    action_1 probe_cb = { g, (act_1) probe_receive };
    http_op_jockey_register_callback(g->jockey, probe_cb);
    async_execute(g->async, probe_cb);
}

static void probe_json_receive(globals_t *g)
{
    if (!g->json_request)
        return;
    int code = jsonop_response_code(g->json_request);
    if (code < 0) {
        if (errno == EAGAIN)
            return;
        perror(PROGRAM);
    } else if (code == 200) {
        json_thing_t *body = jsonop_response_body(g->json_request);
        json_utf8_dump(body, stdout);
        g->success = true;
    }
    jsonop_close(g->json_request);
    g->json_request = NULL;
    if (g->success && g->args->spam >= 0)
        async_timer_start(g->async, async_now(g->async) + g->args->spam,
                          (action_1) { g, (act_1) get_next });
    else close_and_exit(g);
}

static void get_next_json(globals_t *g)
{
    g->json_request =
        jsonop_make_get_request(g->async, g->client, g->args->uri);
    if (g->args->timeout >= 0)
        jsonop_set_timeout(g->json_request, g->args->timeout * ASYNC_MS);
    action_1 probe_cb = { g, (act_1) probe_json_receive };
    jsonop_register_callback(g->json_request, probe_cb);
    async_execute(g->async, probe_cb);
}

static void get_next(globals_t *g)
{
    g->success = false;
    if (g->args->json)
        get_next_json(g);
    else
        get_next_raw(g);
}

static void get_it(globals_t *g)
{
    g->client = open_http_client_2(g->async, g->dns);
    if (g->args->proxy)
        http_client_set_proxy_from_uri(g->client, g->args->proxy);
    if (g->args->unverified) {
        g->ca_bundle = make_unverified_tls_ca_bundle();
        http_client_set_tls_ca_bundle(g->client, g->ca_bundle);
    } else if (g->args->pinned) {
        g->ca_bundle = make_pinned_tls_ca_bundle(g->args->pem_path, NULL);
        http_client_set_tls_ca_bundle(g->client, g->ca_bundle);
    } else if (g->args->pem_path) {
        g->ca_bundle = make_tls_ca_bundle(g->args->pem_path, NULL);
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
    fprintf(f, "    --json\n");
    fprintf(f, "    --proxy <uri>\n");
    fprintf(f, "    --timeout <milliseconds>\n");
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

static int parse_cmdline(int argc, const char *const argv[], args_t *args)
{
    int i = 1;
    while (i < argc && argv[i][0] == '-') {
        if (!strcmp(argv[i], "--json")) {
            i++;
            args->json = true;
            continue;
        }
        if (!strcmp(argv[i], "--proxy")) {
            if (++i >= argc)
                bad_usage();
            args->proxy = argv[i++];
            continue;
        }
        if (!strcmp(argv[i], "--timeout")) {
            if (++i >= argc)
                bad_usage();
            args->timeout = strtol(argv[i++], NULL, 10);
            continue;
        }
        if (!strcmp(argv[i], "--trace-include")) {
            if (++i >= argc)
                bad_usage();
            args->trace_include = argv[i++];
            continue;
        }
        if (!strcmp(argv[i], "--trace-exclude")) {
            if (++i >= argc)
                bad_usage();
            args->trace_exclude = argv[i++];
            continue;
        }
        if (!strcmp(argv[i], "--spam")) {
            if (++i >= argc)
                bad_usage();
            const char *start = argv[i++];
            char *end;
            double interval = strtod(start, &end);
            if (start == end || interval < 0)
                bad_usage();
            args->spam = (int64_t) (interval * ASYNC_S);
            continue;
        }
        if (!strcmp(argv[i], "--unverified")) {
            i++;
            args->unverified = true;
            continue;
        }
        if (!strcmp(argv[i], "--pinned")) {
            i++;
            args->pinned = true;
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
    args->uri = argv[i++];
    args->pem_path = i < argc ? argv[i++] : NULL;
    return i;
}

int main(int argc, const char *const *argv)
{
    args_t args = {
        .spam = -1,
        .timeout = -1,
    };
    int i = parse_cmdline(argc, argv, &args);
    if (!args.proxy)
        args.proxy = getenv("http_proxy");
    if (i != argc) {
        print_usage(stderr);
        return EXIT_FAILURE;
    }
    if (args.unverified && args.pinned) {
        fprintf(stderr, "%s: --unverified and --pinned may not be "
                "specified at the same time\n", PROGRAM);
        return EXIT_FAILURE;
    }
    if (args.pinned && !args.pem_path) {
        fprintf(stderr, "%s: --pinned requires you to specify a pem-file\n",
                PROGRAM);
        return EXIT_FAILURE;
    }
    fstrace_t *trace = fstrace_direct(stderr);
    if (!set_up_tracing(trace, args.trace_include, args.trace_exclude)) {
        fprintf(stderr, "%s: bad regular expression\n", PROGRAM);
        return EXIT_FAILURE;
    }
    globals_t g = {
        .async = make_async(),
        .args = &args,
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
