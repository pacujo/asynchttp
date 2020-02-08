#include "asynchttp/jsonop.h"

#include <async/async.h>
#include <encjson.h>
#include <fstrace.h>

#include <assert.h>
#include <errno.h>
#include <string.h>

static const char *PROGRAM = "jsonop-request-quick-close";

typedef struct {
    async_t *async;
    fsadns_t *dns;
    http_client_t *client;
    const char *uri;
    jsonop_t * op;
} globals_t;

static void finish(globals_t *g)
{
    http_client_close(g->client);
    async_execute(g->async, (action_1){g->async, (act_1)async_quit_loop});
}

static void close_request(globals_t *g)
{
    jsonop_close(g->op);
    async_execute(g->async, (action_1){g, (act_1)finish});
}

static void jsonop_callback(globals_t *g)
{
    (void)g;
    assert(false);
}

static void make_request(globals_t *g)
{
    json_thing_t *discbody = json_make_object();
    g->op = jsonop_make_request(g->async, g->client, g->uri, discbody);
    json_destroy_thing(discbody);
    jsonop_register_callback(g->op, (action_1){g, (act_1)jsonop_callback});
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

static void print_usage(FILE *f)
{
    fprintf(f, "Usage: %s <uri> [ <pem-file> ]\n", PROGRAM);
    fprintf(f, "\n");
    fprintf(f, "Options:\n");
    fprintf(f, "    --trace-include <regex>\n");
    fprintf(f, "    --trace-exclude <regex>\n");
    fprintf(f, "    -h,--help\n");

}

static int parse_cmdline(int argc, const char *const argv[],
                         const char **trace_include,
                         const char **trace_exclude)
{
    *trace_include = NULL;
    *trace_exclude = NULL;
    int i = 1;
    while (i < argc && argv[i][0] == '-') {
        if (!strcmp(argv[i], "--trace-include")) {
            if (++i >= argc) {
                print_usage(stderr);
                exit(1);
            }
            *trace_include = argv[i++];
            continue;
        }
        if (!strcmp(argv[i], "--trace-exclude")) {
            if (++i >= argc) {
                print_usage(stderr);
                exit(1);
            }
            *trace_exclude = argv[i++];
            continue;
        }
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            print_usage(stdout);
            exit(0);
        }
        print_usage(stderr);
        exit(1);
    }
    return i;
}

int main(int argc, const char *const *argv)
{
    const char *trace_include;
    const char *trace_exclude;
    int i = parse_cmdline(argc, argv, &trace_include, &trace_exclude);
    if (i != argc) {
        print_usage(stderr);
        return EXIT_FAILURE;
    }
    fstrace_t *trace = set_up_tracing(trace_include, trace_exclude);
    if (!trace) {
        fprintf(stderr, "%s: bad regular expression\n", PROGRAM);
        return EXIT_FAILURE;
    }
    globals_t g;
    g.async = make_async();
    g.dns = fsadns_make_resolver(g.async, 10,
                                 (action_1) { trace, (act_1) fstrace_reopen });
    g.client = open_http_client_2(g.async, g.dns);
    g.uri = "http://fstestdomain.com";
    g.op = NULL;

    async_execute(g.async, (action_1){&g, (act_1)make_request});
    async_execute(g.async, (action_1){&g, (act_1)close_request});
    while (async_loop(g.async) < 0)
        if (errno != EINTR) {
            perror(PROGRAM);
            return EXIT_FAILURE;
        }
    fsadns_destroy_resolver(g.dns);
    async_flush(g.async, async_now(g.async) + 5 * ASYNC_S);
    destroy_async(g.async);
    fstrace_close(trace);
    return EXIT_SUCCESS;
}
