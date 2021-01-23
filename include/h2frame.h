#ifndef __ASYNCHTTP_H2FRAME__
#define __ASYNCHTTP_H2FRAME__

#include <stdbool.h>
#include <unistd.h>
#include <fsdyn/list.h>
#include <async/bytestream_1.h>

typedef struct {
    unsigned parameter;
    uint32_t value;
} h2frame_setting_t;

typedef struct {
    unsigned frame_type;
    uint32_t stream_id;
    union {
        struct {
            bool end_stream;
            size_t data_length;
            bytestream_1 data;
        } data;
        struct {
            bool end_stream, end_headers, priority, exclusive;
            uint32_t dependency;
            unsigned weight;
            list_t *headers; /* of const hpack_header_field_t */
        } headers;
        struct {
            bool exclusive;
            uint32_t dependency;
            unsigned weight;
        } priority;
        struct {
            uint32_t error_code;
        } rst_stream;
        struct {
            bool ack;
            list_t *settings; /* of h2frame_setting_t */
        } settings;
        struct {
            bool end_headers;
            uint32_t promised;
            list_t *headers; /* of const hpack_header_field_t */
        } push_promise;
        struct {
            bool ack;
            uint8_t data[8];
        } ping;
        struct {
            uint32_t last_stream_id;
            uint32_t error_code;
            uint8_t *debug_data;
            size_t debug_data_length;
        } goaway;
        struct {
            uint32_t increment;
        } window_update;
        struct {
            bool end_headers;
            list_t *headers; /* of const hpack_header_field_t */
        } continuation;
    };
} h2frame_t;

void h2frame_free(h2frame_t *frame);

/* Allocate a setting. Free with a simple fsfree(). */
h2frame_setting_t *h2frame_make_setting(unsigned parameter, uint32_t value);

/*  a bytestream that is the HTTP/2 frame encoding of the given frame. */
bytestream_1 h2frame_encode(async_t *async, h2frame_t *frame);

const char *h2frame_trace_error_code(void /*uint32_t*/ *p);

#endif
