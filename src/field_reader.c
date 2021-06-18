#include "field_reader.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <async/bytestream_1.h>
#include <fsdyn/bytearray.h>
#include <fsdyn/fsalloc.h>
#include <fstrace.h>

#include "asynchttp_version.h"

static void __attribute__((noinline)) protocol_violation(void)
{
    /* set your breakpoint here*/
    errno = EPROTO;
}

typedef enum {
    FIELD_READER_AT_START,
    FIELD_READER_IN_MIDDLE,
    FIELD_READER_AFTER_CR,
    FIELD_READER_AVAILABLE,
    FIELD_READER_UNAVAILABLE
} field_reader_state_t;

struct field_reader {
    uint64_t uid;
    field_reader_state_t state;
    bytestream_1 stream;
    byte_array_t *buffer;
    char tail[2000], *end_of_fields, *end_of_leftovers;
};

FSTRACE_DECL(ASYNCHTTP_FIELD_READER_CREATE,
             "UID=%64u PTR=%p STREAM=%p MAX-SIZE=%z");

field_reader_t *make_field_reader(bytestream_1 stream, size_t max_size)
{
    field_reader_t *reader = fsalloc(sizeof *reader);
    reader->uid = fstrace_get_unique_id();
    FSTRACE(ASYNCHTTP_FIELD_READER_CREATE, reader->uid, reader, stream.obj,
            max_size);
    reader->state = FIELD_READER_AT_START;
    reader->stream = stream;
    reader->buffer = make_byte_array(max_size);
    return reader;
}

FSTRACE_DECL(ASYNCHTTP_FIELD_READER_CLOSE, "UID=%64u");

void field_reader_close(field_reader_t *reader)
{
    FSTRACE(ASYNCHTTP_FIELD_READER_CLOSE, reader->uid);
    destroy_byte_array(reader->buffer);
    fsfree(reader);
}

static const char *trace_state(void *pstate)
{
    switch (*(field_reader_state_t *) pstate) {
        case FIELD_READER_AT_START:
            return "FIELD_READER_AT_START";
        case FIELD_READER_IN_MIDDLE:
            return "FIELD_READER_IN_MIDDLE";
        case FIELD_READER_AFTER_CR:
            return "FIELD_READER_AFTER_CR";
        case FIELD_READER_AVAILABLE:
            return "FIELD_READER_AVAILABLE";
        case FIELD_READER_UNAVAILABLE:
            return "FIELD_READER_UNAVAILABLE";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCHTTP_FIELD_READER_SET_STATE, "UID=%64u OLD=%I NEW=%I");

static void set_reader_state(field_reader_t *reader, field_reader_state_t state)
{
    if (FSTRACE_ENABLED(ASYNCHTTP_FIELD_READER_SET_STATE) &&
        reader->state != state)
        /* limit fstrace clutter */
        FSTRACE(ASYNCHTTP_FIELD_READER_SET_STATE, reader->uid, trace_state,
                &reader->state, trace_state, &state);
    reader->state = state;
}

FSTRACE_DECL(ASYNCHTTP_FIELD_READER_READ, "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCHTTP_FIELD_READER_READ_DUMP, "UID=%64u TEXT=%A");

int field_reader_read(field_reader_t *reader)
{
    switch (reader->state) {
        case FIELD_READER_AVAILABLE:
        case FIELD_READER_UNAVAILABLE:
            abort();
        default:;
    }
    for (;;) {
        ssize_t count = bytestream_1_read(reader->stream, reader->tail,
                                          sizeof reader->tail);
        FSTRACE(ASYNCHTTP_FIELD_READER_READ, reader->uid, sizeof reader->tail,
                count);
        FSTRACE(ASYNCHTTP_FIELD_READER_READ_DUMP, reader->uid, reader->tail,
                count);
        if (count < 0)
            return -1;
        if (count == 0) {
            if (reader->state == FIELD_READER_AT_START)
                return 0;
            set_reader_state(reader, FIELD_READER_UNAVAILABLE);
            protocol_violation();
            return -1;
        }

        size_t i;
        for (i = 0; i < count; i++)
            switch (reader->tail[i]) {
                case '\r':
                    switch (reader->state) {
                        case FIELD_READER_AT_START:
                            set_reader_state(reader, FIELD_READER_AFTER_CR);
                            break;
                        default:
                            set_reader_state(reader, FIELD_READER_IN_MIDDLE);
                    }
                    break;
                case '\n':
                    switch (reader->state) {
                        case FIELD_READER_AT_START:
                        case FIELD_READER_AFTER_CR:
                            if (!byte_array_append(reader->buffer, reader->tail,
                                                   i + 1)) {
                                set_reader_state(reader,
                                                 FIELD_READER_UNAVAILABLE);
                                protocol_violation();
                                return -1;
                            }
                            set_reader_state(reader, FIELD_READER_AVAILABLE);
                            reader->end_of_fields = reader->tail + i + 1;
                            reader->end_of_leftovers = reader->tail + count;
                            return 1;
                        default:
                            set_reader_state(reader, FIELD_READER_AT_START);
                    }
                    break;
                default:
                    set_reader_state(reader, FIELD_READER_IN_MIDDLE);
            }
        if (!byte_array_append(reader->buffer, reader->tail, count)) {
            set_reader_state(reader, FIELD_READER_UNAVAILABLE);
            protocol_violation();
            return -1;
        }
    }
}

FSTRACE_DECL(ASYNCHTTP_FIELD_READER_COMBINE, "UID=%64u BYTES=%z");

char *field_reader_combine(field_reader_t *reader, const char **end)
{
    assert(reader->state == FIELD_READER_AVAILABLE);
    size_t buffer_size = byte_array_size(reader->buffer);
    char *buffer = fsalloc(buffer_size);
    memcpy(buffer, byte_array_data(reader->buffer), buffer_size);
    *end = buffer + buffer_size;
    FSTRACE(ASYNCHTTP_FIELD_READER_COMBINE, reader->uid, buffer_size);
    return buffer;
}

char *field_reader_leftover_bytes(field_reader_t *reader)
{
    assert(reader->state == FIELD_READER_AVAILABLE);
    return reader->end_of_fields;
}

FSTRACE_DECL(ASYNCHTTP_FIELD_READER_LEFT_OVER, "UID=%64u LEFT-OVER=%z");

size_t field_reader_leftover_size(field_reader_t *reader)
{
    assert(reader->state == FIELD_READER_AVAILABLE);
    size_t left_over = reader->end_of_leftovers - reader->end_of_fields;
    FSTRACE(ASYNCHTTP_FIELD_READER_LEFT_OVER, reader->uid, left_over);
    return left_over;
}
