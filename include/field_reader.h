#ifndef __ASYNCHTTP_FIELD_READER__
#define __ASYNCHTTP_FIELD_READER__

#include <async/bytestream_1.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct field_reader field_reader_t;

field_reader_t *make_field_reader(bytestream_1 stream, size_t max_size);
void field_reader_close(field_reader_t *reader);

/* Return <0, errno == EAGAIN: try again.
 * Return <0, errno == EPROTO: fatal error.
 * Return <0, other errno: maybe transient, maybe fatal.
 * Return 0: a clean disconnect at start.
 * Return >0: all fields successfully read in.
 */
int field_reader_read(field_reader_t *reader);

char *field_reader_combine(field_reader_t *reader, const char **end);
char *field_reader_leftover_bytes(field_reader_t *reader);
size_t field_reader_leftover_size(field_reader_t *reader);

#ifdef __cplusplus
}
#endif

#endif
