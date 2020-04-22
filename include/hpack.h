#ifndef __ASYNCHTTP_HPACK__
#define __ASYNCHTTP_HPACK__

#include <stddef.h>

typedef struct hpack_table hpack_table_t;

typedef enum {
    HPACK_NO_LITERAL,           /* RFC 7541, Section 6.1. */
    HPACK_UPDATE,               /* RFC 7541, Section 6.2.1. */
    HPACK_NO_UPDATE,            /* RFC 7541, Section 6.2.2. */
    HPACK_NEVER_UPDATE,         /* RFC 7541, Section 6.2.3. */
} hpack_repr_t;

typedef struct {
    hpack_repr_t representation;
    bool new_name; /* must be false if representation == HPACK_NO_LITERAL */
    union {
        struct {
            unsigned index;
        } no_literal;
        struct {
            unsigned index;
            const char *value;
        } indexed;
        struct {
            const char *name, *value;
        } new;
    };
} hpack_header_field_t;


/* HPACK-encode a header field. The encoding is truncated if the given
 * buffer size is too small but the returned value is the total
 * encoding size. */
size_t hpack_encode_header_field(const hpack_header_field_t *header,
                                 void *buffer, size_t size);

/* Decode a header field and return the number of bytes consumed or a
 * negative number in case of a decoding error.
 *
 * Upon a successful return *header contains a pointer to the decoded
 * header field. The caller is reponsible for freeing the header after
 * use with hpack_free_header_field(). */
ssize_t hpack_decode_header_field(const void *buffer, size_t size,
                                  hpack_header_field_t **header,
                                  size_t max_string_length);

/* Free a header field that was returned by
 * hpack_decode_header_Field(). */
void hpack_free_header_field(hpack_header_field_t *header);

/* Create an hpack compression context. */
hpack_table_t *make_hpack_table(void);
void destroy_hpack_table(hpack_table_t *table);

/* Set the current dynamic table size. */
size_t hpack_table_get_size(hpack_table_t *table);

/* Set the dynamic table size. The end result may be different from
 * that requested and is returned. */
size_t hpack_table_set_size(hpack_table_t *table, size_t size);

/* Convert a name-value pair to a compressed header field. Use
 * hpack_free_header_field() to free the result. The operation alters
 * the state of the compression context. */
hpack_header_field_t *hpack_table_encode(hpack_table_t *table,
                                         const char *name, const char *value);

/* Convert a compressed header field into a name-value pair. Use
 * fsfree() to deallocate them. The operation alters the state of the
 * compression context. */
bool hpack_table_decode(hpack_table_t *table,
                        const hpack_header_field_t *header,
                        char **name, char **value);

#endif
