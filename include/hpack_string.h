#ifndef __ASYNCHTTP_HPACK_STRING__
#define __ASYNCHTTP_HPACK_STRING__

#include <stddef.h>
#include <stdbool.h>

/* Encode a NUL-terminated C string into the given buffer. Truncate
 * the encoding if the given buffer size is too small, but always
 * return the size of the whole encoding.
 *
 * The function chooses plain or Huffman encoding based on which is
 * sorter. */
size_t hpack_encode_string(const char *s, void *buffer, size_t size);

/* Like hpack_encode_string() except that plain encoding is used
 * unconditionally. */
size_t hpack_encode_plain_string(const char *s, void *buffer, size_t size);

/* Like hpack_encode_string() except that Huffman encoding is used
 * unconditionally. */
size_t hpack_encode_huffman(const char *s, void *buffer, size_t size);

/* Decode a string starting from the header. Return the number of
 * bytes consumed from the buffer or a negative number in case of an
 * error.
 *
 * On a successful return, *s contains a NUL terminated C string. The
 * caller is responsible for disposing of the string with fsfree().
 *
 * The maximum length of the decoded string is given in max_length. If
 * the length is exceeded, a negative number is returend.
 *
 * Note that decoding a NUL character in the string is considered an
 * encoding error, as a C string cannot hold NUL characters. */
ssize_t hpack_decode_string(const void *buffer, size_t size, char **s,
                            size_t max_length);

/* Decode a string header from the given buffer and return the length
 * of the header or a negative number if the buffer doesn't contain a
 * full, legal string header.
 *
 * On a successful return, *huffman_encoded indicates is the body is
 * encoded using Huffman or plain encoding, and *body_size contains
 * the length of the string payload encoding. */
ssize_t hpack_decode_string_header(const void *buffer, size_t size,
                                   bool *huffman_encoded, size_t *body_size);

/* Decode a string starting from the body encoding (plain). The
 * given buffer size must match the encoding size precisely (as
 * returned by hpack_decode_string_header()). Return the length of the
 * decoding or a negative number in case of an error.
 *
 * The function writes at most *strbuf_size decoded characters in
 * strbuf and updates *strbuf_size. A NUL termination is not provided.
 *
 * Note that decoding a NUL character in the string is considered an
 * encoding error, as a C string cannot hold NUL characters. */
ssize_t hpack_decode_plain_string(const void *buffer, size_t size,
                                  char *strbuf, size_t strbuf_size);

/* Decode a string starting from the body encoding (Huffman). The
 * given buffer size must match the encoding size precisely (as
 * returned by hpack_decode_string_header()). Return the length of the
 * decoding or a negative number in case of an error.
 *
 * The function writes at most *strbuf_size decoded characters in
 * strbuf and updates *strbuf_size. A NUL termination is not provided.
 *
 * Note that decoding a NUL character in the string is considered an
 * encoding error, as a C string cannot hold NUL characters. */
ssize_t hpack_decode_huffman(const void *buffer, size_t size,
                             char *strbuf, size_t strbuf_size);

#endif
