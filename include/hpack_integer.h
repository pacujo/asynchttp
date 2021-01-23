#ifndef __ASYNCHTTP_HPACK_INTEGER__
#define __ASYNCHTTP_HPACK_INTEGER__

#include <stdint.h>
#include <unistd.h>

/* Encode an unsigned integer into the given buffer. Return the number
 * of bytes taken by the encoding. The returned value may be greater
 * than the given size, in which case the encoding is truncated.
 *
 * prefix_length must be between 1 and 7. prefix is unshifted.
 *
 * Note: 10 bytes are enough to encode any 64-bit number with any
 * prefix. */
size_t hpack_encode_integer(uint64_t value,
                            uint8_t prefix, unsigned prefix_length,
                            void *buffer, size_t size);

/* Decode an unsigned integer from the given buffer. If the buffer
 * does not contain a legal integer encoding, a negative number is
 * returned. Otherwise, the number of bytes used in the decoding is
 * returned.
 *
 * prefix_length must be between 1 and 7. The returned prefix is
 * unshifted. */
ssize_t hpack_decode_integer(const void *buffer, size_t size,
                             unsigned prefix_length, uint8_t *prefix,
                             uint64_t *value);

#endif
