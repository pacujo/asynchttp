#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <fsdyn/fsalloc.h>
#include "hpack_integer.h"
#include "hpack_string.h"
#include "asynchttp_version.h"

typedef struct {
    uint32_t encoding;
    unsigned bit_width;
} huffman_coding_t;

#include "huffman_tables.c"
static const huffman_coding_t HUFFMAN_EOS = { 0x3fffffff, 30 };

static size_t huffman_encoding_size(const char *s)
{
    const char *p = s;
    uint64_t bit_size = 7;
    while (*p)
        bit_size += huffman[*p++ & 0xff].bit_width;
    size_t size = bit_size / 8;
    if (size * 8 != bit_size)
        return -1;
    return size;
}

size_t hpack_encode_plain_string(const char *s, void *buffer, size_t size)
{
    size_t body_size = strlen(s);
    size_t cursor = hpack_encode_integer(body_size, 0, 1, buffer, size);
    uint8_t *q = buffer;
    if (cursor + body_size <= size)
        memcpy(q + cursor, s, body_size);
    else if (cursor < size)
        memcpy(q + cursor, s, size - cursor);
    return cursor + body_size;
}

size_t hpack_encode_huffman(const char *s, void *buffer, size_t size)
{
    size_t body_size = huffman_encoding_size(s);
    size_t cursor = hpack_encode_integer(body_size, 0x80, 1, buffer, size);
    uint8_t *q = buffer;
    uint8_t bit_count = 0;
    uint64_t accumulator = 0;
    const char *p = s;
    while (*p) {
        const huffman_coding_t *coding = huffman + *p++;
        accumulator = (accumulator << coding->bit_width) | coding->encoding;
        bit_count += coding->bit_width;
        while (bit_count >= 8) {
            bit_count -= 8;
            if (cursor < size)
                q[cursor++] = (accumulator >> bit_count) & 0xff;
            else cursor++;
        }
    }
    if (bit_count) {
        accumulator =
            (accumulator << HUFFMAN_EOS.bit_width) | HUFFMAN_EOS.encoding;
        bit_count += HUFFMAN_EOS.bit_width - 8;
        if (cursor < size)
            q[cursor++] = (accumulator >> bit_count) & 0xff;
        else cursor++;
    }
    return cursor;
}

size_t hpack_encode_string(const char *s, void *buffer, size_t size)
{
    size_t huff_size = hpack_encode_huffman(s, buffer, size);
    size_t plain_size = hpack_encode_plain_string(s, NULL, 0);
    if (plain_size < huff_size)
        return hpack_encode_plain_string(s, buffer, size);
    return huff_size;
}

ssize_t hpack_decode_string_header(const void *buffer, size_t size,
                                   bool *huffman_encoded, size_t *body_size)
{
    uint8_t prefix;
    uint64_t length;
    ssize_t count = hpack_decode_integer(buffer, size, 1, &prefix, &length);
    if (count < 0)
        return -1;
    *huffman_encoded = prefix == 0x80;
    *body_size = length;
    if (*body_size != length)
        return -1;
    return count;
}

static bool find_zero(const uint8_t *buffer, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++)
        if (!buffer[i])
            return true;
    return false;
}

ssize_t hpack_decode_plain_string(const void *buffer, size_t size,
                                  char *strbuf, size_t strbuf_size)
{
    if (find_zero(buffer, size))
        return -1;          /* NULs prohibited in C strings */
    if (size < strbuf_size) {
        memcpy(strbuf, buffer, size);
        strbuf[size] = '\0';
    } else if (strbuf_size) {
        memcpy(strbuf, buffer, strbuf_size - 1);
        strbuf[strbuf_size - 1] = '\0';
    }
    return size;
}

ssize_t hpack_decode_huffman(const void *buffer, size_t size,
                             char *strbuf, size_t strbuf_size)
{
    const uint8_t *p = buffer, *end = p + size;
    uint64_t accumulator = 0;
    unsigned bit_count = 0;
    char *q = strbuf;
    size_t cursor = 0;
    for (;;) {
        while (bit_count < 32) {
            if (p >= end)
                for (;;) {
                    uint32_t bit_field = accumulator << (32 - bit_count);
                    uint8_t value;
                    unsigned bit_width;
                    if (!huffman_decode_0_0(bit_field, &value, &bit_width) ||
                        bit_width > bit_count) {
                        if (bit_count > 7)
                            return -1;
                        return cursor;
                    }
                    if (!value)
                        return -1;          /* NULs prohibited in C strings */
                    if (cursor < strbuf_size)
                        q[cursor++] = value;
                    else cursor++;
                    bit_count -= bit_width;
                }
            accumulator = accumulator << 8 | *p++;
            bit_count += 8;
        }
        uint32_t bit_field = accumulator >> (bit_count - 32);
        uint8_t value;
        unsigned bit_width;
        if (!huffman_decode_0_0(bit_field, &value, &bit_width))
            return -1;
        assert(!(value & ~0xff));
        if (!value)
            return -1;          /* NULs prohibited in C strings */
        if (cursor < strbuf_size)
            q[cursor++] = value;
        else cursor++;
        bit_count -= bit_width;
    }
}

ssize_t hpack_decode_string(const void *buffer, size_t size, char **s,
                            size_t max_length)
{
    bool huffman_encoded;
    size_t encoding_size;
    ssize_t count =
        hpack_decode_string_header(buffer, size, &huffman_encoded,
                                   &encoding_size);
    if (count < 0 || count + encoding_size > size)
        return -1;
    const uint8_t *p = buffer;
    p += count;
    ssize_t decoding_size;
    char *q;
    if (huffman_encoded) {
        decoding_size = hpack_decode_huffman(p, encoding_size, NULL, 0);
        if (decoding_size < 0 || decoding_size > max_length)
            return -1;
        q = fsalloc(decoding_size + 1);
        hpack_decode_huffman(p, encoding_size, q, decoding_size);
    } else {
        decoding_size = hpack_decode_plain_string(p, encoding_size, NULL, 0);
        if (decoding_size < 0 || decoding_size > max_length)
            return -1;
        q = fsalloc(decoding_size + 1);
        hpack_decode_plain_string(p, encoding_size, q, decoding_size);
    }
    q[decoding_size] = '\0';
    *s = q;
    return count + encoding_size;
}
