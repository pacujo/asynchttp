typedef struct {
    uint32_t encoding;
    unsigned bit_width;
} huffman_coding_t;

#include "huffman_tables.c"

static size_t huffman_size(const char *s)
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

static const huffman_coding_t HUFFMAN_EOS = { 0x3fffffff, 30 };

bytestream_1 hpack_encode_huffman(async_t *async, const char *s)
{
    size_t size = huffman_size(s);
    uint8_t *buffer = fsalloc(size);
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
            *q++ = (accumulator >> bit_count) & 0xff;
        }
    }
    if (bit_count) {
        accumulator =
            (accumulator << HUFFMAN_EOS.bit_width) | HUFFMAN_EOS.encoding;
        bit_count += HUFFMAN_EOS.bit_width - 8;
        *q++ = (accumulator >> bit_count) & 0xff;
    }
    assert(q - buffer == size);
    bytestream_1 length = hpack_encode_integer(async, size, 0x80, 1);
    action_1 close_action = { buffer, (act_1) fsfree };
    bytestream_1 body =
        blobstream_as_bytestream_1(adopt_blobstream(async, buffer, size,
                                                    close_action));
    concatstream_t *encoding = concatenate_two_streams(async, length, body);
    return concatstream_as_bytestream_1(encoding);
}

