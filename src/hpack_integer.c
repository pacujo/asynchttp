#include "hpack_integer.h"
#include "asynchttp_version.h"

size_t hpack_encode_integer(uint64_t value,
                            uint8_t prefix, unsigned prefix_length,
                            void *buffer, size_t size)
{
    uint8_t *p = buffer;
    size_t cursor = 0;
    uint8_t leader_mask = 0xff >> prefix_length;
    if (value < leader_mask) {
        if (cursor < size)
            p[cursor++] = prefix | value;
        else cursor++;
    } else {
        if (cursor < size)
            p[cursor++] = prefix | leader_mask;
        else cursor++;
        for (value -= leader_mask; value > 127; value >>= 7)
            if (cursor < size)
                p[cursor++] = 0x80 | (value & 0x7f);
            else cursor++;
        if (cursor < size)
            p[cursor++] = value;
        else cursor++;
    }
    return cursor;
}

ssize_t hpack_decode_integer(const void *buffer, size_t size,
                             unsigned prefix_length, uint8_t *prefix,
                             uint64_t *value)
{
    const uint8_t *p = buffer;
    const uint8_t *end = p + size;
    if (p >= end)
        return -1;
    uint8_t leader_mask = 0xff >> prefix_length;
    uint8_t byte = *p++;
    *value = byte & leader_mask;
    *prefix = byte ^ *value;
    if (*value < leader_mask)
        return p - (const uint8_t *) buffer;
    unsigned shift;
    for (shift = 0; p < end; shift += 7) {
        byte = *p++;
        uint64_t digit = byte & 0x7f;
        uint64_t increment = digit << shift;
        if (digit != increment >> shift)
            return -1;
        *value += increment;
        if (!(byte & 0x80))
            return p - (const uint8_t *) buffer;
    }
    return -1;
}
