#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <fsdyn/fsalloc.h>
#include <fsdyn/charstr.h>
#include "hpack_integer.h"
#include "hpack_string.h"
#include "hpack.h"
#include "asynchttp_version.h"

static size_t encode_indexed(unsigned index, void *buffer, size_t size)
{
    return hpack_encode_integer(index, 0x80, 1, buffer, size);
}

static size_t encode_string_at(const char *s, uint8_t *buffer, size_t size,
                               size_t cursor)
{
    if (cursor >= size)
        return cursor + hpack_encode_string(s, NULL, 0);
    return cursor + hpack_encode_string(s, buffer + cursor, size - cursor);
}

static size_t encode_indexed_literal(unsigned index, const char *value,
                                     uint8_t prefix, unsigned prefix_length,
                                     void *buffer, size_t size)
{
    size_t cursor =
        hpack_encode_integer(index, prefix, prefix_length, buffer, size);
    cursor = encode_string_at(value, buffer, size, cursor);
    return cursor;
}

static size_t encode_new_literal(const char *name, const char *value,
                                 uint8_t prefix, unsigned prefix_length,
                                 void *buffer, size_t size)
{
    size_t cursor =
        hpack_encode_integer(0, prefix, prefix_length, buffer, size);
    cursor = encode_string_at(name, buffer, size, cursor);
    cursor = encode_string_at(value, buffer, size, cursor);
    return cursor;
}

size_t hpack_encode_header_field(const hpack_header_field_t *header,
                                 void *buffer, size_t size)
{
    switch (header->representation) {
        case HPACK_NO_LITERAL:
            assert(!header->new_name);
            return encode_indexed(header->no_literal.index,
                                  buffer, size);
        case HPACK_UPDATE:
            if (header->new_name)
                return encode_new_literal(header->new.name,
                                          header->new.value,
                                          0x40, 2, buffer, size);
            return encode_indexed_literal(header->indexed.index,
                                          header->indexed.value,
                                          0x40, 2, buffer, size);
        case HPACK_NO_UPDATE:
            if (header->new_name)
                return encode_new_literal(header->new.name,
                                          header->new.value,
                                          0, 4, buffer, size);
            return encode_indexed_literal(header->indexed.index,
                                          header->indexed.value,
                                          0, 4, buffer, size);
        case HPACK_NEVER_UPDATE:
            if (header->new_name)
                return encode_new_literal(header->new.name,
                                          header->new.value,
                                          0x10, 4, buffer, size);
            return encode_indexed_literal(header->indexed.index,
                                          header->indexed.value,
                                          0x10, 4, buffer, size);
        default:
            assert(false);
    }
}

static ssize_t decode_index(const void *buffer, size_t size,
                            unsigned prefix_length, unsigned *index)
{
    uint8_t dummy_prefix;
    uint64_t value;
    ssize_t count = hpack_decode_integer(buffer, size,
                                         prefix_length, &dummy_prefix, &value);
    if (count < 0)
        return -1;
    *index = value;
    if (*index != value)
        return -1;
    return count;
}

static hpack_header_field_t *make_no_literal(unsigned index)
{
    hpack_header_field_t *header = fsalloc(sizeof *header);
    header->representation = HPACK_NO_LITERAL;
    header->new_name = false;
    header->no_literal.index = index;
    return header;
}

static ssize_t decode_no_literal(const void *buffer, size_t size,
                                 hpack_header_field_t **pheader)
{
    unsigned index;
    ssize_t count = decode_index(buffer, size, 1, &index);
    if (count < 0)
        return -1;
    *pheader = make_no_literal(index);
    return count;
}

static hpack_header_field_t *make_indexed(hpack_repr_t representation,
                                          unsigned index, char *value)
{
    hpack_header_field_t *header = fsalloc(sizeof *header);
    header->representation = representation;
    header->new_name = false;
    header->indexed.index = index;
    header->indexed.value = value;
    return header;
}

static hpack_header_field_t *make_new(hpack_repr_t representation,
                                      char *name, char *value)
{
    hpack_header_field_t *header = fsalloc(sizeof *header);
    header->representation = representation;
    header->new_name = true;
    header->new.name = name;
    header->new.value = value;
    return header;
}

static ssize_t decode_named_literal(const void *buffer, size_t size,
                                    unsigned prefix_length,
                                    hpack_repr_t representation,
                                    hpack_header_field_t **pheader,
                                    size_t max_string_length)
{
    const uint8_t *p = buffer;
    unsigned index;
    ssize_t count = decode_index(p, size, prefix_length, &index);
    if (count < 0)
        return -1;
    size_t cursor = count;
    if (index) {
        char *value;
        count = hpack_decode_string(p + cursor, size - cursor,
                                    &value, max_string_length);
        if (count < 0)
            return -1;
        cursor += count;
        *pheader = make_indexed(representation, index, value);
        return cursor;
    }
    char *name;
    count = hpack_decode_string(p + cursor, size - cursor, &name,
                                max_string_length);
    if (count < 0)
        return -1;
    cursor += count;
    char *value;
    count = hpack_decode_string(p + cursor, size - cursor, &value,
                                max_string_length);
    if (count < 0) {
        fsfree(name);
        return -1;
    }
    cursor += count;
    *pheader = make_new(representation, name, value);
    return cursor;
}

void hpack_free_header_field(hpack_header_field_t *header)
{
    if (header->representation != HPACK_NO_LITERAL) {
        if (header->new_name) {
            fsfree((char *) header->new.name);
            fsfree((char *) header->new.value);
        } else fsfree((char *) header->indexed.value);
    }
    fsfree(header);
}

ssize_t hpack_decode_header_field(const void *buffer, size_t size,
                                  hpack_header_field_t **pheader,
                                  size_t max_string_length)
{
    if (size < 1)
        return -1;
    switch (*(const uint8_t *) buffer & 0xc0) {
        case 0x00:
            return decode_named_literal(buffer, size, 4, HPACK_NO_UPDATE,
                                        pheader, max_string_length);
        case 0x10:
            return decode_named_literal(buffer, size, 4, HPACK_NEVER_UPDATE,
                                        pheader, max_string_length);
        case 0x40: case 0x50: case 0x60: case 0x70:
            return decode_named_literal(buffer, size, 2, HPACK_UPDATE,
                                        pheader, max_string_length);
        case 0x80: case 0x90: case 0xa0: case 0xb0:
        case 0xc0: case 0xd0: case 0xe0: case 0xf0:
            return decode_no_literal(buffer, size, pheader);
        default:
            return -1;
    }
}

enum {
    STATIC_BASE = 1,            /* lowest static index */
    STATIC_ENTRY_COUNT = 61,    /* from the spec */
    DYNAMIC_BASE = STATIC_ENTRY_COUNT + 1, /* lowest dynamic index */
    NOMINAL_ENTRY_OVERHEAD = 32, /* bytes; from the spec */
    MINIMUM_ENTRY_SIZE = NOMINAL_ENTRY_OVERHEAD + 1, /* bytes */
    DEFAULT_TABLE_SIZE = 4096,  /* bytes; from the spec */
    MAX_OFFERED_TABLE_SIZE = 50000, /* >= DEFAULT_TABLE_SIZE */
    DYNAMIC_ENTRY_COUNT = (MAX_OFFERED_TABLE_SIZE / MINIMUM_ENTRY_SIZE) + 1,
};

static struct {
    const char *name, *value;
} static_table[STATIC_ENTRY_COUNT] = {
    { ":authority", "" },       /* 1 */
    { ":method", "GET" },       /* 2 */
    { ":method", "POST" },      /* 3 */
    { ":path", "/" },           /* 4 */
    { ":path", "/index.html" }, /* 5 */
    { ":scheme", "http" },      /* 6 */
    { ":scheme", "https" },     /* 7 */
    { ":status", "200" },       /* 8 */
    { ":status", "204" },       /* 9 */
    { ":status", "206" },       /* 10 */
    { ":status", "304" },       /* 11 */
    { ":status", "400" },       /* 12 */
    { ":status", "404" },       /* 13 */
    { ":status", "500" },       /* 14 */
    { "accept-charset", "" },
    { "accept-encoding", "gzip, deflate" },
    { "accept-language", "" },
    { "accept-ranges", "" },
    { "accept", "" },
    { "access-control-allow-origin", "" },
    { "age", "" },
    { "allow", "" },
    { "authorization", "" },
    { "cache-control", "" },
    { "content-disposition", "" },
    { "content-encoding", "" },
    { "content-language", "" },
    { "content-length", "" },
    { "content-location", "" },
    { "content-range", "" },
    { "content-type", "" },
    { "cookie", "" },
    { "date", "" },
    { "etag", "" },
    { "expect", "" },
    { "expires", "" },
    { "from", "" },
    { "host", "" },
    { "if-match", "" },
    { "if-modified-since", "" },
    { "if-none-match", "" },
    { "if-range", "" },
    { "if-unmodified-since", "" },
    { "last-modified", "" },
    { "link", "" },
    { "location", "" },
    { "max-forwards", "" },
    { "proxy-authenticate", "" },
    { "proxy-authorization", "" },
    { "range", "" },
    { "referer", "" },
    { "refresh", "" },
    { "retry-after", "" },
    { "server", "" },
    { "set-cookie", "" },
    { "strict-transport-security", "" },
    { "transfer-encoding", "" },
    { "user-agent", "" },
    { "vary", "" },
    { "via", "" },
    { "www-authenticate", "" },
};

struct hpack_table {
    unsigned dynamic_entry_begin; /* initially 0 */
    unsigned dynamic_entry_count; /* initially 0 */
    size_t current_size;          /* sum of entry[i].size */
    size_t size_limit;            /* initially DEFAULT_TABLE_SIZE */
    struct {
        char *name, *value;
        size_t size;           /* strlen(name) + strlen(value) + 32 */
    } dynamic_table[DYNAMIC_ENTRY_COUNT];
};

/* Return a negative value if the index is not legal. */
static int index_to_static_pos(unsigned index)
{
    if (index == 0 || index >= DYNAMIC_BASE)
        return -1;
    return index - STATIC_BASE;
}

/* Return a negative value if the index is not legal. */
static int index_to_dynamic_pos(hpack_table_t *table, unsigned index)
{
    if (index < DYNAMIC_BASE)
        return -1;
    int n = index - DYNAMIC_BASE;
    if (n >= table->dynamic_entry_count)
        return -1;
    n += table->dynamic_entry_begin;
    if (n >= DYNAMIC_ENTRY_COUNT)
        return n - DYNAMIC_ENTRY_COUNT;
    return n;
}

static void evict(hpack_table_t *table)
{
    unsigned drop_point =
        table->dynamic_entry_begin + --table->dynamic_entry_count;
    if (drop_point >= DYNAMIC_ENTRY_COUNT)
        drop_point -= DYNAMIC_ENTRY_COUNT;
    table->current_size -= table->dynamic_table[drop_point].size;
    fsfree(table->dynamic_table[drop_point].name);
    fsfree(table->dynamic_table[drop_point].value);
}

static size_t dynamic_entry_length(const char *name, const char *value)
{
    return NOMINAL_ENTRY_OVERHEAD + strlen(name) + strlen(value);
}

static void add(hpack_table_t *table, const char *name, const char *value)
{
    size_t addition = dynamic_entry_length(name, value);
    if (table->size_limit < addition)
        while (table->current_size)
            evict(table);
    else {
        size_t allowance = table->size_limit - addition;
        while (table->current_size > allowance)
            evict(table);
        if (!table->dynamic_entry_begin--)
            table->dynamic_entry_begin += DYNAMIC_ENTRY_COUNT;
        unsigned insert_point = table->dynamic_entry_begin;
        table->current_size += addition;
        table->dynamic_table[insert_point].name = charstr_dupstr(name);
        table->dynamic_table[insert_point].value = charstr_dupstr(value);
        table->dynamic_entry_count++;
    }
}

/* Return 0 if there is no match. Return a positive index if there is
 * a complete match. Return a negative index if there is a name
 * match. */
static int find_index(hpack_table_t *table, const char *name, const char *value)
{
    int name_index = 0;
    int i;
    for (i = 0; i < STATIC_ENTRY_COUNT; i++) {
        if (charstr_case_cmp(name, static_table[i].name))
            continue;
        name_index = STATIC_BASE + i;
        if (!strcmp(value, static_table[i].value))
            return name_index;
    }
    int end = table->dynamic_entry_begin + table->dynamic_entry_count;
    if (end > DYNAMIC_ENTRY_COUNT) {
        end -= DYNAMIC_ENTRY_COUNT;
        for (i = table->dynamic_entry_begin; i < DYNAMIC_ENTRY_COUNT; i++) {
            if (charstr_case_cmp(name, table->dynamic_table[i].name))
                continue;
            name_index = DYNAMIC_BASE + i - table->dynamic_entry_begin;
            if (!strcmp(value, table->dynamic_table[i].value))
                return name_index;
        }
        for (i = STATIC_ENTRY_COUNT; i <  end; i++) {
            if (charstr_case_cmp(name, table->dynamic_table[i].name))
                continue;
            name_index = DYNAMIC_BASE + DYNAMIC_ENTRY_COUNT +
                i - table->dynamic_entry_begin;
            if (!strcmp(value, table->dynamic_table[i].value))
                return name_index;
        }
    } else
        for (i = table->dynamic_entry_begin; i < end; i++) {
            if (charstr_case_cmp(name, table->dynamic_table[i].name))
                continue;
            name_index = DYNAMIC_BASE + i - table->dynamic_entry_begin;
            if (!strcmp(value, table->dynamic_table[i].value))
                return name_index;
        }
    return -name_index;
}

hpack_table_t *make_hpack_table()
{
    hpack_table_t *table = fsalloc(sizeof *table);
    table->dynamic_entry_begin = table->dynamic_entry_count = 0;
    table->current_size = 0;
    table->size_limit = DEFAULT_TABLE_SIZE;
    return table;
}

void destroy_hpack_table(hpack_table_t *table)
{
    while (table->current_size)
        evict(table);
    fsfree(table);
}

size_t hpack_table_get_size(hpack_table_t *table)
{
    return table->size_limit;
}

size_t hpack_table_set_size(hpack_table_t *table, size_t size)
{
    if (size <= DEFAULT_TABLE_SIZE)
        table->size_limit = DEFAULT_TABLE_SIZE;
    if (size <= MAX_OFFERED_TABLE_SIZE)
        table->size_limit = size;
    else table->size_limit = MAX_OFFERED_TABLE_SIZE;
    return table->size_limit;
}

hpack_header_field_t *hpack_table_encode(hpack_table_t *table,
                                         const char *name, const char *value)
{
    int index = find_index(table, name, value);
    if (index > 0)
        return make_no_literal(index);
    add(table, name, value);
    if (index < 0)
        return make_indexed(HPACK_UPDATE, -index, charstr_dupstr(value));
    return make_new(HPACK_UPDATE,
                    charstr_lcase_str(charstr_dupstr(name)),
                    charstr_dupstr(value));
}

/* Return the header field name and value. Use fsfree() to deallocate them. */
bool hpack_table_decode(hpack_table_t *table,
                        const hpack_header_field_t *header,
                        char **name, char **value)
{
    if (header->representation == HPACK_NO_LITERAL) {
        int pos = index_to_static_pos(header->no_literal.index);
        if (pos >= 0) {
            *name = charstr_dupstr(static_table[pos].name);
            *value = charstr_dupstr(static_table[pos].value);
            return true;
        }
        pos = index_to_dynamic_pos(table, header->no_literal.index);
        if (pos < 0)
            return false;
        *name = charstr_dupstr(table->dynamic_table[pos].name);
        *value = charstr_dupstr(table->dynamic_table[pos].value);
        return true;
    }            
    if (header->new_name) {
        *name = charstr_dupstr(header->new.name);
        *value = charstr_dupstr(header->new.value);
    } else {
        int pos = index_to_static_pos(header->indexed.index);
        if (pos >= 0) {
            *name = charstr_dupstr(static_table[pos].name);
        } else {
            pos = index_to_dynamic_pos(table, header->indexed.index);
            if (pos < 0)
                return false;
            *name = charstr_dupstr(table->dynamic_table[pos].name);
        }
        *value = charstr_dupstr(header->indexed.value);
    }
    if (header->representation == HPACK_UPDATE)
        add(table, *name, *value);
    return true;
}
