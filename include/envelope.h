#ifndef __ASYNCHTTP_ENVELOPE__
#define __ASYNCHTTP_ENVELOPE__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HTTP_ENV_REQUEST,
    HTTP_ENV_RESPONSE,
} http_env_type_t;

typedef struct http_env http_env_t;
typedef struct http_env_iter http_env_iter_t;

/* All strings passed to the envelope must stay valid throughout its
 * lifetime. All strings are unprocessed and unvalidated, ie, they are
 * expressed in the "wire format." */
http_env_t *make_http_env_request(const char *method, const char *path,
                                  const char *protocol);
http_env_t *make_http_env_response(const char *protocol, unsigned code,
                                   const char *explanation);

/* Make a shallow copy of an envelope. You can add headers and trailers
 * to the copy without affecting the original. */
http_env_t *copy_http_env(const http_env_t *envelope);
void destroy_http_env(http_env_t *envelope);

/* Add header to the envelope. The strings passed must stay valid throughout the
 * lifetime of the envelope. */
void http_env_add_header(http_env_t *envelope, const char *field,
                         const char *value);

/* Add header to the envelope.
 *
 * If free_field is true, then envelope acquires ownership of the field argument
 * and will deallocate it using fsfree() on destruction. If free_field is false,
 * the field must stay valid throughout the lifetime of the envelope. The
 * behavior for the value argument is analogous. */
void http_env_add_header_2(http_env_t *envelope, char *field, bool free_field,
                           char *value, bool free_value);

/* Chunked encoding supports trailer fields that are appended to the
 * message body. The strings passed must stay valid throughout the lifetime of
 * the envelope. */
void http_env_add_trailer(http_env_t *envelope, const char *field,
                          const char *value);

/* Add trailer to the envelope.
 *
 * If free_field is true, then envelope acquires ownership of the field argument
 * and will deallocate it using fsfree() on destruction. If free_field is false,
 * the field must stay valid throughout the lifetime of the envelope. The
 * behavior for the value argument is analogous. */
void http_env_add_trailer_2(http_env_t *envelope, char *field, bool free_field,
                            char *value, bool free_value);

/* Chunked encoding supports extensions that are appended to the chunk
 * length. This function allows you to specify the extensions for the
 * terminal chunk (whose length is 0). 'final_extensions' must be an
 * empty string or start with a semicolon and not contain the final
 * CRLF. */
void http_env_set_final_extensions(http_env_t *envelope,
                                   const char *final_extensions);

/* Return the envelope type. */
http_env_type_t http_env_get_type(const http_env_t *envelope);

/* Return the envelope protocol (e.g., "HTTP/1.1"). */
const char *http_env_get_protocol(const http_env_t *envelope);

/* Return the method of a request or NULL if the envelope is not a
 * request. */
const char *http_env_get_method(const http_env_t *envelope);

/* Return the path of a request or NULL if the envelope is not a
 * request. */
const char *http_env_get_path(const http_env_t *envelope);

/* Return the response code a response or -1 if the envelope is not a
 * response. */
int http_env_get_code(const http_env_t *envelope);

/* Return the explanation of a response or NULL if the envelope is not a
 * response. */
const char *http_env_get_explanation(const http_env_t *envelope);

/* Iterate through the header fields of an envelope. Initially, specify
 * NULL as 'iter'. Pass the returned iterator to the next call and so on
 * until NULL is returned. If a non-null iterator is returned, 'name'
 * and 'value' are filled in. */
http_env_iter_t *http_env_get_next_header(const http_env_t *envelope,
                                          http_env_iter_t *iter,
                                          const char **field,
                                          const char **value);

/* Like http_env_get_next_header(), but consider only fields matching
 * 'name' (case-insensitive). */
http_env_iter_t *http_env_get_next_matching_header(const http_env_t *envelope,
                                                   http_env_iter_t *iter,
                                                   const char *field,
                                                   const char **value);

/* Get the first header field matching 'field' case-insensitively and
 * return its value. Return NULL, if no matching field is found. */
const char *http_env_get_matching_header(const http_env_t *envelope,
                                         const char *field);

http_env_iter_t *http_env_get_next_trailer(const http_env_t *envelope,
                                           http_env_iter_t *iter,
                                           const char **field,
                                           const char **value);
http_env_iter_t *http_env_get_next_matching_trailer(const http_env_t *envelope,
                                                    http_env_iter_t *iter,
                                                    const char *field,
                                                    const char **value);
const char *http_env_get_matching_trailer(const http_env_t *envelope,
                                          const char *field);

/* Compare (8-bit) ASCII strings case-insensitively (and unsignedly).
 * Useful for comparing method names, field names and some field values.
 * Not encumbered with locales. Return values as with strcmp(3). */
int compare_case_insensitively(const char *a, const char *b);

/* Return the final extensions in wire format: either an empty string or
 * starts with a semicolon. */
const char *http_env_get_final_extensions(const http_env_t *envelope);

/* Return NULL in case of an error. */
http_env_t *http_env_parse_request(char *buffer, const char *end);

/* Return NULL in case of an error. */
http_env_t *http_env_parse_response(char *buffer, const char *end);

/* Return NULL in case of an error. */
http_env_t *http_env_parse_headers(http_env_type_t type, char *header_buffer,
                                   const char *end);

/* Return false in case of an error. */
bool http_env_parse_trailers(http_env_t *envelope, char *buffer,
                             const char *end);

#ifdef __cplusplus
}
#endif

#endif
