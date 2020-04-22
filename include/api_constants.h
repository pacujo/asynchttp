#ifndef __ASYNCHTTP_API_CONSTANTS__
#define __ASYNCHTTP_API_CONSTANTS__

#ifdef __cplusplus
extern "C" {
#endif

enum {
    HTTP_DECODE_CHUNKED = -1,     /* assume chunked encoding */
    HTTP_DECODE_EXHAUST = -2,     /* content ends with end-of-stream */
    HTTP_DECODE_OBEY_HEADER = -3  /* inspect headers for content size */
};

enum {
    HTTP_ENCODE_CHUNKED = -1,   /* declare and encode chunked */
    HTTP_ENCODE_RAW = -2        /* no envelope or content processing */
};

#ifdef __cplusplus
}
#endif

#endif
