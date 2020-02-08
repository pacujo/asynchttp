#pragma once
static __attribute__((constructor)) void ASYNCHTTP_VERSION()
{
    extern const char *asynchttp_version_tag;
    if (!*asynchttp_version_tag)
        asynchttp_version_tag++;
}
