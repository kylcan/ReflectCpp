#include <cstdlib>
void truncate_size(size_t len) {
    unsigned short small = (unsigned short)len; // truncation
    char* buf = (char*)malloc(small);
    // if len > 65535, small wraps, buf too small
    free(buf);
}
