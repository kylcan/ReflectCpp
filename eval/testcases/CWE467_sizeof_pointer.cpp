#include <cstring>
void sizeof_ptr(char* dst, const char* src) {
    memcpy(dst, src, sizeof(src)); // BUG: sizeof(pointer) is 8, not string length
}
