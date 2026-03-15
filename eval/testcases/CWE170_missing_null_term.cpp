#include <cstdio>
#include <cstring>
void missing_null(char* dst, const char* src) {
    strncpy(dst, src, 32); // strncpy does NOT guarantee null termination
    printf("%s\n", dst);   // may read past buffer
}
