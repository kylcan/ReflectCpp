#include <cstring>
void wrong_length(char* dst, const char* src) {
    memcpy(dst, src, strlen(src)); // copies strlen bytes but no null terminator; dst may be smaller
}
