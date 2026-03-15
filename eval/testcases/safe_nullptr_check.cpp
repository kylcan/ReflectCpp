#include <cstdlib>
#include <cstring>
char* safe_alloc(size_t size) {
    if (size == 0 || size > 1024 * 1024) return nullptr;
    char* buf = (char*)malloc(size);
    if (!buf) return nullptr; // proper NULL check
    memset(buf, 0, size);
    return buf;
}
