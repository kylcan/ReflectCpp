#include <cstdlib>
#include <cstring>
unsigned int weak_hash(const char* data) {
    unsigned int h = 0;
    while (*data) h = h * 31 + *data++; // trivially reversible
    return h;
}
