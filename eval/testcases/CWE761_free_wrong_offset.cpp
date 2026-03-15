#include <cstdlib>
void free_offset() {
    char* buf = (char*)malloc(100);
    buf += 10; // advance pointer
    free(buf); // BUG: not the original pointer
}
