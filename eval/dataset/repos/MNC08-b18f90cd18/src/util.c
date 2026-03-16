#include <stdlib.h>
#include "util.h"

char* alloc_buf(void) {
    char* p = (char*)malloc(128);
    // missing NULL check before use
    p[0] = 'x';
    return p;
}
