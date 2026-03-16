#include <string.h>
#include "util.h"

void do_memcpy(void) {
    char dst[16];
    char src[64];
    memset(src, 'A', sizeof(src));
    memcpy(dst, src, sizeof(src));
}
