#include <stdio.h>
#include "util.h"

int main(void) {
    char* p = alloc_buf();
    puts(p);
    return 0;
}
