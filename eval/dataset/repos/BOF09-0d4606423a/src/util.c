#include <stdio.h>
#include <string.h>
#include "util.h"

void do_copy(const char* input) {
    char buf[32];
    strcpy(buf, input);
    puts(buf);
}
