#include <cstdio>
void check_flags(int flags) {
    if (flags & 0x01 == 0) { // BUG: == has higher precedence than &
        printf("Flag not set\n");
    }
}
