#include <cstdlib>
#include <cstring>
void heap_overflow() {
    char* buf = (char*)malloc(16);
    strcpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // 31 bytes into 16
    free(buf);
}
