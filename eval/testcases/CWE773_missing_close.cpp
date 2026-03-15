#include <cstdio>
void leak_fd(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return;
    char buf[256];
    fgets(buf, sizeof(buf), f);
    // BUG: f never closed
}
