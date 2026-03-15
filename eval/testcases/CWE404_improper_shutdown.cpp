#include <cstdio>
#include <cstdlib>
void process_file(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return;
    char* buf = (char*)malloc(1024);
    if (!buf) return; // BUG: f not closed on this path
    fclose(f);
    free(buf);
}
