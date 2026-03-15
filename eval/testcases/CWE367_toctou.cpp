#include <cstdio>
#include <unistd.h>
#include <sys/stat.h>
void toctou_open(const char* path) {
    struct stat st;
    if (stat(path, &st) == 0 && st.st_uid == getuid()) {
        // Window of vulnerability between stat and fopen
        FILE* f = fopen(path, "r"); // TOCTOU: file could change
        if (f) fclose(f);
    }
}
