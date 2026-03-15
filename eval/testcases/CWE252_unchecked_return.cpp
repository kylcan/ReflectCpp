#include <cstdio>
#include <cstdlib>
void unchecked() {
    FILE* f = fopen("/etc/shadow", "r");
    char buf[256];
    fgets(buf, sizeof(buf), f); // f could be NULL
    fclose(f);
}
