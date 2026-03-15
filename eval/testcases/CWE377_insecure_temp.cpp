#include <cstdio>
#include <cstdlib>
void insecure_temp() {
    char* name = tmpnam(nullptr); // predictable filename
    FILE* f = fopen(name, "w");
    fprintf(f, "secret data\n");
    fclose(f);
}
