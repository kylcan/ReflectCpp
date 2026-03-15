/* CWE-476: NULL Pointer Dereference
 * Vulnerability: return value of fopen not checked before use.
 * Ground truth: line 13, function read_config
 */
#include <cstdio>
#include <cstring>

char config_value[256];

void read_config(const char* path) {
    FILE* fp = fopen(path, "r");
    // BUG: fp may be NULL if file doesn't exist
    fgets(config_value, sizeof(config_value), fp);
    fclose(fp);
}

int main() {
    read_config("/nonexistent/path.conf");
    printf("Config: %s\n", config_value);
    return 0;
}
