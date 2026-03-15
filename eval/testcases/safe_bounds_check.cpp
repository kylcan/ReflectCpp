/* safe_bounds_check.cpp – No vulnerabilities (negative control)
 * Demonstrates correct bounds checking and safe copy functions.
 * Ground truth: NO vulnerabilities.
 */
#include <cstdio>
#include <cstring>
#include <cstdlib>

struct Config {
    char name[64];
    int value;
};

int safe_copy(Config* dst, const char* name, int val) {
    if (!dst || !name) return -1;
    // Safe: snprintf always null-terminates and respects size
    snprintf(dst->name, sizeof(dst->name), "%s", name);
    dst->value = val;
    return 0;
}

void safe_array_fill(int* arr, int size) {
    // Correct bounds: i < size, not i <= size
    for (int i = 0; i < size; i++) {
        arr[i] = i + 1;
    }
}

int main() {
    Config cfg;
    safe_copy(&cfg, "max_connections", 100);
    printf("Config: %s = %d\n", cfg.name, cfg.value);

    int data[10];
    safe_array_fill(data, 10);
    for (int i = 0; i < 10; i++) {
        printf("%d ", data[i]);
    }
    printf("\n");

    // Proper allocation + free
    char* buf = (char*)malloc(128);
    if (buf) {
        snprintf(buf, 128, "allocated safely");
        printf("%s\n", buf);
        free(buf);
    }
    return 0;
}
