#include <cstdlib>
#include <cstring>
void int_to_overflow(int n) {
    int size = n * sizeof(int); // may overflow for large n
    int* buf = (int*)malloc(size);
    memset(buf, 0, n * sizeof(int)); // writes more than allocated if overflow occurred
    free(buf);
}
