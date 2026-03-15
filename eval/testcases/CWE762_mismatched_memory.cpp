#include <cstdlib>
void mismatched() {
    int* p = new int[10];
    free(p); // BUG: should use delete[]
}
