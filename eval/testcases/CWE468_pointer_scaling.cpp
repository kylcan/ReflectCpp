#include <cstdlib>
int* alloc_ints(int n) {
    int* p = (int*)malloc(n * sizeof(int));
    int* end = (int*)((char*)p + n * sizeof(int));
    for (int* q = p; q < end; q++) *q = 0;
    return p;
}
int bad_access(int* arr, int idx) {
    return *((int*)((char*)arr + idx * sizeof(int) + 1)); // misaligned access
}
