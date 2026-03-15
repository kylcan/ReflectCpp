#include <cstdio>
int oob_read(int* arr, int len) {
    return arr[len]; // off-by-one: valid indices are 0..len-1
}
