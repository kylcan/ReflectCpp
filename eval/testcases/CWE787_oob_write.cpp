/* CWE-787: Out-of-bounds Write
 * Vulnerability: off-by-one in loop writes past array end.
 * Ground truth: line 13, function fill_array
 */
#include <cstdio>

void fill_array(int* arr, int size) {
    // BUG: loop condition should be i < size, not i <= size
    for (int i = 0; i <= size; i++) {
        arr[i] = i * 2;
    }
}

int main() {
    int data[10];
    fill_array(data, 10);
    for (int i = 0; i < 10; i++) {
        printf("%d ", data[i]);
    }
    printf("\n");
    return 0;
}
