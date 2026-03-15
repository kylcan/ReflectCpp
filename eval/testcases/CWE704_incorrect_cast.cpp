#include <cstdio>
void bad_cast() {
    double d = 3.14;
    int* ip = (int*)&d; // type punning via pointer cast
    printf("%d\n", *ip); // reads double bits as int
}
