#include <cstdio>
int use_uninit(int flag) {
    int value; // not initialized
    if (flag > 0) value = 42;
    return value; // UB when flag <= 0
}
