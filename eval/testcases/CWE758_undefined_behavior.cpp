#include <climits>
int ub_shift(int x) {
    return x << 33; // UB: shift amount >= bit width of int
}
