#include <cstdlib>
void free_stack() {
    int x = 10;
    free(&x); // freeing stack memory
}
