#include <cstddef>
unsigned int underflow(unsigned int a, unsigned int b) {
    return a - b; // underflows if b > a
}
