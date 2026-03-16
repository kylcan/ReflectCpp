#include "util.h"

int main(int argc, char** argv) {
    const char* input = (argc > 1) ? argv[1] : "hello";
    safe_copy(input);
    return 0;
}
