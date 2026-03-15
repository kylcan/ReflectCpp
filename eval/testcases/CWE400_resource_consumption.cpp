#include <cstdlib>
void allocate_loop(int user_count) {
    for (int i = 0; i < user_count; i++) {
        malloc(1024 * 1024); // 1MB each, no limit, no free
    }
}
