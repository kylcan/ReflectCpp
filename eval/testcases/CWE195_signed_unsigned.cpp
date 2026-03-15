#include <cstring>
int compare_len(int user_len, size_t buf_size) {
    if (user_len < buf_size) return 1; // BUG: signed/unsigned comparison
    return 0;
}
