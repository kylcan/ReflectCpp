#include <cstdio>
void safe_format(char* buf, size_t buf_size, const char* user_input) {
    snprintf(buf, buf_size, "User said: %s", user_input); // bounded
    buf[buf_size - 1] = '\0'; // ensure null termination
}
