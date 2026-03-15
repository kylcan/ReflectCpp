#include <cstdio>
void log_message(const char* user_input) {
    printf(user_input); // format string vulnerability
}
