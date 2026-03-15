#include <cstdio>
#include <cstdlib>
void dangerous_env() {
    char* val = getenv("HOME");
    char buf[256];
    sprintf(buf, "Home: %s", val); // sprintf has no bounds check
}
