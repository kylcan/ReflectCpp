/* CWE-120: Buffer Copy without Checking Size of Input
 * Vulnerability: sprintf with unbounded user input into fixed buffer.
 * Ground truth: line 12, function format_greeting
 */
#include <cstdio>
#include <cstring>

void format_greeting(const char* username) {
    char buf[64];
    // BUG: sprintf has no bounds check
    sprintf(buf, "Welcome, %s! Your session has started.", username);
    printf("%s\n", buf);
}

int main() {
    char long_name[256];
    memset(long_name, 'A', 255);
    long_name[255] = '\0';
    format_greeting(long_name);
    return 0;
}
