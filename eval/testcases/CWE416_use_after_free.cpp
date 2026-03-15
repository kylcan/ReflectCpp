/* CWE-416: Use After Free
 * Vulnerability: pointer used after free inside conditional branch.
 * Ground truth: line 18, function process_data
 */
#include <cstdlib>
#include <cstdio>
#include <cstring>

struct Packet {
    char data[128];
    int type;
};

void process_data(Packet* pkt, bool should_release) {
    if (should_release) {
        free(pkt);
    }
    // BUG: use-after-free when should_release == true
    printf("Processing packet type: %d\n", pkt->type);
}

int main() {
    Packet* p = (Packet*)malloc(sizeof(Packet));
    p->type = 42;
    strcpy(p->data, "hello");
    process_data(p, true);
    return 0;
}
