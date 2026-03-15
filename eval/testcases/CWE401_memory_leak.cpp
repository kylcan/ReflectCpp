/* CWE-401: Missing Release of Memory after Effective Lifetime
 * Vulnerability: allocated buffer leaked on error path.
 * Ground truth: line 19, function decrypt_payload
 */
#include <cstdlib>
#include <cstdio>
#include <cstring>

int validate_header(const unsigned char* data, size_t len) {
    return (len >= 4 && data[0] == 0xAA) ? 0 : -1;
}

int decrypt_payload(const unsigned char* input, size_t len) {
    unsigned char* work_buf = (unsigned char*)malloc(len);
    if (!work_buf) return -1;

    memcpy(work_buf, input, len);

    if (validate_header(work_buf, len) != 0) {
        // BUG: work_buf is not freed on this error path
        printf("Invalid header\n");
        return -2;
    }

    printf("Decrypted %zu bytes\n", len);
    free(work_buf);
    return 0;
}

int main() {
    unsigned char bad[] = {0x00, 0x01, 0x02};
    decrypt_payload(bad, sizeof(bad));
    return 0;
}
