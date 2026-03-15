/* CWE-200: Exposure of Sensitive Information
 * Vulnerability: private key material logged to stdout.
 * Ground truth: line 19, function log_connection_info
 */
#include <cstdio>
#include <cstring>

struct TlsSession {
    char server_name[64];
    unsigned char session_key[32];
    int cipher_suite;
};

void log_connection_info(const TlsSession* sess) {
    printf("Connected to: %s, cipher: %d\n", sess->server_name, sess->cipher_suite);
    // BUG: leaking session key to log output
    printf("Session key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", sess->session_key[i]);
    }
    printf("\n");
}

int main() {
    TlsSession s;
    strcpy(s.server_name, "example.com");
    memset(s.session_key, 0x42, 32);
    s.cipher_suite = 0x1301;
    log_connection_info(&s);
    return 0;
}
