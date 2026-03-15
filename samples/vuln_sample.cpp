/*
 * vuln_sample.cpp – Deliberately vulnerable C++ sample for audit-agent testing.
 *
 * Contains:
 *   1. A subtle buffer overflow triggered only inside a specific branch.
 *   2. A potential null-pointer dereference.
 *   3. A memory leak of sensitive data.
 *   4. An information-leakage path through a TEE boundary.
 *
 * DO NOT use this code in production – it exists solely to exercise the
 * multi-agent reflection pipeline.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>

// Simulated TEE context structure
struct TeeContext {
    char enclave_id[32];
    unsigned char* secret_key;
    size_t key_len;
    int trust_level;  // 0 = untrusted, 1 = trusted
};

// -----------------------------------------------------------------------
// Vulnerability 1: Stack buffer overflow in a conditional branch.
// The overflow only triggers when `is_admin` is true AND `input` exceeds
// 64 bytes – a subtle bug that naive scanners often miss or hallucinate
// the wrong trigger condition for.
// -----------------------------------------------------------------------
void process_request(const char* input, bool is_admin) {
    char buffer[64];

    if (is_admin) {
        // BUG: strcpy has no bounds check; if input > 63 chars → overflow
        strcpy(buffer, input);
        printf("[ADMIN] Processing: %s\n", buffer);
    } else {
        // Safe path – bounded copy
        strncpy(buffer, input, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
        printf("[USER] Processing: %s\n", buffer);
    }
}

// -----------------------------------------------------------------------
// Vulnerability 2: Null-pointer dereference.
// `ctx` is used without a NULL check after a potentially failing malloc.
// -----------------------------------------------------------------------
TeeContext* init_tee_context(const char* enclave_name) {
    TeeContext* ctx = (TeeContext*)malloc(sizeof(TeeContext));
    // BUG: no NULL check on ctx before use
    strncpy(ctx->enclave_id, enclave_name, sizeof(ctx->enclave_id) - 1);
    ctx->enclave_id[sizeof(ctx->enclave_id) - 1] = '\0';
    ctx->secret_key = nullptr;
    ctx->key_len = 0;
    ctx->trust_level = 0;
    return ctx;
}

// -----------------------------------------------------------------------
// Vulnerability 3: Memory leak of sensitive data.
// `secret_buf` is allocated but never freed if the early-return fires,
// leaving key material in heap memory.
// -----------------------------------------------------------------------
int load_secret_key(TeeContext* ctx, const char* key_data, size_t key_len) {
    unsigned char* secret_buf = (unsigned char*)malloc(key_len);
    if (!secret_buf) return -1;

    memcpy(secret_buf, key_data, key_len);

    if (ctx->trust_level != 1) {
        // BUG: secret_buf is never freed on this path
        printf("ERROR: context is not trusted\n");
        return -2;
    }

    ctx->secret_key = secret_buf;
    ctx->key_len = key_len;
    return 0;
}

// -----------------------------------------------------------------------
// Vulnerability 4: Information leakage across TEE boundary.
// The function prints the raw secret key bytes to stdout, which may be
// observable outside the enclave.
// -----------------------------------------------------------------------
void debug_dump_context(const TeeContext* ctx) {
    printf("Enclave: %s, Trust: %d\n", ctx->enclave_id, ctx->trust_level);
    if (ctx->secret_key) {
        // BUG: leaking secret key material to untrusted output
        printf("Key (%zu bytes): ", ctx->key_len);
        for (size_t i = 0; i < ctx->key_len; i++) {
            printf("%02x", ctx->secret_key[i]);
        }
        printf("\n");
    }
}

// -----------------------------------------------------------------------
// main – exercise the vulnerable paths
// -----------------------------------------------------------------------
int main() {
    // Trigger the admin buffer-overflow path
    char long_input[256];
    memset(long_input, 'A', sizeof(long_input) - 1);
    long_input[sizeof(long_input) - 1] = '\0';

    process_request(long_input, true);   // overflow
    process_request(long_input, false);  // safe

    TeeContext* ctx = init_tee_context("test-enclave-001");
    load_secret_key(ctx, "SUPERSECRETKEY!!", 16);
    debug_dump_context(ctx);

    // Intentionally not freeing ctx to demonstrate leak
    return 0;
}
