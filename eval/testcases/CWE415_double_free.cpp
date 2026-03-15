/* CWE-415: Double Free
 * Vulnerability: buffer freed twice due to shared ownership confusion.
 * Ground truth: line 22, function cleanup_context
 */
#include <cstdlib>
#include <cstdio>
#include <cstring>

struct Context {
    char* name;
    char* data;
};

Context* create_context(const char* name, const char* data) {
    Context* ctx = (Context*)malloc(sizeof(Context));
    ctx->name = strdup(name);
    ctx->data = strdup(data);
    return ctx;
}

void cleanup_context(Context* ctx) {
    free(ctx->name);
    free(ctx->data);
    free(ctx);
}

int main() {
    Context* c = create_context("test", "payload");
    cleanup_context(c);
    // BUG: double free – ctx already freed above
    cleanup_context(c);
    return 0;
}
