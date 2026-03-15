#include <cstdlib>
void* sign_extend_alloc(char size) {
    // char is signed: negative value sign-extends to huge size_t
    return malloc((size_t)size);
}
