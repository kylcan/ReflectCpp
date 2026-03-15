#include <cstdio>
struct Base { int type; };
struct TypeA { int type; int data; };
struct TypeB { int type; char* ptr; };
void process(Base* b) {
    if (b->type == 1) {
        TypeB* tb = (TypeB*)b; // could actually be TypeA
        printf("%s\n", tb->ptr); // type confusion if wrong
    }
}
