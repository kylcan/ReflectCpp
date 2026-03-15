#include <pthread.h>
int shared_counter = 0;
void* increment(void* arg) {
    for (int i = 0; i < 1000000; i++)
        shared_counter++; // data race: no synchronization
    return nullptr;
}
