#include <mutex>
#include <vector>
class ThreadSafeCounter {
    mutable std::mutex mtx;
    int count = 0;
public:
    void increment() {
        std::lock_guard<std::mutex> lock(mtx);
        count++;
    }
    int get() const {
        std::lock_guard<std::mutex> lock(mtx);
        return count;
    }
};
