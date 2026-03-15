#include <vector>
#include <stdexcept>
int safe_access(const std::vector<int>& v, size_t idx) {
    return v.at(idx); // throws std::out_of_range if invalid
}
void safe_push(std::vector<int>& v, int val) {
    v.push_back(val); // vector manages its own memory
}
