#include <limits>
#include <stdexcept>
int safe_cast(long long val) {
    if (val > std::numeric_limits<int>::max() || val < std::numeric_limits<int>::min())
        throw std::overflow_error("Value out of int range");
    return static_cast<int>(val);
}
