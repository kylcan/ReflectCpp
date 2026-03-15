#include <string>
#include <algorithm>
std::string safe_concat(const std::string& a, const std::string& b) {
    return a + b; // std::string handles memory automatically
}
std::string safe_substr(const std::string& s, size_t pos, size_t len) {
    if (pos >= s.size()) return "";
    return s.substr(pos, len); // bounds checked
}
