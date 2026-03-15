/* safe_raii.cpp – No vulnerabilities (negative control)
 * Demonstrates correct RAII, smart pointers, and bounds checking.
 * Ground truth: NO vulnerabilities.
 */
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

class SecureBuffer {
public:
    explicit SecureBuffer(size_t size) : data_(size, 0) {}
    ~SecureBuffer() {
        // Zero out memory before deallocation
        memset(data_.data(), 0, data_.size());
    }
    unsigned char* data() { return data_.data(); }
    size_t size() const { return data_.size(); }
private:
    std::vector<unsigned char> data_;
};

std::string safe_greeting(const std::string& username) {
    // Bounded: std::string handles allocation automatically
    return "Welcome, " + username + "!";
}

int safe_file_read(const char* path) {
    FILE* fp = fopen(path, "r");
    if (!fp) {
        // Proper NULL check
        printf("Cannot open file: %s\n", path);
        return -1;
    }
    char buf[256];
    if (fgets(buf, sizeof(buf), fp)) {
        printf("Read: %s", buf);
    }
    fclose(fp);
    return 0;
}

int main() {
    auto buf = std::make_unique<SecureBuffer>(128);
    printf("Buffer size: %zu\n", buf->size());

    std::string greeting = safe_greeting("Alice");
    printf("%s\n", greeting.c_str());

    safe_file_read("/etc/hostname");
    return 0;
}
