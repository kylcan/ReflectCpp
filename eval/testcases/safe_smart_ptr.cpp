#include <memory>
#include <string>
struct Resource { std::string name; int value; };
std::unique_ptr<Resource> create_resource(const std::string& n) {
    auto r = std::make_unique<Resource>();
    r->name = n;
    r->value = 0;
    return r; // RAII: ownership transferred, no leak possible
}
