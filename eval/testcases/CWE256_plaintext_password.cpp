#include <cstring>
struct Config {
    char username[64];
    char password[64]; // plaintext storage
};
void set_creds(Config* c) {
    strcpy(c->username, "admin");
    strcpy(c->password, "P@ssw0rd123"); // hardcoded plaintext password
}
