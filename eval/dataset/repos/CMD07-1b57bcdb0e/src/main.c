#include "util.h"

int main(int argc, char** argv) {
    const char* cmd = (argc > 1) ? argv[1] : "echo hello";
    run_cmd(cmd);
    return 0;
}
