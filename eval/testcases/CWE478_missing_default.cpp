enum Command { CMD_READ = 0, CMD_WRITE = 1, CMD_DELETE = 2 };
int dispatch(Command cmd, int* data) {
    switch (cmd) {
        case CMD_READ: return *data;
        case CMD_WRITE: *data = 0; return 0;
        // missing CMD_DELETE and default
    }
    return -1; // may reach here with CMD_DELETE
}
