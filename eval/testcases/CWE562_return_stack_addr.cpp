int* return_local() {
    int x = 42;
    return &x; // returning address of local variable
}
