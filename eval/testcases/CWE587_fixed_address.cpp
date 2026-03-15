void write_fixed() {
    int* p = (int*)0xDEADBEEF; // fixed address assignment
    *p = 42; // undefined behavior
}
