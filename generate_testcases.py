#!/usr/bin/env python3
"""Generate 40 new C++ test cases for the eval framework."""
import json
from pathlib import Path

OUT = Path(__file__).parent / "eval" / "testcases"

# (filename, code, labels:[{cwe_id, line, function, description}])
CASES: list[tuple[str, str, list[dict]]] = [
    # ── Memory Safety ─────────────────────────────────────────────
    ("CWE122_heap_overflow.cpp", """\
#include <cstdlib>
#include <cstring>
void heap_overflow() {
    char* buf = (char*)malloc(16);
    strcpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // 31 bytes into 16
    free(buf);
}
""", [{"cwe_id":"CWE-122","line":5,"function":"heap_overflow","description":"Heap buffer overflow: strcpy writes 31 bytes into 16-byte heap buffer."}]),

    ("CWE125_oob_read.cpp", """\
#include <cstdio>
int oob_read(int* arr, int len) {
    return arr[len]; // off-by-one: valid indices are 0..len-1
}
""", [{"cwe_id":"CWE-125","line":3,"function":"oob_read","description":"Out-of-bounds read: accessing arr[len] when valid range is 0..len-1."}]),

    ("CWE131_wrong_buf_size.cpp", """\
#include <cstdlib>
#include <cstring>
struct Record { char name[64]; int id; };
Record* create_records(int n) {
    Record* p = (Record*)malloc(n); // BUG: should be n * sizeof(Record)
    memset(p, 0, n * sizeof(Record));
    return p;
}
""", [{"cwe_id":"CWE-131","line":5,"function":"create_records","description":"Incorrect buffer size: malloc(n) should be malloc(n * sizeof(Record))."}]),

    ("CWE170_missing_null_term.cpp", """\
#include <cstdio>
#include <cstring>
void missing_null(char* dst, const char* src) {
    strncpy(dst, src, 32); // strncpy does NOT guarantee null termination
    printf("%s\\n", dst);   // may read past buffer
}
""", [{"cwe_id":"CWE-170","line":4,"function":"missing_null","description":"Improper null termination: strncpy(dst,src,32) does not null-terminate if src >= 32 chars."}]),

    ("CWE805_wrong_length.cpp", """\
#include <cstring>
void wrong_length(char* dst, const char* src) {
    memcpy(dst, src, strlen(src)); // copies strlen bytes but no null terminator; dst may be smaller
}
""", [{"cwe_id":"CWE-805","line":3,"function":"wrong_length","description":"Buffer access with incorrect length value: memcpy uses strlen(src) without checking dst size."}]),

    # ── Pointer / Memory Management ───────────────────────────────
    ("CWE457_uninitialized_var.cpp", """\
#include <cstdio>
int use_uninit(int flag) {
    int value; // not initialized
    if (flag > 0) value = 42;
    return value; // UB when flag <= 0
}
""", [{"cwe_id":"CWE-457","line":5,"function":"use_uninit","description":"Use of uninitialized variable: 'value' not set when flag <= 0."}]),

    ("CWE467_sizeof_pointer.cpp", """\
#include <cstring>
void sizeof_ptr(char* dst, const char* src) {
    memcpy(dst, src, sizeof(src)); // BUG: sizeof(pointer) is 8, not string length
}
""", [{"cwe_id":"CWE-467","line":3,"function":"sizeof_ptr","description":"Use of sizeof() on pointer type: copies 8 bytes instead of string length."}]),

    ("CWE468_pointer_scaling.cpp", """\
#include <cstdlib>
int* alloc_ints(int n) {
    int* p = (int*)malloc(n * sizeof(int));
    int* end = (int*)((char*)p + n * sizeof(int));
    for (int* q = p; q < end; q++) *q = 0;
    return p;
}
int bad_access(int* arr, int idx) {
    return *((int*)((char*)arr + idx * sizeof(int) + 1)); // misaligned access
}
""", [{"cwe_id":"CWE-468","line":9,"function":"bad_access","description":"Incorrect pointer scaling: misaligned access due to +1 byte offset."}]),

    ("CWE562_return_stack_addr.cpp", """\
int* return_local() {
    int x = 42;
    return &x; // returning address of local variable
}
""", [{"cwe_id":"CWE-562","line":3,"function":"return_local","description":"Return of stack variable address: &x invalid after function returns."}]),

    ("CWE590_free_not_heap.cpp", """\
#include <cstdlib>
void free_stack() {
    int x = 10;
    free(&x); // freeing stack memory
}
""", [{"cwe_id":"CWE-590","line":4,"function":"free_stack","description":"Free of memory not on the heap: freeing address of stack variable."}]),

    ("CWE761_free_wrong_offset.cpp", """\
#include <cstdlib>
void free_offset() {
    char* buf = (char*)malloc(100);
    buf += 10; // advance pointer
    free(buf); // BUG: not the original pointer
}
""", [{"cwe_id":"CWE-761","line":5,"function":"free_offset","description":"Free of pointer not at start of buffer: buf was advanced by 10 bytes."}]),

    ("CWE762_mismatched_memory.cpp", """\
#include <cstdlib>
void mismatched() {
    int* p = new int[10];
    free(p); // BUG: should use delete[]
}
""", [{"cwe_id":"CWE-762","line":4,"function":"mismatched","description":"Mismatched memory management: new[] paired with free() instead of delete[]."}]),

    # ── Integer Issues ────────────────────────────────────────────
    ("CWE191_integer_underflow.cpp", """\
#include <cstddef>
unsigned int underflow(unsigned int a, unsigned int b) {
    return a - b; // underflows if b > a
}
""", [{"cwe_id":"CWE-191","line":3,"function":"underflow","description":"Integer underflow: unsigned subtraction wraps when b > a."}]),

    ("CWE194_sign_extension.cpp", """\
#include <cstdlib>
void* sign_extend_alloc(char size) {
    // char is signed: negative value sign-extends to huge size_t
    return malloc((size_t)size);
}
""", [{"cwe_id":"CWE-194","line":4,"function":"sign_extend_alloc","description":"Unexpected sign extension: negative char cast to size_t becomes huge value."}]),

    ("CWE195_signed_unsigned.cpp", """\
#include <cstring>
int compare_len(int user_len, size_t buf_size) {
    if (user_len < buf_size) return 1; // BUG: signed/unsigned comparison
    return 0;
}
""", [{"cwe_id":"CWE-195","line":3,"function":"compare_len","description":"Signed to unsigned comparison: negative user_len compares as very large unsigned."}]),

    ("CWE197_numeric_truncation.cpp", """\
#include <cstdlib>
void truncate_size(size_t len) {
    unsigned short small = (unsigned short)len; // truncation
    char* buf = (char*)malloc(small);
    // if len > 65535, small wraps, buf too small
    free(buf);
}
""", [{"cwe_id":"CWE-197","line":3,"function":"truncate_size","description":"Numeric truncation: size_t to unsigned short loses upper bits."}]),

    ("CWE369_divide_by_zero.cpp", """\
int average(int* arr, int count) {
    int sum = 0;
    for (int i = 0; i < count; i++) sum += arr[i];
    return sum / count; // division by zero when count == 0
}
""", [{"cwe_id":"CWE-369","line":4,"function":"average","description":"Divide by zero: no check for count == 0."}]),

    ("CWE680_int_to_buf_overflow.cpp", """\
#include <cstdlib>
#include <cstring>
void int_to_overflow(int n) {
    int size = n * sizeof(int); // may overflow for large n
    int* buf = (int*)malloc(size);
    memset(buf, 0, n * sizeof(int)); // writes more than allocated if overflow occurred
    free(buf);
}
""", [{"cwe_id":"CWE-680","line":4,"function":"int_to_overflow","description":"Integer overflow to buffer overflow: n*sizeof(int) may wrap, malloc allocates less than memset writes."}]),

    # ── Format String / Dangerous Functions ───────────────────────
    ("CWE134_format_string.cpp", """\
#include <cstdio>
void log_message(const char* user_input) {
    printf(user_input); // format string vulnerability
}
""", [{"cwe_id":"CWE-134","line":3,"function":"log_message","description":"Format string vulnerability: user_input used as printf format string."}]),

    ("CWE242_dangerous_function.cpp", """\
#include <cstdio>
void read_input(char* buf) {
    gets(buf); // inherently dangerous, no bounds check
}
""", [{"cwe_id":"CWE-242","line":3,"function":"read_input","description":"Use of inherently dangerous function: gets() has no bounds checking."}]),

    ("CWE676_dangerous_func.cpp", """\
#include <cstdio>
#include <cstdlib>
void dangerous_env() {
    char* val = getenv("HOME");
    char buf[256];
    sprintf(buf, "Home: %s", val); // sprintf has no bounds check
}
""", [{"cwe_id":"CWE-676","line":6,"function":"dangerous_env","description":"Use of potentially dangerous function: sprintf without bounds checking."}]),

    # ── Logic / Concurrency ───────────────────────────────────────
    ("CWE362_race_condition.cpp", """\
#include <pthread.h>
int shared_counter = 0;
void* increment(void* arg) {
    for (int i = 0; i < 1000000; i++)
        shared_counter++; // data race: no synchronization
    return nullptr;
}
""", [{"cwe_id":"CWE-362","line":5,"function":"increment","description":"Race condition: shared_counter modified without synchronization."}]),

    ("CWE367_toctou.cpp", """\
#include <cstdio>
#include <unistd.h>
#include <sys/stat.h>
void toctou_open(const char* path) {
    struct stat st;
    if (stat(path, &st) == 0 && st.st_uid == getuid()) {
        // Window of vulnerability between stat and fopen
        FILE* f = fopen(path, "r"); // TOCTOU: file could change
        if (f) fclose(f);
    }
}
""", [{"cwe_id":"CWE-367","line":8,"function":"toctou_open","description":"TOCTOU race: file state may change between stat() check and fopen()."}]),

    ("CWE480_incorrect_operator.cpp", """\
#include <cstdio>
void check_flags(int flags) {
    if (flags & 0x01 == 0) { // BUG: == has higher precedence than &
        printf("Flag not set\\n");
    }
}
""", [{"cwe_id":"CWE-480","line":3,"function":"check_flags","description":"Use of incorrect operator: == binds tighter than &, condition always false."}]),

    ("CWE835_infinite_loop.cpp", """\
void infinite(unsigned int n) {
    unsigned int i = n;
    while (i >= 0) { // always true for unsigned
        i--;
    }
}
""", [{"cwe_id":"CWE-835","line":3,"function":"infinite","description":"Infinite loop: unsigned int >= 0 is always true."}]),

    ("CWE843_type_confusion.cpp", """\
#include <cstdio>
struct Base { int type; };
struct TypeA { int type; int data; };
struct TypeB { int type; char* ptr; };
void process(Base* b) {
    if (b->type == 1) {
        TypeB* tb = (TypeB*)b; // could actually be TypeA
        printf("%s\\n", tb->ptr); // type confusion if wrong
    }
}
""", [{"cwe_id":"CWE-843","line":7,"function":"process","description":"Type confusion: unsafe cast to TypeB without verifying actual type."}]),

    # ── Resource Management ───────────────────────────────────────
    ("CWE252_unchecked_return.cpp", """\
#include <cstdio>
#include <cstdlib>
void unchecked() {
    FILE* f = fopen("/etc/shadow", "r");
    char buf[256];
    fgets(buf, sizeof(buf), f); // f could be NULL
    fclose(f);
}
""", [{"cwe_id":"CWE-252","line":6,"function":"unchecked","description":"Unchecked return value: fopen may return NULL, fgets on NULL is UB."}]),

    ("CWE400_resource_consumption.cpp", """\
#include <cstdlib>
void allocate_loop(int user_count) {
    for (int i = 0; i < user_count; i++) {
        malloc(1024 * 1024); // 1MB each, no limit, no free
    }
}
""", [{"cwe_id":"CWE-400","line":4,"function":"allocate_loop","description":"Uncontrolled resource consumption: unbounded allocation in user-controlled loop."}]),

    ("CWE404_improper_shutdown.cpp", """\
#include <cstdio>
#include <cstdlib>
void process_file(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return;
    char* buf = (char*)malloc(1024);
    if (!buf) return; // BUG: f not closed on this path
    fclose(f);
    free(buf);
}
""", [{"cwe_id":"CWE-404","line":7,"function":"process_file","description":"Improper resource shutdown: file handle f leaked when malloc fails."}]),

    ("CWE773_missing_close.cpp", """\
#include <cstdio>
void leak_fd(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return;
    char buf[256];
    fgets(buf, sizeof(buf), f);
    // BUG: f never closed
}
""", [{"cwe_id":"CWE-773","line":3,"function":"leak_fd","description":"Missing close of file descriptor: fopen without corresponding fclose."}]),

    # ── Information / Crypto ──────────────────────────────────────
    ("CWE256_plaintext_password.cpp", """\
#include <cstring>
struct Config {
    char username[64];
    char password[64]; // plaintext storage
};
void set_creds(Config* c) {
    strcpy(c->username, "admin");
    strcpy(c->password, "P@ssw0rd123"); // hardcoded plaintext password
}
""", [{"cwe_id":"CWE-256","line":8,"function":"set_creds","description":"Plaintext storage of password: password stored without hashing."}]),

    ("CWE327_broken_crypto.cpp", """\
#include <cstdlib>
#include <cstring>
unsigned int weak_hash(const char* data) {
    unsigned int h = 0;
    while (*data) h = h * 31 + *data++; // trivially reversible
    return h;
}
""", [{"cwe_id":"CWE-327","line":4,"function":"weak_hash","description":"Use of broken cryptographic algorithm: trivial hash function, not suitable for security."}]),

    ("CWE377_insecure_temp.cpp", """\
#include <cstdio>
#include <cstdlib>
void insecure_temp() {
    char* name = tmpnam(nullptr); // predictable filename
    FILE* f = fopen(name, "w");
    fprintf(f, "secret data\\n");
    fclose(f);
}
""", [{"cwe_id":"CWE-377","line":4,"function":"insecure_temp","description":"Insecure temporary file: tmpnam generates predictable filename, race condition possible."}]),

    # ── Additional Edge Cases ─────────────────────────────────────
    ("CWE478_missing_default.cpp", """\
enum Command { CMD_READ = 0, CMD_WRITE = 1, CMD_DELETE = 2 };
int dispatch(Command cmd, int* data) {
    switch (cmd) {
        case CMD_READ: return *data;
        case CMD_WRITE: *data = 0; return 0;
        // missing CMD_DELETE and default
    }
    return -1; // may reach here with CMD_DELETE
}
""", [{"cwe_id":"CWE-478","line":3,"function":"dispatch","description":"Missing default case in switch: CMD_DELETE not handled, falls through silently."}]),

    ("CWE587_fixed_address.cpp", """\
void write_fixed() {
    int* p = (int*)0xDEADBEEF; // fixed address assignment
    *p = 42; // undefined behavior
}
""", [{"cwe_id":"CWE-587","line":2,"function":"write_fixed","description":"Assignment of fixed address to pointer: writing to hardcoded address 0xDEADBEEF."}]),

    ("CWE704_incorrect_cast.cpp", """\
#include <cstdio>
void bad_cast() {
    double d = 3.14;
    int* ip = (int*)&d; // type punning via pointer cast
    printf("%d\\n", *ip); // reads double bits as int
}
""", [{"cwe_id":"CWE-704","line":4,"function":"bad_cast","description":"Incorrect type conversion: casting double* to int* violates strict aliasing."}]),

    ("CWE758_undefined_behavior.cpp", """\
#include <climits>
int ub_shift(int x) {
    return x << 33; // UB: shift amount >= bit width of int
}
""", [{"cwe_id":"CWE-758","line":3,"function":"ub_shift","description":"Undefined behavior: left shift by 33 exceeds bit width of int (32)."}]),

    # ── Safe Controls (8 new) ─────────────────────────────────────
    ("safe_smart_ptr.cpp", """\
#include <memory>
#include <string>
struct Resource { std::string name; int value; };
std::unique_ptr<Resource> create_resource(const std::string& n) {
    auto r = std::make_unique<Resource>();
    r->name = n;
    r->value = 0;
    return r; // RAII: ownership transferred, no leak possible
}
""", []),

    ("safe_string_ops.cpp", """\
#include <string>
#include <algorithm>
std::string safe_concat(const std::string& a, const std::string& b) {
    return a + b; // std::string handles memory automatically
}
std::string safe_substr(const std::string& s, size_t pos, size_t len) {
    if (pos >= s.size()) return "";
    return s.substr(pos, len); // bounds checked
}
""", []),

    ("safe_container.cpp", """\
#include <vector>
#include <stdexcept>
int safe_access(const std::vector<int>& v, size_t idx) {
    return v.at(idx); // throws std::out_of_range if invalid
}
void safe_push(std::vector<int>& v, int val) {
    v.push_back(val); // vector manages its own memory
}
""", []),

    ("safe_raii_file.cpp", """\
#include <fstream>
#include <string>
std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    return content; // file closed by RAII destructor
}
""", []),

    ("safe_checked_cast.cpp", """\
#include <limits>
#include <stdexcept>
int safe_cast(long long val) {
    if (val > std::numeric_limits<int>::max() || val < std::numeric_limits<int>::min())
        throw std::overflow_error("Value out of int range");
    return static_cast<int>(val);
}
""", []),

    ("safe_mutex.cpp", """\
#include <mutex>
#include <vector>
class ThreadSafeCounter {
    mutable std::mutex mtx;
    int count = 0;
public:
    void increment() {
        std::lock_guard<std::mutex> lock(mtx);
        count++;
    }
    int get() const {
        std::lock_guard<std::mutex> lock(mtx);
        return count;
    }
};
""", []),

    ("safe_snprintf.cpp", """\
#include <cstdio>
void safe_format(char* buf, size_t buf_size, const char* user_input) {
    snprintf(buf, buf_size, "User said: %s", user_input); // bounded
    buf[buf_size - 1] = '\\0'; // ensure null termination
}
""", []),

    ("safe_nullptr_check.cpp", """\
#include <cstdlib>
#include <cstring>
char* safe_alloc(size_t size) {
    if (size == 0 || size > 1024 * 1024) return nullptr;
    char* buf = (char*)malloc(size);
    if (!buf) return nullptr; // proper NULL check
    memset(buf, 0, size);
    return buf;
}
""", []),
]

# Write .cpp files
for filename, code, _ in CASES:
    path = OUT / filename
    path.write_text(code, encoding="utf-8")

# Build combined labels from existing + new
labels_path = OUT / "labels.json"
existing: dict = {}
if labels_path.exists():
    existing = json.loads(labels_path.read_text())

for filename, _, file_labels in CASES:
    existing[filename] = file_labels

# Sort keys for readability
sorted_labels = dict(sorted(existing.items()))
labels_path.write_text(json.dumps(sorted_labels, indent=2, ensure_ascii=False), encoding="utf-8")

print(f"Generated {len(CASES)} test case files")
print(f"Total labels.json entries: {len(sorted_labels)}")
print(f"Vuln cases: {sum(1 for v in sorted_labels.values() if v)}")
print(f"Safe controls: {sum(1 for v in sorted_labels.values() if not v)}")
