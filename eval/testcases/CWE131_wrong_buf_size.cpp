#include <cstdlib>
#include <cstring>
struct Record { char name[64]; int id; };
Record* create_records(int n) {
    Record* p = (Record*)malloc(n); // BUG: should be n * sizeof(Record)
    memset(p, 0, n * sizeof(Record));
    return p;
}
