/* CWE-190: Integer Overflow or Wraparound
 * Vulnerability: unchecked multiplication may wrap, causing under-allocation.
 * Ground truth: line 14, function alloc_matrix
 */
#include <cstdlib>
#include <cstdio>
#include <cstdint>

struct Matrix {
    double* cells;
    uint32_t rows, cols;
};

Matrix* alloc_matrix(uint32_t rows, uint32_t cols) {
    // BUG: rows * cols * sizeof(double) may silently overflow for large inputs
    size_t nbytes = (size_t)rows * cols * sizeof(double);
    Matrix* m = (Matrix*)malloc(sizeof(Matrix));
    if (!m) return nullptr;
    m->cells = (double*)malloc(nbytes);
    m->rows = rows;
    m->cols = cols;
    return m;
}

int main() {
    // Only dangerous with huge values; small values exercise the path
    Matrix* m = alloc_matrix(4, 4);
    if (m && m->cells) {
        m->cells[0] = 1.0;
        printf("cell[0] = %f\n", m->cells[0]);
        free(m->cells);
    }
    free(m);
    return 0;
}
