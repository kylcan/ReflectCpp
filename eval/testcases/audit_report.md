# 🔒 Repository Security Audit Report

**Root:** `eval/testcases`  
**Files scanned:** 10  
**Files with vulnerabilities:** 10  
**Total confirmed:** 30  
**Total rejected:** 0  
**Total time:** 2.5s

## Per-File Summary

| File | Confirmed | Rejected | Iterations | Time |
|------|-----------|----------|------------|------|
| `eval/testcases/CWE120_buffer_overflow.cpp` | 3 | 0 | 1 | 1.0s |
| `eval/testcases/CWE190_integer_overflow.cpp` | 3 | 0 | 1 | 0.3s |
| `eval/testcases/CWE200_info_leak.cpp` | 3 | 0 | 1 | 0.1s |
| `eval/testcases/CWE401_memory_leak.cpp` | 3 | 0 | 1 | 0.2s |
| `eval/testcases/CWE415_double_free.cpp` | 3 | 0 | 1 | 0.1s |
| `eval/testcases/CWE416_use_after_free.cpp` | 3 | 0 | 1 | 0.3s |
| `eval/testcases/CWE476_null_deref.cpp` | 3 | 0 | 1 | 0.1s |
| `eval/testcases/CWE787_oob_write.cpp` | 3 | 0 | 1 | 0.1s |
| `eval/testcases/safe_bounds_check.cpp` | 3 | 0 | 1 | 0.1s |
| `eval/testcases/safe_raii.cpp` | 3 | 0 | 1 | 0.1s |

## Detailed Findings

### eval/testcases/CWE120_buffer_overflow.cpp

**1. Buffer Overflow (CWE-120)**
- CWE: CWE-120
- Location: vuln_sample.cpp:39
- Severity: High (CVSS 8.1)
- Description: Unbounded strcpy in admin branch may overflow buffer[64].
- Remediation: Replace strcpy with strncpy(buffer, input, sizeof(buffer)-1).

**2. Null Pointer Dereference (CWE-476)**
- CWE: CWE-476
- Location: vuln_sample.cpp:55
- Severity: Medium (CVSS 5.9)
- Description: malloc result may be null before dereference.
- Remediation: Add NULL check after malloc: if (!ctx) return nullptr;

**3. Memory Leak (CWE-401)**
- CWE: CWE-401
- Location: vuln_sample.cpp:76
- Severity: Medium (CVSS 6.5)
- Description: Early return path may leak secret buffer.
- Remediation: Add free(secret_buf) before early return.

### eval/testcases/CWE190_integer_overflow.cpp

**1. Buffer Overflow (CWE-120)**
- CWE: CWE-120
- Location: vuln_sample.cpp:39
- Severity: High (CVSS 8.1)
- Description: Unbounded strcpy in admin branch may overflow buffer[64].
- Remediation: Replace strcpy with strncpy(buffer, input, sizeof(buffer)-1).

**2. Null Pointer Dereference (CWE-476)**
- CWE: CWE-476
- Location: vuln_sample.cpp:55
- Severity: Medium (CVSS 5.9)
- Description: malloc result may be null before dereference.
- Remediation: Add NULL check after malloc: if (!ctx) return nullptr;

**3. Memory Leak (CWE-401)**
- CWE: CWE-401
- Location: vuln_sample.cpp:76
- Severity: Medium (CVSS 6.5)
- Description: Early return path may leak secret buffer.
- Remediation: Add free(secret_buf) before early return.

### eval/testcases/CWE200_info_leak.cpp

**1. Buffer Overflow (CWE-120)**
- CWE: CWE-120
- Location: vuln_sample.cpp:39
- Severity: High (CVSS 8.1)
- Description: Unbounded strcpy in admin branch may overflow buffer[64].
- Remediation: Replace strcpy with strncpy(buffer, input, sizeof(buffer)-1).

**2. Null Pointer Dereference (CWE-476)**
- CWE: CWE-476
- Location: vuln_sample.cpp:55
- Severity: Medium (CVSS 5.9)
- Description: malloc result may be null before dereference.
- Remediation: Add NULL check after malloc: if (!ctx) return nullptr;

**3. Memory Leak (CWE-401)**
- CWE: CWE-401
- Location: vuln_sample.cpp:76
- Severity: Medium (CVSS 6.5)
- Description: Early return path may leak secret buffer.
- Remediation: Add free(secret_buf) before early return.

### eval/testcases/CWE401_memory_leak.cpp

**1. Buffer Overflow (CWE-120)**
- CWE: CWE-120
- Location: vuln_sample.cpp:39
- Severity: High (CVSS 8.1)
- Description: Unbounded strcpy in admin branch may overflow buffer[64].
- Remediation: Replace strcpy with strncpy(buffer, input, sizeof(buffer)-1).

**2. Null Pointer Dereference (CWE-476)**
- CWE: CWE-476
- Location: vuln_sample.cpp:55
- Severity: Medium (CVSS 5.9)
- Description: malloc result may be null before dereference.
- Remediation: Add NULL check after malloc: if (!ctx) return nullptr;

**3. Memory Leak (CWE-401)**
- CWE: CWE-401
- Location: vuln_sample.cpp:76
- Severity: Medium (CVSS 6.5)
- Description: Early return path may leak secret buffer.
- Remediation: Add free(secret_buf) before early return.

### eval/testcases/CWE415_double_free.cpp

**1. Buffer Overflow (CWE-120)**
- CWE: CWE-120
- Location: vuln_sample.cpp:39
- Severity: High (CVSS 8.1)
- Description: Unbounded strcpy in admin branch may overflow buffer[64].
- Remediation: Replace strcpy with strncpy(buffer, input, sizeof(buffer)-1).

**2. Null Pointer Dereference (CWE-476)**
- CWE: CWE-476
- Location: vuln_sample.cpp:55
- Severity: Medium (CVSS 5.9)
- Description: malloc result may be null before dereference.
- Remediation: Add NULL check after malloc: if (!ctx) return nullptr;

**3. Memory Leak (CWE-401)**
- CWE: CWE-401
- Location: vuln_sample.cpp:76
- Severity: Medium (CVSS 6.5)
- Description: Early return path may leak secret buffer.
- Remediation: Add free(secret_buf) before early return.

### eval/testcases/CWE416_use_after_free.cpp

**1. Buffer Overflow (CWE-120)**
- CWE: CWE-120
- Location: vuln_sample.cpp:39
- Severity: High (CVSS 8.1)
- Description: Unbounded strcpy in admin branch may overflow buffer[64].
- Remediation: Replace strcpy with strncpy(buffer, input, sizeof(buffer)-1).

**2. Null Pointer Dereference (CWE-476)**
- CWE: CWE-476
- Location: vuln_sample.cpp:55
- Severity: Medium (CVSS 5.9)
- Description: malloc result may be null before dereference.
- Remediation: Add NULL check after malloc: if (!ctx) return nullptr;

**3. Memory Leak (CWE-401)**
- CWE: CWE-401
- Location: vuln_sample.cpp:76
- Severity: Medium (CVSS 6.5)
- Description: Early return path may leak secret buffer.
- Remediation: Add free(secret_buf) before early return.

### eval/testcases/CWE476_null_deref.cpp

**1. Buffer Overflow (CWE-120)**
- CWE: CWE-120
- Location: vuln_sample.cpp:39
- Severity: High (CVSS 8.1)
- Description: Unbounded strcpy in admin branch may overflow buffer[64].
- Remediation: Replace strcpy with strncpy(buffer, input, sizeof(buffer)-1).

**2. Null Pointer Dereference (CWE-476)**
- CWE: CWE-476
- Location: vuln_sample.cpp:55
- Severity: Medium (CVSS 5.9)
- Description: malloc result may be null before dereference.
- Remediation: Add NULL check after malloc: if (!ctx) return nullptr;

**3. Memory Leak (CWE-401)**
- CWE: CWE-401
- Location: vuln_sample.cpp:76
- Severity: Medium (CVSS 6.5)
- Description: Early return path may leak secret buffer.
- Remediation: Add free(secret_buf) before early return.

### eval/testcases/CWE787_oob_write.cpp

**1. Buffer Overflow (CWE-120)**
- CWE: CWE-120
- Location: vuln_sample.cpp:39
- Severity: High (CVSS 8.1)
- Description: Unbounded strcpy in admin branch may overflow buffer[64].
- Remediation: Replace strcpy with strncpy(buffer, input, sizeof(buffer)-1).

**2. Null Pointer Dereference (CWE-476)**
- CWE: CWE-476
- Location: vuln_sample.cpp:55
- Severity: Medium (CVSS 5.9)
- Description: malloc result may be null before dereference.
- Remediation: Add NULL check after malloc: if (!ctx) return nullptr;

**3. Memory Leak (CWE-401)**
- CWE: CWE-401
- Location: vuln_sample.cpp:76
- Severity: Medium (CVSS 6.5)
- Description: Early return path may leak secret buffer.
- Remediation: Add free(secret_buf) before early return.

### eval/testcases/safe_bounds_check.cpp

**1. Buffer Overflow (CWE-120)**
- CWE: CWE-120
- Location: vuln_sample.cpp:39
- Severity: High (CVSS 8.1)
- Description: Unbounded strcpy in admin branch may overflow buffer[64].
- Remediation: Replace strcpy with strncpy(buffer, input, sizeof(buffer)-1).

**2. Null Pointer Dereference (CWE-476)**
- CWE: CWE-476
- Location: vuln_sample.cpp:55
- Severity: Medium (CVSS 5.9)
- Description: malloc result may be null before dereference.
- Remediation: Add NULL check after malloc: if (!ctx) return nullptr;

**3. Memory Leak (CWE-401)**
- CWE: CWE-401
- Location: vuln_sample.cpp:76
- Severity: Medium (CVSS 6.5)
- Description: Early return path may leak secret buffer.
- Remediation: Add free(secret_buf) before early return.

### eval/testcases/safe_raii.cpp

**1. Buffer Overflow (CWE-120)**
- CWE: CWE-120
- Location: vuln_sample.cpp:39
- Severity: High (CVSS 8.1)
- Description: Unbounded strcpy in admin branch may overflow buffer[64].
- Remediation: Replace strcpy with strncpy(buffer, input, sizeof(buffer)-1).

**2. Null Pointer Dereference (CWE-476)**
- CWE: CWE-476
- Location: vuln_sample.cpp:55
- Severity: Medium (CVSS 5.9)
- Description: malloc result may be null before dereference.
- Remediation: Add NULL check after malloc: if (!ctx) return nullptr;

**3. Memory Leak (CWE-401)**
- CWE: CWE-401
- Location: vuln_sample.cpp:76
- Severity: Medium (CVSS 6.5)
- Description: Early return path may leak secret buffer.
- Remediation: Add free(secret_buf) before early return.
