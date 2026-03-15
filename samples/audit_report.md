# 🔒 Repository Security Audit Report

**Root:** `samples`  
**Files scanned:** 1  
**Files with vulnerabilities:** 1  
**Total confirmed:** 3  
**Total rejected:** 0  
**Total time:** 0.7s

## Per-File Summary

| File | Confirmed | Rejected | Iterations | Time |
|------|-----------|----------|------------|------|
| `samples/vuln_sample.cpp` | 3 | 0 | 1 | 0.7s |

## Detailed Findings

### samples/vuln_sample.cpp

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
