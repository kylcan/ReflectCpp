from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    files: dict[str, str]  # repo-relative path -> content
    expected_cwes: list[str]


TEMPLATE_HEADER = """/*
Synthetic repo-level security sample generated for SentinelAgent eval.
Case: {case_id}
*/
"""


def _stable_id(prefix: str, files: dict[str, str]) -> str:
    """Stable case id derived from repo contents (excluding README).

    We explicitly exclude README.md to avoid circular dependencies where the
    README contains the case id.
    """
    material = {
        k: files[k]
        for k in sorted(files)
        if k != "README.md"
    }
    blob = json.dumps(material, sort_keys=True, ensure_ascii=False).encode("utf-8")
    h = hashlib.sha256(prefix.encode("utf-8") + b"\n" + blob).hexdigest()[:10]
    return f"{prefix}-{h}"


def _common_repo_scaffold() -> dict[str, str]:
    """Repo-like scaffolding that should NOT introduce extra vulnerability patterns."""
    cmake = """cmake_minimum_required(VERSION 3.10)
project(SentinelEval C)

set(CMAKE_C_STANDARD 99)
include_directories(include)

add_library(util STATIC src/util.c)
add_executable(app src/main.c)
target_link_libraries(app util)
"""

    makefile = """CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Iinclude

all: app

app: src/main.c src/util.c include/util.h
	$(CC) $(CFLAGS) -o $@ src/main.c src/util.c

clean:
	rm -f app
"""

    return {
        "CMakeLists.txt": cmake,
        "Makefile": makefile,
        "LICENSE": "Synthetic dataset content for evaluation only.\n",
        "docs/SECURITY.md": "# Security\n\nThis is a synthetic project used for eval.\n",
        "third_party/README.md": "Third-party dependencies would live here in a real repo.\n",
        "include/config.h": "#pragma once\n#define APP_NAME \"sentinel-eval\"\n",
        "src/version.c": "const char* app_version(void) { return \"0.1.0\"; }\n",
    }


def _repo_files(util_h: str, util_c: str, main_c: str, extra_files: dict[str, str] | None = None) -> dict[str, str]:
    files: dict[str, str] = {
        "include/util.h": util_h,
        "src/util.c": util_c,
        "src/main.c": main_c,
    }
    files.update(_common_repo_scaffold())
    if extra_files:
        files.update(extra_files)
    return files


def _with_readme(case_id: str, files: dict[str, str]) -> dict[str, str]:
    out = dict(files)
    out["README.md"] = TEMPLATE_HEADER.format(case_id=case_id) + "\n\nThis is a synthetic repo-level eval case.\n"
    return out


def _case_strcpy(i: int) -> CaseSpec:
    util_h = """#pragma once
void do_copy(const char* input);
"""
    util_c = """#include <stdio.h>
#include <string.h>
#include "util.h"

void do_copy(const char* input) {
    char buf[32];
    strcpy(buf, input);
    puts(buf);
}
"""
    main_c = """#include <stdio.h>
#include "util.h"

int main(int argc, char** argv) {
    const char* input = (argc > 1) ? argv[1] : "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    do_copy(input);
    return 0;
}
"""
    files = _repo_files(util_h, util_c, main_c)
    case_id = _stable_id(f"BOF{i:02d}", files)
    return CaseSpec(case_id, _with_readme(case_id, files), ["CWE-120"])


def _case_system(i: int) -> CaseSpec:
    util_h = """#pragma once
void run_cmd(const char* cmd);
"""
    util_c = """#include <stdlib.h>
#include "util.h"

void run_cmd(const char* cmd) {
    system(cmd);
}
"""
    main_c = """#include "util.h"

int main(int argc, char** argv) {
    const char* cmd = (argc > 1) ? argv[1] : "echo hello";
    run_cmd(cmd);
    return 0;
}
"""
    files = _repo_files(util_h, util_c, main_c)
    case_id = _stable_id(f"CMD{i:02d}", files)
    return CaseSpec(case_id, _with_readme(case_id, files), ["CWE-78"])


def _case_malloc_no_check(i: int) -> CaseSpec:
    util_h = """#pragma once
char* alloc_buf(void);
"""
    util_c = """#include <stdlib.h>
#include "util.h"

char* alloc_buf(void) {
    char* p = (char*)malloc(128);
    // missing NULL check before use
    p[0] = 'x';
    return p;
}
"""
    main_c = """#include <stdio.h>
#include "util.h"

int main(void) {
    char* p = alloc_buf();
    puts(p);
    return 0;
}
"""
    files = _repo_files(util_h, util_c, main_c)
    case_id = _stable_id(f"MNC{i:02d}", files)
    return CaseSpec(case_id, _with_readme(case_id, files), ["CWE-476"])


def _case_memcpy(i: int) -> CaseSpec:
    util_h = """#pragma once
void do_memcpy(void);
"""
    util_c = """#include <string.h>
#include "util.h"

void do_memcpy(void) {
    char dst[16];
    char src[64];
    memset(src, 'A', sizeof(src));
    memcpy(dst, src, sizeof(src));
}
"""
    main_c = """#include "util.h"

int main(void) {
    do_memcpy();
    return 0;
}
"""
    files = _repo_files(util_h, util_c, main_c)
    case_id = _stable_id(f"MCP{i:02d}", files)
    return CaseSpec(case_id, _with_readme(case_id, files), ["CWE-120"])


def _case_rand(i: int) -> CaseSpec:
    util_h = """#pragma once
int weak_token(void);
"""
    util_c = """#include <stdlib.h>
#include "util.h"

int weak_token(void) {
    return rand();
}
"""
    main_c = """#include <stdio.h>
#include "util.h"

int main(void) {
    printf(\"%d\\n\", weak_token());
    return 0;
}
"""
    files = _repo_files(util_h, util_c, main_c)
    case_id = _stable_id(f"RNG{i:02d}", files)
    return CaseSpec(case_id, _with_readme(case_id, files), ["CWE-338"])


def _case_safe_control(i: int) -> CaseSpec:
    util_h = """#pragma once
void safe_copy(const char* input);
"""
    util_c = """#include <stdio.h>
#include <string.h>
#include "util.h"

void safe_copy(const char* input) {
    char buf[32];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    puts(buf);
}
"""
    main_c = """#include "util.h"

int main(int argc, char** argv) {
    const char* input = (argc > 1) ? argv[1] : "hello";
    safe_copy(input);
    return 0;
}
"""
    files = _repo_files(util_h, util_c, main_c)
    case_id = _stable_id(f"SAFE{i:02d}", files)
    return CaseSpec(case_id, _with_readme(case_id, files), [])


def build_cases(n_each: int = 10) -> list[CaseSpec]:
    cases: list[CaseSpec] = []

    for i in range(n_each):
        cases.append(_case_strcpy(i))
    for i in range(n_each):
        cases.append(_case_system(i))
    for i in range(n_each):
        cases.append(_case_malloc_no_check(i))
    for i in range(n_each):
        cases.append(_case_memcpy(i))
    for i in range(n_each):
        cases.append(_case_rand(i))

    # Add at least 10 safe controls
    for i in range(max(10, n_each)):
        cases.append(_case_safe_control(i))

    return cases


def write_dataset(dataset_dir: Path, cases: Iterable[CaseSpec]) -> Path:
    dataset_dir.mkdir(parents=True, exist_ok=True)
    repos_dir = dataset_dir / "repos"
    if repos_dir.exists():
        shutil.rmtree(repos_dir)
    repos_dir.mkdir(parents=True, exist_ok=True)

    legacy_cases_dir = dataset_dir / "cases"
    if legacy_cases_dir.exists():
        shutil.rmtree(legacy_cases_dir)

    index_path = dataset_dir / "cases.jsonl"

    with index_path.open("w", encoding="utf-8") as f:
        for case in cases:
            repo_dir = repos_dir / case.case_id
            repo_dir.mkdir(parents=True, exist_ok=True)
            for rel_path, content in case.files.items():
                out_path = repo_dir / rel_path
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(content, encoding="utf-8")
            record = {
                "id": case.case_id,
                "repo_path": str(Path("eval") / "dataset" / "repos" / case.case_id),
                "entry": "src/main.c",
                "expected_cwes": case.expected_cwes,
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return index_path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    dataset_dir = root / "eval" / "dataset"
    cases = build_cases(n_each=10)  # 10*5 + 10 safe = 60
    index_path = write_dataset(dataset_dir, cases)
    print(f"Wrote dataset index: {index_path}")
    print(f"Total cases: {len(list(cases))}")


if __name__ == "__main__":
    main()
