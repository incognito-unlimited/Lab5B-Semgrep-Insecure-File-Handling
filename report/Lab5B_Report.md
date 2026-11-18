# LAB 5B — Semgrep Analysis and Remediation of Insecure File Handling

| Detail | Value |
|---|---|
| Name | Aditey Mehra |
| Roll Number | 2301730266 |
| University | K.R. Mangalam University |
| Programme | B.Tech CSE (AI & ML) |
| Section | D |
| Semester | 7 |
| Subject | Secure Coding and Vulnerabilities |
| Lab | 5B |
| GitHub Repository | https://github.com/incognito-unlimited/Lab5B-Semgrep-Insecure-File-Handling |

---

## 1. Aim

To write a small Python program that opens a user-provided filename without path validation, analyse the insecure file-handling pattern using Semgrep, remediate the path-traversal risk by restricting access to a safe directory, compare static-analysis findings before and after the fix, and publish the source, evidence and report to GitHub.

## 2. Objectives

1. Create a minimal Python program that directly opens a user-supplied path.
2. Run Semgrep to identify insecure file access or path traversal risks.
3. Interpret the finding and explain its security impact.
4. Modify the program to enforce a safe-directory boundary.
5. Run Semgrep again using the same ruleset and compare findings.
6. Capture actual outputs and publish the work to GitHub.

## 3. Introduction

A program that directly opens an untrusted filename may allow a user to select files outside the application's intended storage directory. Relative traversal components such as `../`, absolute paths and symlinks can all undermine assumptions about where a file is located. Python's `open()` accepts any path-like string the operating system will resolve, so a name that appears to be a simple filename can navigate out of the intended folder. If the file is opened for reading, the result is unauthorised information disclosure; with a write sink, the same primitive becomes arbitrary file modification.

Semgrep can identify suspicious code patterns before deployment, but rule coverage varies by ruleset. This experiment therefore records both the registry scan and a documented custom rule, then confirms the result with functional tests. No finding is claimed unless it was actually emitted by the scanner.

## 4. Vulnerable program

File: `vulnerable.py`

```python
filename = input("Enter filename: ")

with open(filename, "r", encoding="utf-8") as file:
    print(file.read())
```

The user-controlled `filename` flows directly into `open()`. There is no allowlist, canonicalisation or containment check. A harmless synthetic marker file, `secret.txt`, was placed at the project root, and a second marker `D:\Projects\outside.txt` was used for the multi-segment traversal test. No real sensitive file was accessed.

## 5. Semgrep findings — before fix

Environment and toolchain:

```
Semgrep version: 1.185.0 (OSS engine)
Platform: Ubuntu 26.04.1 LTS (Linux 6.18.58.1-microsoft-standard-WSL2)
Python: 3.14.4
Rulesets: p/python (151 rules) and rules/insecure_file_handling.yml
```

Commands executed:

```bash
semgrep --version
semgrep scan --config p/python vulnerable.py
semgrep scan --config p/python --json --output evidence/semgrep_registry_before.json vulnerable.py
semgrep scan --config rules/insecure_file_handling.yml vulnerable.py
semgrep scan --config rules/insecure_file_handling.yml --json --output evidence/semgrep_before.json vulnerable.py
```

The `p/python` registry ruleset reported **0 findings** (151 rules, 1 target). It does not model this `input() → direct open()` data flow. In accordance with the lab brief, a custom rule was created at `rules/insecure_file_handling.yml` and applied to both programs:

```yaml
pattern: |
  $FILENAME = input(...)
  ...
  with open($FILENAME, ...) as $FILE:
    ...
```

**Actual finding from the custom rule:**

| Field | Value |
|---|---|
| Rule ID | `rules.python-insecure-file-handling-unvalidated-filename` |
| Severity | `ERROR` (displayed as `Blocking` in the text output) |
| Confidence | `HIGH` (declared in the YAML; not emitted in JSON `extra` by Semgrep OSS) |
| File and lines | `vulnerable.py`, lines 1–4 |
| Vulnerable expression | `open(filename, "r", encoding="utf-8")` with `filename` from `input()` |

Matched source, preserved verbatim in `evidence/semgrep_before.txt`:

```
1┆ filename = input("Enter filename: ")
2┆
3┆ with open(filename, "r", encoding="utf-8") as file:
4┆     print(file.read())
```

Semgrep OSS reports `requires login` for the JSON `lines` and `fingerprint` fields; the real matched source is available in the text output.

## 6. Security impact

`../secret.txt` escapes `safe_files/` because the filesystem resolves `..` after the path is passed to `open()`. Repeated parent segments, absolute paths and symlinks achieve the same result. In this lab the disclosed content is a harmless marker, but in a real application the same flaw could expose credentials, source code or configuration. The vulnerable program also emits Python tracebacks containing absolute paths for error cases, giving an attacker useful reconnaissance information.

## 7. Secure implementation

File: `secure_file_reader.py` (key sections)

```python
SAFE_DIR = Path(__file__).resolve().parent / "safe_files"

def _validate_filename(filename: str) -> None:
    if not isinstance(filename, str) or not filename.strip():
        raise InvalidFilenameError("Filename must be a non-empty string")
    if len(filename) > MAX_FILENAME_LENGTH:
        raise InvalidFilenameError("Filename is too long")
    if "\x00" in filename:
        raise InvalidFilenameError("Filename contains a null byte")
    candidate = Path(filename)
    if candidate.is_absolute() or candidate.drive or filename.startswith(("/", "\\")):
        raise InvalidFilenameError("Absolute paths are not allowed")

def resolve_within_directory(filename: str, base_dir: Path = SAFE_DIR):
    _validate_filename(filename)
    safe_root = base_dir.resolve()
    candidate = (safe_root / filename).resolve()
    try:
        candidate.relative_to(safe_root)
    except ValueError:
        raise OutsideDirectoryError(
            "Access outside the permitted directory is not allowed"
        ) from None
    return safe_root, candidate
```

`read_user_file()` additionally checks that the candidate is a regular file, opens it with `O_NOFOLLOW | O_CLOEXEC`, and on Linux re-verifies the descriptor's real target through `/proc/self/fd/<fd>` before reading. `main()` catches the safe exception types and prints short generic errors. No string-prefix comparison is used.

**Residual risk:** a determined attacker with concurrent write access to the filesystem could still swap intermediate directory components between the containment check and the open (TOCTOU). Complete mitigation requires directory-descriptor-relative `openat()` operations throughout. The no-follow flag and descriptor re-verification reduce but do not fully eliminate this risk in a hostile shared filesystem.

## 8. Semgrep analysis — after fix

The same Semgrep version, rulesets and options were run against `secure_file_reader.py`:

```bash
semgrep scan --config p/python secure_file_reader.py
semgrep scan --config rules/insecure_file_handling.yml secure_file_reader.py
```

| Ruleset | Before | After | Severity | Finding removed |
|---|---:|---:|---|---|
| `p/python` (151 rules) | 0 | 0 | none | no finding existed |
| Custom rule | 1 | 0 | `ERROR` | `rules.python-insecure-file-handling-unvalidated-filename` |
| **Total** | **1** | **0** | — | **1 removed, 0 remaining** |

No scan errors occurred in either run. The custom rule's single `ERROR` finding at `vulnerable.py:1–4` was resolved.

## 9. Functional testing

Command: `python3 tests/functional_tests.py` (full real output in `evidence/test_results.txt`).

| # | Input | vulnerable.py | secure_file_reader.py | Expected |
|---|---|---|---|---|
| 1 | `valid.txt` | ALLOWED | ALLOWED | allow |
| 2 | `../secret.txt` | ESCAPED (marker leaked) | REJECTED | block |
| 3 | `../../outside.txt` | ESCAPED | REJECTED | block |
| 4 | absolute path to `secret.txt` | ESCAPED | REJECTED | block |
| 5 | empty filename | TRACEBACK (`FileNotFoundError`) | CLEAN ERROR | clean error |
| 6 | `missing.txt` | TRACEBACK | CLEAN ERROR | clean error |
| 7 | `escape_link.txt` → `../secret.txt` | ESCAPED | REJECTED | block |

Observations:

* The vulnerable program leaked out-of-scope content in 4 of 7 cases and raised unhandled tracebacks in 2 of 7 cases.
* The secure program rejected all four escape attempts: single traversal, multiple segments, absolute path and symlink.
* The secure program returned a clean, non-traceback result in 7 of 7 cases and still read `safe_files/valid.txt`.
* The temporary symlink was removed by the harness after the run.

## 10. Screenshots

All screenshots are genuine captures of real files and program output:

1. `evidence/screenshots/01_vulnerable_source.png`
2. `evidence/screenshots/02_semgrep_before.png`
3. `evidence/screenshots/03_secure_source.png`
4. `evidence/screenshots/04_semgrep_after.png`
5. `evidence/screenshots/05_valid_file_read.png`
6. `evidence/screenshots/06_rejected_traversal.png`
7. `evidence/screenshots/07_github_repository.png`

Screenshots 5 and 6 show verbatim console transcripts captured from actual program runs (`evidence/valid_read_console.txt` and `evidence/rejected_traversal_console.txt`).

## 11. GitHub URL

https://github.com/incognito-unlimited/Lab5B-Semgrep-Insecure-File-Handling

## 12. Result and conclusion

The vulnerable implementation demonstrably read files outside its permitted directory using harmless synthetic markers. The default registry ruleset produced no findings, so a narrowly scoped custom rule was documented and applied to both versions: 1 `ERROR` finding before remediation and 0 after, with identical Semgrep version, rulesets and options. The hardened implementation passed all seven functional cases: it preserved valid access, rejected every traversal, absolute-path and symlink attempt, and returned safe error messages without tracebacks. The experiment confirms that secure file handling depends on canonical resolution and containment verification rather than string-prefix checks, and that static analysis must be complemented by an accurately targeted rule and runtime testing when a generic ruleset misses the vulnerable data flow.
