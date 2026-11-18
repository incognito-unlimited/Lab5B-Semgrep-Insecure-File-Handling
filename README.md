# Lab 5B — Semgrep: Analysis and Remediation of Insecure File Handling

**Student:** Aditey Mehra (2301730266)  
**University:** K.R. Mangalam University  
**Programme:** B.Tech CSE (AI & ML) — Section D — Semester 7  
**Subject:** Secure Coding and Vulnerabilities  
**Repository:** https://github.com/incognito-unlimited/Lab5B-Semgrep-Insecure-File-Handling

---

## 1. Aim

To write a small Python program that opens a user-supplied filename directly, analyse the insecure file-handling pattern with Semgrep, remediate the path-traversal risk by restricting access to a fixed safe directory, rerun the identical scan, verify the fix functionally, and publish the source and evidence to GitHub.

## 2. Objectives

- Create a minimal program that directly opens a user-supplied path with `open()`.
- Run Semgrep with a Python ruleset and record the real findings (or the absence of them).
- Explain the rule ID, severity, source location and security impact.
- Document a custom Semgrep rule when the default ruleset misses the exact pattern.
- Restrict file access to a predefined safe directory using resolved-path containment.
- Rerun the same Semgrep version, rulesets and options and compare findings.
- Execute seven security tests against both implementations.
- Capture genuine screenshots, publish to GitHub and produce the report.

## 3. Project structure

```
Lab5B-Semgrep-Insecure-File-Handling/
├── vulnerable.py                      # intentionally vulnerable direct open()
├── secure_file_reader.py              # remediated, safe-directory reader
├── secret.txt                         # synthetic marker OUTSIDE safe_files/
├── safe_files/
│   └── valid.txt                      # legitimate file INSIDE the safe directory
├── rules/
│   └── insecure_file_handling.yml     # documented custom Semgrep rule
├── tests/
│   └── functional_tests.py            # reproducible 7-case test harness
├── evidence/
│   ├── semgrep_before.txt             # before: registry + custom rule (text)
│   ├── semgrep_before.json            # before: custom rule (machine-readable)
│   ├── semgrep_registry_before.json   # before: p/python JSON
│   ├── semgrep_after.txt              # after: registry + custom rule (text)
│   ├── semgrep_after.json             # after: custom rule JSON
│   ├── semgrep_registry_after.json    # after: p/python JSON
│   ├── semgrep_comparison.txt         # before/after comparison
│   ├── semgrep_tool_info.txt          # Semgrep version
│   ├── test_results.txt               # full functional-test output
│   ├── valid_read_console.txt         # verbatim transcript: valid read
│   ├── rejected_traversal_console.txt # verbatim transcript: rejections
│   └── screenshots/                   # 7 genuine screenshots
├── report/
│   └── Lab5B_Report.md
├── README.md
└── .gitignore
```

A second harmless marker, `D:\Projects\outside.txt`, is used by the `../../outside.txt` test case. It lives outside this repository.

## 4. Toolchain

Semgrep was installed in a WSL Ubuntu virtual environment:

```bash
python3 -m venv /home/aditey/semgrep-venv
/home/aditey/semgrep-venv/bin/pip install semgrep
/home/aditey/semgrep-venv/bin/semgrep --version
# 1.185.0
```

Environment: Ubuntu 26.04.1 LTS, Linux 6.18.58.1-microsoft-standard-WSL2, Python 3.14.4 (WSL) / 3.11.9 (Windows).

## 5. Vulnerable implementation

`vulnerable.py` accepts a filename from standard input and passes it straight to `open()`:

```python
filename = input("Enter filename: ")

with open(filename, "r", encoding="utf-8") as file:
    print(file.read())
```

There is no validation, canonicalisation or containment check. `../secret.txt` walks out of the intended directory, an absolute path bypasses any base directory entirely, and a symlink inside the working directory can point anywhere the process can read. Only synthetic marker files were used as escape targets.

## 6. Semgrep analysis — before remediation

Commands actually executed from the project root:

```bash
semgrep --version
semgrep scan --config p/python vulnerable.py
semgrep scan --config p/python --json --output evidence/semgrep_registry_before.json vulnerable.py
semgrep scan --config rules/insecure_file_handling.yml vulnerable.py
semgrep scan --config rules/insecure_file_handling.yml --json --output evidence/semgrep_before.json vulnerable.py
```

**Result:** the 151-rule `p/python` registry set reported **0 findings** — it does not model this `input() → direct open()` flow. As the lab brief directs, a documented custom rule was created and applied identically to both programs.

**Custom-rule finding (verbatim from `evidence/semgrep_before.txt`):**

| Field | Value |
|---|---|
| Rule ID | `rules.python-insecure-file-handling-unvalidated-filename` |
| Severity | `ERROR` (shown as `Blocking` in text output) |
| Confidence | `HIGH` (declared in the YAML; Semgrep OSS does not emit it in JSON `extra`) |
| File / lines | `vulnerable.py`, lines 1–4 |
| Message | User-controlled input from `input()` is passed directly to `open()` without path validation or a containment check. |

Matched source:

```
1┆ filename = input("Enter filename: ")
2┆
3┆ with open(filename, "r", encoding="utf-8") as file:
4┆     print(file.read())
```

Semgrep OSS returns `requires login` for the JSON `lines` and `fingerprint` fields; the genuine matched source is preserved in the text evidence.

**Security impact:** a user-controlled filename can disclose any file readable by the process — credentials, configuration or application source. The unhandled exceptions in error cases also leak absolute filesystem paths and stack traces.

## 7. Secure implementation

`secure_file_reader.py` applies defence in depth:

- `SAFE_DIR` is anchored to the script location: `Path(__file__).resolve().parent / "safe_files"`.
- Empty, overlong, null-byte-containing and absolute paths (POSIX, drive-letter, UNC) are rejected.
- `Path.resolve()` canonicalises both the safe root and the candidate, collapsing `..` and following symlinks.
- `candidate.relative_to(safe_root)` enforces containment — no string-prefix comparison.
- On POSIX, `os.open()` uses `O_NOFOLLOW | O_CLOEXEC`; on Linux `/proc/self/fd/<fd>` is re-resolved and re-checked to reduce TOCTOU risk.
- Missing files and permission errors are converted into short, generic messages with no paths or tracebacks.

Residual TOCTOU risk remains for adversarially concurrent filesystem modification (for example, an attacker swapping intermediate directory components between the containment check and the open). Full mitigation would require directory-descriptor-relative `openat()` operations throughout; the `O_NOFOLLOW` and descriptor re-verification steps here substantially reduce but do not entirely eliminate that risk on a filesystem shared with an active attacker.

## 8. Semgrep analysis — after remediation

The exact same version, rulesets and options were rerun against `secure_file_reader.py`:

```bash
semgrep scan --config p/python secure_file_reader.py
semgrep scan --config rules/insecure_file_handling.yml secure_file_reader.py
```

| Ruleset | Before | After |
|---|---:|---:|
| `p/python` (151 rules) | 0 | 0 |
| Custom rule | 1 (`ERROR`, `vulnerable.py:1–4`) | 0 |
| **Total** | **1** | **0** |

One finding removed, none remaining, no scan errors. The clean static result is corroborated by functional testing.

## 9. Functional testing

Run `python3 tests/functional_tests.py` (real output in `evidence/test_results.txt`). The harness sets the working directory to `safe_files/`, creates a temporary `escape_link.txt → ../secret.txt` symlink, runs all seven cases against both programs, records real stdout/stderr/exit codes and removes the symlink.

| # | Input | vulnerable.py | secure_file_reader.py |
|---|---|---|---|
| 1 | `valid.txt` | allowed | allowed |
| 2 | `../secret.txt` | **escaped** | rejected |
| 3 | `../../outside.txt` | **escaped** | rejected |
| 4 | absolute path to `secret.txt` | **escaped** | rejected |
| 5 | empty filename | traceback | clean error |
| 6 | `missing.txt` | traceback | clean error |
| 7 | `escape_link.txt` (symlink) | **escaped** | rejected |

The vulnerable program leaked out-of-scope content in 4/7 cases and produced unhandled tracebacks in 2/7. The secure program rejected all four escape attempts and returned clean, non-traceback results in 7/7 cases while still reading the valid file.

## 10. Evidence and screenshots

- `evidence/semgrep_before.txt`, `evidence/semgrep_after.txt` — complete text scans (both rulesets).
- `evidence/semgrep_before.json`, `evidence/semgrep_after.json` — custom-rule JSON.
- `evidence/semgrep_registry_before.json`, `evidence/semgrep_registry_after.json` — registry JSON.
- `evidence/semgrep_comparison.txt` — generated comparison and finding detail.
- `evidence/test_results.txt` — full functional-test transcript.
- `evidence/valid_read_console.txt`, `evidence/rejected_traversal_console.txt` — verbatim console transcripts.

Genuine screenshots in `evidence/screenshots/`:

1. `01_vulnerable_source.png` — vulnerable source in VS Code.
2. `02_semgrep_before.png` — 1 `ERROR` finding with rule ID and matched source.
3. `03_secure_source.png` — remediated source.
4. `04_semgrep_after.png` — 0 findings.
5. `05_valid_file_read.png` — real console transcript for the valid filename.
6. `06_rejected_traversal.png` — real console transcript for all rejected inputs.
7. `07_github_repository.png` — published GitHub repository.

## 11. Result and conclusion

Direct use of a user-controlled filename in `open()` was reproduced with harmless synthetic markers. The default `p/python` ruleset produced no findings, so a narrowly scoped custom rule was documented and applied to both versions: 1 `ERROR` finding before remediation and 0 after, with identical version, rulesets and options. The remediated reader combines input validation, absolute-path rejection, canonical resolution, resolved-path containment, symlink handling and safe error handling, and passed all seven functional cases without leaking an out-of-scope file or exposing a traceback. Effective file-handling security requires canonical containment checks plus runtime testing; static analysis must be supported by an appropriately targeted rule when a generic ruleset misses the vulnerable data flow.

---

**GitHub URL:** https://github.com/incognito-unlimited/Lab5B-Semgrep-Insecure-File-Handling
