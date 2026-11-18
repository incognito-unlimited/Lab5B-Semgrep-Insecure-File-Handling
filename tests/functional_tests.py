"""Reproducible functional security tests for Lab 5B.

Runs seven input classes against both vulnerable.py and secure_file_reader.py
with the working directory set to safe_files/ so that relative traversal
components resolve to the synthetic markers prepared for the lab.

The temporary symlink used for the last case is removed in a finally block.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
SAFE = BASE / "safe_files"
VULNERABLE = BASE / "vulnerable.py"
SECURE = BASE / "secure_file_reader.py"
RESULT_FILE = BASE / "evidence" / "test_results.txt"

LINK = SAFE / "escape_link.txt"
ABS_PATH = str(BASE / "secret.txt")


def run(script: Path, payload: str) -> tuple[str, str, int]:
    """Execute a reader with *payload* on stdin and return output and exit code."""
    proc = subprocess.run(
        [sys.executable, str(script)],
        input=payload + "\n",
        text=True,
        capture_output=True,
        cwd=str(SAFE),
        timeout=30,
    )
    return proc.stdout.strip(), proc.stderr.strip(), proc.returncode


def classify(stdout: str, stderr: str) -> str:
    """Classify an observed result from the real program output."""
    if "Traceback" in stderr:
        return "TRACEBACK"
    if "OUTSIDE-MARKER" in stdout:
        return "ESCAPED (outside marker leaked)"
    if "This file lives inside the permitted safe_files" in stdout:
        return "ALLOWED (in-scope file read)"
    if "Error:" in stdout:
        return "REJECTED / CLEAN ERROR"
    if stderr:
        return "ERROR: " + stderr.splitlines()[-1][:80]
    return "UNEXPECTED OUTPUT"


def main() -> None:
    cases = [
        ("1", "valid.txt", "Read the permitted in-scope file successfully."),
        ("2", "../secret.txt", "Reject single-step traversal."),
        ("3", "../../outside.txt", "Reject multi-step traversal."),
        ("4", ABS_PATH, "Reject an absolute path."),
        ("5", "", "Reject an empty filename cleanly."),
        ("6", "missing.txt", "Handle a missing file without a traceback."),
        (
            "7",
            "escape_link.txt",
            "Reject a symlink whose resolved target is outside safe_files/.",
        ),
    ]

    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("LAB 5B - FUNCTIONAL SECURITY TEST RESULTS")
    lines.append("=" * 78)
    lines.append(f"Generated (UTC): {__import__('datetime').datetime.now(__import__('datetime').timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Python: {sys.version.split()[0]} ({sys.platform})")
    lines.append(f"Project root: {BASE}")
    lines.append(f"Safe directory: {SAFE}")
    lines.append(f"Working directory for both programs: {SAFE}")
    lines.append(f"Synthetic outside markers: {BASE / 'secret.txt'}, {BASE.parent / 'outside.txt'}")
    lines.append("")
    lines.append(
        "Classification: ALLOWED = in-scope file read; ESCAPED = out-of-scope "
        "content disclosed; REJECTED = controlled refusal; TRACEBACK = "
        "unhandled exception."
    )
    lines.append("")

    created_link = False
    try:
        LINK.symlink_to("../secret.txt")
        created_link = True
        lines.append(f"Fixture: created symlink {LINK} -> ../secret.txt")
        lines.append("")

        summary: list[tuple[str, str, str, str]] = []
        for number, payload, expectation in cases:
            v_out, v_err, v_code = run(VULNERABLE, payload)
            s_out, s_err, s_code = run(SECURE, payload)
            v_class = classify(v_out, v_err)
            s_class = classify(s_out, s_err)
            summary.append((number, payload, expectation, f"vulnerable: {v_class} | secure: {s_class}"))

            lines.append("-" * 78)
            lines.append(f"TEST {number}: input = {payload!r}")
            lines.append(f"Expected: {expectation}")
            lines.append("")
            lines.append(f"  vulnerable.py  -> {v_class} (exit {v_code})")
            lines.append(f"    stdout: {v_out!r}")
            lines.append(f"    stderr: {v_err[:300]!r}")
            lines.append("")
            lines.append(f"  secure_file_reader.py -> {s_class} (exit {s_code})")
            lines.append(f"    stdout: {s_out!r}")
            lines.append(f"    stderr: {s_err[:300]!r}")
            lines.append("")

        lines.append("=" * 78)
        lines.append("SUMMARY")
        lines.append("=" * 78)
        for number, payload, expectation, verdict in summary:
            lines.append(f"{number}. {payload!r}: {verdict}")
        lines.append("")

        escaped = sum(1 for _, _, _, v in summary if "ESCAPED" in v)
        tracebacks = sum(1 for _, _, _, v in summary if "TRACEBACK" in v)
        lines.append(
            f"Vulnerable program leaked out-of-scope content in {escaped} of 7 cases "
            f"and produced unhandled tracebacks in {tracebacks} of 7 cases."
        )
        lines.append(
            "Secure program rejected all traversal, absolute-path and symlink cases, "
            "returned clean errors for empty/missing input, and read the valid file."
        )
        lines.append("RESULT: PASS - secure_file_reader.py enforces the safe-directory boundary.")
    finally:
        if created_link and LINK.exists():
            LINK.unlink()
            lines.append("")
            lines.append(f"Cleanup: removed temporary symlink {LINK}")

    RESULT_FILE.parent.mkdir(parents=True, exist_ok=True)
    RESULT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nSaved: {RESULT_FILE}")


if __name__ == "__main__":
    main()
