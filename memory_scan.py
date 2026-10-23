#!/usr/bin/env python3
"""Offline scanner for poisoning patterns in durable agent memory.

Agents keep persistent memory: markdown notes, JSONL stores, instruction
files. Content that lands there is trusted across sessions, which makes it a
target: text that once appeared in a web page or email can end up saved as a
standing instruction the agent follows forever. This tool audits a directory
of memory files for that pattern. It never runs an agent, never calls a
model, and cannot prove a memory store is safe - it is a heuristic scanner
for human review, not a verdict.

Severity is conjunction-based: a standing preference ("always",
"remember to") is not an attack by itself - users legitimately write those.
It is reported as info so a human can confirm it came from the user. It is
escalated only when combined with a risk signal (exfiltration, concealment,
authority claim, override, encoded payload) in the same entry.
"""

import argparse
import json
import os
import re
import sys

SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}
TEXT_EXTENSIONS = {".md", ".txt", ".markdown", ".jsonl", ".json", ".yaml", ".yml"}

PATTERNS = {
    "durable-imperative": (
        r"\b(always|from now on|remember to|never forget|going forward|in the future you (must|should|will))\b",
        "standing instruction persisted in memory"),
    "exfiltration": (
        r"(https?://\S+|[\w.+-]+@[\w-]+\.[\w.]+).*?(send|post|upload|forward|exfiltrat|transmit|report back)|"
        r"(send|post|upload|forward|exfiltrat|transmit).*?(https?://\S+|[\w.+-]+@[\w-]+\.[\w.]+)|"
        r"(curl|wget)\b[^|]*\|\s*(sh|bash|zsh|python)",
        "asks for data to leave the local store"),
    "concealment": (
        r"\b(don't|do not|never)\s+(tell|inform|mention|show|disclose)\b[^.\n]*(user|human|anyone)|"
        r"\bhide\b[^.\n]*\b(this|it|these|the fact)\b|\bkeep\b[^.\n]*\bsecret\b",
        "asks for its presence or actions to be hidden"),
    "authority-claim": (
        r"\b(the user (has )?(approved|authorized|confirmed)|admin(istrator)? mode|developer message|"
        r"you are now|act as (a|an|the) (admin|root|system))\b",
        "claims approval or authority that stored text cannot grant itself"),
    "override-instruction": (
        r"\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|your|earlier)\s+"
        r"(instructions|rules|guidelines|training)|\bnew (system )?instructions?:",
        "tries to replace the agent's standing rules"),
    "encoded-payload": (
        r"\b[A-Za-z0-9+/]{120,}={0,2}\b",
        "long encoded blob hides content from review"),
}
RISK_CODES = {"exfiltration", "concealment", "authority-claim", "override-instruction", "encoded-payload"}
BASE_SEVERITY = {
    "durable-imperative": "info",
    "exfiltration": "error",
    "concealment": "error",
    "authority-claim": "warning",
    "override-instruction": "error",
    "encoded-payload": "warning",
}
COMPILED = {code: re.compile(pat, re.IGNORECASE) for code, (pat, _label) in PATTERNS.items()}


def finding(code, severity, path, line_no, detail):
    return {"code": code, "severity": severity, "source": "%s:%d" % (path, line_no),
            "detail": detail}


def iter_entries(path):
    """Yield (line_no, text) entries. JSONL files yield one entry per record's
    text field; other files yield one entry per line."""
    with open(path, errors="replace") as f:
        raw = f.read()
    if path.endswith(".jsonl"):
        for i, line in enumerate(raw.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                yield i, line
                continue
            if isinstance(rec, dict):
                text = rec.get("text") or rec.get("content") or rec.get("body") or ""
                yield i, str(text) if text else line
            else:
                yield i, line
    else:
        for i, line in enumerate(raw.splitlines(), 1):
            if line.strip():
                yield i, line


def scan_file(path):
    findings = []
    for line_no, text in iter_entries(path):
        hits = []
        for code, regex in COMPILED.items():
            if regex.search(text):
                hits.append(code)
        if not hits:
            continue
        has_durable = "durable-imperative" in hits
        risks = [h for h in hits if h in RISK_CODES]
        for code in hits:
            severity = BASE_SEVERITY[code]
            detail = PATTERNS[code][1]
            if code == "durable-imperative" and risks:
                severity = "warning"
                detail += "; combined with %s in the same entry - verify this came from the user" % ", ".join(sorted(risks))
            elif code in risks and has_durable:
                severity = "error"
                detail += "; written as a standing instruction, so it persists across sessions"
            findings.append(finding(code, severity, path, line_no, detail))
    return findings


def scan(path):
    findings = []
    files = []
    if os.path.isfile(path):
        files.append(path)
    elif os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            for name in sorted(names):
                if os.path.splitext(name)[1].lower() in TEXT_EXTENSIONS:
                    files.append(os.path.join(root, name))
    else:
        return [finding("no-input", "error", path, 0, "path not found")]
    if not files:
        return [finding("no-input", "error", path, 0, "no scannable text files found")]
    for f in files:
        findings.extend(scan_file(f))
    return findings


def filter_severity(findings, min_severity):
    floor = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER[f["severity"]] >= floor]


def format_text(findings):
    return "\n".join("%-7s %-20s %-24s %s" % (
        f["severity"].upper(), f["code"], f["source"], f["detail"])
        for f in findings)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit durable agent memory files for poisoning patterns.")
    parser.add_argument("path", help="memory file or directory to scan")
    parser.add_argument("--min-severity", choices=["info", "warning", "error"], default="info")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args(argv)

    findings = filter_severity(scan(args.path), args.min_severity)
    if args.format == "json":
        print(json.dumps(findings, indent=2))
    elif findings:
        print(format_text(findings))
    else:
        print("no findings")
    return 1 if any(f["severity"] == "error" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
