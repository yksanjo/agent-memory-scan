# agent-memory-scan

Offline scanner for poisoning patterns in durable agent memory.

Agents keep persistent memory: markdown notes, JSONL stores, instruction files. Content that lands there is trusted across sessions, which makes it a target - text that once appeared in a web page or email can end up saved as a standing instruction the agent follows forever. Memory-poisoning attacks on coding and harness agents are a documented 2026 attack class. This tool audits a directory of memory files for those patterns and reports findings with file and line numbers. It never runs an agent, never calls a model, never touches the network.

## Severity is conjunction-based

A standing preference is not an attack. Users legitimately write "always use metric units" in their notes. So a durable-imperative pattern alone is reported as **info** - flagged for a human to confirm it came from the user, never as a verdict. It escalates only when combined with a risk signal in the same entry.

| Code | Alone | Combined with durable-imperative | Pattern family |
| --- | --- | --- | --- |
| `durable-imperative` | info | warning | "always", "from now on", "remember to", "never forget" |
| `exfiltration` | error | error | send/upload/forward paired with a URL or email, curl/wget piped to a shell |
| `concealment` | error | error | asks for its presence or actions to be hidden from the user |
| `override-instruction` | error | error | "ignore previous instructions", rule replacement |
| `authority-claim` | warning | error | claims user approval or admin identity that stored text cannot grant itself |
| `encoded-payload` | warning | error | long base64-looking blob hiding content from review |

"Combined" escalation reflects what makes memory poisoning dangerous: a risk signal written as a standing instruction persists across sessions.

## Usage

```bash
python3 memory_scan.py /path/to/memory-dir
python3 memory_scan.py notes.md --min-severity warning
python3 memory_scan.py memory.jsonl --format json
python3 demo.py
python3 -m unittest test_memory_scan
```

Scans `.md`, `.markdown`, `.txt`, `.jsonl`, `.json`, `.yaml`, `.yml` files. JSONL records are read entry by entry (`text`, `content`, or `body` fields); other files are scanned line by line. Exit code is 1 when any reported finding is an error, else 0.

## Honest limits

- **A clean scan does not prove a memory store is safe.** Regex heuristics miss paraphrased, translated, and encoded attacks, and produce false positives on security writing, quoted examples, and unusual prose. This tool supports human review; it does not replace it.
- Standing preferences are reported as info precisely because many are legitimate. An info finding is a prompt to verify provenance ("did the user actually write this?"), not an accusation.
- Matching is per-entry: a durable-imperative on one line and an exfiltration pattern on the next line are not combined, though an attacker can split them exactly that way.
- URL detection flags any send-to-URL phrasing, including legitimate backup or sync instructions a user wrote themselves. Provenance is the question, and only the user can answer it.
- It scans text as stored. It cannot tell how an entry got there, whether it ever influenced a model, or what an agent did with it.
- Demo fixtures are synthetic and invented.

## License

MIT
