"""
detector.py — Hardware Trojan Heuristic Detector
LLM4Security Hardware Trojan Lab — Task 5

Approach: Combination scoring rather than single-pattern matching.
A single pattern (e.g., a counter, a magic constant) is normal RTL.
Only combinations of suspicious patterns together warrant flagging.

Scoring threshold: >= 3 signals → SUSPICIOUS

Heuristics cover T1 (counter/value-based), T2 (FSM/covert-channel),
and T3 (DoS/sequence-based) trojans.

Folders scanned by default:
  trojan_outputs, trojaned_outputs, demo_designs, batch_trojan_designs
"""

import re
import csv
import sys
from pathlib import Path
from datetime import datetime


# ---------------------------------------------------------------------------
# Heuristic patterns
# Each entry: (key, compiled_regex, description, points)
# ---------------------------------------------------------------------------

HEURISTICS = [

    # ------------------------------------------------------------------
    # T1 — Counter / value-based triggers
    # ------------------------------------------------------------------
    (
        "multi_condition_trigger",
        re.compile(r'==.*&&.*==.*&&', re.MULTILINE),
        "Three or more simultaneous equality checks — rare in normal logic, "
        "very common in trojan trigger conditions",
        2,
    ),
    (
        "two_condition_trigger",
        re.compile(r'==.*&&.*==', re.MULTILINE),
        "Two simultaneous equality checks joined by && — weaker trigger signal "
        "but still suspicious when combined with other patterns",
        1,
    ),
    (
        "counter_increments_conditionally",
        re.compile(
            # Matches < and <= comparisons as well as == since some trojans
            # gate the counter on `if (counter < threshold)`
            r'if\s*\(.*[=<>!].*\).*\n.*<=.*\+\s*1',
            re.MULTILINE,
        ),
        "Register increment inside a conditional — event counter used to delay "
        "trigger activation; catches < and <= conditions too",
        1,
    ),
    (
        "magic_constant_hex",
        re.compile(r"==\s*\d+'h[0-9A-Fa-f]{2,}", re.MULTILINE),
        "Comparison against a hexadecimal literal — suspicious in combination "
        "with counters or activation registers",
        1,
    ),
    (
        "magic_constant_binary",
        re.compile(r"==\s*\d+'b[01]{3,}", re.MULTILINE),
        "Comparison against a multi-bit binary literal (3+ bits) — T2/T3 trojans "
        "use binary patterns for shift register or sequence matching",
        1,
    ),
    (
        "counter_threshold_compare",
        re.compile(r"==\s*\d+'d\d+\b", re.MULTILINE),
        "Comparison against a decimal literal threshold — counters that trip "
        "after N cycles are a classic time-delayed trigger",
        1,
    ),
    (
        "activation_register",
        re.compile(
            r'\breg\b.*\b(active|flag|armed|enable|trig|dos)\b|'
            r'\b(active|flag|armed|enable|trig|dos)\b.*\breg\b',
            re.IGNORECASE | re.MULTILINE,
        ),
        "Register with an activation-style name (active, flag, armed, enable, "
        "trig, dos) — a trojan latches its armed state in a dedicated register",
        1,
    ),
    (
        "functional_substitution",
        re.compile(
            # Condition can be a complex expression, not just a single identifier.
            # Relaxed to not require an assignment after else (could be a case stmt).
            # Also handles comment lines between the if body and else.
            r'if\s*\([^)]+\)\s*\n\s*\w+\s*=(?!=).*\n\s*(//[^\n]*)?\s*else',
            re.MULTILINE,
        ),
        "Conditional override of combinational output — normal result replaced "
        "under trigger condition; handles complex conditions and inline comments",
        2,
    ),
    (
        "bit_flip_payload",
        re.compile(r'<=\s*~\w+(\[\d+\]|\[[\w:]+\])?', re.MULTILINE),
        "Output assigned the bitwise complement of a register — classic T1 "
        "payload that flips specific bits to corrupt transmitted data",
        2,
    ),
    (
        "reset_clears_multiple_regs",
        re.compile(
            r'if\s*\(.*rst.*\).*\n.*<=\s*[0-9]+\'b0.*\n.*<=\s*[0-9]+\'b0',
            re.MULTILINE,
        ),
        "Reset clears multiple registers to zero — trojan state elements must "
        "be invisible after reset to avoid detection",
        1,
    ),

    # ------------------------------------------------------------------
    # T2 — FSM / covert-channel trojans
    # ------------------------------------------------------------------
    (
        "shift_register_trigger",
        re.compile(r'<=\s*\{.*\[.*:.*\]\s*,.*\[.*\]\s*\}', re.MULTILINE),
        "Shift register concatenation — used in T2 trojans to accumulate a "
        "bit sequence over time for trigger detection",
        2,
    ),
    (
        "covert_output_port",
        re.compile(
            r'output\s+reg\s+\w*(covert|leak|out|hidden|side)\w*',
            re.IGNORECASE | re.MULTILINE,
        ),
        "Output port with a covert/leak-style name — T2 trojans exfiltrate "
        "data through an extra output pin not in the original design",
        2,
    ),
    (
        "serial_data_leak",
        re.compile(
            r'<=\s*\w+\s*\[\s*\w+_state\s*\]|'
            r'<=\s*\w+\s*\[\s*leak_\w+\s*\]|'
            r'<=\s*\w+\s*\[\s*\w+_count\s*\]',
            re.MULTILINE,
        ),
        "Output assigned from a state-indexed register — serial bit-by-bit "
        "data exfiltration pattern used in T2 payloads",
        2,
    ),

    # ------------------------------------------------------------------
    # T3 — DoS / sequence-based trojans
    # ------------------------------------------------------------------
    (
        "localparam_fsm",
        re.compile(
            # Three or more consecutive localparam declarations — hallmark of
            # a hidden FSM encoding trigger states (IDLE, SEQ1, SEQ2, DOS_ON...)
            r'localparam\s+\w+\s*=\s*\d+.*\n'
            r'(\s*localparam\s+\w+\s*=\s*\d+.*\n){2,}',
            re.MULTILINE,
        ),
        "Three or more localparam declarations in sequence — trojan FSMs use "
        "named states to encode trigger sequences",
        2,
    ),
    (
        "countdown_timer",
        re.compile(r'<=\s*\w+\s*-\s*1', re.MULTILINE),
        "Register decrement assignment — countdown timers control how long a "
        "DoS payload remains active after trigger",
        1,
    ),
    (
        "suspicious_parameter",
        re.compile(
            r'parameter\s+\w*(TROJAN|MAGIC|SECRET|TRIGGER|DOS|DURATION|SEQUENCE)\w*',
            re.IGNORECASE,
        ),
        "Parameter with a suspicious name (TROJAN, MAGIC, TRIGGER, DOS, etc.) — "
        "T3 trojans often declare named constants for trigger sequence and duration",
        1,
    ),
    (
        "dos_payload",
        re.compile(
            # Output forced to a constant zero under an activation signal
            r'if\s*\(\w+\)\s*\n\s*\w+\s*=\s*\d+\'[bh]0+',
            re.MULTILINE,
        ),
        "Output forced to constant zero under an activation condition — "
        "denial-of-service payload that silently zeros all outputs",
        2,
    ),
]

SUSPICIOUS_THRESHOLD = 3

# Folders scanned when no CLI argument is provided
DEFAULT_FOLDERS = [
    "trojan_outputs",
    "trojaned_outputs",
    "demo_designs",
    "batch_trojan_designs",
]


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------

def analyze_file(filepath: Path) -> dict:
    try:
        content = filepath.read_text(errors="replace")
    except OSError as e:
        return {
            "folder": filepath.parent.name,
            "file": filepath.name,
            "path": str(filepath),
            "error": str(e),
            "score": 0,
            "flags": [],
            "suspicious": False,
            "evidence": [],
        }

    score = 0
    flags = []
    evidence = []

    for key, pattern, description, weight in HEURISTICS:
        matches = pattern.findall(content)
        if matches:
            score += weight
            flags.append(key)
            snippets = [
                m.strip()[:80] if isinstance(m, str) else str(m[0]).strip()[:80]
                for m in matches[:2]
            ]
            evidence.append({
                "heuristic": key,
                "weight": weight,
                "description": description,
                "examples": snippets,
            })

    suspicious = score >= SUSPICIOUS_THRESHOLD

    return {
        "folder": filepath.parent.name,
        "file": filepath.name,
        "path": str(filepath),
        "score": score,
        "flags": flags,
        "suspicious": suspicious,
        "evidence": evidence,
        "error": None,
    }


# ---------------------------------------------------------------------------
# Directory scan
# ---------------------------------------------------------------------------

def scan_directory(folder: str) -> list[dict]:
    results = []
    verilog_files = list(Path(folder).rglob("*.v"))

    if not verilog_files:
        print(f"[WARNING] No .v files found under '{folder}'")
        return results

    for vfile in verilog_files:
        result = analyze_file(vfile)
        results.append(result)
        status = "SUSPICIOUS" if result["suspicious"] else "clean"
        print(f"  [{status:^10}] {result['folder']}/{result['file']}  "
              f"(score={result['score']}, flags={result['flags']})")

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Output: CSV summary table
# ---------------------------------------------------------------------------

def write_csv(results: list[dict], output_path: str = None):
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"trojan_detection_results_{timestamp}.csv"

    fieldnames = ["folder", "file", "score", "suspicious", "flags", "error"]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "folder":     r["folder"],
                "file":       r["file"],
                "score":      r["score"],
                "suspicious": r["suspicious"],
                "flags":      "; ".join(r["flags"]),
                "error":      r.get("error") or "",
            })
    print(f"\n[CSV] Results written to: {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Output: Human-readable report
# ---------------------------------------------------------------------------

def print_report(results: list[dict]):
    total   = len(results)
    flagged = sum(1 for r in results if r["suspicious"])
    clean   = total - flagged

    print("\n" + "=" * 65)
    print("  HARDWARE TROJAN HEURISTIC DETECTOR — RESULTS SUMMARY")
    print("=" * 65)
    print(f"  Files scanned : {total}")
    print(f"  SUSPICIOUS    : {flagged}  (score >= {SUSPICIOUS_THRESHOLD})")
    print(f"  Clean         : {clean}")
    print("=" * 65)

    if flagged == 0:
        print("  No files exceeded the suspicion threshold.")
        return

    print("\n  FLAGGED FILES:\n")
    for r in results:
        if not r["suspicious"]:
            continue
        print(f"  File  : {r['folder']}/{r['file']}")
        print(f"  Score : {r['score']}  (threshold={SUSPICIOUS_THRESHOLD})")
        print(f"  Flags : {', '.join(r['flags'])}")
        if r["evidence"]:
            print("  Evidence:")
            for ev in r["evidence"]:
                print(f"    [{ev['weight']}pt] {ev['heuristic']}: "
                      f"{ev['description'][:60]}...")
                for ex in ev["examples"]:
                    print(f"          → {ex}")
        print()


# ---------------------------------------------------------------------------
# Evaluation: TP/FP/FN/TN against ground truth
# ---------------------------------------------------------------------------

def evaluate(results: list[dict], ground_truth: dict[str, bool]) -> dict:
    tp = fp = fn = tn = 0
    rows = []

    for r in results:
        fname     = r["file"]
        predicted = r["suspicious"]
        actual    = ground_truth.get(fname)

        if actual is None:
            rows.append((f"{r['folder']}/{fname}", predicted, "UNKNOWN", "—"))
            continue

        if predicted and actual:
            label = "TP"; tp += 1
        elif predicted and not actual:
            label = "FP"; fp += 1
        elif not predicted and actual:
            label = "FN"; fn += 1
        else:
            label = "TN"; tn += 1

        rows.append((f"{r['folder']}/{fname}", predicted, actual, label))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    print("\n" + "=" * 65)
    print("  EVALUATION AGAINST GROUND TRUTH")
    print("=" * 65)
    print(f"  {'File':<45} {'Pred':^6} {'Actual':^6} {'Label':^5}")
    print(f"  {'-'*45} {'-'*6} {'-'*6} {'-'*5}")
    for fname, pred, actual, label in rows:
        print(f"  {fname:<45} {str(pred):^6} {str(actual):^6} {label:^5}")

    print()
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"  Precision : {precision:.2f}")
    print(f"  Recall    : {recall:.2f}")
    print(f"  F1        : {f1:.2f}")
    print()
    print("  Discussion:")
    if fp > 0:
        print(f"  - {fp} false positive(s): clean files scored >= {SUSPICIOUS_THRESHOLD}.")
        print("    Likely caused by magic constants or conditional counters in")
        print("    legitimate RTL. Consider raising threshold or adding context checks.")
    if fn > 0:
        print(f"  - {fn} false negative(s): trojaned files scored < {SUSPICIOUS_THRESHOLD}.")
        print("    Trojan may use patterns not yet covered by current heuristics.")
    if fp == 0 and fn == 0:
        print("  - Perfect separation on this sample set.")
        print("    Note: sample set is small; real-world performance will vary.")

    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1": f1}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) > 1:
        folders = sys.argv[1:]   # accept one or more folder args
    else:
        folders = DEFAULT_FOLDERS

    results = []
    for folder in folders:
        if Path(folder).exists():
            print(f"\nScanning: {Path(folder).resolve()}\n")
            results += scan_directory(folder)
        else:
            print(f"[SKIP] Folder not found: '{folder}'")

    if not results:
        print("\n[ERROR] No .v files found in any scanned folder.")
        print(f"Usage: python detector.py [folder1] [folder2] ...")
        print(f"Default folders: {DEFAULT_FOLDERS}")
        sys.exit(1)

    results.sort(key=lambda r: r["score"], reverse=True)

    print_report(results)
    write_csv(results)

    # ------------------------------------------------------------------
    # Ground truth
    # True  = trojaned   False = clean
    # Add any additional files from demo_designs / batch_trojan_designs
    # as you discover them.
    # ------------------------------------------------------------------
    ground_truth = {
        # --- Trojaned designs ---
        "alu_simple_HT1_gpt-4.1_A1.v":        True,
        "alu_simple_HT2_gpt-4.1_A1.v":        True,
        "aes_sbox_HT1_gpt-4.1_A1.v":          True,
        "aes_sbox_HT2_gpt-4.1_A1.v":          True,
        "aes_sbox_HT3_gpt-4.1_A1.v":          True,
        "aes_sbox_HT4_gpt-4.1_A1.v":          True,
        "uart_controller_HT1_gpt-4.1_A1.v":   True,
        "uart_controller_HT2_gpt-4.1_A1.v":   True,
        "uart_controller_HT3_gpt-4.1_A1.v":   True,
        "uart_controller_HT4_gpt-4.1_A1.v":   True,
        "shift_reg_HT1_gpt-4.1_A1.v":         True,
        "shift_reg_HT2_gpt-4.1_A1.v":         True,

        # --- Clean baseline designs (demo_designs / batch_trojan_designs) ---
        "alu_simple.v":       False,
        "shift_reg.v":        False,
        "aes_sbox.v":         False,
        "uart_controller.v":  False,
    }

    if any(r["file"] in ground_truth for r in results):
        evaluate(results, ground_truth)
    else:
        print("\n[INFO] No ground truth labels matched scanned files.")
        print("       Update the ground_truth dict in __main__ to enable evaluation.")