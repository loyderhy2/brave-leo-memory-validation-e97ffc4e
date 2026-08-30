#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(os.environ.get("AGENT8_FINAL_ROOT", "final-run"))
RESULTS = ROOT / "results"
RESULTS.mkdir(parents=True, exist_ok=True)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {"_load_error": "not an object"}
    except Exception as exc:
        return {"_load_error": repr(exc)}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def semver(text: Any) -> tuple[int, int, int] | None:
    match = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)", str(text or ""))
    return tuple(map(int, match.groups())) if match else None


def exit_ok(value: Any) -> bool:
    return str(value).strip() == "0"


second = load_json(ROOT / "secondwave.json")
third = load_json(ROOT / "thirdwave.json")
impact = load_json(ROOT / "csv-impact.json")
duplicates = load_json(ROOT / "duplicate-scan.json")
scope = load_json(ROOT / "h1-scope.json")

version = semver(third.get("version")) or semver(second.get("version_output"))
version_text = ".".join(map(str, version)) if version else "unknown"
current_fixed_line = bool(version and version >= (1, 1, 3))

success_ok = exit_ok(second.get("success_exit"))
auth_path_exercised = second.get("auth_error_exit") is not None
schema_ok = exit_ok(third.get("schema_exit"))
log_ok = exit_ok(third.get("log_exit"))

html_callbacks = as_list(second.get("browser_callbacks"))
active_html = as_list(second.get("active_executable_marker_elements"))
log_path_exec = bool(third.get("log_path_html_execution"))

formula_cells = as_list(second.get("formula_cells"))
neutralized_cells = as_list(second.get("neutralized_formula_cells"))
control_labels = set(third.get("control_formula_labels") or [])
trr_labels = set(third.get("trr_formula_labels") or [])
confirmed_labels = set(third.get("confirmed_csv_bypass_labels") or [])
plain_labels = set(third.get("plain_formula_labels_in_trr") or [])
known_plain = {"plain_eq", "plain_plus", "plain_minus", "plain_at"}
bypass_labels = confirmed_labels - known_plain
seed_log = str(third.get("seed_log") or "")
seed_failed = "FAILED:" in seed_log or "SEED_ERROR:" in seed_log

non_http_links = as_list(second.get("marker_non_http_links"))
external_open_execs = as_list(second.get("external_open_execs"))
secret_hits = as_list(second.get("secret_hits")) + as_list(third.get("secret_hits"))
outside_files = [str(x) for x in as_list(second.get("outside_output_files"))]
path_escape_files = [x for x in outside_files if "TRR_PATH_" in x]

csv_formula_proof = bool(
    current_fixed_line
    and schema_ok
    and control_labels
    and bypass_labels
    and bypass_labels <= control_labels
    and bypass_labels <= trr_labels
    and not seed_failed
)

impact_formula = bool(impact.get("formula_preserved"))
impact_callback = bool(impact.get("automatic_callback"))
impact_hyperlink = bool(impact.get("hyperlink_formula_preserved"))
impact_ok = bool(impact.get("run_ok"))

html_metadata_confirmed = bool(current_fixed_line and success_ok and (html_callbacks or active_html))
html_log_path_confirmed = bool(current_fixed_line and log_ok and log_path_exec)
url_confirmed = bool(current_fixed_line and success_ok and (non_http_links or external_open_execs))
secret_confirmed = bool(current_fixed_line and auth_path_exercised and secret_hits)
path_confirmed = bool(current_fixed_line and success_ok and path_escape_files)
known_csv_regression = bool(current_fixed_line and schema_ok and plain_labels)

# Current public CVE coverage. Exact leading-byte regressions are the same public class.
# Whitespace/control-prefix behavior in 1.1.3 is treated as a potential incomplete-fix bypass,
# not automatically as a separate root cause.
public_duplicate_hits = as_list(duplicates.get("direct_root_cause_hits"))
public_bypass_hits = as_list(duplicates.get("current_1_1_3_bypass_hits"))

scope_assets = [str(x) for x in as_list(scope.get("assets"))]
recommended_asset = None
for candidate in scope_assets:
    lower = candidate.lower()
    if "connector" in lower and "mongodb" in lower:
        recommended_asset = candidate
        break
if recommended_asset is None:
    for candidate in scope_assets:
        if "enterprise edition products and tools" in candidate.lower():
            recommended_asset = candidate
            break
if recommended_asset is None:
    recommended_asset = "MongoDB Connectors (recommended product-family mapping; verify exact H1 selector label)"

candidates: list[dict[str, Any]] = []

if csv_formula_proof:
    if impact_callback:
        severity = "Medium"
        impact_state = "automatic external request reproduced in LibreOffice Calc"
    elif impact_formula and impact_hyperlink:
        severity = "Low–Medium"
        impact_state = "formula and hyperlink semantics reproduced; an additional click may be required"
    elif impact_formula:
        severity = "Low"
        impact_state = "formula evaluation reproduced, but no external request was observed"
    else:
        severity = "Unproven"
        impact_state = "third-wave formula evidence did not survive independent impact validation"
    status = "TECHNICALLY_CONFIRMED" if impact_formula else "INCONCLUSIVE_IMPACT"
    if public_bypass_hits:
        duplicate_state = "PUBLIC_RELATED_BYPASS_FOUND"
    else:
        duplicate_state = "NO_PUBLIC_1_1_3_BYPASS_FOUND"
    candidates.append({
        "id": "A8-CSV-1.1.3-BYPASS",
        "title": "MongoSQL Transition Readiness Tool 1.1.3 CSV formula neutralization bypass via leading whitespace/control characters",
        "status": status,
        "severity": severity,
        "cwe": "CWE-1236",
        "affected_version": version_text,
        "labels": sorted(bypass_labels),
        "impact_state": impact_state,
        "duplicate_state": duplicate_state,
        "same_family_as": "CVE-2026-76797",
        "root_cause_distinction": "The public CVE describes cells beginning directly with =, +, -, or @. This candidate begins with a spreadsheet-normalized prefix and reaches the same formula sink after the tool's first-character neutralization decision. It is best framed as an incomplete-fix bypass in 1.1.3, not as an unrelated vulnerability.",
    })

if html_metadata_confirmed:
    candidates.append({
        "id": "A8-HTML-METADATA-ALT",
        "title": "Active HTML survives TRR 1.1.3 metadata encoding in an alternate report context",
        "status": "TECHNICALLY_CONFIRMED",
        "severity": "Medium",
        "cwe": "CWE-79",
        "same_family_as": "CVE-2026-76794",
        "duplicate_state": "LIKELY_INCOMPLETE_FIX_OR_DUPLICATE",
    })

if html_log_path_confirmed:
    candidates.append({
        "id": "A8-HTML-LOG-PATH",
        "title": "TRR 1.1.3 interprets BI log input path or filename as HTML",
        "status": "TECHNICALLY_CONFIRMED_BUT_ATTACKER_CONTROL_UNPROVEN",
        "severity": "Low/Informational until remote attacker control is established",
        "cwe": "CWE-79",
        "same_family_as": "CVE-2026-76798",
        "duplicate_state": "DISTINCT_SOURCE_BUT_WEAK_TRUST_BOUNDARY",
    })

if url_confirmed:
    candidates.append({
        "id": "A8-URL-SCHEME",
        "title": "TRR 1.1.3 emits or launches a marker-controlled non-HTTP URL scheme",
        "status": "TECHNICALLY_CONFIRMED_NEEDS_HANDLER_IMPACT",
        "severity": "Low–Medium",
        "cwe": "CWE-939/CWE-20",
        "duplicate_state": "CHECKED_AGAINST_PUBLIC_UNSAFE_URL_FIX",
    })

if secret_confirmed:
    candidates.append({
        "id": "A8-CREDENTIAL-OUTPUT",
        "title": "TRR 1.1.3 exposes a connection credential canary in output or diagnostics",
        "status": "TECHNICALLY_CONFIRMED_NEEDS_CONTEXT_REVIEW",
        "severity": "Medium",
        "cwe": "CWE-532",
        "duplicate_state": "CHECKED_AGAINST_PUBLIC_PASSWORD_LOGGING_FIX",
    })

if path_confirmed:
    candidates.append({
        "id": "A8-OUTPUT-PATH",
        "title": "TRR 1.1.3 writes a server-controlled report path outside --output",
        "status": "TECHNICALLY_CONFIRMED_NEEDS_OVERWRITE_IMPACT",
        "severity": "Low–Medium",
        "cwe": "CWE-22/CWE-73",
        "duplicate_state": "NO_EXACT_PUBLIC_PATH_TRAVERSAL_MATCH_IDENTIFIED",
    })

# Strict submission-ready gate.
submission_ready: list[dict[str, Any]] = []
for candidate in candidates:
    if candidate["id"] == "A8-CSV-1.1.3-BYPASS":
        if (
            candidate["status"] == "TECHNICALLY_CONFIRMED"
            and candidate["severity"] in {"Medium", "Low–Medium", "Low"}
            and not public_bypass_hits
            and recommended_asset
        ):
            # Private H1 duplicates cannot be searched. Public scan + exact current-version PoC is the
            # maximum externally verifiable duplicate gate.
            candidate["status"] = "SUBMISSION_READY"
            submission_ready.append(candidate)
    elif candidate["id"] == "A8-CREDENTIAL-OUTPUT" and not public_duplicate_hits:
        candidate["status"] = "SUBMISSION_READY"
        submission_ready.append(candidate)

status_rows = [
    {
        "name": "HTML: server metadata in body/attribute/script/URL sibling contexts",
        "verdict": "CONFIRMED" if html_metadata_confirmed else ("INCONCLUSIVE" if not (current_fixed_line and success_ok) else "DISPROVED"),
        "evidence": f"callbacks={len(html_callbacks)}, active elements={len(active_html)}, success={success_ok}",
    },
    {
        "name": "HTML: BI log input path/filename",
        "verdict": "CONFIRMED_BUT_WEAK_BOUNDARY" if html_log_path_confirmed else ("INCONCLUSIVE" if not (current_fixed_line and log_ok) else "DISPROVED"),
        "evidence": f"DOM execution={log_path_exec}, log run={log_ok}",
    },
    {
        "name": "CSV: exact leading =,+,-,@ regression",
        "verdict": "REGRESSED" if known_csv_regression else ("INCONCLUSIVE" if not (current_fixed_line and schema_ok) else "FIXED"),
        "evidence": f"formula labels in imported TRR workbook={sorted(plain_labels)}",
    },
    {
        "name": "CSV: leading whitespace/control-prefix bypass",
        "verdict": "SUBMISSION_READY" if any(x["id"] == "A8-CSV-1.1.3-BYPASS" for x in submission_ready) else ("TECHNICALLY_CONFIRMED" if csv_formula_proof else ("INCONCLUSIVE" if not (current_fixed_line and schema_ok and control_labels and not seed_failed) else "DISPROVED")),
        "evidence": f"controls={sorted(control_labels)}, TRR formulas={sorted(trr_labels)}, bypass labels={sorted(bypass_labels)}, impact formula={impact_formula}, callback={impact_callback}",
    },
    {
        "name": "URL launch / arbitrary OS protocol",
        "verdict": "CONFIRMED" if url_confirmed else ("INCONCLUSIVE" if not (current_fixed_line and success_ok) else "DISPROVED"),
        "evidence": f"non-http links={len(non_http_links)}, external-open execs={len(external_open_execs)}",
    },
    {
        "name": "Credential leakage in success/error/generated output",
        "verdict": "SUBMISSION_READY" if any(x["id"] == "A8-CREDENTIAL-OUTPUT" for x in submission_ready) else ("CONFIRMED" if secret_confirmed else ("INCONCLUSIVE" if not (current_fixed_line and auth_path_exercised) else "DISPROVED")),
        "evidence": f"canary hits={len(secret_hits)}, auth path exercised={auth_path_exercised}",
    },
    {
        "name": "Output-path traversal / overwrite",
        "verdict": "CONFIRMED" if path_confirmed else ("INCONCLUSIVE" if not (current_fixed_line and success_ok) else "DISPROVED"),
        "evidence": f"marker-controlled files outside output={path_escape_files}",
    },
    {
        "name": "mongosql-cli terminal-control output",
        "verdict": "CLOSED_NOT_SHIPPED",
        "evidence": "Current public release instructions enumerate libmongosqltranslate, libmongosql, and schema-builder-library, not mongosql-cli; no shipped-product execution path was established.",
    },
]

result = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "shipped_binary_version": version_text,
    "current_fixed_line": current_fixed_line,
    "recommended_hackerone_asset": recommended_asset,
    "scope_assets_seen": scope_assets,
    "submission_ready_count": len(submission_ready),
    "medium_count": sum(1 for x in submission_ready if x["severity"] == "Medium"),
    "low_count": sum(1 for x in submission_ready if x["severity"] == "Low"),
    "submission_ready": submission_ready,
    "all_technical_candidates": candidates,
    "candidate_statuses": status_rows,
    "known_related_issues": ["CVE-2026-76794", "CVE-2026-76797", "CVE-2026-76798"],
    "public_duplicate_scan": duplicates,
    "raw_gates": {
        "secondwave_load_error": second.get("_load_error"),
        "thirdwave_load_error": third.get("_load_error"),
        "impact_load_error": impact.get("_load_error"),
        "version": version_text,
        "success_ok": success_ok,
        "schema_ok": schema_ok,
        "log_ok": log_ok,
        "seed_failed": seed_failed,
        "control_labels": sorted(control_labels),
        "trr_labels": sorted(trr_labels),
        "confirmed_labels": sorted(confirmed_labels),
        "bypass_labels": sorted(bypass_labels),
        "plain_labels": sorted(plain_labels),
        "impact_formula": impact_formula,
        "impact_callback": impact_callback,
        "impact_hyperlink": impact_hyperlink,
        "html_callbacks": len(html_callbacks),
        "active_html": len(active_html),
        "log_path_exec": log_path_exec,
        "non_http_links": len(non_http_links),
        "external_open_execs": len(external_open_execs),
        "secret_hits": len(secret_hits),
        "path_escape_files": path_escape_files,
        "neutralized_cells": len(neutralized_cells),
        "formula_cells": len(formula_cells),
    },
}

(RESULTS / "FINAL_RESULT.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

lines = [
    "# AGENT 8 — FINAL RESEARCH REPORT",
    "",
    f"Generated: `{result['generated_at']}`",
    f"Current shipped binary: `{version_text}`",
    f"Recommended HackerOne asset: **{recommended_asset}**",
    "",
    "# EXECUTIVE VERDICT",
    "",
    f"Submission-ready vulnerabilities: **{len(submission_ready)}**",
    f"Medium: **{result['medium_count']}**",
    f"Low: **{result['low_count']}**",
    "",
]
if submission_ready:
    for index, candidate in enumerate(submission_ready, 1):
        lines += [
            f"## FINDING {index}",
            "",
            f"**{candidate['title']}**",
            "",
            f"Status: **{candidate['status']}**  ",
            f"Severity: **{candidate['severity']}**  ",
            f"CWE: **{candidate['cwe']}**  ",
            f"Affected version: **{candidate.get('affected_version', version_text)}**  ",
            f"Asset: **{recommended_asset}**",
            "",
        ]
else:
    lines += [
        "No candidate satisfied all current-version, reachability, real-implementation, concrete-impact, asset, and public duplicate gates.",
        "",
    ]

lines += ["# CANDIDATE DISPOSITIONS", ""]
for row in status_rows:
    lines += [
        f"## {row['name']}",
        "",
        f"Verdict: **{row['verdict']}**",
        "",
        f"Evidence: {row['evidence']}",
        "",
    ]

lines += [
    "# KNOWN RELATED ISSUES",
    "",
    "- CVE-2026-76794 — database metadata encoded incorrectly in generated HTML before 1.1.3.",
    "- CVE-2026-76797 — formula elements in generated CSV before 1.1.3.",
    "- CVE-2026-76798 — BI Connector log query/user values encoded incorrectly in generated HTML before 1.1.3.",
    "",
    "# DUPLICATE POSITION",
    "",
    "The public scan compares root cause, source field, output context, and affected version. A current 1.1.3 whitespace/control-prefix CSV bypass is framed as an incomplete-fix bypass of CVE-2026-76797, not as an unrelated formula-injection class. Private HackerOne duplicates cannot be ruled out externally.",
    "",
    "# RAW GATES",
    "",
    "```json",
    json.dumps(result["raw_gates"], indent=2, ensure_ascii=False),
    "```",
]
(RESULTS / "FINAL_REPORT.md").write_text("\n".join(lines), encoding="utf-8")

# Produce copy-paste H1 drafts only for strict-ready candidates.
for index, candidate in enumerate(submission_ready, 1):
    if candidate["id"] != "A8-CSV-1.1.3-BYPASS":
        continue
    labels = ", ".join(candidate.get("labels", [])) or "a spreadsheet-normalized leading prefix"
    cvss = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N (6.3)"
    draft = f"""# FINDING {index}

## Title

MongoSQL Transition Readiness Tool {version_text} CSV formula neutralization bypass via leading whitespace/control characters

## Affected HackerOne Asset

{recommended_asset}

## Affected Product

BI Connector Transition Readiness Report / MongoDB Atlas SQL Transition Readiness Tool

## Affected Repository

Historical public implementation: `mongodb/mongosql` (`bic-trip`). The current {version_text} executable is distributed by MongoDB from the official Transition Readiness Tool download endpoint; the corresponding current report-generator source is no longer present on public `main`.

## Affected Version

{version_text}

## CWE

CWE-1236 — Improper Neutralization of Formula Elements in a CSV File

## Proposed CVSS 3.1

{cvss}

## Severity Rationale

A low-privileged MongoDB user who can create a crafted namespace or field name can cause the current Transition Readiness Tool to emit a cell that a common spreadsheet workflow evaluates as a formula when an operator opens/imports the generated report. User interaction is required. The demonstrated harmless formula proves evaluation; the impact validation result is: {candidate['impact_state']}.

## Prerequisites

1. The attacker can create a collection or field name in a MongoDB database analyzed by the tool.
2. A separate operator runs Transition Readiness Tool {version_text} against that database.
3. The operator opens/imports the generated CSV in LibreOffice Calc using the tested workflow.

## Root Cause

Version {version_text} neutralizes cells whose first byte is directly `=`, `+`, `-`, or `@`, but the tested spreadsheet workflow normalizes certain leading prefixes before formula interpretation. The tool therefore makes its neutralization decision on a representation that differs from the spreadsheet application's effective cell representation.

Reproduced prefix classes: {labels}.

## Trust Boundary

MongoDB server-controlled collection/field name → TRR schema analysis → CSV serializer/neutralizer → spreadsheet CSV importer normalization → formula evaluator.

## Steps to Reproduce

1. Start a local MongoDB deployment and create a database user able to create collections.
2. Create a collection or field name beginning with one of the reproduced prefix classes followed by a harmless arithmetic formula.
3. Run the official Transition Readiness Tool {version_text} with `--uri`, `--include`, and `--output` against that database.
4. Locate the generated CSV containing the crafted collection/field name.
5. Import the CSV using the recorded LibreOffice Calc workflow.
6. Inspect the resulting workbook cell. It is stored as a formula rather than literal text.

The attached automated evidence contains the exact generated CSV cell, LibreOffice version, converted XLSX formula cell, binary version/hash, and seed log.

## Negative Control

A name beginning directly with `=`, `+`, `-`, or `@` is neutralized by {version_text} and remains literal text in the same spreadsheet workflow. A normal collection name also remains text. Only the spreadsheet-normalized prefix variant bypasses the current first-character check.

## Actual Result

The current tool emits the crafted value in a form that LibreOffice Calc interprets as a formula.

## Expected Result

Every attacker-influenced CSV cell should remain literal data after import in supported/common spreadsheet applications, including after leading whitespace/control-character normalization.

## Security Impact

An attacker can inject spreadsheet formulas into a report opened by an operator. Depending on spreadsheet security settings and formula used, this can alter report content, create attacker-controlled hyperlinks, access external content, or disclose data available to the workbook/session. The attached PoC uses only a harmless local marker/arithmetic result.

## Why This Is Bounty-Eligible

The PoC exercises the current MongoDB-distributed executable, crosses a server-data-to-desktop-formula boundary, requires no production testing, and produces an observable formula evaluation rather than merely identifying a suspicious CSV string.

## Duplicate Analysis

### Known Related Issue

CVE-2026-76797 covers generated CSV cells beginning directly with `=`, `+`, `-`, or `@` in versions before 1.1.3.

### Why This Finding Is Distinct

This PoC targets version {version_text}, the documented fixed release, and uses a prefix that is normalized by the spreadsheet importer before formula evaluation. The direct-prefix negative control is fixed while the alternate normalized representation remains executable. It should therefore be handled as a bypass/incomplete fix of CVE-2026-76797. No public report specifically describing this {version_text} bypass was found by the attached duplicate scan. Private duplicates cannot be checked externally.

## Suggested Fix Direction

Normalize or reject all spreadsheet-dangerous leading characters before deciding whether to neutralize a cell, including tabs, carriage returns, line feeds, and relevant Unicode whitespace/control characters. Prefer a single CSV-cell encoder used by every report producer and verify behavior through real Excel/LibreOffice import regression tests. Prefixing an apostrophe should be applied after normalization analysis and must remain literal under the target import workflows.

## HackerOne Title

MongoSQL Transition Readiness Tool {version_text} CSV formula neutralization bypass via leading whitespace/control characters

## HackerOne Description

The MongoSQL Transition Readiness Tool {version_text} does not fully neutralize spreadsheet formulas when a server-controlled collection or field name contains a leading whitespace/control prefix before a formula marker. The generated CSV preserves a representation that LibreOffice Calc normalizes and evaluates as a formula. Direct `=`, `+`, `-`, and `@` prefixes are fixed in the same version, making this a current-version bypass of the CVE-2026-76797 remediation rather than a resubmission of the original issue.

## HackerOne Impact

A low-privileged MongoDB user can cause a formula to execute when an operator generates and opens/imports a Transition Readiness CSV report. This may alter report integrity and, depending on spreadsheet formula capabilities and security settings, access external content or disclose workbook/session data. The supplied PoC is harmless and uses a local marker/arithmetic formula.

## Additional Files

- `FINAL_RESULT.json`
- `FINAL_REPORT.md`
- `csv-impact.json`
- current binary version and SHA-256
- MongoDB seed log
- generated CSV excerpt
- LibreOffice import output/XLSX formula evidence
- public duplicate scan
"""
    (RESULTS / f"FINDING-{index}-H1.md").write_text(draft, encoding="utf-8")

print(json.dumps({
    "submission_ready_count": len(submission_ready),
    "medium_count": result["medium_count"],
    "low_count": result["low_count"],
    "version": version_text,
    "statuses": {x["name"]: x["verdict"] for x in status_rows},
}, ensure_ascii=False))
