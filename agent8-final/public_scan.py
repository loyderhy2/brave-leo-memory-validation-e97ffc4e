#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

root = Path("final-run")
results = root / "results"
results.mkdir(parents=True, exist_ok=True)
token = os.environ.get("GITHUB_TOKEN", "")
headers = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "agent8-mongosql-public-duplicate-scan",
}
if token:
    headers["Authorization"] = f"Bearer {token}"


def fetch(url: str, *, use_auth: bool = False) -> tuple[int | None, str]:
    request = urllib.request.Request(url, headers=headers if use_auth else {"User-Agent": headers["User-Agent"]})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except Exception as exc:
        return None, repr(exc)


queries = [
    '"MongoSQL Transition Readiness Tool" "1.1.3" formula',
    '"Transition Readiness Tool" "leading whitespace" CSV',
    '"CVE-2026-76797" bypass',
    '"CVE-2026-76797" incomplete fix',
    '"BI Connector Transition Readiness Report" formula',
    '"SQL-3322" MongoSQL',
    '"SQL-3320" MongoSQL',
    '"SQL-3321" MongoSQL',
    'repo:mongodb/mongosql formula CSV security',
    'repo:mongodb/docs "CVE-2026-76797"',
]
scan: dict[str, Any] = {
    "queries": [],
    "direct_root_cause_hits": [],
    "current_1_1_3_bypass_hits": [],
    "known_cves": {},
    "docs": {},
}
for query in queries:
    url = "https://api.github.com/search/issues?q=" + urllib.parse.quote(query) + "&per_page=20"
    status, body = fetch(url, use_auth=True)
    entry: dict[str, Any] = {"query": query, "status": status, "items": [], "error": None}
    try:
        parsed = json.loads(body)
        for item in parsed.get("items", []):
            normalized = {
                "title": item.get("title"),
                "url": item.get("html_url"),
                "state": item.get("state"),
                "created_at": item.get("created_at"),
                "updated_at": item.get("updated_at"),
                "repository_url": item.get("repository_url"),
                "body_excerpt": str(item.get("body") or "")[:2000],
            }
            entry["items"].append(normalized)
            text = (str(normalized["title"]) + "\n" + normalized["body_excerpt"]).lower()
            if any(term in text for term in ["cve-2026-76797", "sql-3322", "formula"]):
                scan["direct_root_cause_hits"].append(normalized)
            if "1.1.3" in text and any(term in text for term in ["bypass", "whitespace", "control character", "incomplete fix"]):
                scan["current_1_1_3_bypass_hits"].append(normalized)
    except Exception as exc:
        entry["error"] = f"{exc!r}; body={body[:1000]}"
    scan["queries"].append(entry)

# De-duplicate by URL.
for key in ["direct_root_cause_hits", "current_1_1_3_bypass_hits"]:
    unique = {}
    for item in scan[key]:
        unique[item.get("url") or json.dumps(item, sort_keys=True)] = item
    scan[key] = list(unique.values())

for cve in ["CVE-2026-76794", "CVE-2026-76797", "CVE-2026-76798"]:
    suffix = cve.split("-")[-1]
    url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/76xxx/{cve}.json"
    status, body = fetch(url)
    entry: dict[str, Any] = {"status": status, "url": url}
    try:
        parsed = json.loads(body)
        cna = parsed.get("containers", {}).get("cna", {})
        entry.update({
            "title": cna.get("title"),
            "description": (cna.get("descriptions") or [{}])[0].get("value"),
            "affected": cna.get("affected"),
            "metrics": cna.get("metrics"),
        })
    except Exception as exc:
        entry["error"] = f"{exc!r}; body={body[:1000]}"
    scan["known_cves"][cve] = entry

for name, url in {
    "transition_guide": "https://raw.githubusercontent.com/mongodb/docs/main/content/sql-interface/source/transition-bic-to-atlas-sql.txt",
    "changelog": "https://raw.githubusercontent.com/mongodb/docs/main/content/sql-interface/source/changelog.txt",
    "mongosql_release": "https://raw.githubusercontent.com/mongodb/mongosql/main/RELEASE.md",
}.items():
    status, body = fetch(url)
    scan["docs"][name] = {
        "status": status,
        "url": url,
        "relevant_lines": [
            line for line in body.splitlines()
            if any(term.lower() in line.lower() for term in [
                "Transition Readiness", "1.1.3", "CVE-2026-767", "libmongosql",
                "schema-builder-library", "connector"
            ])
        ][:200],
    }

(root / "duplicate-scan.json").write_text(json.dumps(scan, indent=2, ensure_ascii=False), encoding="utf-8")

# Best-effort current public HackerOne scope extraction. We do not invent an asset when the page
# does not expose a parseable scope list.
scope: dict[str, Any] = {"assets": [], "sources": [], "errors": []}
for url in [
    "https://hackerone.com/mongodb?type=team",
    "https://hackerone.com/mongodb/policy_scopes",
]:
    status, body = fetch(url)
    scope["sources"].append({"url": url, "status": status, "length": len(body)})
    if status is None:
        scope["errors"].append(body[:1000])
        continue
    for phrase in [
        "MongoDB Connectors",
        "Enterprise Edition Products and Tools",
        "MongoDB Owned GitHub Repositories",
        "Atlas SQL",
        "BI Connector",
    ]:
        if phrase.lower() in body.lower() and phrase not in scope["assets"]:
            scope["assets"].append(phrase)
(root / "h1-scope.json").write_text(json.dumps(scope, indent=2, ensure_ascii=False), encoding="utf-8")
