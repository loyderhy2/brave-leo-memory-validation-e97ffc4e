# Agent 8 second-wave TRR validation

Version: `bic-trip 1.1.3`
Success exit: `124`
Auth error exit: `1`

## Mechanical classifications
- **html: disproved**
- **csv: disproved**
- **url_launch: disproved**
- **secret: disproved**
- **path: disproved**

## Counts
- output files: 1
- active executable marker elements: 0
- browser callbacks: 0
- formula-leading CSV cells: 0
- neutralized formula cells: 0
- marker-controlled non-http links: 0
- TRR external-open execs: 0
- canary hits in tool output: 0
- outside-output files: 0
- path-marker filesystem entries: 0

## Full JSON
```json
{
  "version_output": "bic-trip 1.1.3",
  "success_exit": "124",
  "auth_error_exit": "1",
  "files": [
    "TRR_OUT_GUARD.txt"
  ],
  "extensions": {
    ".txt": 1
  },
  "html": [],
  "links": [],
  "active_executable_marker_elements": [],
  "marker_non_http_links": [],
  "csv_files": [],
  "formula_cells": [],
  "neutralized_formula_cells": [],
  "secret_hits": [],
  "outside_output_files": [],
  "path_marker_files": [],
  "browser_callbacks": [],
  "execve_calls": [
    "execve(\"../bin/AtlasSQLReadinessReport-linux\", [\"../bin/AtlasSQLReadinessReport-linux\", \"--uri\", \"mongodb://trruser:TRR_SECRET_CANARY_7A91FD@127.0.0.1:27017/admin?authSource=admin\", \"--output\", \"/home/runner/work/brave-leo-memory-validation-e97ffc4e/brave-leo-memory-validation-e97ffc4e/secondwave/work/out\", \"--include\", \"trrtest.*\"], 0x7fff81e55918 /* 115 vars */) = 0"
  ],
  "external_open_execs": [],
  "classifications": {
    "html": "disproved",
    "csv": "disproved",
    "url_launch": "disproved",
    "secret": "disproved",
    "path": "disproved"
  }
}
```