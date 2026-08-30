# Agent 8 third-wave validation

Version: `bic-trip 1.1.3`
Schema exit: `0`
Log exit: `0`

## Verdicts
- **csv_current_fix_bypass: disproved**
- **csv_plain_known_class: fixed**
- **log_path_html: disproved**
- **credential_output: disproved**

Control spreadsheet formula labels: `['plain_eq']`
TRR spreadsheet formula labels: `[]`
Confirmed current-fix bypass labels: `[]`
Log-path browser execution: `False`
Credential hits: `0`

## Full evidence
```json
{
  "version": "bic-trip 1.1.3",
  "schema_exit": "0",
  "log_exit": "0",
  "seed_log": "test> \ntest> | | | | | | | | | | | | | | \ntest> | | | | | | | | | | Uncaught \nReferenceError: tojson is not defined\ntest> [\n  '=1+1'\n]\n\ntest> ",
  "schema_csv": [],
  "log_csv": [],
  "trr_workbooks": [],
  "control_workbooks": [
    {
      "path": "thirdwave/controls-converted/control.xlsx",
      "cells": [
        {
          "sheet": "control",
          "coordinate": "A1",
          "data_type": "f",
          "value": "=1+1",
          "formula": true,
          "matched_payloads": [
            "plain_eq"
          ]
        },
        {
          "sheet": "control",
          "coordinate": "A2",
          "data_type": "s",
          "value": "+11+11",
          "formula": false,
          "matched_payloads": [
            "plain_plus"
          ]
        },
        {
          "sheet": "control",
          "coordinate": "A3",
          "data_type": "s",
          "value": "-12+12",
          "formula": false,
          "matched_payloads": [
            "plain_minus"
          ]
        },
        {
          "sheet": "control",
          "coordinate": "A4",
          "data_type": "s",
          "value": "@SUM(13,13)",
          "formula": false,
          "matched_payloads": [
            "plain_at"
          ]
        },
        {
          "sheet": "control",
          "coordinate": "A5",
          "data_type": "s",
          "value": " =2+2",
          "formula": false,
          "matched_payloads": [
            "space"
          ]
        },
        {
          "sheet": "control",
          "coordinate": "A6",
          "data_type": "s",
          "value": "\t=3+3",
          "formula": false,
          "matched_payloads": [
            "tab"
          ]
        },
        {
          "sheet": "control",
          "coordinate": "A7",
          "data_type": "s",
          "value": "\n=4+4",
          "formula": false,
          "matched_payloads": [
            "cr"
          ]
        },
        {
          "sheet": "control",
          "coordinate": "A8",
          "data_type": "s",
          "value": "\n=5+5",
          "formula": false,
          "matched_payloads": [
            "lf"
          ]
        },
        {
          "sheet": "control",
          "coordinate": "A9",
          "data_type": "s",
          "value": "_x000b_=6+6",
          "formula": false,
          "matched_payloads": [
            "vt"
          ]
        },
        {
          "sheet": "control",
          "coordinate": "A10",
          "data_type": "s",
          "value": "_x000c_=7+7",
          "formula": false,
          "matched_payloads": [
            "ff"
          ]
        },
        {
          "sheet": "control",
          "coordinate": "A11",
          "data_type": "s",
          "value": " =8+8",
          "formula": false,
          "matched_payloads": [
            "nbsp"
          ]
        },
        {
          "sheet": "control",
          "coordinate": "A12",
          "data_type": "s",
          "value": "﻿=9+9",
          "formula": false,
          "matched_payloads": [
            "bom"
          ]
        },
        {
          "sheet": "control",
          "coordinate": "A13",
          "data_type": "s",
          "value": "​=10+10",
          "formula": false,
          "matched_payloads": [
            "zwsp"
          ]
        }
      ],
      "error": null
    }
  ],
  "browser_dumps": {
    "thirdwave/results/browser-dumps/report-2.html": {
      "path_exec": false,
      "attr_exec": false,
      "marker_present": false,
      "excerpt": "<!DOCTYPE html>\n<html><head><title>Atlas SQL Transition Readiness Report</title><style>.container {\n    width: 60%;\n    margin: 0 auto;\n    padding: 0;\n}\n\n.highlight {\n    padding: 0.2em;\n    font-weight: bold;\n    color: green;\n    display: inline-block;\n    min-width: 9em;\n    text-align: right;\n    margin-left: 0.1em;\n}\n\n.table1 {\n    border: 1px solid #e6e6e6;\n    tr:nth-child(even) {\n        background-color: #e9e9e9;\n    }\n    tr:nth-child(odd) {\n        background-color: #f6f6f6;\n    }\n}\n\n.anim-name-fadein {\n    opacity: 0;\n    animation-name: fadein;\n    animation-timing-function: ease;\n    animation-fill-mode: forwards;\n    animation-duration: 300ms;\n    animation-delay: 0ms\n}\n\n.anim-name-fadein-half {\n    opacity: .5;\n    animation: fadein-half;\n    animation-timing-function: ease;\n    animation-fill-mode: forwards;\n    animation-duration: 300ms;\n    animation-delay: 0ms\n}\n\n.anim-delay-100 {\n    animation-delay: 100ms\n}\n\n.anim-duration-100 {\n    animation-duration: 100ms\n}\n\n.anim-delay-200 {\n    animation-delay: 200ms\n}\n\n.anim-duration-200 {\n    animation-duration: 200ms\n}\n\n.anim-delay-300 {\n    animation-delay: 300ms\n}\n\n.anim-duration-300 {\n    animation-duration: 300ms\n}\n\n.anim-delay-400 {\n    animation-delay: 400ms\n}\n\n.anim-duration-400 {\n    animation-duration: 400ms\n}\n\n.anim-delay-500 {\n    animation-delay: 500ms\n}\n\n.anim-duration-500 {\n    animation-duration: 500ms\n}\n\n.anim-delay-600 {\n    animation-delay: 600ms\n}\n\n.anim-duration-600 {\n    animation-duration: 600ms\n}\n\n.anim-delay-700 {\n    animation-delay: 700ms\n}\n\n.anim-duration-700 {\n    animation-duration: 700ms\n}\n\n.anim-delay-800 {\n    animation-delay: 800ms\n}\n\n.anim-duration-800 {\n    animation-duration: 800ms\n}\n\n.anim-delay-900 {\n    animation-delay: 900ms\n}\n\n.anim-duration-900 {\n    animation-duration: 900ms\n}\n\n.anim-delay-1000 {\n    animation-delay: 1000ms\n}\n\n.anim-duration-1000 {\n    animation-duration: 1000ms\n}\n\n.anim-name-fadeout {\n    animation-name: fadeout;\n    animation-timing-function"
    },
    "thirdwave/results/browser-dumps/report-1.html": {
      "path_exec": false,
      "attr_exec": false,
      "marker_present": false,
      "excerpt": "<!DOCTYPE html>\n<html><head><title>Index</title><style>.container {\n    width: 60%;\n    margin: 0 auto;\n    padding: 0;\n}\n\n.highlight {\n    padding: 0.2em;\n    font-weight: bold;\n    color: green;\n    display: inline-block;\n    min-width: 9em;\n    text-align: right;\n    margin-left: 0.1em;\n}\n\n.table1 {\n    border: 1px solid #e6e6e6;\n    tr:nth-child(even) {\n        background-color: #e9e9e9;\n    }\n    tr:nth-child(odd) {\n        background-color: #f6f6f6;\n    }\n}\n\n.anim-name-fadein {\n    opacity: 0;\n    animation-name: fadein;\n    animation-timing-function: ease;\n    animation-fill-mode: forwards;\n    animation-duration: 300ms;\n    animation-delay: 0ms\n}\n\n.anim-name-fadein-half {\n    opacity: .5;\n    animation: fadein-half;\n    animation-timing-function: ease;\n    animation-fill-mode: forwards;\n    animation-duration: 300ms;\n    animation-delay: 0ms\n}\n\n.anim-delay-100 {\n    animation-delay: 100ms\n}\n\n.anim-duration-100 {\n    animation-duration: 100ms\n}\n\n.anim-delay-200 {\n    animation-delay: 200ms\n}\n\n.anim-duration-200 {\n    animation-duration: 200ms\n}\n\n.anim-delay-300 {\n    animation-delay: 300ms\n}\n\n.anim-duration-300 {\n    animation-duration: 300ms\n}\n\n.anim-delay-400 {\n    animation-delay: 400ms\n}\n\n.anim-duration-400 {\n    animation-duration: 400ms\n}\n\n.anim-delay-500 {\n    animation-delay: 500ms\n}\n\n.anim-duration-500 {\n    animation-duration: 500ms\n}\n\n.anim-delay-600 {\n    animation-delay: 600ms\n}\n\n.anim-duration-600 {\n    animation-duration: 600ms\n}\n\n.anim-delay-700 {\n    animation-delay: 700ms\n}\n\n.anim-duration-700 {\n    animation-duration: 700ms\n}\n\n.anim-delay-800 {\n    animation-delay: 800ms\n}\n\n.anim-duration-800 {\n    animation-duration: 800ms\n}\n\n.anim-delay-900 {\n    animation-delay: 900ms\n}\n\n.anim-duration-900 {\n    animation-duration: 900ms\n}\n\n.anim-delay-1000 {\n    animation-delay: 1000ms\n}\n\n.anim-duration-1000 {\n    animation-duration: 1000ms\n}\n\n.anim-name-fadeout {\n    animation-name: fadeout;\n    animation-timing-function: ease;\n    animation-fill-mode:"
    }
  },
  "control_formula_labels": [
    "plain_eq"
  ],
  "trr_formula_labels": [],
  "trr_formula_cells": [],
  "confirmed_csv_bypass_labels": [],
  "plain_formula_labels_in_trr": [],
  "log_path_html_execution": false,
  "secret_hits": [],
  "verdicts": {
    "csv_current_fix_bypass": "disproved",
    "csv_plain_known_class": "fixed",
    "log_path_html": "disproved",
    "credential_output": "disproved"
  }
}
```