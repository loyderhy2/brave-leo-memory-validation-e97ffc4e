from pathlib import Path
from urllib.parse import urlsplit
from bs4 import BeautifulSoup
import csv
import json
import re

root = Path('secondwave')
out = root / 'work' / 'out'
res = root / 'results'
files = [p for p in out.rglob('*') if p.is_file()] if out.exists() else []
report = {
    'version_output': (res / 'version.txt').read_text(errors='replace').strip() if (res / 'version.txt').exists() else '',
    'success_exit': (res / 'success.exit').read_text().strip() if (res / 'success.exit').exists() else None,
    'auth_error_exit': (res / 'auth-error.exit').read_text().strip() if (res / 'auth-error.exit').exists() else None,
    'files': [str(p.relative_to(out)) for p in files],
}
report['extensions'] = {}
for p in files:
    report['extensions'][p.suffix.lower()] = report['extensions'].get(p.suffix.lower(), 0) + 1

marker_re = re.compile(r'TRR_[A-Z0-9_]+')
html_findings = []
links = []
for p in files:
    if p.suffix.lower() not in {'.html', '.htm'}:
        continue
    raw = p.read_text(errors='replace')
    soup = BeautifulSoup(raw, 'html.parser')
    active = []
    for tag in soup.find_all(True):
        serialized = str(tag)
        markers = marker_re.findall(serialized)
        if not markers:
            continue
        attrs = {k: str(v) for k, v in tag.attrs.items()}
        executable = (
            tag.name in {'script', 'img', 'svg', 'iframe', 'object', 'embed', 'math'}
            or any(k.lower().startswith('on') for k in attrs)
        )
        active.append({
            'tag': tag.name,
            'attrs': attrs,
            'markers': markers,
            'executable': executable,
            'snippet': serialized[:1000],
        })
        for key, value in attrs.items():
            if key.lower() in {'href', 'src', 'action', 'formaction', 'xlink:href'}:
                links.append({
                    'file': str(p.relative_to(out)),
                    'tag': tag.name,
                    'attr': key,
                    'value': value,
                    'scheme': urlsplit(value).scheme.lower(),
                    'markers': markers,
                })
    html_findings.append({
        'file': str(p.relative_to(out)),
        'active_marker_elements': active,
        'raw_markers': marker_re.findall(raw),
    })
report['html'] = html_findings
report['links'] = links
report['active_executable_marker_elements'] = [
    item
    for page in html_findings
    for item in page['active_marker_elements']
    if item['executable']
]
report['marker_non_http_links'] = [
    item for item in links if item['scheme'] not in {'', 'http', 'https', 'mailto'}
]

formula = []
neutralized = []
csv_files = []
for p in files:
    if p.suffix.lower() != '.csv':
        continue
    rows = list(csv.reader(p.open(newline='', errors='replace')))
    csv_files.append({
        'file': str(p.relative_to(out)),
        'rows': len(rows),
        'max_cols': max([len(row) for row in rows] or [0]),
    })
    for row_index, row in enumerate(rows, 1):
        for column_index, cell in enumerate(row, 1):
            stripped = cell.lstrip('\ufeff \t\r\n')
            finding = {
                'file': str(p.relative_to(out)),
                'row': row_index,
                'col': column_index,
                'cell': cell[:1000],
            }
            if stripped.startswith(('=', '+', '-', '@')):
                formula.append(finding)
            if stripped.startswith("'") and stripped[1:].lstrip().startswith(('=', '+', '-', '@')):
                neutralized.append(finding)
report['csv_files'] = csv_files
report['formula_cells'] = formula
report['neutralized_formula_cells'] = neutralized

canaries = ['TRR_SECRET_CANARY_7A91FD', 'TRR_SECRET_CANARY_7A91FD_WRONG']
secret_hits = []
tool_outputs = list(files) + [
    res / name
    for name in [
        'success.stdout', 'success.stderr', 'auth-error.stdout',
        'auth-error.stderr', 'chromium.stderr'
    ]
]
for p in tool_outputs:
    if not p.exists() or not p.is_file():
        continue
    text = p.read_text(errors='replace')
    for canary in canaries:
        for match in re.finditer(re.escape(canary), text):
            secret_hits.append({
                'file': str(p),
                'canary': canary,
                'context': text[max(0, match.start() - 200):match.end() + 200],
            })
report['secret_hits'] = secret_hits

work = root / 'work'
outside = []
for p in work.rglob('*') if work.exists() else []:
    if p.is_file() and out not in p.parents and p.name != 'TRR_PARENT_GUARD.txt':
        outside.append(str(p.relative_to(work)))
report['outside_output_files'] = outside
report['path_marker_files'] = [str(p) for p in root.rglob('*') if 'TRR_PATH_' in str(p)]
report['browser_callbacks'] = (
    (res / 'browser-callbacks.log').read_text(errors='replace').splitlines()
    if (res / 'browser-callbacks.log').exists() else []
)

execs = []
for p in res.glob('strace-success*'):
    for line in p.read_text(errors='replace').splitlines():
        if 'execve(' in line:
            execs.append(line[:4000])
report['execve_calls'] = execs
report['external_open_execs'] = [
    line for line in execs
    if any(token in line.lower() for token in [
        'xdg-open', 'gio', 'sensible-browser', 'firefox', 'chromium', 'cmd.exe', 'shellexecute'
    ])
]

report['classifications'] = {
    'html': 'potential' if report['active_executable_marker_elements'] or report['browser_callbacks'] else 'disproved',
    'csv': 'potential' if formula else 'disproved',
    'url_launch': 'potential' if report['marker_non_http_links'] or report['external_open_execs'] else 'disproved',
    'secret': 'potential' if secret_hits else 'disproved',
    'path': 'potential' if outside or report['path_marker_files'] else 'disproved',
}
(res / 'analysis.json').write_text(json.dumps(report, indent=2, ensure_ascii=False))

lines = [
    '# Agent 8 second-wave TRR validation',
    '',
    f"Version: `{report['version_output']}`",
    f"Success exit: `{report['success_exit']}`",
    f"Auth error exit: `{report['auth_error_exit']}`",
    '',
    '## Mechanical classifications',
]
for key, value in report['classifications'].items():
    lines.append(f'- **{key}: {value}**')
lines += [
    '',
    '## Counts',
    f"- output files: {len(files)}",
    f"- active executable marker elements: {len(report['active_executable_marker_elements'])}",
    f"- browser callbacks: {len(report['browser_callbacks'])}",
    f"- formula-leading CSV cells: {len(formula)}",
    f"- neutralized formula cells: {len(neutralized)}",
    f"- marker-controlled non-http links: {len(report['marker_non_http_links'])}",
    f"- TRR external-open execs: {len(report['external_open_execs'])}",
    f"- canary hits in tool output: {len(secret_hits)}",
    f"- outside-output files: {len(outside)}",
    f"- path-marker filesystem entries: {len(report['path_marker_files'])}",
    '',
    '## Full JSON',
    '```json',
    json.dumps(report, indent=2, ensure_ascii=False),
    '```',
]
(res / 'analysis.md').write_text('\n'.join(lines))
