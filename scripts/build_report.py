#!/usr/bin/env python3
"""Turn genuine CLI output into a security-oriented, evidence-based brief.

Never invent findings or classify an empty result as proof of safety. Outputs:
summary.md (Job Summary), report.json (structured), report.html (presentation).
"""
import html
import json
import os
from collections import Counter
from pathlib import Path
import xml.etree.ElementTree as ET

OUT = Path(os.environ.get('RESULT_DIR', 'results'))
TOOL = os.environ.get('TOOL', 'nmap')
MODE = os.environ.get('TARGET_MODE', 'local')
LAB = os.environ.get('LAB_TARGET', 'miniapp')
PROFILE = os.environ.get('PROFILE', 'quick')


def read_json(name):
    try:
        data = json.loads((OUT / name).read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def read_jsonl(name):
    path = OUT / name
    if not path.exists():
        return [], [f'{name} was not generated']
    data, warnings = [], []
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            if isinstance(record, dict):
                data.append(record)
        except ValueError:
            warnings.append(f'Non-JSON entry in {name}; check tool.log')
    return data, sorted(set(warnings))


def text(value, maxlen=180):
    return str(value if value is not None else '-').replace('\n', ' ').replace('\r', ' ').strip()[:maxlen]


def md(value):
    return text(value).replace('|', '\\|').replace('`', "'").replace('<', '&lt;').replace('>', '&gt;')


def add_observation(report, label, evidence, interpretation):
    report['observations'].append({'label': label, 'evidence': text(evidence, 500),
                                   'interpretation': interpretation})


def analyze_nmap(report):
    path = OUT / 'nmap.xml'
    if not path.exists():
        report['warnings'].append('Nmap did not produce nmap.xml; check installation, tool.log, and command exit status.')
        return
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        report['warnings'].append('Nmap XML is not parseable; examine nmap.txt and tool.log.')
        return
    ports, state_counts, nse = [], Counter(), []
    for host in root.findall('host'):
        for ext in host.findall('./ports/extraports'):
            state_counts[ext.get('state', 'unknown')] += int(ext.get('count', 0))
        for node in host.findall('./ports/port'):
            state = node.find('state')
            service = node.find('service')
            name = (service.get('name', '') if service is not None else '')
            product = (service.get('product', '') if service is not None else '')
            version = (service.get('version', '') if service is not None else '')
            row = {'port': node.get('portid', '?'), 'protocol': node.get('protocol', '?'),
                   'state': state.get('state', 'unknown') if state is not None else 'unknown',
                   'service': ' '.join(filter(None,[name,product,version])) or 'unknown',
                   'product': product or '-', 'version': version or '-'}
            state_counts[row['state']] += 1
            ports.append(row)
            for script in node.findall('script'):
                sid = script.get('id', '')
                output = text(script.get('output',''), 700)
                nse.append({'port': row['port'], 'script': sid, 'output': output})
                if output:
                    kind = {'http-title': 'HTTP title', 'http-headers': 'HTTP response headers',
                            'ssl-cert': 'TLS certificate metadata'}.get(sid, 'Nmap NSE evidence')
                    add_observation(report, f'{kind} ({row["port"]}/tcp)', output,
                                    'Reported by an explicit read-only Nmap script; validate the context before interpreting the security impact.')
    report['metrics'] = {'open_ports': state_counts['open'], 'closed_ports': state_counts['closed'],
                         'filtered_ports': state_counts['filtered'], 'nse_observations': len(nse),
                         'ports_checked': sum(state_counts.values())}
    report['items'] = ports[:40]
    report['checks'] = ['Selected TCP ports', 'Service/version fingerprinting' if PROFILE == 'detailed' else 'TCP connect scan']
    if PROFILE == 'detailed': report['checks'].append('NSE: http-title, http-headers, ssl-cert (where applicable)')
    if state_counts['open']:
        add_observation(report, 'Accessible TCP services',
                        ', '.join(f"{x['port']}/tcp: {x['service']}" for x in ports if x['state'] == 'open'),
                        'Confirm whether these services and versions are expected and patched. An open port does not establish a vulnerability.')
    elif report['status'] == 'completed':
        report['warnings'].append('No open ports on the selected port list. This is not a complete host assessment.')
    report['limitations'].append('Only the selected TCP ports were examined; -Pn skips host discovery. NSE scripts run only when applicable.')
    report['next_steps'].append('Compare the open ports, service versions, HTTP headers and TLS metadata with your approved deployment inventory.')


def analyze_subfinder(report):
    data, warnings = read_jsonl('subfinder.jsonl')
    report['warnings'] += warnings
    hosts = sorted({str(item.get('host', '')).lower().strip('.') for item in data if item.get('host')})
    sources = Counter()
    source_hosts = {}
    for item in data:
        names = item.get('sources') or item.get('source') or []
        if isinstance(names, str): names = [names]
        for name in names if isinstance(names,list) else []:
            sources[str(name)] += 1
            source_hosts.setdefault(str(item.get('host','')).lower(), set()).add(str(name))
    dns = read_json('subdomains-dns.json')
    records = {item['host']:item for item in dns.get('records',[]) if isinstance(item,dict) and item.get('host')}
    report['checks'] = ['Passive source enumeration (no brute force)', 'Bounded DNS A/AAAA/CNAME lookups for up to 30 discovered names']
    report['metrics'] = {'subdomains_found': len(hosts), 'sources_reporting_findings': len(sources),
                         'dns_enriched_hosts': len(records),
                         'dns_hosts_with_addresses': sum(bool(r.get('a') or r.get('aaaa')) for r in records.values())}
    report['items'] = [{'host':h,'sources':sorted(source_hosts.get(h,[])),
                        'addresses':(records.get(h,{}).get('a',[]) + records.get(h,{}).get('aaaa',[]))[:8],
                        'cname':records.get(h,{}).get('cname',[])} for h in hosts[:50]]
    if hosts:
        add_observation(report, 'Passive subdomain candidates', f'{len(hosts)} names: '+', '.join(hosts[:8]),
                        'Names are candidate assets, not verified scope or exploitable services.')
    elif report['status'] == 'completed':
        add_observation(report, 'No passive subdomains returned', '0 results from configured providers',
                        'Source availability, credentials, and public indexing affect coverage. This is not evidence that the domain lacks subdomains.')
    if sources:
        add_observation(report, 'Passive source attribution', ', '.join(f'{x}: {y}' for x,y in sources.most_common(10)),
                        'Source attribution applies to returned records, not all attempted providers.')
    if records:
        resolved=[r for r in records.values() if r.get('a') or r.get('aaaa')]
        add_observation(report,'DNS resolution of discovered names',f'{len(resolved)}/{len(records)} have A/AAAA answers',
                        'DNS resolution only; no HTTP or port scanning of discovered subdomains was performed.')
    report['limitations'].append('Passive sources are incomplete and many require credentials. Only up to 30 discovered names receive DNS enrichment.')
    report['next_steps'].append('Compare candidates with the authorized asset inventory and independently verify ownership before any active test.')


def _headers(item):
    headers = item.get('headers') or {}
    if isinstance(headers, dict):
        return {str(k).lower(): str(v)[:200] for k,v in headers.items()}
    # httpx -irh may emit raw response as a string, not headers as a dict.
    raw = item.get('response') or item.get('header') or ''
    result = {}
    if isinstance(raw, str):
        for line in raw.splitlines()[:70]:
            if ':' in line and not line.startswith('HTTP/'):
                k,v = line.split(':',1)
                if k and len(k)<70 and ' ' not in k: result[k.lower()] = v.strip()[:200]
    return result


def analyze_httpx(report):
    data, warnings = read_jsonl('httpx.jsonl')
    report['warnings'] += warnings
    rows = []
    found = Counter()
    for item in data[:50]:
        tech = item.get('tech') or item.get('technologies') or []
        if isinstance(tech,str): tech=[tech]
        headers = _headers(item)
        checks = ('strict-transport-security','content-security-policy','x-content-type-options',
                  'x-frame-options','referrer-policy')
        present = [h for h in checks if h in headers]
        absent = [h for h in checks if h not in headers]
        tls = item.get('tls') or item.get('tls_grab') or item.get('tls_data') or {}
        if not isinstance(tls,dict): tls={ 'value':text(tls,150) }
        row = {'url':item.get('url','-'),'status':item.get('status_code','-'),
               'title':text(item.get('title','-'),110), 'server':item.get('webserver','-') or '-',
               'content_type':item.get('content_type','-') or '-',
               'technologies':list(map(str,tech))[:12],
               'redirect':item.get('location','-') or '-',
               'ip':item.get('host') or item.get('a') or '-',
               'cdn':item.get('cdn_name') or item.get('cdn') or '-',
               'cname':item.get('cname') or '-',
               'tls':text(json.dumps(tls,ensure_ascii=False),400) if tls else '-',
               'security_headers_present':present, 'security_headers_absent':absent if headers else [],
               'response_time':item.get('time',item.get('response_time','-'))}
        rows.append(row)
        if isinstance(row['status'],int): found[str(row['status'])]+=1
    report['items'] = rows
    report['checks'] = ['HTTP response status/title/server', 'Technology/CDN/IP/CNAME metadata',
                        'Redirect location and TLS certificate metadata when HTTPS', 'Security response headers',
                        'Three known paths in detailed mode, except explicit non-root URLs']
    report['metrics']={'http_responses':len(data),'unique_urls':len({r['url'] for r in rows}),
                       'http_status_codes':dict(found),'https_responses':sum(str(x['url']).startswith('https://') for x in rows)}
    if rows:
        add_observation(report,'Observed HTTP endpoints', ', '.join(f"{r['url']} → {r['status']}" for r in rows[:6]),
                        'Evidence of HTTP responses from requested paths; a non-200 status is still a useful result.')
        technologies=sorted({t for row in rows for t in row['technologies']})
        if technologies: add_observation(report,'Detected technologies',', '.join(technologies[:15]),
                        'Signatures may be incomplete or inaccurate; compare with deployment manifests and versions.')
        for row in rows[:5]:
            if row['redirect'] != '-':
                add_observation(report,'Redirect',f"{row['url']} → {row['redirect']}",
                                'Verify redirect destinations and intended scheme; redirection alone is not a vulnerability.')
            if row['tls'] != '-':
                add_observation(report,'TLS metadata for '+str(row['url']),row['tls'],
                                'Check certificate names, issuers and validity; TLS metadata is not a vulnerability verdict.')
            if row['security_headers_present'] or row['security_headers_absent']:
                add_observation(report,'Security headers for '+str(row['url']),
                        'Present: '+(', '.join(row['security_headers_present']) or 'none') +
                        '; absent: '+(', '.join(row['security_headers_absent']) or 'none'),
                        'Header applicability depends on scheme, content and deployment policy; missing a header is not proof of exploitation.')
    elif report['status']=='completed':
        report['warnings'].append('No HTTPx response was recorded; check DNS, TLS and tool.log. Preflight status alone is not a scanner result.')
    else: report['warnings'].append('HTTPx failed or never ran; no security conclusion is possible.')
    report['limitations'].append('HTTP fingerprinting is not vulnerability confirmation; a few known paths only, no crawling, fuzzing or exploit execution.')
    report['next_steps'].append('Validate response metadata, certificate and security headers against the deployment policy, focusing on unexpected exposures.')


def analyze_nuclei(report):
    data,warnings=read_jsonl('nuclei.jsonl')
    report['warnings']+=warnings
    rows=[]; counts=Counter()
    for item in data[:60]:
        info=item.get('info') or {}
        if not isinstance(info,dict): info={}
        tid=str(item.get('template-id') or item.get('templateID') or '-')
        severity=str(info.get('severity','info')).lower()
        counts[severity]+=1
        rows.append({'template':tid,'name':info.get('name','-'),
                    'severity':severity, 'matched_at':item.get('matched-at',item.get('host','-')),
                    'kind':'Response evidence' if 'response-observed' in tid else 'Template condition'})
    report['metrics']={'template_matches':len(data),'by_severity':dict(counts),
                       'external_templates_configured':8 if PROFILE=='detailed' and MODE=='external' else (6 if MODE=='external' else 1)}
    report['checks'] = (['HTTP status evidence', 'Missing security header indicators (contextual)']
                        + (['Read-only .git/HEAD metadata marker and security.txt presence'] if PROFILE=='detailed' else [])) \
                        if MODE=='external' else ['Lab-specific simulated exposure/fingerprint template']
    report['items']=rows
    for row in rows:
        add_observation(report, row['name'],
                        f"{row['template']} | {row['severity']} | {row['matched_at']}",
                        'Matched condition from a named template, not proof of exploitation. Validate the response before escalating.')
    if not rows:
        report['warnings'].append('No Nuclei templates matched; verify connectivity, template loading, and expected response conditions in tool.log.')
        if report['status'] != 'completed': report['warnings'].append('Nuclei did not complete successfully; no reliable finding verdict.')
    report['limitations'].append('Only curated read-only templates run (six external standard; two extra in external detailed mode; one local). No broad public template pack or exploit chain.')
    report['next_steps'].append('Review matching template definitions and server responses; fix exposures based on verified policy or asset configuration.')


def add_connectivity(report, preflight):
    dns = preflight.get('dns') or {}
    http = preflight.get('http_preflight') or {}
    addresses = dns.get('addresses') or []
    addresses = [x for x in addresses if x]
    if addresses:
        add_observation(report, 'DNS/host resolution', ', '.join(addresses[:8]),
                        'This is connectivity context, not a security finding.')
    elif dns.get('error'):
        report['warnings'].append('DNS lookup failed: ' + text(dns['error'], 220))
    get = preflight.get('http_get') or {}
    if get.get('attempted') and get.get('status') is not None:
        add_observation(report, 'Independent HTTP GET preflight', f"HTTP {get['status']}",
                        'Read-only diagnostic request; not a tool match or proof of vulnerability.')
    elif get.get('error'):
        report['warnings'].append('GET preflight failed: '+text(get['error'],220))
    if report['tool'] == 'httpx' and get.get('headers'):
        headers = get['headers']
        keys = ('strict-transport-security','content-security-policy','x-content-type-options',
                'x-frame-options','referrer-policy')
        available = [key for key in keys if key in headers]
        absent = [key for key in keys if key not in headers]
        add_observation(report,'HTTP GET security headers',
                        'Present: '+(', '.join(available) or 'none') + '; absent: '+(', '.join(absent) or 'none'),
                        'These are response metadata, not a vulnerability verdict. Applicability depends on the page and scheme.')
    if http.get('attempted'):
        status = http.get('status')
        if status is not None:
            add_observation(report, 'Independent HTTP HEAD preflight', f'HTTP {status}',
                            'A diagnostic probe, not a scanner match; HEAD and GET can behave differently.')
        elif http.get('error'):
            report['warnings'].append('HTTP HEAD diagnostic failed: ' + text(http['error'], 220))
        headers = http.get('headers') or {}
        if headers:
            for name in ('server', 'content-type', 'location', 'x-powered-by'):
                if headers.get(name):
                    add_observation(report, f'Observed HTTP {name} header', headers[name],
                                    'Server-provided metadata; confirm it is accurate before relying on it.')
            if report['tool'] == 'nuclei' and report['mode'] == 'external' and str(report['target']).startswith('https://'):
                header_names = ('strict-transport-security', 'content-security-policy',
                                'x-content-type-options', 'x-frame-options', 'referrer-policy')
                available = [name for name in header_names if name in headers]
                absent = [name for name in header_names if name not in headers]
                add_observation(report, 'Security headers on HEAD response',
                                f"present: {', '.join(available) or 'none'}; absent: {', '.join(absent) or 'none'}",
                                'Header presence is contextual only. A HEAD response may differ from GET; missing headers do not automatically imply exploitability.')


def create_model():
    target = read_json('target.json')
    runtime = read_json('tool-execution.json')
    preflight = read_json('preflight.json')
    target_name = target.get('url') or target.get('host') or LAB
    code = runtime.get('exit_code')
    report = {
        'project': 'Hacking Automation: GitHub I Am Your Master',
        'tool': TOOL, 'mode': MODE, 'profile': PROFILE, 'target': target_name,
        'status': 'not_completed' if code is None else ('failed' if code != 0 else 'completed'),
        'exit_code': code, 'duration_seconds': runtime.get('elapsed_seconds'),
        'metrics': {}, 'checks': [], 'observations': [], 'items': [], 'warnings': [],
        'limitations': [], 'next_steps': [],
        'notes': ['Only explicitly authorized, project-related targets.',
                  'GitHub-hosted execution does not provide anonymity.'],
    }
    if TOOL == 'nmap':
        analyze_nmap(report)
    elif TOOL == 'subfinder':
        analyze_subfinder(report)
    elif TOOL == 'httpx':
        analyze_httpx(report)
    elif TOOL == 'nuclei':
        analyze_nuclei(report)
    else:
        report['warnings'].append(f'Unknown tool: {TOOL}')
    if preflight.get('host'):
        add_connectivity(report, preflight)
    elif preflight:
        report['warnings'].append('Invalid preflight: host is blank; DNS and HTTP preflight claims have been ignored.')
    if not preflight and (OUT / 'preflight.json').exists() is False:
        report['warnings'].append('Preflight file absent; target validation or initialization may have failed.')
    elif preflight and not preflight.get('host'):
        report['warnings'].append('Preflight has an empty host; its DNS/HTTP observations cannot be trusted.')
    if code is None:
        report['warnings'].insert(0, 'No tool execution record. The workflow may have failed before the scanner started.')
    elif code != 0:
        report['warnings'].insert(0, f'Tool exited with code {code}. Output is incomplete or unreliable.')
    if not report['observations']:
        report['warnings'].append('No verifiable observation could be extracted; review preflight and tool.log.')
    return report


def render_markdown(report):
    lines = [f"# {report['project']}", '',
             '## Security reconnaissance brief', '',
             f"**Tool:** `{md(report['tool'])}` · **Target:** `{md(report['target'])}` · **Mode:** `{md(report['mode'])}` · **Profile:** `{md(report['profile'])}`", '',
             f"**Execution:** `{report['status']}` · **Exit code:** `{report['exit_code']}` · **Tool runtime:** `{report['duration_seconds'] if report['duration_seconds'] is not None else '?'}s`", '']
    if report.get('checks'):
        lines += ['### Checks performed', ''] + [f'- {md(x)}' for x in report['checks']] + ['']
    if report['metrics']:
        lines += ['### Key measurements', '']
        lines += [f"- **{key.replace('_', ' ').capitalize()}:** {value}" for key, value in report['metrics'].items()]
        lines.append('')
    lines += ['### Observations and interpretation', '']
    for ob in report['observations']:
        lines += [f"- **{md(ob['label'])}:** {md(ob['evidence'])}  ",
                  f"  *Meaning:* {md(ob['interpretation'])}"]
    if not report['observations']:
        lines += ['No verified observation available; consult diagnostic files.']
    lines.append('')
    if report['items']:
        lines += ['### Tool results (selected evidence)', '']
        keys = {
            'nmap': [('port', 'Port'), ('protocol', 'Protocol'), ('state', 'State'), ('service', 'Service')],
            'subfinder': [('host', 'Subdomain')],
            'httpx': [('url', 'URL'), ('status', 'Status'), ('title', 'Title'), ('server', 'Server'),
                      ('content_type', 'Content type'), ('technologies', 'Technologies')],
            'nuclei': [('template', 'Template'), ('kind', 'Meaning'), ('severity', 'Severity'), ('matched_at', 'Target')],
        }.get(report['tool'], [])
        if keys:
            lines += ['| ' + ' | '.join(label for _, label in keys) + ' |',
                      '|' + '|'.join('---' for _ in keys) + '|']
            for item in report['items'][:30]:
                cells = []
                for key, _ in keys:
                    val = item.get(key, '-')
                    cells.append(md(', '.join(val) if isinstance(val, list) else val))
                lines.append('| ' + ' | '.join(cells) + ' |')
            lines.append('')
    if report['warnings']:
        lines += ['### Uncertainty / issues', ''] + [f"- {md(s)}" for s in report['warnings']] + ['']
    lines += ['### Scope and next steps', '']
    lines += [f"- **Limit:** {md(s)}" for s in report['limitations']]
    lines += [f"- **Next:** {md(s)}" for s in report['next_steps']]
    lines += ['', '### Evidence', '',
              'See `report.json`, `tool.log`, `tool-execution.json`, `preflight.json`, and the native tool output in the downloadable artifact.', '',
              '**Important:** A missing finding is not proof of security. A match is not proof of an exploitable vulnerability. Do not publish sensitive target data in a public repository.', '']
    return '\n'.join(lines)


def render_html(report):
    esc = lambda s: html.escape(text(s, 600), quote=True)
    obs = ''.join(f'<article><h3>{esc(o["label"])}</h3><p class="evidence">{esc(o["evidence"])}</p><p>{esc(o["interpretation"])}</p></article>'
                  for o in report['observations']) or '<p>No verified observation available.</p>'
    metrics = ''.join(f'<div class="metric"><strong>{esc(v)}</strong><small>{esc(k.replace("_", " "))}</small></div>'
                      for k, v in report['metrics'].items())
    rows = ''.join('<tr><td>' + '</td><td>'.join(esc(', '.join(v) if isinstance(v, list) else v)
                                                   for v in row.values()) + '</td></tr>' for row in report['items'][:30])
    columns = ''.join(f'<th>{esc(k.replace("_", " "))}</th>' for k in report['items'][0]) if report['items'] else ''
    table = f'<table><thead><tr>{columns}</tr></thead><tbody>{rows}</tbody></table>' if rows else ''
    notes = ''.join(f'<li>{esc(w)}</li>' for w in report['warnings']) or '<li>No additional warnings.</li>'
    limitations = ''.join(f'<li>{esc(x)}</li>' for x in report['limitations'] + report['next_steps'])
    return f'''<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security Recon Brief</title>
<style>body{{background:#0b1120;color:#e2e8f0;font:16px system-ui;margin:0}}main{{max-width:1050px;margin:auto;padding:40px 28px}}
h1{{font-size:2rem;color:#fff}}.sub{{color:#9ca3af}}.stats{{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}}.metric,article{{background:#15213a;border:1px solid #30425e;border-radius:12px;padding:16px}}.metric{{min-width:130px}}.metric strong{{font-size:26px;display:block;color:#93c5fd}}small{{display:block;color:#aab7cf;text-transform:capitalize}}article{{margin:10px 0}}h2{{margin-top:36px}}h3{{margin:0}}.evidence{{color:#93c5fd;overflow-wrap:anywhere}}table{{border-collapse:collapse;width:100%;font-size:14px}}td,th{{padding:9px;border-bottom:1px solid #30425e;text-align:left;overflow-wrap:anywhere}}th{{color:#c4b5fd}}li{{margin:9px 0}}.notice{{color:#fbbf24}}@media print{{body{{background:#fff;color:#111}}article,.metric{{background:#fff}}}}</style></head><body><main>
<p class="sub">Hacking Automation: GitHub I Am Your Master</p><h1>Security Reconnaissance Brief</h1>
<p><strong>{esc(report['tool'])}</strong> · {esc(report['target'])} · {esc(report['mode'])} · {esc(report['profile'])}</p>
<p class="sub">Execution: {esc(report['status'])} · Exit code: {esc(report['exit_code'])} · Runtime: {esc(report['duration_seconds'])}s</p>
<div class="stats">{metrics}</div><h2>Checks performed</h2><ul>{"".join("<li>"+esc(c)+"</li>" for c in report.get("checks",[]))}</ul><h2>Evidence & interpretation</h2>{obs}<h2>Tool observations</h2>{table or '<p>No tool results were recorded.</p>'}
<h2>Uncertainties</h2><ul>{notes}</ul><h2>Scope and follow-up</h2><ul>{limitations}</ul>
<p class="notice">No finding does not mean the target is secure; findings do not automatically prove exploitability. Results are limited to the selected authorized target and checks.</p>
</main></body></html>'''


def create_report():
    return render_markdown(create_model())


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    try:
        report = create_model()
    except Exception as exc:
        report = {
            'project': 'Hacking Automation: GitHub I Am Your Master',
            'tool': TOOL, 'mode': MODE, 'profile': PROFILE, 'target': 'unknown',
            'status': 'report_error', 'exit_code': None, 'duration_seconds': None,
            'checks': [], 'metrics': {}, 'observations': [], 'items': [],
            'warnings': [f'Report parser failed: {type(exc).__name__}: {text(exc)}',
                         'No security conclusion is possible; inspect tool.log and the raw output.'],
            'limitations': ['Report generation error; raw evidence may still exist.'],
            'next_steps': ['Inspect the report parser and tool logs before repeating the test.'],
        }
    (OUT / 'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    (OUT / 'summary.md').write_text(render_markdown(report), encoding='utf-8')
    (OUT / 'report.html').write_text(render_html(report), encoding='utf-8')
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as handle:
            handle.write(render_markdown(report) + '\n')
    print(render_markdown(report))


if __name__ == '__main__':
    main()
