#!/usr/bin/env python3
"""Summarize scan output and publish a readable GitHub Actions job summary."""

import json
import os
from pathlib import Path
import xml.etree.ElementTree as ET

OUT = Path(os.environ.get("RESULT_DIR", "results"))
TOOL = os.environ.get("TOOL", "nmap")
LAB = os.environ.get("LAB_TARGET", "miniapp")
MODE = os.environ.get("TARGET_MODE", "local")


def load_jsonl(filename):
    path = OUT / filename
    if not path.exists():
        return [], [f"Missing file: {filename}"]
    items, errors = [], []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                items.append(value)
        except json.JSONDecodeError:
            # Some tools send startup messages to the same output stream.
            if line.strip():
                errors.append(line[:240])
    return items, errors


def escape(value):
    return str(value).replace("|", "\\|").replace("\n", " ").replace("`", "'")[:180]


def create_report():
    OUT.mkdir(parents=True, exist_ok=True)
    try:
        target_data = json.loads((OUT / "target.json").read_text())
    except (OSError, json.JSONDecodeError):
        target_data = {}
    target_description = target_data.get("url") or target_data.get("host") or (LAB if MODE == "local" else "not validated")
    lines = ["# Results — Hacking Automation: GitHub I Am Your Master", "",
             f"**Tool:** `{escape(TOOL)}`", f"**Mode:** `{escape(MODE)}`",
             f"**Target:** `{escape(target_description)}`", "",
             "**Scope:** only project-related and explicitly authorized targets. External inputs accept a single host, IP or URL.", "",
             "**Privacy:** a GitHub egress IP does not guarantee anonymity.", ""]

    runtime_path = OUT / "tool-execution.json"
    runtime = {}
    if runtime_path.exists():
        try:
            runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    if runtime:
        exit_code = runtime.get("exit_code")
        lines += ["## Execution diagnostics", "",
                  f"**Tool process exit code:** `{escape(exit_code)}`",
                  f"**Tool duration (excluding startup):** `{escape(runtime.get('elapsed_seconds', '?'))}` seconds", ""]
        if exit_code != 0:
            lines += ["**Execution failure:** the tool exited with an error. Check `tool.log` and the workflow logs. A missing finding is not a negative scan result.", ""]
    else:
        lines += ["**Execution did not reach the completion-recording step.** Check workflow logs for earlier failures.", ""]
    preflight_path = OUT / "preflight.json"
    if preflight_path.exists():
        try:
            preflight = json.loads(preflight_path.read_text(encoding="utf-8"))
            dns = preflight.get("dns", {})
            http = preflight.get("http_preflight", {})
            lines += [f"**Resolved IPs:** `{escape(', '.join(dns.get('addresses') or []) or 'none')}`"]
            if dns.get("error"):
                lines += [f"**DNS warning:** {escape(dns['error'])}"]
            if http.get("attempted"):
                lines += [f"**HTTP HEAD preflight status:** `{escape(http.get('status') or 'not available')}`"]
                if http.get("error"):
                    lines += [f"**Preflight warning:** {escape(http['error'])}"]
            lines += ["", "Preflight data is diagnostic only; it is not a scanner finding.", ""]
        except (OSError, ValueError):
            pass

    if TOOL == "nmap":
        xml_path = OUT / "nmap.xml"
        if xml_path.exists():
            try:
                root = ET.parse(xml_path).getroot()
                data = []
                for port in root.findall(".//port"):
                    state = port.find("state")
                    service = port.find("service")
                    data.append((port.get("portid", "?"), port.get("protocol", "?"),
                                 state.get("state", "?") if state is not None else "?",
                                 service.get("name", "unknown") if service is not None else "unknown"))
                if not data:
                    lines += ["**No port entries in Nmap XML.** Check `nmap.txt`, `tool.log`, the selected port list and external firewall rules.", ""]
                elif not any(row[2] == "open" for row in data):
                    lines += ["**No open ports among the selected ports.** A firewall or a different application port may explain this. This is not a full host scan.", ""]
                lines += [f"**Ports in XML output:** {len(data)}", "",
                          "| Port | Protocol | State | Service |", "|---|---|---|---|"]
                lines += [f"| {escape(a)} | {escape(b)} | {escape(c)} | {escape(d)} |" for a, b, c, d in data]
            except ET.ParseError as exc:
                lines += [f"Unable to parse XML: {escape(exc)}"]
        else:
            lines += ["No XML output was produced. Check the job logs for details."]
    elif TOOL == "subfinder":
        data, errors = load_jsonl("subfinder.jsonl")
        hosts = sorted({str(item.get("host", "")) for item in data if item.get("host")})
        lines += [f"**Discovered subdomains:** {len(hosts)}", "",
                  "Results depend on available passive sources; zero findings does not prove none exist.", ""]
        lines += [f"- `{escape(host)}`" for host in hosts[:40]]
        if not hosts:
            lines += ["No subdomains returned by the consulted passive sources. This does not mean the domain has none; examine `tool.log` for source or network errors."]
        if errors:
            lines += ["", "Non-JSON content was found in the machine-readable file; check tool logs and possible format changes."]
    elif TOOL == "httpx":
        data, _ = load_jsonl("httpx.jsonl")
        lines += [f"**HTTP responses:** {len(data)}", "",
                  "| URL | HTTP | Title | Server |", "|---|---|---|---|"]
        for item in data:
            lines.append(f"| {escape(item.get('url', '-'))} | {escape(item.get('status_code', '-'))} | "
                         f"{escape(item.get('title', '-'))} | {escape(item.get('webserver', '-'))} |")
        if not data:
            lines += ["", "No HTTP response was recorded. Confirm URL, scheme, DNS resolution, TLS, connectivity, and `tool.log`. This does not prove the site is down."]
    elif TOOL == "nuclei":
        data, _ = load_jsonl("nuclei.jsonl")
        lines += [f"**Informational template matches:** {len(data)}", "",
                  "| Template | Severity | Target |", "|---|---|---|"]
        for item in data:
            info = item.get("info", {})
            severity = info.get("severity", "info") if isinstance(info, dict) else "info"
            lines.append(f"| {escape(item.get('template-id', '-'))} | {escape(severity)} | "
                         f"{escape(item.get('matched-at', item.get('host', '-')))} |")
        if not data:
            lines += ["", "No Nuclei template matched. This is not proof of a secure target. Review `tool.log`, preflight diagnostics, and template match conditions."]
        lines += ["", "Only the supplied informational templates are executed; matches alone do not prove exploitable vulnerabilities. No exploitation is performed."]
    else:
        lines += ["Unknown tool."]

    lines += ["", "## Run files", "",
              "Download `tool.log`, `tool-execution.json`, `preflight.json` and the tool's native output from the **Artifacts** section.",
              "Do not publish third-party host data or secrets in a public repository.", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    report = create_report()
    path = OUT / "summary.md"
    path.write_text(report, encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(report + "\n")
    print(report)
