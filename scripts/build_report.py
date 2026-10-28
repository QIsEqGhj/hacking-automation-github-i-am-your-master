#!/usr/bin/env python3
"""Summarize scan output and publish a readable GitHub Actions job summary."""

import json
import os
from pathlib import Path
import xml.etree.ElementTree as ET

OUT = Path(os.environ.get("RESULT_DIR", "results"))
TOOL = os.environ.get("TOOL", "nmap")
LAB = os.environ.get("LAB_TARGET", "miniapp")


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
    lines = ["# Results — Hacking Automation: GitHub in Your Master", "",
             f"**Tool:** `{escape(TOOL)}`", f"**Local lab target:** `{escape(LAB)}`", "",
             "**Scope:** the miniapp or Juice Shop hosted on this runner, except Subfinder (authorized project domain).", "",
             "**Privacy:** a GitHub egress IP does not guarantee anonymity.", ""]

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
        if errors and not hosts:
            lines += ["", "Non-JSON output was recorded; check `subfinder.jsonl`."]
    elif TOOL == "httpx":
        data, _ = load_jsonl("httpx.jsonl")
        lines += [f"**HTTP responses:** {len(data)}", "",
                  "| URL | HTTP | Title | Server |", "|---|---|---|---|"]
        for item in data:
            lines.append(f"| {escape(item.get('url', '-'))} | {escape(item.get('status_code', '-'))} | "
                         f"{escape(item.get('title', '-'))} | {escape(item.get('webserver', '-'))} |")
    elif TOOL == "nuclei":
        data, _ = load_jsonl("nuclei.jsonl")
        lines += [f"**Educational template matches:** {len(data)}", "",
                  "| Template | Severity | Target |", "|---|---|---|"]
        for item in data:
            info = item.get("info", {})
            severity = info.get("severity", "info") if isinstance(info, dict) else "info"
            lines.append(f"| {escape(item.get('template-id', '-'))} | {escape(severity)} | "
                         f"{escape(item.get('matched-at', item.get('host', '-')))} |")
        lines += ["", "The templates are educational. `/debug` is intentional in the miniapp; the Juice Shop template only fingerprints the app. No exploitation is performed."]
    else:
        lines += ["Unknown tool."]

    lines += ["", "## Run files", "",
              "Download complete outputs from the **Artifacts** section of this workflow run.",
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
