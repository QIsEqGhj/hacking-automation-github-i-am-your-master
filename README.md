# Hacking Automation: GitHub I Am Your Master

An educational, on-demand offensive-security reconnaissance lab for **authorized targets related to this repository**. GitHub-hosted runners execute a single CLI tool per workflow run and publish actual measurements and interpreted reports. This is not an anonymity service or a general-purpose scanning platform.

## Quick start

1. Create a public GitHub repository, then upload this entire directory including `.github/workflows/offensive-lab.yml` and `scripts/`, `lab/` and `templates/`.
2. Open **Actions → Hacking Automation | Offensive Recon Lab → Run workflow**.
3. For your first reliable run choose: `tool=httpx`, `target_mode=local`, `lab_target=miniapp`, `scan_profile=detailed`, and `authorization_confirmed=true`.
4. Inspect the job steps, **Job Summary**, and **Artifacts → hacking-automation-...** for `report.html`, `report.json`, `summary.md`, `preflight.json`, `tool-execution.json`, `tool.log` and native CLI results.
5. Next try external mode with your own deployed project: `tool=httpx`, `target_mode=external`, `target_url=https://YOUR-AUTHORIZED-SITE.example`, `scan_profile=detailed`, `authorization_confirmed=true`, `project_related_confirmed=true`. Clear the other target inputs.

### Manual workflow inputs

| Input | Meaning |
| --- | --- |
| `tool` | `nmap`, `subfinder`, `httpx`, `nuclei` |
| `target_mode` | `local` (in-runner lab) or `external` (authorized project host) |
| `lab_target` | `miniapp` (port 8765) or `juice-shop` (port 3000); ignored in external mode |
| `target_domain` | Domain or FQDN for external Nmap, Subfinder or HTTPx |
| `target_ip` | Single external IP for Nmap or HTTPx |
| `target_url` | Single HTTP(S) URL for HTTPx or Nuclei |
| `ports` | Comma-separated individual TCP ports for external Nmap, up to 10; default `22,80,443,3000,8080,8443` |
| `scan_profile` | `quick` or `detailed` (default `detailed`) |
| `authorization_confirmed` | Required acknowledgment of permission to test |
| `project_related_confirmed` | Additional acknowledgment for external targets |

**Exactly one** external target field must be set, appropriate to the selected tool. There is no fixed list of hostnames. No ranges or CIDR targeting, no custom shell arguments and no brute-force discovery. Nuclei external requires `target_url`, but now accepts HTTP **or** HTTPS URLs. Do not submit URLs with tokens, passwords or query strings. Public repository logs/artifacts can be readable by others.

## What each tool actually does

| Tool | Quick | Detailed | Files |
| --- | --- | --- | --- |
| Nmap | TCP connect probe of selected ports | Adds lightweight service/version detection and safe `http-title,http-headers,ssl-cert` NSE scripts | `nmap.xml`, `nmap.txt` |
| Subfinder | Passive provider discovery (2-minute budget) | Broader passive `-all` sources (4-minute budget); enrich up to 30 names with A/AAAA/CNAME DNS results | `subfinder.jsonl`, `subdomains-dns.json` |
| ProjectDiscovery HTTPx | HTTP status/title/server, IP, CNAME, technology and CDN fingerprints, TLS metadata, redirect, latency, plus sanitized GET header preflight | Up to three known paths (`/`, `/robots.txt`, `/.well-known/security.txt`), except when a specific URL path is provided | `httpx.jsonl`, `preflight.json` |
| Nuclei | Curated six HTTP informational checks for external targets or one lab-specific local template | Adds read-only checks for `/.git/HEAD` metadata and the standard `security.txt` file for external targets | `nuclei.jsonl` |

This is **not** a full vulnerability assessment. Header observations are contextual; they must not be treated as exploit confirmations. `Nuclei` uses only templates checked into this repository, **not** a broad library of community templates. No destructive tests are included.

### Evidence and interpretation

Every job **attempts** to generate `report.json`, `summary.md` and `report.html`, even if the scan fails, through a separate `if: always()` workflow step. `tool-execution.json` distinguishes a completed command from a failed command. The report lists checks performed, meaningful observed results, limitations and suggested manual verification. Empty results do not mean an asset is secure. `preflight.json` distinguishes HTTP `HEAD` and `GET` diagnostics from real tool findings; an empty `host` is rejected rather than counted as a successful target check.

`HTTPx` artifacts intentionally avoid raw HTTP response headers and bodies; a sanitized selection of header names and values is written by the preflight step. Do not publish secrets, session tokens, or private details in public artifacts. GitHub artifact retention is set to **7 days**.

## Example configurations

- **Local Nmap:** `tool=nmap`, `target_mode=local`, `lab_target=miniapp`, `scan_profile=detailed` (port 8765).
- **External Nmap:** `tool=nmap`, `target_mode=external`, `target_domain=YOUR-OWN-SITE`, `ports=80,443,8080`, `scan_profile=detailed`.
- **External HTTPx:** `tool=httpx`, `target_mode=external`, `target_url=https://YOUR-OWN-SITE`, `scan_profile=detailed`.
- **External Nuclei:** `tool=nuclei`, `target_mode=external`, `target_url=https://YOUR-OWN-SITE`, `scan_profile=detailed`.
- **Subfinder:** `tool=subfinder`, `target_mode=external`, `target_domain=YOUR-OWN-ROOT-DOMAIN`, `scan_profile=detailed`. Passive providers may return zero results even when subdomains exist; some providers require optional API credentials not configured by this lab.

The placeholders above are not routable targets. Replace them with a project you administer and whose hosting terms permit the specified activity. Do not treat the OWASP public demos as unrestricted scanning targets.

## Troubleshooting

1. If `report.json` is absent, confirm that the **Generate interpreted security brief and job summary** step actually ran; check that the full repository, not just the YAML, was uploaded.
2. If `preflight.json` reports an empty host or DNS `addresses: [""]`, the input was lost or validated incorrectly. The current code rejects an empty host. Verify you selected `external` and populated exactly one appropriate target input.
3. If preflight returns 200 but the scanner returns zero JSONL results, inspect `tool.log`, the CLI exit code, TLS settings, and tool-specific input syntax. Preflight success is **not** scan success.
4. If Nmap finds no ports, verify the **actual** server port and that the chosen path is accessible from the runner. A CDN can hide origin services.
5. If Subfinder returns zero names, passive coverage may be insufficient; `-all` still does not guarantee results.
6. If Nuclei returns zero findings, this means none of the **curated templates matched**. It is not evidence of a secure application.
7. If HTTPx output is empty for an explicit HTTPS URL, test with an owned site that you know accepts HTTPS; an explicit URL preserves its requested scheme. For domain/IP HTTPx has the default HTTPS→HTTP fallback.

## Limitations and validation

- Runners use cloud infrastructure and are **not anonymous**. Account records, network logs and public artifacts can provide traceability.
- The project deliberately limits per-run targets and requests. Avoid intrusive or repetitive scans, even on test platforms, unless authorized by their operators and by your infrastructure provider.
- Local tests cover input validation, the local application, report parsing and sample evidence; **actual Docker-based tool execution on GitHub Actions remains to be validated**.
- The `nuclei` and `httpx` images are presently referenced via upstream `latest`; production deployments should pin vetted image digests after the first working test.

For presentation purposes, show the **command, raw evidence, interpreted brief, and uncertainty** together. The point is to demonstrate honest reconnaissance rather than invent successful findings.
