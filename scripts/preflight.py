#!/usr/bin/env python3
"""Non-fatal diagnostics for a single explicitly authorized project target.

Checks DNS and, for HTTP tools, sends one HEAD request. This is connectivity
preflight, not a vulnerability scan; it cannot certify a tool found anything.
"""
import argparse
import http.client
import ipaddress
import json
import socket
import ssl
from pathlib import Path
from urllib.parse import urlsplit


def inspect(host: str, url: str, tool: str) -> dict:
    result = {"tool": tool, "host": host, "dns": {"addresses": [], "error": None},
              "http_preflight": {"attempted": False, "status": None, "error": None}}
    try:
        try:
            ipaddress.ip_address(host)
            addresses = [host]
        except ValueError:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
        result["dns"]["addresses"] = addresses[:10]
    except (socket.gaierror, OSError) as exc:
        result["dns"]["error"] = str(exc)
    if tool not in ("httpx", "nuclei") or not url:
        return result
    parsed = urlsplit(url)
    result["http_preflight"]["attempted"] = True
    conn = None
    try:
        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=6, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=6)
        conn.request("HEAD", parsed.path or "/", headers={"User-Agent": "OffensiveLab-Preflight/1.0"})
        response = conn.getresponse()
        result["http_preflight"]["status"] = response.status
        result["http_preflight"]["location"] = response.getheader("location")
        response.read(0)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        result["http_preflight"]["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if conn:
            conn.close()
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--url', default='')
    parser.add_argument('--tool', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    data = inspect(args.host, args.url, args.tool)
    Path(args.output).write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    print(f"DNS addresses: {', '.join(data['dns']['addresses']) or 'none'}")
    if data['dns']['error']:
        print(f"DNS warning: {data['dns']['error']}")
    if data['http_preflight']['attempted']:
        print('HTTP HEAD preflight: ' + (str(data['http_preflight']['status']) if data['http_preflight']['status'] is not None else data['http_preflight']['error'] or 'unknown'))
        print('HEAD preflight is diagnostic; websites may reject HEAD while accepting GET.')

if __name__ == '__main__':
    main()
