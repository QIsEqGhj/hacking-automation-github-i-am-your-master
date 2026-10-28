#!/usr/bin/env python3
"""Small, non-fatal connectivity check (DNS and one HTTP HEAD).

Only selected non-sensitive headers are saved. A HEAD response is not a Nuclei
or HTTPx finding and must not be presented as one.
"""
import argparse
import http.client
import ipaddress
import json
import socket
import ssl
from pathlib import Path
from urllib.parse import urlsplit

SAFE_HEADERS = (
    'content-type', 'server', 'location', 'strict-transport-security',
    'content-security-policy', 'x-content-type-options', 'x-frame-options',
    'referrer-policy', 'permissions-policy', 'x-powered-by',
)


def inspect(host: str, url: str, tool: str) -> dict:
    if not host or not host.strip():
        raise ValueError('Preflight target host is empty; check the workflow inputs and target normalization')
    result = {
        'tool': tool, 'host': host,
        'dns': {'addresses': [], 'error': None},
        'http_preflight': {'attempted': False, 'status': None, 'error': None,
                           'headers': {}, 'method': 'HEAD'},
    }
    try:
        try:
            ipaddress.ip_address(host)
            addresses = [host]
        except ValueError:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
        result['dns']['addresses'] = [x for x in addresses if x][:10]
    except (socket.gaierror, OSError) as exc:
        result['dns']['error'] = f'{type(exc).__name__}: {exc}'
    if tool not in ('httpx', 'nuclei') or not url:
        return result
    result['http_get'] = {'attempted': False, 'status': None, 'error': None, 'headers': {}, 'method': 'GET'}

    parsed = urlsplit(url)
    if not parsed.hostname or parsed.hostname.lower() != host.lower():
        raise ValueError('Preflight URL host does not match the validated target')
    result['http_preflight']['attempted'] = True
    conn = None
    try:
        if parsed.scheme == 'https':
            conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=6,
                                               context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=6)
        conn.request('HEAD', parsed.path or '/', headers={'User-Agent': 'OffensiveLab-Preflight/1.0'})
        response = conn.getresponse()
        result['http_preflight']['status'] = response.status
        result['http_preflight']['headers'] = {
            name: response.getheader(name)[:400]
            for name in SAFE_HEADERS if response.getheader(name)
        }
        response.read(0)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        result['http_preflight']['error'] = f'{type(exc).__name__}: {exc}'[:400]
    finally:
        if conn:
            conn.close()
    # GET metadata often differs from HEAD. Do not read bodies or follow redirects.
    get = result['http_get']
    get['attempted'] = True
    conn = None
    try:
        if parsed.scheme == 'https':
            conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=6,
                                               context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=6)
        conn.request('GET', parsed.path or '/', headers={'User-Agent': 'OffensiveLab-Preflight/1.0'})
        response = conn.getresponse()
        get['status'] = response.status
        get['headers'] = {name: response.getheader(name)[:400]
                          for name in SAFE_HEADERS if response.getheader(name)}
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        get['error'] = f'{type(exc).__name__}: {exc}'[:400]
    finally:
        if conn: conn.close()
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
        http = data['http_preflight']
        print('HTTP HEAD preflight: ' + (str(http['status']) if http['status'] is not None else http['error'] or 'unknown'))
        print('HEAD is diagnostic only; a website may reject HEAD and still respond to GET.')
        get = data.get('http_get') or {}
        print('HTTP GET preflight: ' + (str(get.get('status')) if get.get('status') is not None else get.get('error') or 'unknown'))


if __name__ == '__main__':
    main()
