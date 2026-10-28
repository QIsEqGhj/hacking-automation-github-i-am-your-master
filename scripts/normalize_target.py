#!/usr/bin/env python3
"""Validate one target and produce safe, structured arguments for the demo tools."""
import argparse
import ipaddress
import json
import re
import sys
from urllib.parse import urlsplit, urlunsplit


def normalize_host(value: str) -> tuple[str, int]:
    value = value.strip('[]')
    try:
        address = ipaddress.ip_address(value)
        if address.is_link_local or address.is_multicast or address.is_unspecified:
            raise ValueError('Link-local, multicast, and unspecified IP addresses are not valid demo targets')
        return str(address), address.version
    except ValueError as exc:
        if 'not valid demo targets' in str(exc):
            raise
    # International names can be normalized, but unsafe characters and wildcards are rejected.
    try:
        name = value.encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise ValueError('Invalid hostname') from exc
    if len(name) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+', name):
        raise ValueError('Expected a single fully qualified domain or IP address, not a list or range')
    return name, 0


def normalize(tool: str, target: str, ports: str) -> dict:
    target = target.strip()
    if not target or len(target) > 2048 or any(c.isspace() for c in target) or any(c in target for c in '\r\n\x00'):
        raise ValueError('Specify a single hostname, IP address, or HTTP(S) URL without whitespace')
    if tool == 'subfinder':
        if '://' in target or '/' in target or ':' in target:
            raise ValueError('Subfinder requires only a domain name')
        domain, version = normalize_host(target)
        if version or '.' not in domain:
            raise ValueError('Subfinder requires a fully qualified domain, not an IP')
        return dict(host=domain, url='', domain=domain, ports='', ipv6=False)

    # Bare IPv6 addresses are allowed for Nmap; HTTP-based tools need URL brackets.
    try:
        raw_ip = ipaddress.ip_address(target.strip('[]'))
        host, version = normalize_host(str(raw_ip))
        url = f'http://[{host}]' if version == 6 else f'http://{host}'
        if tool == 'nmap':
            url = ''
    except ValueError:
        if '://' in target:
            parsed = urlsplit(target)
            if parsed.scheme not in ('http', 'https'):
                raise ValueError('Only http and https URLs are accepted')
        else:
            parsed = urlsplit('//'+target)
        if parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise ValueError('Credentials, fragments, and query strings are not accepted')
        if not parsed.hostname:
            raise ValueError('Target hostname is missing')
        host, version = normalize_host(parsed.hostname)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError('Invalid TCP port in URL') from exc
        if parsed.path and (tool == 'nmap' or (not target.startswith(('https://','http://')))):
            raise ValueError('Paths require an explicit HTTP(S) URL and cannot be used with Nmap')
        netloc = f'[{host}]' if version == 6 else host
        if port:
            netloc += ':'+str(port)
        scheme = parsed.scheme or ('http' if version else 'https')
        url = urlunsplit((scheme, netloc, parsed.path or '', '', ''))
    if tool == 'nuclei' and not url.startswith('https://'):
        raise ValueError('External Nuclei informational HTTPS-header template requires an https:// URL')

    selected_ports = []
    if tool == 'nmap':
        candidates = ports.split(',')
        if not 1 <= len(candidates) <= 10:
            raise ValueError('Provide between 1 and 10 individual TCP ports')
        for item in candidates:
            if not item.isascii() or not item.isdigit():
                raise ValueError('Ports must be comma-separated integers (no ranges)')
            number = int(item)
            if number < 1 or number > 65535:
                raise ValueError('Port must be between 1 and 65535')
            selected_ports.append(number)
    return dict(host=host, url=url, domain=host if not version else '', ports=','.join(map(str,dict.fromkeys(selected_ports))), ipv6=version == 6)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tool', required=True, choices=['nmap', 'subfinder', 'httpx', 'nuclei'])
    parser.add_argument('--target', required=True)
    parser.add_argument('--ports', default='80,443')
    args = parser.parse_args()
    try:
        print(json.dumps(normalize(args.tool,args.target,args.ports),ensure_ascii=True))
    except ValueError as exc:
        print(f'Invalid external target: {exc}',file=sys.stderr)
        sys.exit(2)

if __name__ == '__main__':
    main()
