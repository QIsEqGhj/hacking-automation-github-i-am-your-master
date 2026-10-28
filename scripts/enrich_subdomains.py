#!/usr/bin/env python3
"""Enrich passive Subfinder results using bounded DNS A/AAAA/CNAME lookups."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path


def collect(datafile: Path, maximum: int = 30, resolver=None):
    hosts = []
    if datafile.exists():
        for line in datafile.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            host = str(item.get('host', '')).strip().lower().rstrip('.') if isinstance(item, dict) else ''
            if host and host not in hosts:
                hosts.append(host)
            if len(hosts) >= maximum:
                break
    if resolver is None:
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver(configure=True)
            resolver.timeout = 2.0
            resolver.lifetime = 3.0
        except ImportError:
            return [{'host':h,'dns_error':'dnspython is not installed'} for h in hosts]
    def lookup(host):
        result = {'host': host, 'a': [], 'aaaa': [], 'cname': [], 'dns_errors': []}
        for typ, key in [('A','a'),('AAAA','aaaa'),('CNAME','cname')]:
            try:
                answer = resolver.resolve(host, typ, lifetime=3.0)
                result[key] = [str(x).rstrip('.') for x in answer][:8]
            except Exception as exc:
                result['dns_errors'].append(f'{typ}: {type(exc).__name__}')
        return result
    results = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(lookup,h):h for h in hosts}
        for future in as_completed(futures):
            try: results.append(future.result())
            except Exception as exc: results.append({'host':futures[future],'dns_error':str(exc)[:120]})
    return sorted(results,key=lambda x:x['host'])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--max-hosts',type=int,default=30)
    args=parser.parse_args()
    results=collect(Path(args.input), min(30,max(1,args.max_hosts)))
    Path(args.output).write_text(json.dumps({'records':results,'processed':len(results),'limit':30},indent=2)+'\n')
    print(f'DNS enrichment: {len(results)} passive names checked (up to 30)')
if __name__=='__main__': main()
