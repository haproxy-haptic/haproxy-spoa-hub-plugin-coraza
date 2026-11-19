#!/usr/bin/env python3
"""Interleaved, single-in-flight release-plugin comparison through a real hub."""
import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import platform
from statistics import median
import subprocess
import tempfile
import time

from spop import Client, message


POLICY = """Include @coraza.conf-recommended
SecRxPreFilter On
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule ARGS "@streq benchmark-body-control" "id:10101,phase:2,deny,status:409"
SecRule RESPONSE_BODY "@streq benchmark-response-control" "id:10102,phase:4,deny,status:412"
"""


def request(method='GET', query='', media=None, body=b'', *, path='/catalog/search'):
    headers = 'Host: shop.example.com\r\nUser-Agent: BackendBench/1.0\r\nAccept: */*\r\n'
    if media:
        headers += f'Content-Type: {media}\r\nContent-Length: {len(body)}\r\n'
    return message('check-request', {
        'src-ip': '192.0.2.1', 'src-port': 42000, 'dst-ip': '192.0.2.2', 'dst-port': 443,
        'method': method, 'path': path, 'query': query, 'version': 'HTTP/1.1',
        'headers': headers.encode(), 'body': body, 'body-mode': 'buffered' if media else 'none',
        'body-complete': True,
    })


GET = request(query='category=books&page=2')
FORM = request('POST', media='application/x-www-form-urlencoded', body=b'category=books&page=2')
JSON = request('POST', media='application/json', body=b'{"category":"books","page":2}')


def response(tx_id, body=b'available'):
    return message('check-response', {
        'id': tx_id, 'status': 200, 'version': 'HTTP/1.1', 'body': body,
        'headers': f'Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n'.encode(),
    })


def check(result, action='allow', status=0, rule_id=None, prefix=''):
    expected = {'coraza.__status': 'ok', 'coraza.' + prefix + 'action': action,
                'coraza.' + prefix + 'status': status}
    if rule_id is not None:
        expected['coraza.' + prefix + 'rule_id'] = rule_id
    for key, value in expected.items():
        if result.get(key) != value:
            raise ValueError(f'expected {key}={value!r}: {result}')


def probes(client, responses):
    decisions = {}
    def verify(label, data, *args, **kwargs):
        _, result = client.notify(data)
        check(result, *args, **kwargs)
        decisions[label] = {k: v for k, v in result.items() if k != 'coraza.id'}
        return result.get('coraza.id')
    for label, payload in [('GET', GET), ('form', FORM), ('json', JSON)]:
        tx_id = verify(label, payload)
        if responses:
            verify(label + '-response', response(tx_id), prefix='resp_')
    # Ordinary method outside the CRS default allowlist exercises stock CRS enforcement.
    verify('crs-method', request('BREW'), 'deny', 403, 949110)
    verify('form-control', request('POST', media='application/x-www-form-urlencoded',
                                   body=b'label=benchmark-body-control'), 'deny', 409, 10101)
    verify('json-control', request('POST', media='application/json',
                                   body=b'{"label":"benchmark-body-control"}'), 'deny', 409, 10101)
    if responses:
        tx_id = verify('response-control-request', GET)
        verify('response-control', response(tx_id, b'benchmark-response-control'),
               'deny', 412, 10102, 'resp_')
    return decisions


class HubStartupError(RuntimeError):
    pass


@contextmanager
def hub(binary, plugin, directory, cpus, responses, policy=POLICY):
    directory.mkdir()
    address = directory / 'hub.sock'
    config = directory / 'hub.toml'
    config.write_text(f'''plugin_dir = {json.dumps(str(plugin.parent))}
default_timeout_ms = 2000
worker_threads = 1
max_blocking_threads = 2
log_level = "error"
[[listeners]]
type = "unix"
address = {json.dumps(str(address))}
[[plugins]]
name = "coraza"
library = {json.dumps(plugin.name)}
messages = ["check-request", "check-response"]
[plugins.params]
directives = {json.dumps(policy)}
response_check = {str(responses).lower()}
rule_watch_interval_ms = 0
''')
    log = directory / 'hub.log'
    with log.open('w') as sink:
        process = subprocess.Popen([binary, '--config', config], cwd=directory,
                                   stdout=sink, stderr=subprocess.STDOUT,
                                   preexec_fn=lambda: os.sched_setaffinity(0, cpus))
    try:
        deadline = time.monotonic() + 60
        while True:
            if process.poll() is not None:
                raise HubStartupError(f'hub exited ({process.returncode}): {log.read_text()[-4000:]}')
            try:
                client = Client(address)
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() > deadline:
                    raise RuntimeError(f'hub startup timeout: {log.read_text()[-4000:]}')
                time.sleep(0.05)
            else:
                break
        try:
            yield process.pid, client
        finally:
            client.sock.close()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def sample(pid, client, workload, payload, count):
    # Linux per-process CPU clock includes Tokio and all Go runtime workers.
    clock = (~pid << 3) | 2
    start = time.clock_gettime_ns(clock)
    latency = []
    for _ in range(count):
        elapsed, result = client.notify(payload)
        check(result)
        if workload == 'request-response':
            extra, reply = client.notify(response(result['coraza.id']))
            check(reply, prefix='resp_')
            elapsed += extra
        latency.append(elapsed / 1000)
    cpu_us = (time.clock_gettime_ns(clock) - start) / (count * 1000)
    latency.sort()
    def percentile(q):
        return latency[math.ceil(len(latency) * q) - 1]
    return {'p50_us': percentile(0.50), 'p95_us': percentile(0.95),
            'p99_us': percentile(0.99), 'hub_cpu_us': cpu_us}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_plugin(path):
    go = subprocess.run(['go', 'version', '-m', path], text=True, capture_output=True)
    symbols = subprocess.check_output(['nm', '--defined-only', path], text=True)
    names = {row.split()[-1] for row in symbols.splitlines() if row.split()}
    if not names:
        raise ValueError(f'need unstripped release library to check symbols: {path}')
    markers = ('runtime.main', 'crosscall2', '_cgo_init', 'libinjection_sqli', 'libinjection_xss')
    return {'bytes': path.stat().st_size, 'go_build_info': go.returncode == 0 and bool(go.stdout.strip()),
            'go_version': go.stdout.splitlines()[0].split(': ', 1)[-1] if go.stdout.strip() else None,
            'defined_markers': sorted(names.intersection(markers))}


def inspect_backends(workers):
    artifacts = {name: inspect_plugin(path) for name, path in workers.items()}
    if not artifacts['go']['go_build_info'] or 'runtime.main' not in artifacts['go']['defined_markers']:
        raise ValueError(f"missing Go runtime in Go comparator: {artifacts['go']}")
    if artifacts['rust']['go_build_info'] or artifacts['rust']['defined_markers']:
        raise ValueError(f"unexpected Go/C detector in Rust comparator: {artifacts['rust']}")
    return artifacts


def memory(pid):
    # Kernel RSS high-water and proportional resident pages of this hub process.
    fields = {}
    for filename, keys in [('status', ('VmHWM',)), ('smaps_rollup', ('Pss', 'Rss'))]:
        for row in Path(f'/proc/{pid}/{filename}').read_text().splitlines():
            key, _, value = row.partition(':')
            if key in keys:
                size, unit = value.split()
                if unit != 'kB':
                    raise ValueError(f'unexpected memory unit {unit}')
                fields[key + '_KiB'] = int(size)
    return fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('hub', 'go', 'rust', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--server-cpus', required=True, help='two or more comma-separated logical CPUs')
    parser.add_argument('--client-cpu', required=True, type=int)
    parser.add_argument('--pairs', type=int, default=12)
    parser.add_argument('--count', type=int, default=300)
    args = parser.parse_args()
    cpus = {int(value) for value in args.server_cpus.split(',')}
    if args.client_cpu in cpus or len(cpus) < 2 or args.pairs < 2 or args.count < 1:
        parser.error('use separate client and server CPUs, at least two pairs and a positive count')
    workers = {k: getattr(args, k).resolve(strict=True) for k in ('go', 'rust')}
    binary = args.hub.resolve(strict=True)
    artifacts = inspect_backends(workers)
    os.sched_setaffinity(0, {args.client_cpu})
    result = {
        'host': platform.platform(), 'hub_version': subprocess.check_output([binary, '--version'], text=True).strip(),
        'sha256': {k: digest(v) for k, v in {'hub': binary, **workers}.items()},
        'artifacts': artifacts, 'post_workload_memory': {},
        'policy_sha256': hashlib.sha256(POLICY.encode()).hexdigest(),
        'server_cpus': sorted(cpus), 'client_cpu': args.client_cpu,
        'pairs': args.pairs, 'requests_per_batch': args.count,
        'probes': {}, 'probe_field_differences': {}, 'batches': {}, 'summary': {},
    }
    with tempfile.TemporaryDirectory(prefix='spoa-bench-') as temp:
        for profile, workloads in [('request', {'get': GET, 'form': FORM, 'json': JSON}),
                                   ('response', {'request-response': GET})]:
            with ExitStack() as stack:
                servers = {name: stack.enter_context(hub(binary, path, Path(temp) / (profile + name),
                                                        cpus, profile == 'response'))
                           for name, path in workers.items()}
                result['probes'][profile] = {k: probes(client, profile == 'response')
                                             for k, (_, client) in servers.items()}
                go, rust = (result['probes'][profile][name] for name in ('go', 'rust'))
                result['probe_field_differences'][profile] = {
                    label: {field: {'go': go[label].get(field), 'rust': rust[label].get(field)}
                            for field in sorted(go[label].keys() | rust[label].keys())
                            if go[label].get(field) != rust[label].get(field)}
                    for label in go if go[label] != rust[label]
                }
                for workload, payload in workloads.items():
                    for pid, client in servers.values():
                        sample(pid, client, workload, payload, 100)
                    batches = []
                    for pair in range(args.pairs):
                        order = ('go', 'rust') if pair % 2 == 0 else ('rust', 'go')
                        batches.append({name: sample(*servers[name], workload, payload, args.count)
                                        for name in order})
                    result['batches'][workload] = batches
                    summary = {}
                    for metric in batches[0]['go']:
                        summary[metric] = {
                            name: round(median(b[name][metric] for b in batches), 2)
                            for name in workers
                        }
                        summary[metric]['paired_rust_change_pct'] = round(median(
                            100 * (b['rust'][metric] / b['go'][metric] - 1) for b in batches), 2)
                    result['summary'][workload] = summary
                    result['post_workload_memory'][workload] = {
                        name: memory(pid) for name, (pid, _) in servers.items()
                    }
                    print(workload, json.dumps(summary), flush=True)
    with args.output.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')


if __name__ == '__main__':
    main()
