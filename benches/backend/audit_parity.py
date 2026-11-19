#!/usr/bin/env python3
"""Compare serial JSON audit selection and contents through real Go and Rust plugins."""
import argparse
from difflib import unified_diff
import json
import os
from pathlib import Path
import re
import tempfile

from compare import POLICY, check, hub, request
from spop import message


BASE = """SecRuleEngine On
SecRequestBodyAccess On
SecAuditEngine RelevantOnly
SecAuditLogFormat JSON
SecAuditLogParts ABFHKZ
"""

POLICIES = {
    'crs': 'SecRule ARGS_GET:kind "@streq books" "id:511,phase:1,deny,status:409,log,msg:catalog"\n' + POLICY + '\nSecAuditEngine RelevantOnly\nSecAuditLogFormat JSON\nSecAuditLogParts ABFHKZ',

    'flags': BASE + '''
SecRule ARGS_GET:kind "@streq books" "id:501,phase:1,pass,nolog,auditlog,msg:'kind',logdata:'%{MATCHED_VAR}'"
SecRule ARGS_GET:kind "@streq books" "id:502,phase:1,pass,log,noauditlog,msg:'private-rule'"
SecRule ARGS_POST:marker "@streq two" "id:503,phase:2,pass,auditlog,msg:'marker'"
''',
    'status': BASE + '''
SecAuditLogRelevantStatus "^(403|418|503)$"
SecRule ARGS_GET:kind "@streq books" "id:504,phase:1,pass,log,msg:'books'"
SecRule ARGS_GET:kind "@streq tea" "id:505,phase:1,deny,status:418,nolog"
''',
    'all': BASE + '''
SecAuditEngine On
SecRule ARGS_GET:kind "@streq books" "id:506,phase:1,pass,ctl:auditLogParts=-B,ctl:auditLogParts=-F"
SecRule ARGS_GET:kind "@streq tea" "id:507,phase:1,pass,ctl:auditEngine=Off"
''',
    'detect': BASE + '''
SecRuleEngine DetectionOnly
SecAuditLogRelevantStatus "^409$"
SecRule ARGS_GET:kind "@streq books" "id:508,phase:1,deny,status:409,log,msg:'review only'"
''',
    'multi': BASE + '''
SecRule ARGS_GET:kind|ARGS_GET:other "@streq books" "id:509,phase:2,pass,log,msg:'%{MATCHED_VAR_NAME}',logdata:'%{MATCHED_VAR}',severity:NOTICE"
''',
    'chain': BASE + '''
SecRule REQUEST_METHOD "@streq POST" "id:510,phase:2,pass,log,chain,msg:'method'"
SecRule ARGS_GET:kind "@streq books" "logdata:'%{MATCHED_VAR}'"
''',
}

# POST bodies contain a sentinel in a field never referenced in logdata.
PROBES = [('kind=books&other=books', 200), ('kind=tea', 503), ('plain=true', 503), ('plain=true', 200)]


def normalize(record):
    txn = record['transaction']
    assert re.fullmatch(r'\d{4}/\d\d/\d\d \d\d:\d\d:\d\d', txn.pop('timestamp'))
    ts = txn.pop('unix_timestamp')
    assert ts > 0
    producer = txn.get('producer')
    if producer:
        watch = producer.pop('stopwatch')
        assert re.fullmatch(rf'{ts} \d+; combined=\d+, p1=\d+, p2=\d+, p3=\d+, p4=\d+, p5=\d+', watch)
    assert txn['request']['body'] == ''
    assert txn.get('response', {}).get('body', '') == ''
    assert 'NONPUBLIC-BODY' not in json.dumps(record)
    return record


def run(binary, plugin, directory, policy, stdout):
    target = '/dev/stdout' if stdout else directory / 'audit.ndjson'
    with hub(binary, plugin, directory, sorted(os.sched_getaffinity(0))[:1], True,
             policy + f'\nSecAuditLog {target}') as (_, client):
        for query, status in PROBES:
            _, result = client.notify(request('POST', query, 'application/x-www-form-urlencoded',
                                              b'marker=two&unused=NONPUBLIC-BODY-request'))
            if result['coraza.action'] == 'allow':
                _, resp = client.notify(message('check-response', {
                    'id': result['coraza.id'], 'status': status, 'version': 'HTTP/1.1',
                    'headers': b'Content-Type: text/plain\r\nX-Repeat: a\r\nX-Repeat: b\r\n',
                    'body': b'NONPUBLIC-BODY-response',
                }))
                check(resp, prefix='resp_')
    source = directory / 'hub.log' if stdout else target
    rows = []
    for line in source.read_text().splitlines():
        if stdout and not line.startswith('{'):
            continue
        record = json.loads(line)
        if not stdout or 'transaction' in record:
            rows.append(normalize(record))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('hub', 'go', 'rust'):
        parser.add_argument('--' + option, type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='coraza-audit-') as temp:
        for name, policy in POLICIES.items():
            expected = {'flags': 4, 'status': 2, 'all': 3, 'detect': 1, 'multi': 1, 'chain': 1, 'crs': 3}[name]
            rows = [run(args.hub.resolve(), lib.resolve(), Path(temp) / (name + backend), policy, name == 'flags')
                    for backend, lib in [('go', args.go), ('rust', args.rust)]]
            if rows[0] != rows[1] or len(rows[0]) != expected:
                formatted = [json.dumps(records, sort_keys=True, indent=2).splitlines() for records in rows]
                diff = '\n'.join(unified_diff(*formatted, fromfile='Go', tofile='Rust', lineterm=''))
                raise ValueError(f'{name} expected {expected} records, got {len(rows[0])} and {len(rows[1])}\n{diff}')
            print(f'{name}: {expected} matching records')

if __name__ == '__main__':
    main()
