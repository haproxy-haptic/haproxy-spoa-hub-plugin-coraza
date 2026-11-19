#!/usr/bin/env python3
"""Compare all SPOA variables for benign policies with tagged Go Coraza."""
import argparse
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from compare import FORM, GET, POLICY, HubStartupError, digest, hub, inspect_backends, probes, request, response


FORM_MEDIA = 'application/x-www-form-urlencoded'
BASE = """SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
"""


@dataclass(frozen=True)
class Policy:
    name: str
    directives: str
    requests: tuple[tuple[str, bytes], ...]
    response_body: bytes | None = None


def form(query, body):
    return request('POST', query, FORM_MEDIA, body.encode())


def fixtures():
    split = form('a=green', 'b=blue')

    def count(name, targets, amount):
        return Policy(name, BASE + f'SecRule {targets} "@eq {amount}" "id:10101,phase:2,deny,status:409"',
                      (('split', split), ('empty', request()), ('body-only', form('', 'b=blue'))))

    def runtime_exclusion(collection):
        directives = f'''SecRule REQUEST_METHOD "@streq POST" "id:10100,phase:1,pass,ctl:ruleRemoveTargetById=10101;{collection}:a"
SecRule ARGS "@streq green" "id:10101,phase:2,deny,status:409"
'''
        return Policy('runtime-exclusion-' + collection.lower(), BASE + directives,
                      (('query', form('a=green', 'ignored=blue')), ('body', form('', 'a=green')),
                       ('included-body', form('a=green', 'b=green')), ('get', request(query='a=green'))))

    # Changing the winner lets the single request callback expose header-phase scheduling.
    early = """SecRule REQUEST_METHOD "@streq POST" "id:10101,phase:2,deny,status:409"
SecRule REQUEST_URI "@beginsWith /catalog" "id:10102,phase:1,deny,status:410"
"""
    names = """SecAction "id:10100,phase:1,pass,ctl:requestBodyProcessor=JSON"
SecRule ARGS_NAMES "@endsWith Label" "id:10101,phase:2,deny,status:409"
"""
    matches = """SecRule ARGS:a|ARGS:b|ARGS:c "@streq green" "id:10101,phase:2,deny,status:409,severity:CRITICAL"
"""
    chain = """SecRule REQUEST_METHOD "@streq POST" "id:10101,phase:2,deny,status:409,chain,severity:NOTICE"
SecRule ARGS:b "@streq blue" "setvar:tx.selected=1"
SecRule TX:selected "@eq 1" "id:10102,phase:2,deny,status:410"
"""
    count_actions = """SecRule ARGS:a|ARGS:b "@streq green" "id:10101,phase:2,pass,setvar:tx.seen=+1"
SecRule TX:seen "@eq 2" "id:10102,phase:2,deny,status:409"
"""
    chain_score = """SecRule REQUEST_METHOD "@streq POST" "id:10101,phase:2,pass,chain"
SecRule ARGS:label|ARGS:other "@streq green" "setvar:tx.score=+1"
SecRule TX:score "@eq 3" "id:10104,phase:2,deny,status:411"
SecRule TX:score "@eq 2" "id:10102,phase:2,deny,status:410"
SecRule TX:score "@eq 1" "id:10103,phase:2,deny,status:409"
"""
    response_phases = """SecRule RESPONSE_STATUS "@streq 200" "id:10101,phase:4,deny,status:409"
SecRule RESPONSE_HEADERS:Content-Type "@streq text/plain" "id:10102,phase:3,deny,status:410"
"""
    response_chain = """SecRule REQUEST_METHOD "@streq GET" "id:10101,phase:1,pass,setvar:tx.inspect=1"
SecRule TX:inspect "@eq 1" "id:10102,phase:4,deny,status:412,chain"
SecRule RESPONSE_BODY "@streq selected"
"""
    skip = """SecRule REQUEST_METHOD "@streq POST" "id:10100,phase:2,pass,skipAfter:PASS"
SecRule ARGS:a "@streq green" "id:10101,phase:2,deny,status:409"
SecMarker PASS
SecRule ARGS:b "@streq green" "id:10102,phase:2,deny,status:410"
"""
    regex_literal = """SecAction "id:10601,phase:1,pass,setvar:'tx.pattern=blue'"
SecRule ARGS:colour "@rx ^%{tx.pattern}$" "id:10602,phase:2,deny,status:409"
"""
    pending_skip = """SecRule ARGS_POST:a "@streq green" "id:10501,phase:2,deny,status:412"
{marker}
SecRule REQUEST_METHOD "@streq POST" "id:10502,phase:1,pass,skipAfter:before"
SecRule ARGS_POST:b "@streq green" "id:10503,phase:2,deny,status:409"
"""
    def marker_scope(label, action, markers, expected_name):
        directives = f'''SecRule REQUEST_METHOD "@streq GET" "id:10504,phase:1,pass{action}"
{markers}
SecRule MATCHED_VAR_NAME "@streq {expected_name}" "id:10505,phase:1,deny,status:409"
'''
        return Policy('marker-' + label, BASE + directives, (('get', GET),))

    matched_vars = {
        'plural-reset': """SecRule REQUEST_METHOD "@streq GET" "id:10201,phase:1,pass"
SecRule &MATCHED_VARS "@eq 0" "id:10202,phase:1,deny,status:409"
""",
        'last-scalar': """SecRule REQUEST_METHOD "@streq GET" "id:10201,phase:1,pass"
SecRule REQUEST_URI "@streq /missing" "id:10202,phase:1,pass"
SecRule MATCHED_VAR "@streq GET" "id:10203,phase:1,deny,status:409"
""",
        'chain-scoped': """SecRule REQUEST_METHOD "@streq GET" "id:10201,phase:1,deny,status:409,chain"
SecRule REQUEST_URI "@beginsWith /catalog" "chain"
SecRule MATCHED_VARS:REQUEST_METHOD "@streq GET" "t:none"
""",
        'empty-name': 'SecRule MATCHED_VAR_NAME "@rx ^$" "id:10201,phase:1,deny,status:409"',
        'action-name': """SecAction "id:10201,phase:1,pass,setvar:'tx.name=%{MATCHED_VAR_NAME}'"
SecRule TX:name "@streq UNKNOWN" "id:10202,phase:1,deny,status:409"
""",
    }
    # The HAPTIC WAF catalog inserts these SecActions before loading the CRS.
    catalog = POLICY.replace('Include @owasp_crs/*.conf', '''SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET POST OPTIONS'"
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:'tx.inbound_anomaly_score_threshold=5',setvar:'tx.outbound_anomaly_score_threshold=4'"
Include @owasp_crs/*.conf
SecRuleUpdateTargetById 941320 "!ARGS:comment"''')
    return [
        Policy('phase-winner', BASE + early, (('post', split), ('get', GET))),
        count('count-two', '&ARGS', 2),
        count('count-one', '&ARGS', 1),
        count('excluded-count', '&ARGS|!ARGS:a', 1),
        count('names-count', '&ARGS_NAMES', 2),
        Policy('merged-exclusion', BASE + 'SecRule ARGS|!ARGS:a "@streq green" "id:10101,phase:2,deny,status:409"',
               (('excluded-both', form('a=green', 'a=green')), ('body-only-hit', form('a=green', 'b=green')))),
        Policy('origin-and-case', BASE + 'SecRule ARGS:label "@streq green" "id:10101,phase:2,deny,status:409"',
               (('query-first', form('Label=green', 'LABEL=green')),
                ('body-first', form('Label=red', 'LABEL=green')))),
        Policy('json-names', BASE + names, (('query', request(query='Label=green')),
               ('json', request('POST', '', 'application/json', b'{"Label":"green"}')))),
        Policy('multiple-targets', BASE + matches, (('query', request(query='a=green&b=green&c=green')),
               ('mixed', form('b=green', 'a=green&c=green')), ('body', form('', 'c=green&b=green&a=green')))),
        Policy('chain', BASE + chain, (('body-hit', split), ('body-miss', form('', 'b=red')),
               ('query-hit', form('b=blue', 'b=red')))),
        Policy('action-count', BASE + count_actions, (('query', request(query='a=green&b=green')),
               ('mixed', form('a=green', 'b=green')), ('duplicate', request(query='a=green&a=green')))),
        Policy('chain-score', BASE + chain_score, (('duplicate', form('label=green', 'label=green')),
               ('distinct', form('label=green', 'label=green&other=green')),
               ('query-only', form('label=green', 'other=amber')),
               ('body-only', form('', 'label=green')), ('miss', form('label=red', 'label=red')))),
        Policy('response-phase-winner', BASE + response_phases, (('get', GET),), b'available'),
        Policy('response-chain', BASE + response_chain, (('get', GET), ('post', FORM)), b'selected'),
        *(runtime_exclusion(collection) for collection in ('ARGS', 'ARGS_GET', 'ARGS_POST')),
        Policy('skip-after', BASE + skip, (('query', form('a=green', 'b=red')),
               ('body', form('', 'a=green')), ('marker', form('', 'b=green')), ('get', request(query='a=green')))),
        *(Policy('pending-skip-' + label, BASE + pending_skip.format(marker=marker),
                 (('body', form('', 'a=green&b=green')),))
          for label, marker in (('earlier', 'SecMarker before'), ('absent', ''))),
        marker_scope('ordinary', '', 'SecMarker MARK', 'UNKNOWN'),
        marker_scope('skip-target', ',skipAfter:MARK', 'SecMarker BEFORE\nSecMarker MARK', 'REQUEST_METHOD'),
        marker_scope('after-target', ',skipAfter:MARK', 'SecMarker MARK\nSecMarker AFTER', 'UNKNOWN'),
        Policy('marker-inside-chain', BASE + '''SecRule REQUEST_METHOD "@streq GET" "id:10504,phase:1,deny,status:409,chain"
SecMarker MARK
SecRule REQUEST_URI "@streq /missing" "t:none"
''', (('get', GET),)),
        Policy('regex-literal-operand', BASE + regex_literal, (('tx-value', form('', 'colour=blue')),
               ('literal', form('', 'colour=%25%7Btx.pattern%7D')))),
        *(Policy('regex-' + label, BASE + f'SecRule ARGS:colour "@rx {pattern}" "id:10601,phase:2,deny,status:409"',
                 (('multiline-form', form('', 'colour=red%0Ablue%0Agreen')),))
          for label, pattern in (('anchors', '^blue$'), ('multiline', '(?m)^blue$'), ('dot', '^red.*green$'))),
        *(Policy('matched-vars-' + label, BASE + rules, (('get', GET), ('post', FORM)))
          for label, rules in matched_vars.items()),
        Policy('calendar-year', BASE + 'SecRule TIME_YEAR "@rx ^[0-9]{4}$" "id:10701,phase:1,deny,status:409"',
               (('get', GET),)),
        Policy('uri-representations', BASE + """SecRule REQUEST_URI "@contains café" "id:10701,phase:1,pass,severity:NOTICE"
SecRule REQUEST_URI_RAW "@contains café" "id:10702,phase:1,pass,severity:INFO"
""", (('literal', request(path='/catalog/café')), ('encoded', request(path='/catalog/caf%C3%A9')),
      ('ascii', request(path='/catalog/edition-2')))),
        *(Policy('literal-brace-prefilter-' + mode.lower(),
                 BASE + f'SecRxPreFilter {mode}\nSecRule ARGS:note "@rx ^edition{{ok}}$" "id:10701,phase:2,deny,status:409"',
                 (('match', form('', 'note=edition%7Bok%7D')), ('miss', form('', 'note=second'))))
          for mode in ('On', 'Off')),
        Policy('custom-audit-off', BASE + 'SecAuditEngine Off', (('get', GET),)),
        Policy('stock-crs', POLICY, ()),
        Policy('haptic-catalog', catalog, ()),
    ]


def without_id(result):
    return {key: value for key, value in result.items() if key != 'coraza.id'}


def run(binary, plugin, root, cpus, policies):
    results = {}
    startup_errors = {}
    for index, item in enumerate(policies):
        with ExitStack() as stack:
            try:
                _, client = stack.enter_context(hub(binary, plugin, root / str(index), cpus, True, item.directives))
            except HubStartupError as error:
                startup_errors[item.name] = str(error)
                continue
            if not item.requests:
                results[item.name] = probes(client, True)
                continue
            result = {}
            for label, payload in item.requests:
                _, ack = client.notify(payload)
                if ack.get('coraza.__status') != 'ok' or 'coraza.id' not in ack:
                    raise ValueError(f'{item.name}/{label}: invalid request ACK: {ack}')
                result[label] = without_id(ack)
                if item.response_body is not None:
                    _, reply = client.notify(response(ack['coraza.id'], item.response_body))
                    if reply.get('coraza.__status') != 'ok' or 'coraza.resp_action' not in reply:
                        raise ValueError(f'{item.name}/{label}: invalid response ACK: {reply}')
                    result[label + '-response'] = without_id(reply)
            results[item.name] = result
    return results, startup_errors


def differences(go, rust):
    changed = {}
    for policy, requests in go.items():
        if policy not in rust:
            continue
        for name, reference in requests.items():
            actual = rust[policy][name]
            fields = {k: {'go': reference.get(k), 'rust': actual.get(k)}
                      for k in sorted(reference.keys() | actual.keys())
                      if k not in actual or k not in reference or type(actual[k]) is not type(reference[k])
                      or actual[k] != reference[k]}
            if fields:
                changed[f'{policy}/{name}'] = fields
    return changed


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    for flag in ('hub', 'go', 'rust', 'output'):
        cli.add_argument('--' + flag, type=Path, required=True)
    args = cli.parse_args()
    binaries = {name: getattr(args, name).resolve(strict=True) for name in ('hub', 'go', 'rust')}
    policies = fixtures()
    receipt = {
        'startup_errors': {},
        'hub_version': subprocess.check_output([binaries['hub'], '--version'], text=True).strip(),
        'binary_sha256': {k: digest(v) for k, v in binaries.items()},
        'artifacts': inspect_backends({k: binaries[k] for k in ('go', 'rust')}),
        'policy_sha256': {item.name: hashlib.sha256(item.directives.encode()).hexdigest() for item in policies},
    }
    with tempfile.TemporaryDirectory(prefix='spop-policy-') as tmp:
        for side in ('go', 'rust'):
            root = Path(tmp) / side
            root.mkdir()
            receipt[side], receipt['startup_errors'][side] = run(
                binaries['hub'], binaries[side], root, sorted(os.sched_getaffinity(0))[:2], policies)
    changed = differences(receipt['go'], receipt['rust'])
    receipt['differences'] = changed
    receipt['checked_acks'] = sum(len(acks) for policy, acks in receipt['go'].items() if policy in receipt['rust'])
    with args.output.open('x') as out:
        json.dump(receipt, out, indent=2)
        out.write('\n')
    failures = sum(len(items) for items in receipt['startup_errors'].values())
    print(f"{receipt['checked_acks']} ACKs compared, {len(changed)} differences, {failures} hub startup errors")
    for side, errors in receipt['startup_errors'].items():
        for policy, error in errors.items():
            print(f'{side}/{policy}: {error}')
    for label, fields in changed.items():
        print(label, json.dumps(fields))
    return int(bool(changed or failures))


if __name__ == '__main__':
    raise SystemExit(main())
