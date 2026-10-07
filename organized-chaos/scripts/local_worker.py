"""Execute one exact approved replacement through a local model's file-tool request.

The parent owns approval and candidate acceptance. No arbitrary path, code execution,
or shell tools are exposed. Client cancellation does not prove server cancellation.
"""
import json
from pathlib import Path
import re
import sys

import local_connection as local
import onboarding
from worker_gate import MAX_SOURCE, digest, read_file

TOOL = 'apply_approved_replacement'


def implement(envelope):
    worker = envelope['worker']
    name, source = envelope['filename'], envelope['source']
    if (type(name) is not str or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', name)
            or type(source) is not str or not source or len(source.encode()) > MAX_SOURCE):
        raise ValueError('Invalid approved replacement')
    entry = {'id': worker['model'], 'provider': 'local', 'pool_alias': 'local',
             'enabled': True, 'roles': ['implementation'], 'billing_policy': 'local_only',
             'execution': {'kind': worker['kind'], 'url': worker['url']}}
    onboarding._validate_config({'schema_version': 1, 'models': [entry], 'preferences': {}})
    if worker['kind'] != 'local_http':
        raise ValueError('Expected a local HTTP worker')
    target = Path.cwd() / name
    baseline = read_file(target)
    if digest(baseline) != envelope['baseline_sha256']:
        raise ValueError('Baseline changed')
    url, model = worker['url'], worker['model']

    def instance():
        return local.model_instance(local.request(url, 'GET', '/api/v1/models', timeout=None), model)[:2]

    observed = instance()
    response = local.request(url, 'POST', '/v1/chat/completions', {
        'model': observed[0], 'stream': False, 'temperature': 0, 'store': False,
        'messages': [{'role': 'user', 'content':
            f'The coordinator approved replacing {name} with the exact source below. '
            'Call apply_approved_replacement with no arguments to apply it. '
            'The tool already owns the approved path and bytes. If you cannot apply it, stop.\n'
            'APPROVED SOURCE:\n' + source}],
        'tools': [{'type': 'function', 'function': {'name': TOOL,
            'description': 'Apply the exact coordinator-approved source to its approved file.',
            'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False}}}],
    }, timeout=None)
    if type(response) is not dict or response.get('model') != observed[0]:
        raise ValueError('Unexpected responding model')
    choices = response.get('choices')
    if type(choices) is not list or len(choices) != 1:
        raise ValueError('Expected one tool response')
    choice = choices[0]
    if type(choice) is not dict or choice.get('finish_reason') != 'tool_calls':
        raise ValueError('Worker did not request the file tool')
    message = choice.get('message')
    if type(message) is not dict or message.get('role') != 'assistant':
        raise ValueError('Invalid worker message')
    calls = message.get('tool_calls')
    if type(calls) is not list or len(calls) != 1 or type(calls[0]) is not dict:
        raise ValueError('Expected one file-tool call')
    call = calls[0]
    function = call.get('function')
    if (call.get('type') != 'function' or type(function) is not dict
            or function.get('name') != TOOL or type(function.get('arguments')) is not str
            or json.loads(function['arguments']) != {}):
        raise ValueError('Unapproved tool or arguments')
    if instance() != observed or read_file(target) != baseline:
        raise ValueError('Runtime or baseline changed')
    target.write_bytes(source.encode())
    return {'status': 'applied', 'executor': 'local-file-tool', 'model': model}


def main():
    try:
        raw = sys.stdin.buffer.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise ValueError('Envelope too large')
        result = implement(json.loads(raw))
    except (OSError, ValueError, KeyError, TypeError, local.TestFailed):
        # Do not echo model output or configuration into process logs.
        print(json.dumps({'status': 'failed'}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    sys.exit(main())
