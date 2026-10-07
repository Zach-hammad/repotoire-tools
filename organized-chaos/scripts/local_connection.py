"""One bounded LM Studio response test; invoked in an owned child process.

The parent owns the absolute deadline and cancellation. Closing this HTTP client
does not prove that a runtime has stopped generation. No credentials or tools.
"""
import http.client
import json
import sys
from urllib.parse import urlsplit

import onboarding

MAX_RESPONSE = 128 * 1024
SUCCESS_TEXT = 'LOCAL_CONNECTION_OK'


class TestFailed(Exception):
    def __init__(self, state='test_failed'):
        self.state = state


def request(url, method, path, body=None, *, timeout=40):
    parts = urlsplit(url)
    # Configuration validation admits loopback only. Avoid localhost DNS/proxies.
    host = '127.0.0.1' if parts.hostname == 'localhost' else parts.hostname
    connection = http.client.HTTPConnection(host, parts.port or 80, timeout=timeout)
    try:
        connection.request(method, path, body=None if body is None else json.dumps(body),
                           headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
        response = connection.getresponse()
        if response.status in (401, 403): raise TestFailed('local_auth_required')
        if response.status != 200: raise TestFailed()
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE: raise TestFailed()
        return json.loads(raw)
    finally:
        connection.close()


def model_instance(data, model_id):
    models = data.get('models') if type(data) is dict else None
    if type(models) is not list: raise TestFailed()
    matches = [item for item in models if type(item) is dict and item.get('key') == model_id]
    if len(matches) != 1 or matches[0].get('type') != 'llm': raise TestFailed('model_not_loaded')
    model = matches[0]
    instances = model.get('loaded_instances')
    if type(instances) is not list or len(instances) != 1: raise TestFailed('model_not_loaded')
    instance = instances[0]
    config = instance.get('config') if type(instance) is dict else None
    if (type(instance) is not dict or type(instance.get('id')) is not str or not instance['id']
            or type(config) is not dict or type(config.get('context_length')) is not int
            or config['context_length'] <= 0): raise TestFailed('model_not_loaded')
    return instance['id'], config['context_length'], model


def loaded_instance(data, model_id):
    instance_id, _, model = model_instance(data, model_id)
    caps = model.get('capabilities')
    reasoning = caps.get('reasoning') if type(caps) is dict else None
    options = reasoning.get('allowed_options') if type(reasoning) is dict else None
    if type(options) is not list or 'off' not in options: raise TestFailed('unsupported_local_controls')
    return instance_id


def smoke(model):
    # Reuse the inventory's authority for provider, ID, endpoint and policy shape.
    config = {'schema_version': 1, 'models': [model], 'preferences': {}}
    onboarding._validate_config(config)
    if (not model['enabled'] or model['execution']['kind'] != 'local_http'
            or model['billing_policy'] != 'local_only'): raise TestFailed()
    url, model_id = model['execution']['url'], model['id']
    instance = loaded_instance(request(url, 'GET', '/api/v1/models'), model_id)
    result = request(url, 'POST', '/api/v1/chat', {
        'model': instance, 'input': 'Reply with exactly LOCAL_CONNECTION_OK.',
        'reasoning': 'off', 'max_output_tokens': 64, 'temperature': 0,
        'store': False, 'stream': False, 'integrations': []})
    if type(result) is not dict or result.get('model_instance_id') != instance: raise TestFailed()
    output = result.get('output')
    if (type(output) is not list or len(output) != 1 or type(output[0]) is not dict
            or output[0].get('type') != 'message' or type(output[0].get('content')) is not str
            or output[0]['content'].strip() != SUCCESS_TEXT): raise TestFailed()
    if loaded_instance(request(url, 'GET', '/api/v1/models'), model_id) != instance: raise TestFailed()
    return 'ready'


def availability(model):
    """Bounded metadata-only observation; never sends a generation request."""
    config = {'schema_version': 1, 'models': [model], 'preferences': {}}
    onboarding._validate_config(config)
    if (not model['enabled'] or model['execution']['kind'] != 'local_http'
            or model['billing_policy'] != 'local_only'):
        raise TestFailed('unsupported')
    data = request(model['execution']['url'], 'GET', '/api/v1/models')
    try:
        instance_id, context, _ = model_instance(data, model['id'])
    except TestFailed as error:
        if error.state == 'model_not_loaded': return {'state':'unloaded'}
        raise TestFailed('unavailable')
    if not instance_id:
        return {'state': 'unloaded'}
    return {'state': 'available', 'instance_id': instance_id, 'context_length': context}


def main():
    try:
        raw = sys.stdin.buffer.read(onboarding.MAX_CONFIG_BYTES + 1)
        if len(raw) > onboarding.MAX_CONFIG_BYTES: raise TestFailed()
        envelope = json.loads(raw)
        if type(envelope) is dict and envelope.get('operation') == 'availability':
            result = availability(envelope.get('model'))
            print(json.dumps(result)); return
        state = smoke(envelope)
    except TestFailed as error:
        if 'envelope' in locals() and type(envelope) is dict and envelope.get('operation') == 'availability':
            print(json.dumps({'state': error.state})); return
        state = error.state
    except (OSError, ValueError, TypeError, http.client.HTTPException):
        state = 'test_failed'
    print(json.dumps({'state': state}))


if __name__ == '__main__': main()
