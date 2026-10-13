import json
import unittest
from unittest.mock import Mock

from mcp_http_auth import AuthenticatedFastMCP, HTTPAuth
from starlette.testclient import TestClient


class HTTPAuthTests(unittest.TestCase):
    def make_server(self, *, json_response=True, stateless=True, verifier=None):
        verify = verifier or (lambda token: ('user', 'user', []) if token == 'valid-token' else None)
        server = AuthenticatedFastMCP('private-server',
            http_auth=HTTPAuth('https://mcp.example.test/test', 'test-tenant', 'MCP', verify),
            stateless_http=stateless, json_response=json_response, streamable_http_path='/')
        invoked = Mock(return_value='private business data')
        @server.tool()
        def private_tool() -> str:
            """Private tool description."""
            return invoked()
        return server, invoked

    def rpc(self, client, method, *, headers=None, params=None):
        return client.post('/', headers={'Accept': 'application/json, text/event-stream', **(headers or {})},
                           json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})

    def result(self, response):
        self.assertEqual(response.status_code, 200)
        if response.headers['content-type'].startswith('text/event-stream'):
            return json.loads(next(s[5:].strip() for s in response.text.splitlines() if s.startswith('data:')))
        return response.json()

    def test_all_discovery_and_call_methods_reject_missing_and_invalid_tokens(self):
        server, invoked = self.make_server()
        with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
            for auth in ({}, {'Authorization': 'Bearer invalid'}, {'Authorization': 'Basic valid-token'},
                         {'Authorization': 'Bearer '}, {'Authorization': 'Bearer ' + 'x' * 65537}):
                for method in ('initialize', 'tools/list', 'resources/list', 'resources/templates/list',
                               'prompts/list', 'tools/call'):
                    with self.subTest(auth=list(auth), method=method):
                        r = self.rpc(client, method, headers=auth,
                                     params={'name': 'private_tool', 'arguments': {}})
                        self.assertEqual(r.status_code, 401)
                        self.assertIn('resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/test"', r.headers['www-authenticate'])
                        self.assertEqual(r.headers['cache-control'], 'no-store')
                        self.assertNotIn('Private tool', r.text)
                        self.assertNotIn('private business data', r.text)
        invoked.assert_not_called()

    def test_public_metadata_is_fixed_and_contains_no_catalog(self):
        server, _ = self.make_server()
        with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
            path = '/.well-known/oauth-protected-resource'
            for headers in ({}, {'Authorization': 'Bearer invalid', 'Host': 'spoofed.invalid'}):
                r = client.get(path, headers=headers)
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.json()['resource'], 'https://mcp.example.test/test')
                self.assertEqual(r.json()['scopes_supported'], ['https://mcp.example.test/test/MCP'])
                self.assertNotIn('private_tool', r.text)
                self.assertNotIn('spoofed.invalid', r.text)
            self.assertEqual(client.head(path).content, b'')
            self.assertEqual(client.post(path, json={}).status_code, 405)
            self.assertEqual(client.get(path + '/tools').status_code, 401)

    def test_authenticated_json_and_sse_preserve_discovery_and_calls(self):
        for json_response in (True, False):
            for stateless in (True, False):
                with self.subTest(json=json_response, stateless=stateless):
                    server, invoked = self.make_server(json_response=json_response, stateless=stateless)
                    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
                        headers = {'Authorization': 'bEaReR valid-token'}
                        init = self.rpc(client, 'initialize', headers=headers, params={
                            'protocolVersion': '2024-11-05', 'capabilities': {},
                            'clientInfo': {'name': 'compatibility-test', 'version': '1'}})
                        self.assertIn('serverInfo', self.result(init)['result'])
                        if init.headers.get('mcp-session-id'):
                            headers['Mcp-Session-Id'] = init.headers['mcp-session-id']
                        client.post('/', headers={**headers, 'Accept': 'application/json, text/event-stream'},
                                    json={'jsonrpc': '2.0', 'method': 'notifications/initialized'})
                        catalog = self.result(self.rpc(client, 'tools/list', headers=headers))
                        self.assertEqual(catalog['result']['tools'][0]['name'], 'private_tool')
                        called = self.rpc(client, 'tools/call', headers=headers,
                                          params={'name': 'private_tool', 'arguments': {}})
                        self.assertEqual(self.result(called)['result']['content'][0]['text'], 'private business data')
                        self.assertEqual(called.headers['cache-control'], 'no-store')
                        # A valid session ID is not an authentication credential.
                        session_only = {k: v for k, v in headers.items() if k != 'Authorization'}
                        self.assertEqual(self.rpc(client, 'tools/list', headers=session_only).status_code, 401)
                        self.assertEqual(client.delete('/', headers=session_only).status_code, 401)
                        self.assertEqual(client.get('/', headers=session_only).status_code, 401)
                    invoked.assert_called_once()

    def test_verifier_exception_fails_closed_without_details(self):
        server, invoked = self.make_server(verifier=Mock(side_effect=RuntimeError('private verifier details')))
        with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
            r = self.rpc(client, 'tools/list', headers={'Authorization': 'Bearer something'})
            self.assertEqual(r.status_code, 401)
            self.assertNotIn('private verifier details', r.text)
        invoked.assert_not_called()

    def test_duplicate_authorization_and_query_tokens_do_not_authenticate(self):
        server, invoked = self.make_server()
        with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
            r = client.post('/', headers=[('Authorization', 'Bearer valid-token'),
                                          ('Authorization', 'Bearer invalid')], json={})
            self.assertEqual(r.status_code, 401)
            self.assertEqual(client.post('/?access_token=valid-token', json={}).status_code, 401)
        invoked.assert_not_called()

    def test_legacy_sse_factory_also_protects_discovery_transport(self):
        server, invoked = self.make_server()
        with TestClient(server.sse_app(), base_url="http://localhost:8000") as client:
            self.assertEqual(client.get('/sse').status_code, 401)
            self.assertEqual(client.post('/messages/?session_id=pretend', json={}).status_code, 401)
        invoked.assert_not_called()


if __name__ == '__main__':
    unittest.main()
