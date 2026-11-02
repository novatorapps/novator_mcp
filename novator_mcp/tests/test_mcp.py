import base64
import hashlib
import json
import re
import secrets
from urllib.parse import parse_qs, urlparse

from odoo.tests import HttpCase, tagged
from odoo.tests.common import HOST
from odoo.tools import config

from ..models.mcp_client import redirect_matches, valid_redirect_uri
from ..models.params import param_set

REDIRECT = 'https://claude.ai/api/mcp/auth_callback'


@tagged('post_install', '-at_install')
class TestMcp(HttpCase):

    def setUp(self):
        super().setUp()
        self.user = self.env['res.users'].create({
            'name': 'AI User', 'login': 'ai_user', 'password': 'ai_user_pw_123',
            'group_ids': [(6, 0, [self.env.ref('base.group_user').id, self.env.ref('base.group_partner_manager').id,
                                  self.env.ref('novator_mcp.group_nmcp_user').id])],
        })
        self.outsider = self.env['res.users'].create({
            'name': 'No AI', 'login': 'no_ai', 'password': 'no_ai_pw_123',
            'group_ids': [(6, 0, [self.env.ref('base.group_user').id])],
        })
        self.server = self.env['nmcp.server'].with_user(self.user)

    # ------------------------------------------------------------------ helpers
    def _url(self, path):
        return 'http://%s:%s%s' % (HOST, config['http_port'], path)

    def _register(self):
        r = self.opener.post(self._url('/mcp/oauth/register'), data=json.dumps(
            {'client_name': 'Claude', 'redirect_uris': [REDIRECT]}), headers={'Content-Type': 'application/json'})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()['client_id']

    def _sign_in(self, client_id, login='ai_user', password='ai_user_pw_123'):
        self.authenticate(login, password)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        params = {'response_type': 'code', 'client_id': client_id, 'redirect_uri': REDIRECT, 'state': 'xyz',
                  'code_challenge': challenge, 'code_challenge_method': 'S256'}
        page = self.url_open('/mcp/oauth/authorize?' + '&'.join('%s=%s' % kv for kv in params.items()))
        self.assertIn('Allow', page.text)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        r = self.opener.post(self._url('/mcp/oauth/authorize'), data=dict(params, decision='allow', csrf_token=csrf),
                             allow_redirects=False)
        location = r.headers.get('Location', '')
        self.assertTrue(location.startswith(REDIRECT), location)
        query = parse_qs(urlparse(location).query)
        self.assertEqual(query['state'], ['xyz'])
        self.assertTrue(query.get('iss'))
        return query['code'][0], verifier

    def _token(self, client_id, code, verifier):
        r = self.opener.post(self._url('/mcp/oauth/token'), data={
            'grant_type': 'authorization_code', 'code': code, 'client_id': client_id, 'redirect_uri': REDIRECT,
            'code_verifier': verifier})
        return r

    def _rpc(self, token, method, params=None, version='2025-06-18', headers=None):
        h = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'MCP-Protocol-Version': version}
        h.update(headers or {})
        r = self.opener.post(self._url('/mcp'), data=json.dumps(
            {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}}), headers=h)
        return r

    def _call(self, name, **arguments):
        result = self.server._nmcp_call(name, arguments)
        data = json.loads(result['content'][0]['text']) if not result['isError'] else result['content'][0]['text']
        return result['isError'], data

    # ------------------------------------------------------------------ tests
    def test_01_redirect_rules(self):
        self.assertTrue(valid_redirect_uri(REDIRECT))
        self.assertTrue(valid_redirect_uri('http://localhost:33418/callback'))
        self.assertFalse(valid_redirect_uri('http://example.com/callback'))
        self.assertFalse(valid_redirect_uri('https://example.com/cb#frag'))
        self.assertTrue(redirect_matches('http://127.0.0.1/callback', 'http://127.0.0.1:5555/callback'))
        self.assertFalse(redirect_matches(REDIRECT, 'https://claude.ai/other'))

    def test_02_discovery_and_401(self):
        r = self.opener.post(self._url('/mcp'), data='{}', headers={'Content-Type': 'application/json'})
        self.assertEqual(r.status_code, 401)
        self.assertIn('resource_metadata=', r.headers['WWW-Authenticate'])
        meta = self.url_open('/.well-known/oauth-authorization-server').json()
        self.assertEqual(meta['code_challenge_methods_supported'], ['S256'])
        self.assertTrue(meta['authorization_response_iss_parameter_supported'])
        prm = self.url_open('/.well-known/oauth-protected-resource/mcp').json()
        self.assertTrue(prm['resource'].endswith('/mcp'))

    def test_03_full_sign_in(self):
        client_id = self._register()
        code, verifier = self._sign_in(client_id)
        r = self._token(client_id, code, verifier)
        self.assertEqual(r.status_code, 200, r.text)
        access, refresh = r.json()['access_token'], r.json()['refresh_token']
        init = self._rpc(access, 'initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                                                'clientInfo': {'name': 't', 'version': '1'}}).json()
        self.assertEqual(init['result']['protocolVersion'], '2025-06-18')
        tools = self._rpc(access, 'tools/list').json()['result']['tools']
        self.assertIn('odoo_search_records', [t['name'] for t in tools])
        # second use of the code: refused, and its tokens are revoked
        self.assertEqual(self._token(client_id, code, verifier).status_code, 400)
        self.assertEqual(self._rpc(access, 'tools/list').status_code, 401)
        # refresh still revoked too
        r = self.opener.post(self._url('/mcp/oauth/token'), data={
            'grant_type': 'refresh_token', 'refresh_token': refresh, 'client_id': client_id})
        self.assertEqual(r.status_code, 400)

    def test_04_refresh_and_modern_protocol(self):
        client_id = self._register()
        code, verifier = self._sign_in(client_id)
        tokens = self._token(client_id, code, verifier).json()
        r = self.opener.post(self._url('/mcp/oauth/token'), data={
            'grant_type': 'refresh_token', 'refresh_token': tokens['refresh_token'], 'client_id': client_id})
        self.assertEqual(r.status_code, 200)
        access = r.json()['access_token']
        self.assertEqual(self._rpc(tokens['access_token'], 'tools/list').status_code, 401)
        meta = {'io.modelcontextprotocol/protocolVersion': '2026-07-28'}
        res = self._rpc(access, 'server/discover', {'_meta': meta}, '2026-07-28').json()['result']
        self.assertIn('2026-07-28', res['supportedVersions'])
        self.assertEqual(res['resultType'], 'complete')
        res = self._rpc(access, 'tools/call', {'_meta': meta, 'name': 'odoo_count_records',
                                               'arguments': {'model': 'res.partner'}}, '2026-07-28',
                        {'Mcp-Method': 'tools/call', 'Mcp-Name': 'odoo_count_records'}).json()['result']
        self.assertGreater(res['structuredContent']['count'], 0)
        bad = self._rpc(access, 'tools/list', {'_meta': {'io.modelcontextprotocol/protocolVersion': '1999-01-01'}})
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.json()['error']['code'], -32022)

    def test_05_user_without_group(self):
        client_id = self._register()
        self.authenticate('no_ai', 'no_ai_pw_123')
        page = self.url_open('/mcp/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s'
                             '&code_challenge=%s&code_challenge_method=S256' % (client_id, REDIRECT, 'a' * 43))
        self.assertIn('not allowed', page.text)

    def test_06_api_key(self):
        key = self.env['res.users.apikeys'].with_user(self.user)._generate('rpc', 'test', __import__('datetime').datetime.now() + __import__('datetime').timedelta(days=1))
        r = self._rpc(key, 'tools/call', {'name': 'odoo_whoami', 'arguments': {}})
        self.assertEqual(r.json()['result']['structuredContent']['user']['login'], 'ai_user')
        param_set(self.env, 'novator_mcp.allow_api_keys', False)
        self.assertEqual(self._rpc(key, 'tools/list').status_code, 401)

    def test_10_read_tools(self):
        err, data = self._call('odoo_list_models', query='partner')
        self.assertFalse(err)
        self.assertIn('res.partner', [m['model'] for m in data['models']])
        err, data = self._call('odoo_get_fields', model='res.users', query='password')
        self.assertFalse(data['fields'])
        err, data = self._call('odoo_search_records', model='res.partner', fields=['name', 'parent_id'], limit=2)
        self.assertFalse(err)
        self.assertLessEqual(len(data['records']), 2)
        err, data = self._call('odoo_group_records', model='res.partner', groupby=['is_company'])
        self.assertFalse(err, data)
        err, _data = self._call('odoo_read_records', model='res.users', ids=[self.user.id], fields=['password'])
        self.assertTrue(err)
        err, _data = self._call('odoo_search_records', model='ir.config_parameter')
        self.assertTrue(err)

    def test_11_write_tools_and_log(self):
        err, data = self._call('odoo_create_record', model='res.partner', values={'name': 'From the AI'})
        self.assertFalse(err, data)
        partner = self.env['res.partner'].browse(data['id'])
        self.assertEqual(partner.create_uid, self.user)
        err, _data = self._call('odoo_update_records', model='res.partner', ids=[partner.id],
                                values={'phone': '123'})
        self.assertEqual(partner.phone, '123')
        err, _data = self._call('odoo_call_method', model='res.partner', method='unlink', ids=[partner.id])
        self.assertTrue(err)
        err, _data = self._call('odoo_delete_records', model='res.partner', ids=[partner.id])
        self.assertTrue(err, 'delete is switched off by default')
        log = self.env['nmcp.log'].search([('user_id', '=', self.user.id)])
        self.assertEqual(len(log), 4)
        self.assertEqual(set(log.mapped('state')), {'done', 'denied'})

    def test_12_access_rights_apply(self):
        # a user without the Contacts right cannot create partners through the AI either
        self.user.group_ids = [(3, self.env.ref('base.group_partner_manager').id)]
        err, data = self._call('odoo_create_record', model='res.country', values={'name': 'Nowhere', 'code': 'QQ'})
        self.assertTrue(err, data)

    def test_13_tool_switch(self):
        self.env.ref('novator_mcp.tool_odoo_create_record').active = False
        names = [t['name'] for t in self.server._nmcp_available_tools()]
        self.assertNotIn('odoo_create_record', names)
        err, _data = self._call('odoo_create_record', model='res.partner', values={'name': 'x'})
        self.assertTrue(err)

    def test_14_failed_write_is_rolled_back(self):
        err, _data = self._call('odoo_create_record', model='res.partner', values={'name': 'Half', 'parent_id': 999999})
        self.assertTrue(err)
        self.assertFalse(self.env['res.partner'].search([('name', '=', 'Half')]))
