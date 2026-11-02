"""The MCP endpoint: Streamable HTTP, JSON responses.

Speaks the stateless 2026-07-28 protocol (per-request _meta, server/discover) and the earlier
initialize handshake (2025-11-25, 2025-06-18, 2025-03-26) that most AI apps still use.
"""
import json
import logging

from odoo import http, release
from odoo.http import request

from ..models.params import param_bool
from .oauth import CORS_HEADERS, issuer, preflight

_logger = logging.getLogger(__name__)

LATEST = '2026-07-28'
LEGACY = ['2025-11-25', '2025-06-18', '2025-03-26']
SUPPORTED = [LATEST] + LEGACY
META_VERSION = 'io.modelcontextprotocol/protocolVersion'
META_SERVER = 'io.modelcontextprotocol/serverInfo'

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL = -32700, -32600, -32601, -32602, -32603
HEADER_MISMATCH, UNSUPPORTED_VERSION = -32020, -32022
LIST_TTL_MS = 300000


def server_info():
    return {'name': 'novator-odoo-mcp', 'title': 'Odoo (%s)' % request.env['res.company'].sudo().search(
        [], limit=1).name, 'version': '%s+%s' % (release.version, '1.0')}


class McpEndpoint(http.Controller):

    def _send(self, body, status=200, headers=None):
        if body is None:
            return request.make_response('', status=202, headers=CORS_HEADERS)
        return request.make_response(json.dumps(body, default=str, ensure_ascii=False), status=status,
                                     headers=CORS_HEADERS + [('Content-Type', 'application/json'),
                                                             ('Cache-Control', 'no-store')] + (headers or []))

    def _unauthorized(self, description='Sign in to Odoo to use this connector.'):
        challenge = 'Bearer realm="odoo", resource_metadata="%s/.well-known/oauth-protected-resource/mcp", ' \
                    'scope="odoo", error="invalid_token", error_description="%s"' % (issuer(), description)
        return self._send({'jsonrpc': '2.0', 'id': None,
                           'error': {'code': -32001, 'message': description}}, status=401,
                          headers=[('WWW-Authenticate', challenge)])

    def _authenticate(self):
        """Returns (user_id, client record or None) or None."""
        auth = request.httprequest.headers.get('Authorization', '')
        if not auth.lower().startswith('bearer '):
            return None
        value = auth[7:].strip()
        if not value:
            return None
        if value.startswith('nmcp_at_'):
            token = request.env['nmcp.token'].sudo()._authenticate(value)
            return (token.user_id.id, token.client_id) if token else None
        if not param_bool(request.env, 'novator_mcp.allow_api_keys', True):
            return None
        uid = request.env['res.users.apikeys'].sudo()._check_credentials(scope='rpc', key=value)
        return (uid, None) if uid else None

    @http.route('/mcp', type='http', auth='none', methods=['GET', 'POST', 'DELETE', 'OPTIONS'], csrf=False,
                save_session=False)
    def mcp(self, **kw):
        method = request.httprequest.method
        if method == 'OPTIONS':
            return preflight()
        if method != 'POST':
            # no server-initiated stream and no sessions: everything goes through POST
            return request.make_response('', status=405, headers=CORS_HEADERS + [('Allow', 'POST, OPTIONS')])

        auth = self._authenticate()
        if not auth:
            return self._unauthorized()
        uid, client = auth
        user = request.env['res.users'].sudo().browse(uid)
        if not user.active or not user.has_group('novator_mcp.group_nmcp_user'):
            return self._send({'jsonrpc': '2.0', 'id': None, 'error': {
                'code': -32001, 'message': 'This Odoo user is not allowed to use AI apps.'}}, status=403)
        context = dict(request.env['res.users'].with_user(uid).context_get())
        context['allowed_company_ids'] = [user.company_id.id] + [c.id for c in user.company_ids
                                                                  if c != user.company_id]
        request.update_env(user=uid, context=context)

        try:
            payload = json.loads(request.httprequest.get_data(as_text=True) or 'null')
        except ValueError:
            return self._send({'jsonrpc': '2.0', 'id': None, 'error': {'code': PARSE_ERROR, 'message': 'Parse error'}},
                              status=400)
        headers = request.httprequest.headers
        if isinstance(payload, list):  # JSON-RPC batch (2025-03-26 clients)
            answers = [a for a in (self._handle(m, headers, client)[0] for m in payload) if a is not None]
            return self._send(answers or None)
        body, status = self._handle(payload, headers, client)
        return self._send(body, status)

    # ------------------------------------------------------------------
    def _handle(self, msg, headers, client):
        if not isinstance(msg, dict) or msg.get('jsonrpc') != '2.0':
            return {'jsonrpc': '2.0', 'id': None, 'error': {'code': INVALID_REQUEST, 'message': 'Invalid request'}}, 400
        if 'method' not in msg:
            return None, 202  # a response or notification from the client: nothing to do
        method, msg_id = msg['method'], msg.get('id')
        params = msg.get('params') or {}
        if not isinstance(params, dict):
            return self._error(msg_id, INVALID_PARAMS, 'params must be an object'), 200
        meta = params.get('_meta') if isinstance(params.get('_meta'), dict) else {}
        version = meta.get(META_VERSION) or headers.get('MCP-Protocol-Version')
        modern = version == LATEST

        if version and version not in SUPPORTED and method != 'initialize':
            return self._error(msg_id, UNSUPPORTED_VERSION, 'Unsupported protocol version',
                               {'supported': SUPPORTED, 'requested': version}), 400
        hdr_method = headers.get('Mcp-Method')
        if hdr_method and hdr_method != method:
            return self._error(msg_id, HEADER_MISMATCH, 'Mcp-Method header does not match the request'), 400
        hdr_name = headers.get('Mcp-Name')
        if hdr_name and method in ('tools/call', 'prompts/get') and hdr_name != params.get('name'):
            return self._error(msg_id, HEADER_MISMATCH, 'Mcp-Name header does not match the request'), 400

        if msg_id is None:
            return None, 202  # notifications (initialized, cancelled...) need no answer

        handler = {
            'initialize': self._initialize,
            'server/discover': self._discover,
            'ping': lambda p, c: {},
            'tools/list': self._tools_list,
            'tools/call': self._tools_call,
            'prompts/list': self._prompts_list,
            'prompts/get': self._prompts_get,
            'resources/list': lambda p, c: {'resources': []},
            'resources/templates/list': lambda p, c: {'resourceTemplates': []},
        }.get(method)
        if not handler:
            return self._error(msg_id, METHOD_NOT_FOUND, 'Method not found: %s' % method), 200
        try:
            result = handler(params, client)
        except McpError as e:
            return self._error(msg_id, e.code, e.message), 200
        except Exception:
            _logger.exception('AI Connector: %s failed', method)
            return self._error(msg_id, INTERNAL, 'Internal error'), 200
        if modern:
            result.setdefault('resultType', 'complete')
            result.setdefault('_meta', {})[META_SERVER] = server_info()
            if method in ('tools/list', 'prompts/list', 'resources/list', 'resources/templates/list'):
                result.setdefault('ttlMs', LIST_TTL_MS)
                result.setdefault('cacheScope', 'private')
        return {'jsonrpc': '2.0', 'id': msg_id, 'result': result}, 200

    def _error(self, msg_id, code, message, data=None):
        error = {'code': code, 'message': message}
        if data is not None:
            error['data'] = data
        return {'jsonrpc': '2.0', 'id': msg_id, 'error': error}

    def _capabilities(self):
        return {'tools': {'listChanged': False}, 'prompts': {'listChanged': False},
                'resources': {'listChanged': False}}

    def _initialize(self, params, client):
        asked = params.get('protocolVersion')
        version = asked if asked in LEGACY else LEGACY[0]
        return {'protocolVersion': version, 'capabilities': self._capabilities(), 'serverInfo': server_info(),
                'instructions': request.env['nmcp.server']._nmcp_instructions()}

    def _discover(self, params, client):
        return {'supportedVersions': SUPPORTED, 'capabilities': self._capabilities(),
                'instructions': request.env['nmcp.server']._nmcp_instructions(),
                'ttlMs': LIST_TTL_MS, 'cacheScope': 'private'}

    def _tools_list(self, params, client):
        return {'tools': request.env['nmcp.server']._nmcp_available_tools()}

    def _tools_call(self, params, client):
        name = params.get('name')
        if not isinstance(name, str):
            raise McpError(INVALID_PARAMS, 'name is required')
        return request.env['nmcp.server']._nmcp_call(name, params.get('arguments') or {}, client)

    def _prompts_list(self, params, client):
        prompts = request.env['nmcp.server']._nmcp_prompts()
        return {'prompts': [{k: v for k, v in p.items() if k != 'template'} for p in prompts]}

    def _prompts_get(self, params, client):
        name = params.get('name')
        for prompt in request.env['nmcp.server']._nmcp_prompts():
            if prompt['name'] == name:
                args = params.get('arguments') or {}
                text = prompt['template']
                for key, value in args.items():
                    text = text.replace('{%s}' % key, str(value))
                return {'description': prompt.get('description', ''),
                        'messages': [{'role': 'user', 'content': {'type': 'text', 'text': text}}]}
        raise McpError(INVALID_PARAMS, 'Unknown prompt: %s' % name)


class McpError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message
