"""OAuth 2.1 sign-in for AI apps: 'Sign in with Odoo'.

Discovery (RFC 8414 + RFC 9728), dynamic client registration (RFC 7591), client ID metadata documents,
authorization code with PKCE S256 only, refresh token rotation, revocation (RFC 7009), iss in the
authorization response (RFC 9207).
"""
import base64
import json
import logging
from urllib.parse import quote, urlencode

from odoo import _, fields, http
from odoo.exceptions import UserError
from odoo.http import request

from ..models.params import param_bool

_logger = logging.getLogger(__name__)

CORS_HEADERS = [
    ('Access-Control-Allow-Origin', '*'),
    ('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS'),
    ('Access-Control-Allow-Headers', 'Authorization, Content-Type, Accept, MCP-Protocol-Version, Mcp-Method, '
                                     'Mcp-Name, Mcp-Session-Id, Last-Event-ID'),
    ('Access-Control-Expose-Headers', 'WWW-Authenticate, Mcp-Session-Id, MCP-Protocol-Version'),
    ('Access-Control-Max-Age', '86400'),
]
SCOPE = 'odoo'


def issuer():
    return request.httprequest.host_url.rstrip('/')


def resource_url():
    return issuer() + '/mcp'


def json_response(data, status=200, headers=None):
    return request.make_json_response(data, status=status,
                                      headers=CORS_HEADERS + [('Cache-Control', 'no-store')] + (headers or []))


def preflight():
    return request.make_response('', headers=CORS_HEADERS, status=204)


def oauth_error(error, description=None, status=400, headers=None):
    body = {'error': error}
    if description:
        body['error_description'] = description
    return json_response(body, status=status, headers=headers)


def append_query(url, params):
    return url + ('&' if '?' in url else '?') + urlencode(params)


class McpOAuth(http.Controller):

    # ------------------------------------------------------------------ discovery
    def _resource_metadata(self):
        return {
            'resource': resource_url(),
            'authorization_servers': [issuer()],
            'scopes_supported': [SCOPE],
            'bearer_methods_supported': ['header'],
            'resource_name': request.env['res.company'].sudo().search([], limit=1).name or 'Odoo',
            'resource_documentation': 'https://apps.odoo.com/apps/modules/browse?search=novator_mcp',
        }

    @http.route(['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'],
                type='http', auth='none', methods=['GET', 'OPTIONS'], csrf=False, save_session=False)
    def protected_resource(self, **kw):
        if request.httprequest.method == 'OPTIONS':
            return preflight()
        return json_response(self._resource_metadata())

    @http.route(['/.well-known/oauth-authorization-server', '/.well-known/oauth-authorization-server/mcp',
                 '/.well-known/openid-configuration'],
                type='http', auth='none', methods=['GET', 'OPTIONS'], csrf=False, save_session=False)
    def authorization_server(self, **kw):
        if request.httprequest.method == 'OPTIONS':
            return preflight()
        base = issuer()
        meta = {
            'issuer': base,
            'authorization_endpoint': base + '/mcp/oauth/authorize',
            'token_endpoint': base + '/mcp/oauth/token',
            'revocation_endpoint': base + '/mcp/oauth/revoke',
            'response_types_supported': ['code'],
            'response_modes_supported': ['query'],
            'grant_types_supported': ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported': ['S256'],
            'token_endpoint_auth_methods_supported': ['none', 'client_secret_post', 'client_secret_basic'],
            'revocation_endpoint_auth_methods_supported': ['none', 'client_secret_post', 'client_secret_basic'],
            'scopes_supported': [SCOPE],
            'authorization_response_iss_parameter_supported': True,
            'client_id_metadata_document_supported': param_bool(request.env, 'novator_mcp.allow_cimd', True),
            'service_documentation': 'https://www.novator.co',
        }
        if param_bool(request.env, 'novator_mcp.allow_dcr', True):
            meta['registration_endpoint'] = base + '/mcp/oauth/register'
        return json_response(meta)

    # ------------------------------------------------------------------ registration
    @http.route('/mcp/oauth/register', type='http', auth='none', methods=['POST', 'OPTIONS'], csrf=False,
                save_session=False)
    def register(self, **kw):
        if request.httprequest.method == 'OPTIONS':
            return preflight()
        try:
            meta = json.loads(request.httprequest.get_data(as_text=True) or '{}')
            if not isinstance(meta, dict):
                raise ValueError
        except ValueError:
            return oauth_error('invalid_client_metadata', 'The body must be a JSON object.')
        try:
            client, secret = request.env['nmcp.client'].sudo()._nmcp_register(meta)
        except UserError as e:
            code = str(e.args[0]) if e.args else 'invalid_client_metadata'
            return oauth_error(code, _('Registration refused.'), status=400 if code != 'registration_not_supported' else 403)
        body = {
            'client_id': client.client_id,
            'client_id_issued_at': int(fields.Datetime.now().timestamp()),
            'client_name': client.name,
            'redirect_uris': client._redirect_list(),
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'token_endpoint_auth_method': meta.get('token_endpoint_auth_method') or 'none',
            'scope': SCOPE,
        }
        if secret:
            body.update(client_secret=secret, client_secret_expires_at=0)
        return json_response(body, status=201)

    # ------------------------------------------------------------------ authorization
    def _render_error(self, message):
        return request.render('novator_mcp.oauth_error', {'message': message}, status=400)

    @http.route('/mcp/oauth/authorize', type='http', auth='public', methods=['GET', 'POST'], website=False,
                sitemap=False)
    def authorize(self, **kw):
        params = request.httprequest.values
        client = request.env['nmcp.client'].sudo()._get_client(params.get('client_id'))
        redirect_uri = params.get('redirect_uri') or ''
        if not client:
            return self._render_error(_('This AI app is not known to this Odoo, or it is not allowed here.'))
        if not redirect_uri and len(client._redirect_list()) == 1:
            redirect_uri = client._redirect_list()[0]
        if not redirect_uri or not client._accepts_redirect(redirect_uri):
            return self._render_error(_('The return address of this AI app does not match its registration.'))
        state = params.get('state')

        def back(**values):
            if state:
                values['state'] = state
            values['iss'] = issuer()
            return request.redirect(append_query(redirect_uri, values), local=False)

        if params.get('response_type') != 'code':
            return back(error='unsupported_response_type')
        challenge = params.get('code_challenge')
        if not challenge or params.get('code_challenge_method', 'plain') != 'S256' or not 43 <= len(challenge) <= 128:
            return back(error='invalid_request', error_description='PKCE with S256 is required')
        resource = params.get('resource')
        if resource and not resource.rstrip('/').startswith(issuer()):
            return back(error='invalid_target')

        if request.env.user._is_public():
            return request.redirect('/web/login?redirect=' + quote(request.httprequest.full_path, safe=''))
        user = request.env.user
        if not user.has_group('novator_mcp.group_nmcp_user'):
            return self._render_error(_('Your Odoo user is not allowed to connect AI apps. Ask your administrator.'))

        if request.httprequest.method == 'POST':
            if params.get('decision') != 'allow':
                return back(error='access_denied')
            code = request.env['nmcp.code'].sudo()._issue(client, user, redirect_uri, challenge, SCOPE, resource)
            _logger.info('AI Connector: %s allowed %s', user.login, client.name)
            return back(code=code)

        return request.render('novator_mcp.oauth_consent', {
            'client': client, 'user': user, 'company': user.company_id,
            'params': {k: v for k, v in params.items() if k not in ('decision', 'csrf_token')},
            'redirect_host': redirect_uri.split('/')[2] if '//' in redirect_uri else redirect_uri,
            'tools': request.env['nmcp.tool'].sudo().search([]),
        })

    # ------------------------------------------------------------------ token
    def _client_from_request(self, form):
        client_id, secret = form.get('client_id'), form.get('client_secret')
        auth = request.httprequest.headers.get('Authorization', '')
        if auth.lower().startswith('basic '):
            try:
                raw = base64.b64decode(auth[6:]).decode()
                basic_id, basic_secret = raw.split(':', 1)
                from urllib.parse import unquote_plus
                client_id, secret = unquote_plus(basic_id), unquote_plus(basic_secret)
            except (ValueError, UnicodeDecodeError):
                return None
        client = request.env['nmcp.client'].sudo()._get_client(client_id)
        if not client or not client._check_secret(secret):
            return None
        return client

    @http.route('/mcp/oauth/token', type='http', auth='none', methods=['POST', 'OPTIONS'], csrf=False,
                save_session=False)
    def token(self, **kw):
        if request.httprequest.method == 'OPTIONS':
            return preflight()
        form = request.httprequest.form
        client = self._client_from_request(form)
        if not client:
            return oauth_error('invalid_client', status=401)
        grant = form.get('grant_type')
        if grant == 'authorization_code':
            code = request.env['nmcp.code'].sudo()._redeem(form.get('code') or '', client,
                                                           form.get('redirect_uri') or '', form.get('code_verifier'))
            if not code:
                return oauth_error('invalid_grant')
            if not code.user_id.has_group('novator_mcp.group_nmcp_user'):
                return oauth_error('invalid_grant', 'User not allowed')
            return json_response(request.env['nmcp.token'].sudo()._issue(client, code.user_id, code.scope, code))
        if grant == 'refresh_token':
            data = request.env['nmcp.token'].sudo()._refresh(form.get('refresh_token') or '', client)
            if not data:
                return oauth_error('invalid_grant')
            return json_response(data)
        return oauth_error('unsupported_grant_type')

    @http.route('/mcp/oauth/revoke', type='http', auth='none', methods=['POST', 'OPTIONS'], csrf=False,
                save_session=False)
    def revoke(self, **kw):
        if request.httprequest.method == 'OPTIONS':
            return preflight()
        form = request.httprequest.form
        client = self._client_from_request(form)
        if not client:
            return oauth_error('invalid_client', status=401)
        from ..models.mcp_client import _hash
        value = form.get('token') or ''
        Token = request.env['nmcp.token'].sudo()
        token = Token.search(['|', ('access_hash', '=', _hash(value)), ('refresh_hash', '=', _hash(value)),
                              ('client_id', '=', client.id)], limit=1)
        token.action_revoke()
        return json_response({})
