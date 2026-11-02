import hashlib
import ipaddress
import json
import logging
import secrets
import socket
from datetime import timedelta
from urllib.parse import urlparse

from odoo import _, api, fields, models
from odoo.exceptions import UserError

from .params import param_bool, param_str

_logger = logging.getLogger(__name__)

LOOPBACK_HOSTS = ('localhost', '127.0.0.1', '[::1]', '::1')
CLAUDE_REDIRECTS = ('https://claude.ai/api/mcp/auth_callback', 'https://claude.com/api/mcp/auth_callback')
CIMD_MAX_BYTES = 65536
CIMD_REFRESH = timedelta(hours=24)


def _hash(value):
    return hashlib.sha256((value or '').encode()).hexdigest()


def is_loopback(uri):
    try:
        parsed = urlparse(uri)
    except ValueError:
        return False
    return parsed.scheme == 'http' and (parsed.hostname or '') in LOOPBACK_HOSTS


def valid_redirect_uri(uri):
    """https anywhere, plain http only to this computer (desktop and command line apps)."""
    try:
        parsed = urlparse(uri)
    except ValueError:
        return False
    if parsed.fragment or not parsed.netloc:
        return False
    if parsed.scheme == 'https':
        return True
    return is_loopback(uri)


def redirect_matches(registered, given):
    """Exact match, except that the port of a loopback address is ignored (RFC 8252)."""
    if registered == given:
        return True
    if is_loopback(registered) and is_loopback(given):
        a, b = urlparse(registered), urlparse(given)
        return (a.scheme, a.hostname, a.path, a.query) == (b.scheme, b.hostname, b.path, b.query)
    return False


def public_https_url(url):
    """Client ID Metadata Documents may only be fetched from public https addresses."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        return False
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return False
    return True


class McpClient(models.Model):
    _name = 'nmcp.client'
    _description = 'AI App'
    _order = 'last_used desc, id desc'

    name = fields.Char('App', required=True)
    client_id = fields.Char('Client ID', required=True, index=True, readonly=True, copy=False)
    kind = fields.Selection([('dcr', 'Registered by the app'), ('cimd', 'App metadata document'),
                             ('manual', 'Created here')], default='manual', required=True, readonly=True)
    redirect_uris = fields.Text('Redirect URLs', help='One per line.')
    secret_hash = fields.Char(readonly=True, copy=False, groups='base.group_system')
    confidential = fields.Boolean('Uses a Client Secret', readonly=True)
    client_uri = fields.Char('Website')
    metadata_fetched = fields.Datetime(readonly=True)
    active = fields.Boolean(default=True)
    token_ids = fields.One2many('nmcp.token', 'client_id', string='Connections')
    token_count = fields.Integer(compute='_compute_token_count', string='Active Connections')
    last_used = fields.Datetime(readonly=True)

    _sql_constraints = [('client_id_unique', 'unique(client_id)', 'This client ID already exists.')]

    def _compute_token_count(self):
        data = self.env['nmcp.token']._read_group([('client_id', 'in', self.ids), ('revoked', '=', False)],
                                                 ['client_id'], ['__count'])
        counts = {client.id: count for client, count in data}
        for client in self:
            client.token_count = counts.get(client.id, 0)

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            vals.setdefault('client_id', 'nmcp_' + secrets.token_urlsafe(18))
        return super().create(vals_list)

    # ------------------------------------------------------------------
    def _redirect_list(self):
        self.ensure_one()
        return [line.strip() for line in (self.redirect_uris or '').splitlines() if line.strip()]

    def _accepts_redirect(self, uri):
        self.ensure_one()
        return any(redirect_matches(registered, uri) for registered in self._redirect_list())

    def _check_secret(self, secret):
        self.ensure_one()
        client = self.sudo()
        if not client.confidential:
            return True
        return bool(secret) and secrets.compare_digest(client.secret_hash or '', _hash(secret))

    def action_new_secret(self):
        self.ensure_one()
        secret = 'nmcps_' + secrets.token_urlsafe(32)
        self.sudo().write({'secret_hash': _hash(secret), 'confidential': True})
        return {
            'type': 'ir.actions.act_window', 'res_model': 'nmcp.secret.wizard', 'view_mode': 'form', 'target': 'new',
            'context': {'default_client_id': self.id, 'default_secret': secret},
        }

    def action_revoke_all(self):
        self.mapped('token_ids').filtered(lambda t: not t.revoked).action_revoke()

    # ------------------------------------------------------------------
    @api.model
    def _policy(self):
        return param_str(self.env, 'novator_mcp.clients_policy', 'any')

    @api.model
    def _redirects_allowed(self, uris):
        if not uris or not all(valid_redirect_uri(u) for u in uris):
            return False
        if self._policy() == 'claude':
            return all(u in CLAUDE_REDIRECTS or is_loopback(u) for u in uris)
        return True

    @api.model
    def _nmcp_register(self, meta):
        """Dynamic Client Registration (RFC 7591). Returns (client, secret or None) or raises UserError."""
        if not param_bool(self.env, 'novator_mcp.allow_dcr', True):
            raise UserError('registration_not_supported')
        uris = meta.get('redirect_uris')
        if not isinstance(uris, list) or not all(isinstance(u, str) for u in uris) or len(uris) > 10:
            raise UserError('invalid_redirect_uri')
        if not self._redirects_allowed(uris):
            raise UserError('invalid_redirect_uri')
        method = meta.get('token_endpoint_auth_method') or 'none'
        if method not in ('none', 'client_secret_post', 'client_secret_basic'):
            raise UserError('invalid_client_metadata')
        name = str(meta.get('client_name') or 'AI app')[:80]
        secret = None
        vals = {'name': name, 'kind': 'dcr', 'redirect_uris': '\n'.join(uris),
                'client_uri': str(meta.get('client_uri') or '')[:200] or False}
        if method != 'none':
            secret = 'nmcps_' + secrets.token_urlsafe(32)
            vals.update(secret_hash=_hash(secret), confidential=True)
        return self.sudo().create(vals), secret

    @api.model
    def _get_client(self, client_id):
        """Find a client by ID; an https client ID is a Client ID Metadata Document."""
        if not client_id or len(client_id) > 500:
            return self.browse()
        client = self.sudo().with_context(active_test=False).search([('client_id', '=', client_id)], limit=1)
        if client and not client.active:
            return self.browse()
        if client_id.startswith('https://'):
            fresh = client and client.metadata_fetched and \
                client.metadata_fetched > fields.Datetime.now() - CIMD_REFRESH
            if not fresh:
                client = self._fetch_metadata_document(client_id, client)
        return client

    @api.model
    def _fetch_metadata_document(self, url, client):
        if not param_bool(self.env, 'novator_mcp.allow_cimd', True):
            return self.browse()
        if not public_https_url(url):
            return self.browse()
        import requests
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False, stream=True,
                                headers={'Accept': 'application/json'})
            raw = resp.raw.read(CIMD_MAX_BYTES + 1, decode_content=True)
            if resp.status_code != 200 or len(raw) > CIMD_MAX_BYTES:
                return client
            meta = json.loads(raw)
        except Exception as e:  # network, JSON
            _logger.info('AI Connector: could not read client metadata %s: %s', url, e)
            return client
        uris = meta.get('redirect_uris') if isinstance(meta, dict) else None
        if not isinstance(meta, dict) or meta.get('client_id') != url or not isinstance(uris, list) \
                or not self._redirects_allowed(uris):
            return self.browse()
        vals = {'name': str(meta.get('client_name') or urlparse(url).hostname)[:80], 'kind': 'cimd',
                'redirect_uris': '\n'.join(uris), 'client_uri': str(meta.get('client_uri') or '')[:200] or False,
                'metadata_fetched': fields.Datetime.now()}
        if client:
            client.sudo().write(vals)
            return client
        return self.sudo().create(dict(vals, client_id=url))


class McpSecretWizard(models.TransientModel):
    _name = 'nmcp.secret.wizard'
    _description = 'AI App Secret'

    client_id = fields.Many2one('nmcp.client', readonly=True)
    secret = fields.Char(readonly=True)
