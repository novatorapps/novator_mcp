import base64
import hashlib
import secrets
from datetime import timedelta

from odoo import api, fields, models

from .mcp_client import _hash
from .params import param_int

ACCESS_PREFIX = 'nmcp_at_'
REFRESH_PREFIX = 'nmcp_rt_'


def pkce_s256(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()


class McpCode(models.Model):
    """Short-lived authorization codes (OAuth 2.1, PKCE required)."""
    _name = 'nmcp.code'
    _description = 'AI Connector Authorization Code'
    _log_access = False

    code_hash = fields.Char(required=True, index=True)
    client_id = fields.Many2one('nmcp.client', required=True, ondelete='cascade')
    user_id = fields.Many2one('res.users', required=True, ondelete='cascade')
    redirect_uri = fields.Char(required=True)
    challenge = fields.Char(required=True)
    scope = fields.Char()
    resource = fields.Char()
    expires = fields.Datetime(required=True)
    used = fields.Boolean()

    @api.model
    def _issue(self, client, user, redirect_uri, challenge, scope, resource):
        code = secrets.token_urlsafe(32)
        self.sudo().create({
            'code_hash': _hash(code), 'client_id': client.id, 'user_id': user.id, 'redirect_uri': redirect_uri,
            'challenge': challenge, 'scope': scope or 'odoo', 'resource': resource or False,
            'expires': fields.Datetime.now() + timedelta(minutes=5),
        })
        return code

    @api.model
    def _redeem(self, code, client, redirect_uri, verifier):
        """Returns the code record or an empty recordset. A code works once."""
        rec = self.sudo().search([('code_hash', '=', _hash(code))], limit=1)
        if not rec or rec.client_id != client:
            return self.browse()
        if rec.used:
            # replayed code: revoke what it produced (RFC 6749 4.1.2)
            self.env['nmcp.token'].sudo().search([('code_id', '=', rec.id)]).action_revoke()
            return self.browse()
        rec.used = True
        if rec.expires < fields.Datetime.now() or rec.redirect_uri != redirect_uri:
            return self.browse()
        if not verifier or not secrets.compare_digest(pkce_s256(verifier), rec.challenge):
            return self.browse()
        if not rec.user_id.active:
            return self.browse()
        return rec


class McpToken(models.Model):
    _name = 'nmcp.token'
    _description = 'AI Connection'
    _order = 'create_date desc'

    name = fields.Char(compute='_compute_name')
    user_id = fields.Many2one('res.users', 'User', required=True, ondelete='cascade', index=True, readonly=True)
    client_id = fields.Many2one('nmcp.client', 'AI App', required=True, ondelete='cascade', readonly=True)
    code_id = fields.Many2one('nmcp.code', ondelete='set null', readonly=True)
    access_hash = fields.Char(index=True, readonly=True, groups='base.group_system')
    refresh_hash = fields.Char(index=True, readonly=True, groups='base.group_system')
    expires = fields.Datetime('Access Until', readonly=True)
    refresh_expires = fields.Datetime('Connected Until', readonly=True)
    scope = fields.Char(readonly=True)
    last_used = fields.Datetime(readonly=True)
    revoked = fields.Boolean(readonly=True)
    state = fields.Selection([('active', 'Connected'), ('expired', 'Expired'), ('revoked', 'Disconnected')],
                             compute='_compute_state')

    @api.depends('client_id', 'user_id')
    def _compute_name(self):
        for token in self:
            token.name = '%s - %s' % (token.client_id.name or '', token.user_id.name or '')

    def _compute_state(self):
        now = fields.Datetime.now()
        for token in self:
            if token.revoked:
                token.state = 'revoked'
            elif token.refresh_expires and token.refresh_expires < now:
                token.state = 'expired'
            else:
                token.state = 'active'

    @api.model
    def _lifetimes(self):
        hours = max(param_int(self.env, 'novator_mcp.access_hours', 1), 1)
        days = max(param_int(self.env, 'novator_mcp.refresh_days', 30), 1)
        return timedelta(hours=hours), timedelta(days=days)

    @api.model
    def _issue(self, client, user, scope, code=None):
        access_life, refresh_life = self._lifetimes()
        access, refresh = ACCESS_PREFIX + secrets.token_urlsafe(32), REFRESH_PREFIX + secrets.token_urlsafe(32)
        now = fields.Datetime.now()
        self.sudo().create({
            'user_id': user.id, 'client_id': client.id, 'code_id': code.id if code else False,
            'access_hash': _hash(access), 'refresh_hash': _hash(refresh), 'scope': scope or 'odoo',
            'expires': now + access_life, 'refresh_expires': now + refresh_life,
        })
        client.sudo().last_used = now
        return {
            'access_token': access, 'token_type': 'Bearer', 'expires_in': int(access_life.total_seconds()),
            'refresh_token': refresh, 'scope': scope or 'odoo',
        }

    @api.model
    def _refresh(self, refresh, client):
        token = self.sudo().search([('refresh_hash', '=', _hash(refresh)), ('revoked', '=', False)], limit=1)
        if not token or token.client_id != client or token.refresh_expires < fields.Datetime.now() \
                or not token.user_id.active:
            return None
        # rotate: the old refresh token stops working
        access_life, _refresh_life = self._lifetimes()
        access, new_refresh = ACCESS_PREFIX + secrets.token_urlsafe(32), REFRESH_PREFIX + secrets.token_urlsafe(32)
        token.write({'access_hash': _hash(access), 'refresh_hash': _hash(new_refresh),
                     'expires': fields.Datetime.now() + access_life})
        return {
            'access_token': access, 'token_type': 'Bearer', 'expires_in': int(access_life.total_seconds()),
            'refresh_token': new_refresh, 'scope': token.scope,
        }

    @api.model
    def _authenticate(self, access):
        """Returns the token record for a valid access token, else an empty recordset."""
        token = self.sudo().search([('access_hash', '=', _hash(access)), ('revoked', '=', False)], limit=1)
        now = fields.Datetime.now()
        if not token or token.expires < now or not token.user_id.active or not token.client_id.active:
            return self.browse()
        if not token.last_used or token.last_used < now - timedelta(minutes=5):
            token.last_used = now
            token.client_id.last_used = now
        return token

    def action_revoke(self):
        self.sudo().write({'revoked': True, 'access_hash': False, 'refresh_hash': False})

    @api.model
    def _gc(self):
        now = fields.Datetime.now()
        self.env['nmcp.code'].sudo().search([('expires', '<', now - timedelta(days=1))]).unlink()
        self.sudo().search(['|', ('refresh_expires', '<', now - timedelta(days=30)),
                            '&', ('revoked', '=', True), ('write_date', '<', now - timedelta(days=30))]).unlink()
