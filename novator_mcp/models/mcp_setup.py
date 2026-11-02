from odoo import api, fields, models, release

from .params import param_bool, param_str

PRO_URL = 'https://apps.odoo.com/apps/modules/%s/novator_mcp_pro'


class McpSetup(models.TransientModel):
    """'Connect an AI app' window: the address to paste and the steps for each app."""
    _name = 'nmcp.setup'
    _description = 'Connect an AI App'

    server_url = fields.Char('Connector URL', default=lambda self: self._server_url())
    can_connect = fields.Boolean(default=lambda self: self.env.user.has_group('novator_mcp.group_nmcp_user'))
    pro_installed = fields.Boolean(default=lambda self: self._pro_state() == 'installed')
    api_keys_allowed = fields.Boolean(default=lambda self: param_bool(self.env, 'novator_mcp.allow_api_keys', True))

    @api.model
    def _server_url(self):
        base = param_str(self.env, 'web.base.url', '').rstrip('/')
        return base + '/mcp'

    @api.model
    def _pro_state(self):
        return self.env['ir.module.module'].sudo().search([('name', '=', 'novator_mcp_pro')], limit=1).state

    def action_pro(self):
        return {'type': 'ir.actions.act_url', 'target': 'new', 'url': PRO_URL % ('%s.0' % release.version_info[0])}

    def action_my_connections(self):
        action = self.env['ir.actions.act_window']._for_xml_id('novator_mcp.action_nmcp_token_mine')
        return action
