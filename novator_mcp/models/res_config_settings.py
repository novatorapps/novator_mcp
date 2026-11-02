from odoo import api, fields, models

from .params import param_bool, param_set

BOOL_PARAMS = {
    'nmcp_allow_api_keys': 'novator_mcp.allow_api_keys',
    'nmcp_allow_dcr': 'novator_mcp.allow_dcr',
    'nmcp_allow_cimd': 'novator_mcp.allow_cimd',
}


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    nmcp_all_users = fields.Boolean(
        'Every internal user can connect', implied_group='novator_mcp.group_nmcp_user', group='base.group_user',
        help='Off: only the users you add to "AI Connector / User" can connect an AI app.')
    # stored as 'True' / 'False' so that unticking is remembered (an empty parameter means 'on')
    nmcp_allow_api_keys = fields.Boolean('Odoo API keys')
    nmcp_allow_dcr = fields.Boolean('Apps can register themselves')
    nmcp_allow_cimd = fields.Boolean('Apps identified by their website')
    nmcp_clients_policy = fields.Selection(
        [('any', 'Any AI app'), ('claude', 'Claude only')], string='Allowed AI apps',
        config_parameter='novator_mcp.clients_policy', default='any')
    nmcp_access_hours = fields.Integer('Sign-in renews every (hours)', config_parameter='novator_mcp.access_hours',
                                       default=1)
    nmcp_refresh_days = fields.Integer('Stay connected for (days)', config_parameter='novator_mcp.refresh_days',
                                       default=30)
    nmcp_log_days = fields.Integer('Keep activity for (days)', config_parameter='novator_mcp.log_days', default=90,
                                   help='0 keeps no activity log.')
    @api.model
    def get_values(self):
        res = super().get_values()
        for field, key in BOOL_PARAMS.items():
            res[field] = param_bool(self.env, key, True)
        return res

    def set_values(self):
        super().set_values()
        for field, key in BOOL_PARAMS.items():
            param_set(self.env, key, bool(self[field]))

    nmcp_server_url = fields.Char('Connector URL', default=lambda self: self.env['nmcp.setup']._server_url())
