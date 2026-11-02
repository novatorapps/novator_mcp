from datetime import timedelta

from odoo import api, fields, models

from .params import param_int


class McpLog(models.Model):
    """What the AI did: one line per tool call."""
    _name = 'nmcp.log'
    _description = 'AI Activity'
    _order = 'id desc'

    user_id = fields.Many2one('res.users', 'User', readonly=True, index=True, ondelete='set null')
    client_id = fields.Many2one('nmcp.client', 'AI App', readonly=True, ondelete='set null')
    tool = fields.Char(readonly=True, index=True)
    tool_title = fields.Char('Action', compute='_compute_tool_title')
    model = fields.Char('Document Type', readonly=True, index=True)
    res_ids = fields.Char('Records', readonly=True)
    arguments = fields.Text(readonly=True)
    summary = fields.Char(readonly=True)
    state = fields.Selection([('done', 'Done'), ('error', 'Error'), ('denied', 'Not allowed')],
                             default='done', readonly=True)
    error = fields.Text(readonly=True)
    duration = fields.Integer('Time (ms)', readonly=True)

    def _compute_tool_title(self):
        titles = {t.name: t.title for t in self.env['nmcp.tool'].sudo().with_context(active_test=False).search([])}
        for log in self:
            log.tool_title = titles.get(log.tool, log.tool)

    @api.model
    def _gc(self):
        days = param_int(self.env, 'novator_mcp.log_days', 90)
        if days > 0:
            self.sudo().search([('create_date', '<', fields.Datetime.now() - timedelta(days=days))]).unlink()

    def action_open_records(self):
        self.ensure_one()
        ids = [int(i) for i in (self.res_ids or '').split(',') if i.strip().isdigit()]
        if not self.model or not ids or self.model not in self.env:
            return False
        action = {'type': 'ir.actions.act_window', 'res_model': self.model, 'name': self.model}
        if len(ids) == 1:
            action.update(view_mode='form', res_id=ids[0])
        else:
            action.update(view_mode='tree,form', domain=[('id', 'in', ids)])
        return action
