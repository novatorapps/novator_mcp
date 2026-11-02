from odoo import fields, models


class McpTool(models.Model):
    """One record per tool the AI can use. Switch a tool off and the AI no longer sees it."""
    _name = 'nmcp.tool'
    _description = 'AI Tool'
    _order = 'sequence, id'

    name = fields.Char('Tool', required=True, readonly=True)
    title = fields.Char(required=True, translate=True)
    description = fields.Text('What it does', translate=True)
    sequence = fields.Integer(default=10)
    active = fields.Boolean('On', default=True)
    kind = fields.Selection([('read', 'Reads data'), ('write', 'Changes data'), ('delete', 'Deletes data')],
                            default='read', required=True, readonly=True)
    module = fields.Char(readonly=True, help='App that provides the tool.')
    call_count = fields.Integer('Uses (30 days)', compute='_compute_call_count')

    _sql_constraints = [('name_unique', 'unique(name)', 'A tool with this name already exists.')]

    def _compute_call_count(self):
        since = fields.Datetime.subtract(fields.Datetime.now(), days=30)
        data = self.env['nmcp.log']._read_group([('tool', 'in', self.mapped('name')), ('create_date', '>=', since)],
                                               ['tool'], ['__count'])
        counts = dict(data)
        for tool in self:
            tool.call_count = counts.get(tool.name, 0)

    def action_toggle(self):
        for tool in self:
            tool.active = not tool.active
