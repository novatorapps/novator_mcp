"""The tools the AI can use, and how they run.

Every tool runs as the signed-in Odoo user: Odoo's own access rights and record rules apply, exactly as in
the web client. On top of that, passwords, keys and tokens are never shown or changed, and some technical
models are off limits. Paid add-ons extend this model (hooks at the end of the class).
"""
import json
import re
import time
from datetime import date, datetime

from odoo import _, api, models, release
from odoo.exceptions import AccessError, MissingError, UserError, ValidationError
from odoo.tools import html2plaintext

from .params import param_int

MAX_LIMIT = 200
MAX_TEXT = 4000
MAX_X2MANY = 50

HIDDEN_FIELD = re.compile(r'(passw|secret|token|api_?key|apikey|totp|private_key|signup_|oauth_access|'
                          r'password_crypt|_hash$|^key$)', re.I)
BLOCKED_MODELS = {
    'res.users.apikeys', 'res.users.apikeys.description', 'res.users.apikeys.show', 'ir.config_parameter',
    'ir.rule', 'ir.model.access', 'ir.cron', 'ir.actions.server', 'ir.module.module', 'ir.http',
    'ir.attachment.binary', 'res.users.identitycheck', 'change.password.wizard', 'change.password.own',
    'change.password.user', 'base.module.upgrade', 'base.module.uninstall', 'base.module.update',
    'auth_totp.device', 'auth_totp.wizard', 'res.config.settings', 'res.config', 'ir.mail_server',
    'fetchmail.server', 'ir.logging', 'ir.profile', 'bus.bus',
}
BLOCKED_PREFIXES = ('nmcp.', 'ir.qweb', 'ir.ui.', 'ir.actions', 'base_import.', 'auth_')
ALLOWED_IR = {'ir.attachment', 'ir.model', 'ir.model.fields', 'ir.sequence', 'ir.filters'}
BLOCKED_METHODS = {
    'create', 'write', 'unlink', 'read', 'search', 'search_read', 'search_count', 'browse', 'sudo', 'with_user',
    'with_context', 'with_company', 'with_env', 'exists', 'copy_data', 'export_data', 'load', 'flush_model',
    'flush_recordset', 'invalidate_model', 'invalidate_recordset', 'modified', 'init', 'check_access_rights',
    'check_access_rule', 'check_field_access_rights', 'fields_get', 'get_views', 'web_read', 'web_save',
    'web_search_read', 'read_group', 'web_read_group', 'name_search', 'toggle_active', 'message_post',
    'action_archive', 'action_unarchive', 'filtered', 'mapped', 'sorted', 'ensure_one', 'update', 'new',
    'default_get', 'onchange', 'user_has_groups', 'get_metadata', 'get_external_id', 'get_xml_id',
    'check_access', 'has_access', 'formatted_read_group', 'web_read_group', 'web_search_read', 'search_fetch',
    'fetch', 'read_progress_bar', 'name_create', 'export_data', 'web_override_translations', 'update_field_translations',
    'get_field_translations', 'action_reset_password', 'with_prefetch', 'grouped',
}

SERVER_INSTRUCTIONS = """You are connected to an Odoo database as the signed-in user, with that user's access rights.
How to work with Odoo:
- Start with odoo_list_models to find the document type (model), e.g. sale.order, account.move, res.partner.
- Use odoo_get_fields before reading or writing: field names, types, relations and selection values differ by version and installed apps.
- Domains are lists like [["state","=","sale"],["amount_total",">",1000]]. Use "|" / "&" prefix operators for OR / AND.
- Many2one values are [id, "name"] when read; write them as the id. Use odoo_find_by_name to turn a name into an id.
- For one2many / many2many writes use Odoo commands, e.g. [[0,0,{...}]] to add a line, [[6,0,[ids]]] to set.
- Prefer odoo_group_records for totals and reports instead of reading many records.
- Business actions (confirm an order, post an invoice, validate a transfer) are buttons: use odoo_call_method with the button's method, e.g. action_confirm. If it returns a wizard, create the wizard record with the given context and call its button.
- Before changing or deleting data, tell the user exactly what you will change and ask them to confirm.
- Dates are in UTC as YYYY-MM-DD HH:MM:SS. Amounts are in the document's currency."""


def _schema(props, required=()):
    return {'type': 'object', 'properties': props, 'required': list(required), 'additionalProperties': False}


MODEL = {'type': 'string', 'description': 'Technical model name, e.g. sale.order'}
DOMAIN = {'type': 'array', 'description': 'Odoo domain, e.g. [["state","=","sale"]]', 'items': {}}
FIELDS = {'type': 'array', 'items': {'type': 'string'},
          'description': 'Field names to return. Leave empty for the main fields.'}
IDS = {'type': 'array', 'items': {'type': 'integer'}, 'description': 'Record IDs'}
CONTEXT = {'type': 'object', 'description': 'Optional Odoo context, e.g. {"active_id": 7, "active_model": "sale.order"}'}

TOOLS = [
    {'name': 'odoo_whoami', 'kind': 'read', 'title': 'Who am I',
     'description': 'Signed-in user, companies, language, time zone, Odoo version and installed apps.',
     'inputSchema': _schema({})},
    {'name': 'odoo_list_models', 'kind': 'read', 'title': 'Find document types',
     'description': 'Search the document types (models) the user can read, by technical name or label. '
                    'Example: query "invoice" finds account.move.',
     'inputSchema': _schema({'query': {'type': 'string', 'description': 'Part of the name, e.g. "order"'},
                             'limit': {'type': 'integer', 'default': 40}})},
    {'name': 'odoo_get_fields', 'kind': 'read', 'title': 'Describe fields',
     'description': 'Fields of a model with label, type, relation, required/readonly and selection values.',
     'inputSchema': _schema({'model': MODEL,
                             'query': {'type': 'string', 'description': 'Only fields whose name or label contains this'},
                             'fields': FIELDS}, ['model'])},
    {'name': 'odoo_search_records', 'kind': 'read', 'title': 'Search records',
     'description': 'Search and read records. Returns the total count and the records found.',
     'inputSchema': _schema({'model': MODEL, 'domain': DOMAIN, 'fields': FIELDS,
                             'limit': {'type': 'integer', 'default': 20, 'maximum': MAX_LIMIT},
                             'offset': {'type': 'integer', 'default': 0},
                             'order': {'type': 'string', 'description': 'e.g. "date_order desc"'},
                             'context': CONTEXT}, ['model'])},
    {'name': 'odoo_read_records', 'kind': 'read', 'title': 'Read records',
     'description': 'Read records by ID.',
     'inputSchema': _schema({'model': MODEL, 'ids': IDS, 'fields': FIELDS, 'context': CONTEXT}, ['model', 'ids'])},
    {'name': 'odoo_count_records', 'kind': 'read', 'title': 'Count records',
     'description': 'Count the records that match a domain.',
     'inputSchema': _schema({'model': MODEL, 'domain': DOMAIN}, ['model'])},
    {'name': 'odoo_group_records', 'kind': 'read', 'title': 'Totals and groups',
     'description': 'Totals grouped by fields, like a pivot table. Measures look like "amount_total:sum"; '
                    'group by "date_order:month", "user_id", etc.',
     'inputSchema': _schema({'model': MODEL, 'domain': DOMAIN,
                             'groupby': {'type': 'array', 'items': {'type': 'string'}},
                             'measures': {'type': 'array', 'items': {'type': 'string'}},
                             'orderby': {'type': 'string'},
                             'limit': {'type': 'integer', 'default': 80, 'maximum': 500}},
                     ['model', 'groupby'])},
    {'name': 'odoo_find_by_name', 'kind': 'read', 'title': 'Find by name',
     'description': 'Find records by name (customer, product, user...) and return their IDs.',
     'inputSchema': _schema({'model': MODEL, 'name': {'type': 'string'},
                             'limit': {'type': 'integer', 'default': 10}}, ['model', 'name'])},
    {'name': 'odoo_create_record', 'kind': 'write', 'title': 'Create a record',
     'description': 'Create a record. Ask the user to confirm first.',
     'inputSchema': _schema({'model': MODEL, 'values': {'type': 'object', 'description': 'Field values'},
                             'context': CONTEXT}, ['model', 'values'])},
    {'name': 'odoo_update_records', 'kind': 'write', 'title': 'Update records',
     'description': 'Change field values on one or more records. Ask the user to confirm first.',
     'inputSchema': _schema({'model': MODEL, 'ids': IDS, 'values': {'type': 'object'}, 'context': CONTEXT},
                            ['model', 'ids', 'values'])},
    {'name': 'odoo_call_method', 'kind': 'write', 'title': 'Run a button',
     'description': 'Run a business action (a button), e.g. action_confirm on sale.order or action_post on '
                    'account.move. Ask the user to confirm first.',
     'inputSchema': _schema({'model': MODEL, 'method': {'type': 'string'}, 'ids': IDS,
                             'args': {'type': 'array', 'items': {}}, 'kwargs': {'type': 'object'},
                             'context': CONTEXT}, ['model', 'method'])},
    {'name': 'odoo_post_note', 'kind': 'write', 'title': 'Log a note',
     'description': 'Log an internal note in the chatter of a record.',
     'inputSchema': _schema({'model': MODEL, 'id': {'type': 'integer'}, 'body': {'type': 'string'}},
                            ['model', 'id', 'body'])},
    {'name': 'odoo_delete_records', 'kind': 'delete', 'title': 'Delete records',
     'description': 'Delete records. Cannot be undone: always ask the user to confirm first.',
     'inputSchema': _schema({'model': MODEL, 'ids': IDS}, ['model', 'ids'])},
]


class ToolError(Exception):
    """An error the AI should read and maybe fix (bad model, bad field...)."""


class McpServer(models.AbstractModel):
    _name = 'nmcp.server'
    _description = 'AI Connector Server'

    # ------------------------------------------------------------------ definitions
    @api.model
    def _nmcp_tool_definitions(self):
        """All tools in code. Paid add-ons append theirs."""
        return list(TOOLS)

    @api.model
    def _nmcp_instructions(self):
        return SERVER_INSTRUCTIONS

    @api.model
    def _nmcp_tool_allowed(self, name):
        """Hook: can the current user use this tool? (Paid add-on: per-group rules.)"""
        return True

    @api.model
    def _nmcp_available_tools(self):
        active = {t.name: t for t in self.env['nmcp.tool'].sudo().search([])}
        result = []
        for tool in self._nmcp_tool_definitions():
            rec = active.get(tool['name'])
            if not rec or not self._nmcp_tool_allowed(tool['name']):
                continue
            kind = tool.get('kind', 'read')
            result.append({
                'name': tool['name'], 'title': rec.title or tool['title'],
                'description': tool['description'], 'inputSchema': tool['inputSchema'],
                'annotations': {'title': rec.title or tool['title'], 'readOnlyHint': kind == 'read',
                                'destructiveHint': kind == 'delete', 'idempotentHint': kind == 'read',
                                'openWorldHint': False},
            })
        return result

    @api.model
    def _nmcp_prompts(self):
        """Hook: ready-made prompts (paid add-on: workflows)."""
        return []

    # ------------------------------------------------------------------ dispatch
    @api.model
    def _nmcp_call(self, name, arguments, client=None):
        """Run a tool for the current user. Returns an MCP CallToolResult dict."""
        tools = {t['name']: t for t in self._nmcp_available_tools()}
        log_vals = {'user_id': self.env.uid, 'client_id': client.id if client else False, 'tool': name,
                    'model': (arguments or {}).get('model') if isinstance(arguments, dict) else False,
                    'arguments': json.dumps(arguments, default=str)[:4000]}
        start = time.time()
        if name not in tools:
            return self._nmcp_result_error(_('Unknown or switched off tool: %s', name), log_vals, start, 'denied')
        if not isinstance(arguments, dict):
            arguments = {}
        handler = getattr(self, '_tool_' + name, None)
        if handler is None:
            return self._nmcp_result_error(_('Tool not available: %s', name), log_vals, start)
        try:
            early = self._nmcp_before_call(name, arguments, log_vals)
            if early is not None:
                return early
            with self.env.cr.savepoint():
                data = handler(**arguments)
                self.env.flush_all()
            self._nmcp_after_call(name, arguments, data, log_vals)
            if isinstance(data, dict):
                data = {k: v for k, v in data.items() if not k.startswith('__')}
        except TypeError as e:
            return self._nmcp_result_error(_('Wrong arguments: %s', e), log_vals, start)
        except (AccessError, MissingError) as e:
            return self._nmcp_result_error(_('Not allowed: %s', e), log_vals, start, 'denied')
        except (UserError, ValidationError, ToolError, ValueError, KeyError) as e:
            return self._nmcp_result_error(str(e), log_vals, start)
        except Exception as e:  # noqa: BLE001 - keep the server answering; the error goes back to the AI
            return self._nmcp_result_error('%s: %s' % (type(e).__name__, e), log_vals, start)
        log_vals.update(state='done', duration=int((time.time() - start) * 1000))
        self._nmcp_log(log_vals)
        text = json.dumps(data, default=str, ensure_ascii=False)
        result = {'content': [{'type': 'text', 'text': text}], 'isError': False}
        if isinstance(data, dict):
            result['structuredContent'] = data
        return result

    def _nmcp_result_error(self, message, log_vals, start, state='error'):
        log_vals.update(state=state, error=message[:2000], duration=int((time.time() - start) * 1000))
        self._nmcp_log(log_vals)
        return {'content': [{'type': 'text', 'text': message}], 'isError': True}

    def _nmcp_log(self, vals):
        if param_int(self.env, 'novator_mcp.log_days', 90) == 0:
            return self.env['nmcp.log']
        return self.env['nmcp.log'].sudo().create(vals)

    @api.model
    def _nmcp_before_call(self, name, arguments, log_vals):
        """Hook: return a CallToolResult to stop the call (paid add-on: approvals, limits)."""
        return None

    @api.model
    def _nmcp_after_call(self, name, arguments, data, log_vals):
        """Hook after a successful call (paid add-on: change history and undo)."""
        return None

    # ------------------------------------------------------------------ helpers
    def _h_model(self, model, context=None):
        if not isinstance(model, str) or model not in self.env:
            raise ToolError(_('Unknown model "%s". Use odoo_list_models to find it.', model))
        if not self._h_model_allowed(model):
            raise AccessError(_('The AI connector does not give access to %s.', model))
        Model = self.env[model]
        if context:
            if not isinstance(context, dict):
                raise ToolError(_('context must be an object'))
            safe = {k: v for k, v in context.items() if k not in ('uid', 'su', 'allowed_company_ids')}
            Model = Model.with_context(**safe)
        return Model

    @api.model
    def _h_model_allowed(self, model):
        if model in BLOCKED_MODELS or model.startswith(BLOCKED_PREFIXES):
            return False
        if model.startswith('ir.') and model not in ALLOWED_IR:
            return False
        return True

    def _h_can(self, Model, operation):
        if release.version_info[0] >= 18:
            return Model.has_access(operation)
        return Model.check_access_rights(operation, raise_exception=False)

    def _h_check(self, records, operation):
        if release.version_info[0] >= 18:
            records.check_access(operation)
        else:
            records.check_access_rights(operation)
            records.check_access_rule(operation)

    def _h_visible_fields(self, Model):
        """Fields the user may see, without secrets. {name: description}"""
        info = Model.fields_get(attributes=['string', 'type', 'relation', 'required', 'readonly', 'selection',
                                            'help', 'store'])
        return {name: desc for name, desc in info.items() if not HIDDEN_FIELD.search(name)}

    def _h_pick_fields(self, Model, requested):
        visible = self._h_visible_fields(Model)
        if requested:
            if not isinstance(requested, list):
                raise ToolError(_('fields must be a list of field names'))
            unknown = [f for f in requested if f not in visible]
            if unknown:
                raise ToolError(_('Unknown or hidden fields on %s: %s. Use odoo_get_fields.',
                                  Model._name, ', '.join(map(str, unknown))))
            return requested
        default = ['display_name']
        rec_name = Model._rec_name
        for name in ([rec_name] if rec_name else []) + ['state', 'partner_id', 'date', 'date_order', 'amount_total',
                                                        'user_id', 'company_id', 'email', 'phone', 'active']:
            if name in visible and name not in default:
                default.append(name)
        return default

    def _h_check_values(self, Model, values):
        if not isinstance(values, dict) or not values:
            raise ToolError(_('values must be an object with field values'))
        visible = self._h_visible_fields(Model)
        bad = [f for f in values if f not in visible]
        if bad:
            raise ToolError(_('Unknown or protected fields on %s: %s', Model._name, ', '.join(bad)))
        return values

    def _h_ids(self, ids):
        if isinstance(ids, int):
            ids = [ids]
        if not isinstance(ids, list) or not ids or not all(isinstance(i, int) for i in ids):
            raise ToolError(_('ids must be a list of record IDs'))
        if len(ids) > MAX_LIMIT:
            raise ToolError(_('At most %s records at once', MAX_LIMIT))
        return ids

    def _h_domain(self, domain):
        if domain in (None, ''):
            return []
        if isinstance(domain, str):
            try:
                domain = json.loads(domain)
            except ValueError:
                raise ToolError(_('domain must be a JSON list'))
        if not isinstance(domain, list):
            raise ToolError(_('domain must be a list'))
        return [tuple(d) if isinstance(d, list) else d for d in domain]

    def _h_serialize(self, records, fields_list):
        info = records._fields
        rows = []
        for rec in records:
            row = {'id': rec.id}
            for fname in fields_list:
                field = info.get(fname)
                if field is None:
                    continue
                value = rec[fname]
                if field.type == 'many2one':
                    value = [value.id, value.display_name] if value else False
                elif field.type in ('one2many', 'many2many'):
                    value = value.ids[:MAX_X2MANY] + (['...%s more' % (len(value) - MAX_X2MANY)]
                                                      if len(value) > MAX_X2MANY else [])
                elif field.type == 'binary':
                    value = ('<file, %s bytes>' % len(value)) if value else False
                elif field.type == 'html':
                    value = html2plaintext(value or '')[:MAX_TEXT] if value else False
                elif field.type in ('date', 'datetime'):
                    value = str(value) if value else False
                elif field.type == 'reference':
                    value = '%s,%s' % (value._name, value.id) if value else False
                elif isinstance(value, str) and len(value) > MAX_TEXT:
                    value = value[:MAX_TEXT] + '...'
                elif isinstance(value, (date, datetime)):
                    value = str(value)
                row[fname] = value
            rows.append(row)
        return rows

    def _h_plain(self, value, depth=0):
        """Make a method's return value JSON friendly."""
        if depth > 4:
            return str(value)
        if isinstance(value, models.BaseModel):
            return {'model': value._name, 'ids': value.ids[:MAX_LIMIT],
                    'names': [r.display_name for r in value[:20]]}
        if isinstance(value, dict):
            return {str(k): self._h_plain(v, depth + 1) for k, v in value.items()
                    if not (isinstance(k, str) and HIDDEN_FIELD.search(k))}
        if isinstance(value, (list, tuple)):
            return [self._h_plain(v, depth + 1) for v in value[:MAX_LIMIT]]
        if isinstance(value, (date, datetime)):
            return str(value)
        if isinstance(value, bytes):
            return '<%s bytes>' % len(value)
        if value is None or isinstance(value, (bool, int, float, str)):
            return value
        return str(value)

    # ------------------------------------------------------------------ tools
    def _tool_odoo_whoami(self):
        user = self.env.user
        apps = self.env['ir.module.module'].sudo().search([('state', '=', 'installed'), ('application', '=', True)])
        return {
            'user': {'id': user.id, 'name': user.name, 'login': user.login},
            'company': [user.company_id.id, user.company_id.name],
            'companies': [[c.id, c.name] for c in user.company_ids],
            'language': user.lang, 'timezone': user.tz or 'UTC',
            'odoo_version': release.version, 'apps': sorted(apps.mapped('shortdesc')),
        }

    def _tool_odoo_list_models(self, query='', limit=40):
        domain = [('transient', '=', False)]
        if query:
            domain += ['|', ('model', 'ilike', query), ('name', 'ilike', query)]
        found = []
        for rec in self.env['ir.model'].sudo().search(domain, order='model'):
            if len(found) >= min(int(limit or 40), MAX_LIMIT):
                break
            if rec.model not in self.env or not self._h_model_allowed(rec.model):
                continue
            if not self._h_can(self.env[rec.model], 'read'):
                continue
            found.append({'model': rec.model, 'name': rec.name})
        return {'models': found}

    def _tool_odoo_get_fields(self, model, query='', fields=None):
        Model = self._h_model(model)
        self._h_check(Model, 'read')
        visible = self._h_visible_fields(Model)
        out = {}
        for name, desc in sorted(visible.items()):
            if fields and name not in fields:
                continue
            if query and query.lower() not in name.lower() and query.lower() not in (desc.get('string') or '').lower():
                continue
            item = {'label': desc.get('string'), 'type': desc.get('type')}
            for key in ('relation', 'required', 'readonly', 'selection'):
                if desc.get(key):
                    item[key] = desc[key]
            if not desc.get('store', True):
                item['stored'] = False
            if desc.get('help'):
                item['help'] = desc['help'][:300]
            out[name] = item
        return {'model': model, 'name': self.env['ir.model']._get(model).name, 'fields': out}

    def _tool_odoo_search_records(self, model, domain=None, fields=None, limit=20, offset=0, order=None,
                                  context=None):
        Model = self._h_model(model, context)
        domain = self._h_domain(domain)
        limit = max(1, min(int(limit or 20), MAX_LIMIT))
        names = self._h_pick_fields(Model, fields)
        records = Model.search(domain, limit=limit, offset=int(offset or 0), order=order or None)
        total = Model.search_count(domain) if len(records) == limit or offset else len(records)
        return {'model': model, 'count': total, 'records': self._h_serialize(records, names)}

    def _tool_odoo_read_records(self, model, ids, fields=None, context=None):
        Model = self._h_model(model, context)
        records = Model.browse(self._h_ids(ids)).exists()
        self._h_check(records, 'read')
        return {'model': model, 'records': self._h_serialize(records, self._h_pick_fields(Model, fields))}

    def _tool_odoo_count_records(self, model, domain=None):
        Model = self._h_model(model)
        return {'model': model, 'count': Model.search_count(self._h_domain(domain))}

    def _tool_odoo_group_records(self, model, groupby, domain=None, measures=None, orderby=None, limit=80):
        Model = self._h_model(model)
        self._h_check(Model, 'read')
        if isinstance(groupby, str):
            groupby = [groupby]
        measures = [m for m in (measures or []) if m != '__count']
        visible = self._h_visible_fields(Model)
        for spec in list(groupby) + measures:
            if spec.split(':')[0] not in visible:
                raise ToolError(_('Unknown or hidden field: %s', spec))
        measures = [m if ':' in m else m + ':sum' for m in measures]
        rows = Model._read_group(self._h_domain(domain), groupby, measures + ['__count'],
                                 limit=min(int(limit or 80), 500), order=orderby or None)
        out = []
        for row in rows:
            item = {}
            keys = list(groupby) + [m[:-4] if m.endswith(':sum') else m.replace(':', '_') for m in measures]
            for key, value in zip(keys + ['count'], row):
                if isinstance(value, models.BaseModel):
                    value = [value.id, value.display_name] if len(value) == 1 else value.ids
                item[key] = self._h_plain(value)
            out.append(item)
        return {'model': model, 'groups': out}

    def _tool_odoo_find_by_name(self, model, name, limit=10):
        Model = self._h_model(model)
        found = Model.name_search(name or '', limit=min(int(limit or 10), 50))
        return {'model': model, 'records': [{'id': i, 'name': n} for i, n in found]}

    def _tool_odoo_create_record(self, model, values, context=None):
        Model = self._h_model(model, context)
        record = Model.create(self._h_check_values(Model, values))
        return {'model': model, 'id': record.id, 'name': record.display_name}

    def _tool_odoo_update_records(self, model, ids, values, context=None):
        Model = self._h_model(model, context)
        records = Model.browse(self._h_ids(ids)).exists()
        if not records:
            raise ToolError(_('No records found with these IDs'))
        records.write(self._h_check_values(Model, values))
        return {'model': model, 'updated': records.ids}

    def _tool_odoo_call_method(self, model, method, ids=None, args=None, kwargs=None, context=None):
        if not isinstance(method, str) or not method.isidentifier() or method.startswith('_') \
                or method in BLOCKED_METHODS:
            raise AccessError(_('The method %s cannot be called through the AI connector.', method))
        Model = self._h_model(model, context)
        if method in Model._fields or not callable(getattr(type(Model), method, None)):
            raise ToolError(_('%s has no method %s', model, method))
        records = Model.browse(self._h_ids(ids)).exists() if ids else Model
        if ids and not records:
            raise ToolError(_('No records found with these IDs'))
        result = getattr(records, method)(*(args or []), **(kwargs or {}))
        return {'model': model, 'method': method, 'ids': records.ids, 'result': self._h_plain(result)}

    def _tool_odoo_post_note(self, model, id, body):
        Model = self._h_model(model)
        record = Model.browse(int(id)).exists()
        if not record:
            raise ToolError(_('Record not found'))
        if not hasattr(record, 'message_post'):
            raise ToolError(_('%s has no chatter', model))
        self._h_check(record, 'read')
        subtype = self.env.ref('mail.mt_note', raise_if_not_found=False)
        message = record.message_post(body=body, message_type='comment',
                                      subtype_id=subtype.id if subtype else False)
        return {'model': model, 'id': record.id, 'message_id': message.id}

    def _tool_odoo_delete_records(self, model, ids):
        Model = self._h_model(model)
        records = Model.browse(self._h_ids(ids)).exists()
        names = records.mapped('display_name')
        records.unlink()
        return {'model': model, 'deleted': names}
