"""Settings stored as system parameters, read the same way on every Odoo version."""


def param_str(env, key, default=''):
    value = env['ir.config_parameter'].sudo().get_str(key, None)
    return default if value in (None, False, '') else value


def param_int(env, key, default=0):
    try:
        return int(param_str(env, key, default))
    except (TypeError, ValueError):
        return default


def param_bool(env, key, default=False):
    value = param_str(env, key, None)
    if value is None:
        return default
    return str(value).lower() in ('true', '1', 'yes')


def param_set(env, key, value):
    env['ir.config_parameter'].sudo().set_str(key, str(value))
