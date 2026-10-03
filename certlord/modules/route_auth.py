"""HTTP route registration policy, independent of credential adapters."""


def authenticated_routes(config, module_name, public_handlers=()):
    """Register protected HTTPdis routes for authentication before body parsing.

    Keep application operation permissions, public routes and the explicit local
    fixture mode. Copy route dictionaries instead of mutating caller config.
    """
    backend = (config.get('api_authentication') or {}).get('backend', 'httpdis')
    if backend != 'httpdis':
        return config
    modules = dict(config.get('modules') or {})
    module = dict(modules.get(module_name) or {})
    routes = {}
    for name, value in (module.get('routes') or {}).items():
        route = dict(value)
        if route.get('handler') not in public_handlers:
            route['auth'] = route.get('auth') or True
        routes[name] = route
    module['routes'] = routes
    modules[module_name] = module
    return dict(config, modules=modules)

