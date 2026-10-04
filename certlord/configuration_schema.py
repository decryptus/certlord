"""XYS configuration structure checks, without loading or initializing services."""
from sonicprobe.libs import xys
from certlord.classes.exceptions import CertLordConfigError


xys.add_callback('certlord.config.mapping', lambda value: isinstance(value, dict))
MAPPING = '!~~callback(certlord.config.mapping) null'


def validate_fields(data, schema):
    # Unknown fields belong to extensions. Never use a wildcard that could consume
    # known optional fields before their XYS validators run.
    if not isinstance(data, dict) or not xys.validate(
            {key: value for key, value in data.items() if key in schema}, schema):
        raise CertLordConfigError('Invalid configuration structure')
    return data



CONFIG_SCHEMA = xys.load('''
general?: %s
modules*: %s
api_authentication*: %s
certificate_storage*: %s
ssl_checkers*: %s
''' % (MAPPING, MAPPING, MAPPING, MAPPING, MAPPING))
AUTH_SCHEMA = xys.load('''
backend?: !~~enum(httpdis,local) ''
permissions*: %s
''' % MAPPING)
STORAGE_SCHEMA = xys.load("backend?: !~~enum(vault) ''")
PERMISSIONS_SCHEMA = xys.load('[ !~~enum(read,write,deploy,challenge) "" ]')
CHECKER_SCHEMA = xys.load('enabled?: false')
MODULE_SCHEMA = xys.load('''
auton?: %s
certbot?: %s
tls_verification?: %s
allow_dns_resolv?: %s
''' % (MAPPING, MAPPING, MAPPING, MAPPING))


def validate_configuration(conf):
    validate_fields(conf, CONFIG_SCHEMA)
    auth = conf.get('api_authentication') or {}
    validate_fields(auth, AUTH_SCHEMA)
    for permissions in (auth.get('permissions') or {}).values():
        if not xys.validate(permissions, PERMISSIONS_SCHEMA):
            raise CertLordConfigError('Invalid API permissions configuration')
    validate_fields(conf.get('certificate_storage') or {}, STORAGE_SCHEMA)
    for checker in (conf.get('ssl_checkers') or {}).values():
        validate_fields(checker, CHECKER_SCHEMA)
    modules = conf.get('modules') or {}
    if 'ssl_certs' in modules:
        validate_fields(modules['ssl_certs'], MODULE_SCHEMA)
    return conf


def parse_configuration(conf):
    # Retain DWho's public facade, including credential-file resolution.
    from dwho.config import parse_conf
    return parse_conf(validate_configuration(conf), load_creds=True)
