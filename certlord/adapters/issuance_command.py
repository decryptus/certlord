"""Bind the installed ACME HTTP connector to one issuance attempt."""
import os
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml
from sonicprobe import helpers
from certlord.classes.config import ISSUANCE_HEADER, CERTBOT_INSTALLER_CONFIG_OPTION, DEFAULT_INSTALLER_CONFIG


@contextmanager
def issuance_command(command, attempt):
    args = list(command['args'])
    env = command.get('env')
    source = (env if env is not None else os.environ).get('CBT_HTTPREQ_INST_CONFIG', DEFAULT_INSTALLER_CONFIG)
    for index, arg in enumerate(args):
        if arg == CERTBOT_INSTALLER_CONFIG_OPTION:
            if index + 1 >= len(args):
                raise ValueError('Missing installer configuration path')
            source = args[index + 1]
        elif arg.startswith(CERTBOT_INSTALLER_CONFIG_OPTION + '='):
            source = arg.split('=', 1)[1]
    conf = helpers.load_conf_yaml_file(source)
    if not isinstance(conf, dict):
        raise ValueError('Invalid installer configuration')
    deploy = conf.setdefault('deploy', {})
    headers = deploy.setdefault('headers', {})
    # Remove differently-cased copies before assigning the canonical header.
    for name in list(headers):
        if name.lower() == ISSUANCE_HEADER.lower():
            del headers[name]
    headers[ISSUANCE_HEADER] = attempt
    with TemporaryDirectory(prefix='certlord-issuance-') as directory:
        path = Path(directory) / 'installer.yml'
        with open(path, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
            yaml.safe_dump(conf, stream)
        yield args + [CERTBOT_INSTALLER_CONFIG_OPTION, str(path)], env
