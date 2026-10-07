#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import io
import os
import re
import yaml
from setuptools import find_packages, setup

current_dir = os.path.abspath(os.path.dirname(__file__))


def read_project_file(name):
    with io.open(os.path.join(current_dir, name), 'r', encoding='utf-8') as stream:
        return stream.read()


requirements = [line.strip() for line in read_project_file('requirements.txt').splitlines()
                if line.strip() and not line.lstrip().startswith('#')]
setup_cfg = yaml.safe_load(read_project_file('setup.yml'))
long_desc = read_project_file('README.md')
public_base = setup_cfg['url'] + '/blob/v' + setup_cfg['version'] + '/'
raw_base = setup_cfg['url'].replace('https://github.com/', 'https://raw.githubusercontent.com/') + '/v' + setup_cfg['version'] + '/'
long_desc = re.sub(r'(!\[[^\]]*\])\((?![a-zA-Z][a-zA-Z0-9+.-]*:|#)([^)]+)\)',
                   lambda match: match.group(1) + '(' + raw_base + match.group(2) + ')', long_desc)
long_desc = re.sub(r'\]\((?![a-zA-Z][a-zA-Z0-9+.-]*:|#)([^)]+)\)',
                   lambda match: '](' + public_base + match.group(1) + ')', long_desc)
long_desc = re.sub(r'(src|srcset)="(assets/[^" ]+)"',
                   lambda match: match.group(1) + '="' + raw_base + match.group(2) + '"', long_desc)
long_desc_content_type = 'text/markdown'

setup(
    name                          = setup_cfg['name'],
    version                       = setup_cfg['version'],
    description                   = setup_cfg['description'],
    author                        = setup_cfg['author'],
    author_email                  = setup_cfg['author_email'],
    license                       = setup_cfg['license'],
    url                           = setup_cfg['url'],
    scripts                       = ['bin/certlord'],
    packages                      = find_packages(include=['certlord', 'certlord.*']),
    install_requires              = requirements,
    extras_require                = {'textual': ['dwho[textual]>=0.3.65']},
    python_requires               = ', '.join(setup_cfg['python_requires']),
    classifiers                   = setup_cfg['classifiers'],
    long_description              = long_desc,
    long_description_content_type = long_desc_content_type
)
