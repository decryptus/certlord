"""Authenticated readiness without printing credentials or response bodies."""
import sys
import requests
import yaml
try:
    with open('/etc/certlord/health.yml') as stream:
        credentials = yaml.safe_load(stream)
    response = requests.get('http://127.0.0.1:8666/api/health/ready',
                            auth=(credentials['user'], credentials['password']), timeout=12)
    sys.exit(0 if response.status_code == 200 else 1)
except Exception:
    sys.exit(1)
