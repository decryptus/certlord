"""DWho Redis operations with explicit finite socket waits and no implicit replay."""
import math

from dwho.adapters.redis import DWhoAdapterRedis
from redis import Redis
from redis.backoff import NoBackoff
from redis.connection import parse_url
from redis.retry import Retry

from certlord.classes.config import DEFAULT_REDIS_TIMEOUT
from certlord.classes.exceptions import CertLordConfigError


def redis_adapter(config, prefix):
    adapter = DWhoAdapterRedis(config, load=False)
    for name, conf in config['general']['redis'].items():
        if not name.startswith(prefix):
            continue
        url = conf['url']
        try:
            options = parse_url(url)
            timeouts = {}
            for key in ('socket_timeout', 'socket_connect_timeout'):
                value = options.get(key, DEFAULT_REDIS_TIMEOUT)
                timeout = float(value)
                if isinstance(value, bool) or not math.isfinite(timeout) or timeout <= 0:
                    raise ValueError()
                timeouts[key] = timeout
            if options.get('retry_on_timeout') or options.get('retry_on_error') or 'retry' in options:
                raise ValueError()
        except (TypeError, ValueError):
            raise CertLordConfigError('Redis requires positive finite socket timeouts and disabled retries') from None
        # URL options take precedence in redis-py, so validate those before construction.
        connection = Redis.from_url(url, **timeouts, retry=Retry(NoBackoff(), 0),
                                    retry_on_timeout=False, retry_on_error=[])
        adapter.servers[name] = {'conn': connection,
                                'options': {key: value for key, value in conf.items() if key != 'url'}}
    return adapter
