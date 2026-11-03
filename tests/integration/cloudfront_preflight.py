#!/usr/bin/env python3
"""Compatibility entry point for the contributor read-only preflight."""
from certlord.cloudfront.preflight import main

if __name__ == '__main__':
    raise SystemExit(main())
