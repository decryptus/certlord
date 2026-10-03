"""Issuance callback protocol metadata."""
from certlord.classes.config import ISSUANCE_HEADER


def issuance_header(headers):
    values = [value for name, value in headers.items() if name.lower() == ISSUANCE_HEADER.lower()]
    return values[0] if len(values) == 1 else None
