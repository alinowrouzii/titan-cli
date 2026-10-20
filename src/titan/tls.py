"""TLS for titan.efarda.ir.

The server sends only the leaf certificate. The Certum intermediate is missing,
so Python cannot build a chain. Verification is off for this CLI.
"""

from __future__ import annotations

import ssl


def unverified_context() -> ssl.SSLContext:
    return ssl._create_unverified_context()
