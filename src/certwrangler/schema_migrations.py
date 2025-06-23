"""
This module contains state schema migrations that should be applied.
"""

from typing import Any, Callable, Dict, List


def _cert_migration_00_add_chain(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Switch from storing the CA and intermediate(s) separately to a generic
    chain field.

    This is done to more accurately represent what is returned from the
    ACME server based on RFC 8555. The trust anchor (CA cert) is not
    required to be returned, but can be optionally.
    """
    chain = []
    intermediates = data.pop("intermediates", None)
    ca = data.pop("ca", None)
    if isinstance(intermediates, list):
        for intermediate in intermediates:
            if intermediate is not None:
                chain.append(intermediate)
    if ca is not None:
        chain.append(ca)
    data["chain"] = chain if chain else None
    return data


ACCOUNT_STATE_SCHEMA_MIGRATIONS: List[Callable[[Dict[str, Any]], Dict[str, Any]]] = []
CERT_STATE_SCHEMA_MIGRATIONS: List[Callable[[Dict[str, Any]], Dict[str, Any]]] = [
    _cert_migration_00_add_chain,
]
