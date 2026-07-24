"""Post-bind security-layer abstraction shared by every mechanism family.

A LayerStrategy wraps/unwraps whatever bytes LDAPTransport hands it, so the
rest of the codebase never needs to know whether the active layer is NTLM
sign-only, NTLM seal, Kerberos GSS_GetMIC, or Kerberos GSS_Wrap - only that
`wrap`/`unwrap` exist. `None` (no strategy) means the four no-layer methods:
the LDAP message goes out exactly as encoded, no 4-byte length prefix, no
wrap token.
"""

from __future__ import annotations

from typing import Protocol


class LayerStrategy(Protocol):
    """name is used for result reporting; wrap/unwrap operate on one LDAP
    message's raw encoded bytes at a time (LDAPTransport handles the
    4-byte length-prefix framing itself)."""

    name: str

    def wrap(self, plaintext: bytes) -> bytes: ...

    def unwrap(self, wrapped: bytes) -> bytes: ...
