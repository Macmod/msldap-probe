"""Method registry: one entry per auth-method name, mapping to a bind
builder and the credential fields it needs. Mechanism families (NTLM,
Kerberos) live in their own modules and register their 4-layer variants
here; the three no-layer methods are built directly in this file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from impacket.ldap.ldapasn1 import BindRequest, ResultCode

from .transport import LDAPTransport, open_transport


@dataclass
class Credentials:
    target: str
    port: Optional[int] = None
    domain: str = ""
    username: str = ""
    password: str = ""
    lmhash: str = ""
    nthash: str = ""
    aes_key: str = ""
    kdc_host: Optional[str] = None
    cert_pem: Optional[str] = None
    key_pem: Optional[str] = None
    # ldap (default, no transport-level TLS), starttls (RFC 4511 §4.14 -
    # plain connect, then upgrade in place), or ldaps (implicit TLS from
    # the first byte). Applies uniformly to every method via connect(),
    # independent of whatever SASL security layer (if any) a given method
    # negotiates on top.
    scheme: str = "ldap"
    # The LDAP service's real hostname for Kerberos SPN construction
    # (ldap/<spn_host>) - target is very often a bare IP, and AD doesn't
    # register SPNs against IPs (the same issue ldapx's own Kerberos
    # forwarder work hit earlier). Defaults to target if not given, which
    # only works when target already is a resolvable hostname.
    spn_host: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.spn_host:
            self.spn_host = self.target


@dataclass
class BindOutcome:
    ok: bool
    detail: str
    layer_strategy: object = None  # LayerStrategy | None, kept loosely typed to avoid an import cycle


@dataclass
class Method:
    name: str
    requires: list[str]
    # Builds a fresh, connected (but not yet bound) transport for this method.
    connect: Callable[[Credentials], LDAPTransport]
    # Performs the bind on that transport; on success calls transport.mark_bound(...)
    # and returns ok=True with whatever LayerStrategy (or None) is now active.
    bind: Callable[[LDAPTransport, Credentials], BindOutcome]


REGISTRY: dict[str, Method] = {}


def register(method: Method) -> None:
    if method.name in REGISTRY:
        raise ValueError(f"duplicate method name: {method.name}")
    REGISTRY[method.name] = method


def _connect_plain(creds: Credentials) -> LDAPTransport:
    return open_transport(creds.target, creds.port, creds.scheme, signing=False, cert_pem=creds.cert_pem, key_pem=creds.key_pem)


def bind_result_code(protocol_op) -> ResultCode:
    return protocol_op["bindResponse"]["resultCode"]


def bind_failure_detail(protocol_op) -> str:
    """resultCode plus the DC's own diagnosticMessage - the diagnostic text
    is often the only thing that distinguishes a genuine credentials
    problem from a protocol-level rejection (e.g. AD's SEC_E_QOP_NOT_SUPPORTED
    for an unsupported sign/seal combination shows up as resultCode
    invalidCredentials too - the diagnostic text is what actually says so)."""
    resp = protocol_op["bindResponse"]
    code = resp["resultCode"].prettyPrint()
    diag = str(resp["diagnosticMessage"]).strip()
    return f"{code} ({diag})" if diag else code


_bind_result_code = bind_result_code  # kept for this module's own call sites below


def _bind_simple(transport: LDAPTransport, user_dn: str, password: str) -> BindOutcome:
    req = BindRequest()
    req["version"] = 3
    req["name"] = user_dn
    req["authentication"]["simple"] = password
    resp = transport.send_bind(req)
    code = _bind_result_code(resp)
    if code == ResultCode("success"):
        transport.mark_bound(None)
        return BindOutcome(True, "bind succeeded")
    return BindOutcome(False, bind_failure_detail(resp))


def _bind_anonymous(transport: LDAPTransport, creds: Credentials) -> BindOutcome:
    return _bind_simple(transport, "", "")


def _bind_simple_authenticated(transport: LDAPTransport, creds: Credentials) -> BindOutcome:
    name = f"{creds.username}@{creds.domain}" if "." in creds.domain else (
        f"{creds.domain}\\{creds.username}" if creds.domain else creds.username
    )
    return _bind_simple(transport, name, creds.password)


def _bind_external(transport: LDAPTransport, creds: Credentials) -> BindOutcome:
    req = BindRequest()
    req["version"] = 3
    req["name"] = ""
    req["authentication"]["sasl"]["mechanism"] = "EXTERNAL"
    # RFC 4422 EXTERNAL: credentials optional, empty here (no authzid
    # override) - identity comes from whatever TLS session (if any) is
    # already established. --scheme=ldap (no TLS) or omitting --cert-pem/
    # --key-pem are both valid, non-skipped configurations - they just
    # mean there's no client identity for the target to authenticate as.
    resp = transport.send_bind(req)
    code = _bind_result_code(resp)
    if code == ResultCode("success"):
        transport.mark_bound(None)
        return BindOutcome(True, "bind succeeded (identity from TLS client cert)")
    return BindOutcome(False, bind_failure_detail(resp))


register(Method("anonymous_bind", requires=[], connect=_connect_plain, bind=_bind_anonymous))
register(Method("simple_bind", requires=["username", "password"], connect=_connect_plain, bind=_bind_simple_authenticated))
# No requires: --scheme controls whether there's a TLS session at all, and
# --cert-pem/--key-pem are optional - without them this still runs and
# shows what a target does with an EXTERNAL bind and no client identity,
# rather than silently skipping.
register(Method("sasl_external", requires=[], connect=_connect_plain, bind=_bind_external))
