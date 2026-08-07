"""Method registry: one entry per auth-method name, mapping to a bind
builder and the credential fields it needs. Mechanism families (NTLM,
Kerberos) live in their own modules and register their 4-layer variants
here; the three no-layer methods are built directly in this file.
"""

from __future__ import annotations

from dataclasses import dataclass
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
    lmhash: bytes = b""
    nthash: bytes = b""
    aes_key: str = ""
    # Path to a Kerberos credentials cache file. When set, Kerberos methods
    # use the cached service ticket (or TGT) from this file instead of
    # requesting a fresh TGT from the KDC. Overrides KRB5CCNAME. When None
    # and no other Kerberos credential is supplied, Kerberos methods obtain
    # a TGT in memory from whatever credential was passed (--password,
    # --hashes, or --aes-key) via getKerberosTGT.
    ccache: Optional[str] = None
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
    # register SPNs against IPs. Defaults to target if not given, which
    # only works when target already is a resolvable hostname.
    spn_host: Optional[str] = None
    # Which subkey etype to propose in the Kerberos AP-REQ Authenticator's
    # optional subkey field (RFC 4120 §5.5.1). "none" = no subkey proposed,
    # leaving the DC's msDS-SupportedEncryptionTypes to determine the AP-REP
    # acceptor subkey etype (or none at all). "rc4-hmac", "aes128-cts-hmac-sha1-96",
    # or "aes256-cts-hmac-sha1-96" (default) propose a subkey with that etype.
    # Ignored by non-Kerberos methods.
    propose_subkey: str = "aes256-cts-hmac-sha1-96"
    # Override the AP-REQ GSS-API checksum flags (int bitmask) for Kerberos
    # methods. Combines GSS_C_INTEG_FLAG (0x20) and GSS_C_CONF_FLAG (0x10)
    # per RFC 4121 \u00a74.1.1.1. When set, uses these flags directly for the
    # AP-REQ Authenticator checksum instead of each method family's default
    # (GSSAPI: 0x03, SPNEGO: derived from the bind's own layer). Ignored by
    # non-Kerberos methods.
    cksum_flags: int | None = None
    # Whether an NTLM layer that negotiated SIGN without SEAL should
    # nonetheless encrypt what it sends. False (default) puts on the wire
    # exactly what the negotiated flags describe, so sign-only really is
    # signed-not-encrypted. True reproduces what Active Directory requires -
    # it unseals every post-bind body once any security layer is active, and
    # answers a cleartext one with an unsolicited Notice of Disconnection
    # ("Error decrypting ldap message"), so sign-only only completes against
    # a DC with this set. Ignored by non-NTLM methods.
    ntlm_always_seal: bool = False
    # Which cipher to propose for a DIGEST-MD5 auth-conf bind (RFC 2831
    # §2.1.2). The bind fails up front if the server's challenge doesn't
    # offer it. Ignored by every other method, including the other two
    # DIGEST-MD5 QOP levels, which seal nothing.
    digest_md5_cipher: str = "rc4"
    # Whether a SASL bind should carry an RFC 5929 `tls-server-end-point`
    # channel binding, tying the authentication to the TLS certificate the
    # connection is running on. Only meaningful under --scheme starttls or
    # ldaps; on a plaintext connection there is no channel to bind and the
    # token is omitted regardless. NTLM and Kerberos carry it; simple binds,
    # SASL EXTERNAL and DIGEST-MD5 have nowhere to put one.
    channel_bindings: bool = False
    # Whether the AUTHENTICATE_MESSAGE should declare its MIC through
    # MsvAvFlags bit 0x2. Every NTLM method populates the MIC field either
    # way; this decides only whether the client says so, which per MS-NLMP
    # §3.1.5.1.2 is what a client supplying a MIC is required to do and what
    # gives a server reason to verify it. Off by default, which is what
    # impacket does - it populates the field and never sets the bit.
    # Ignored by non-NTLM methods.
    announce_mic: bool = False
    # Whether NTLM methods compute an NTLMv1 response instead of NTLMv2.
    # NTLMv1's NtChallengeResponse is 24 bytes of DES output with no AV_PAIR
    # list, so everything carried in that list is unavailable: channel
    # bindings (MsvAvChannelBindings) and the MIC declaration (MsvAvFlags)
    # both have nowhere to go, and impacket's computeResponseNTLMv1 does not
    # even accept a channel binding argument. Modern Active Directory
    # refuses NTLMv1 outright unless the LAN Manager authentication level
    # has been lowered. Ignored by non-NTLM methods.
    ntlmv1: bool = False
    # Whether an NTLMv1 bind suppresses extended session security. Off, so
    # --ntlmv1 negotiates ESS. Setting it puts the legacy signing and sealing
    # regime on the wire instead: SIGNKEY yields no key, the signature is the
    # MS-NLMP §3.4.4.1 form, and one sealing key serves both directions
    # half-duplex.
    no_ess: bool = False
    # What NTLM methods put in the AUTHENTICATE_MESSAGE MIC field:
    # "computed" is the HMAC-MD5 of the three messages, "empty" is the field
    # present and all zero, "drop" is no field at all. Independent of
    # announce_mic, which decides only whether a populated field is declared.
    #
    # Dropping it also drops the Version field. MS-NLMP §2.2.1.3 places
    # Version and then MIC between the fixed header and the payload and gives
    # neither a presence flag, so a receiver takes both to be there exactly
    # when NTLMSSP_NEGOTIATE_VERSION is set and they have to be emitted or
    # omitted together. Ignored by non-NTLM methods.
    mic: str = "computed"

    def __post_init__(self) -> None:
        if not self.spn_host:
            self.spn_host = self.target


@dataclass
class BindOutcome:
    ok: bool
    detail: str
    layer_strategy: object = (
        None  # LayerStrategy | None, kept loosely typed to avoid an import cycle
    )


@dataclass
class Method:
    name: str
    requires: list[str]
    # Builds a fresh, connected (but not yet bound) transport for this method.
    connect: Callable[[Credentials], LDAPTransport]
    # Performs the bind on that transport; on success calls transport.mark_bound(...)
    # and returns ok=True with whatever LayerStrategy (or None) is now active.
    bind: Callable[[LDAPTransport, Credentials], BindOutcome]
    # Optional custom eligibility check. Overrides requires when set.
    # Should return (True, "") if eligible, (False, "reason") if not.
    eligible: Callable[[Credentials], tuple[bool, str]] | None = None


REGISTRY: dict[str, Method] = {}


def register(method: Method) -> None:
    if method.name in REGISTRY:
        raise ValueError(f"duplicate method name: {method.name}")
    REGISTRY[method.name] = method


def _connect_plain(creds: Credentials) -> LDAPTransport:
    return open_transport(
        creds.target,
        creds.port,
        creds.scheme,
        signing=False,
        cert_pem=creds.cert_pem,
        key_pem=creds.key_pem,
    )


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


def _bind_simple_authenticated(
    transport: LDAPTransport, creds: Credentials
) -> BindOutcome:
    name = (
        f"{creds.username}@{creds.domain}"
        if "." in creds.domain
        else (f"{creds.domain}\\{creds.username}" if creds.domain else creds.username)
    )
    return _bind_simple(transport, name, creds.password)


def _connect_external(creds: Credentials) -> LDAPTransport:
    """SASL EXTERNAL connect: when a client cert is provided and --scheme
    is ldaps or starttls, forces StartTLS — AD only binds the TLS client
    cert identity to EXTERNAL when the TLS handshake happened in response
    to StartTLS (MS-ADTS: "The presence of the 'EXTERNAL' string value in
    the supportedSASLMechanisms attribute indicates that the DC accepts
    external security mechanisms for LDAP bind requests… the external
    authentication information … comes from the client certificate
    presented by the client during the SSL/TLS handshake that occurs in
    response to the client sending an LDAP_SERVER_START_TLS_OID extended
    operation"), not when TLS was established implicitly via LDAPS.
    An explicit --scheme ldap (no TLS) is left alone — it's a legitimate
    test that shows what a server does with EXTERNAL when no TLS session
    is available to carry an identity."""
    if creds.cert_pem and creds.key_pem and creds.scheme != "ldap":
        return open_transport(
            creds.target,
            creds.port,
            "starttls",
            signing=False,
            cert_pem=creds.cert_pem,
            key_pem=creds.key_pem,
        )
    return _connect_plain(creds)


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


register(
    Method("anonymous_bind", requires=[], connect=_connect_plain, bind=_bind_anonymous)
)
register(
    Method(
        "simple_bind",
        requires=["username", "password"],
        connect=_connect_plain,
        bind=_bind_simple_authenticated,
    )
)
# No requires: --scheme controls whether there's a TLS session at all, and
# --cert-pem/--key-pem are optional - without them this still runs and
# shows what a target does with an EXTERNAL bind and no client identity,
# rather than silently skipping.
#
# connect=_connect_external: uses StartTLS when a client cert is provided
# and --scheme != ldap (ldaps and starttls both go through StartTLS),
# because AD only binds the TLS client cert identity to EXTERNAL when the
# TLS handshake happened in response to StartTLS, not under implicit LDAPS
# TLS.  When --scheme is ldap or no cert is provided, falls through to
# _connect_plain which honours --scheme as-is.
register(
    Method("sasl_external", requires=[], connect=_connect_external, bind=_bind_external)
)
