"""LDAPTransport: thin subclass of impacket's LDAPConnection reusing its
socket/TLS/client-cert/channel-binding setup and send/recv framing, while
replacing its built-in login()/kerberosLogin() (which only ever expose a
single boolean signing flag, confirmed via direct source reading - never a
genuine plain/sign-only/seal-only/sign+seal choice) with this package's own
bind builders and LayerStrategy-based wrap/unwrap.
"""

from __future__ import annotations

import contextlib
import socket
import struct
from typing import Optional

from pyasn1.codec.ber import encoder

from impacket.ldap.ldap import LDAPConnection, LDAPSearchError, LDAPSessionError
from impacket.ldap.ldapasn1 import BindRequest, ExtendedRequest, LDAPMessage, ResultCode, Scope

from .layers import LayerStrategy

# RFC 4511 §4.14 / [MS-ADTS] LDAP_SERVER_START_TLS_OID.
_START_TLS_OID = "1.3.6.1.4.1.1466.20037"


class LDAPTransport(LDAPConnection):
    """signing=True is required for the base class's send()/recv_raw()
    (both gate on its own private/mangled __signing flag) to invoke
    encrypt()/decrypt() at all - those are the two PUBLIC methods this
    subclass overrides to delegate to whatever LayerStrategy is active,
    instead of the base class's own hardcoded KRB5/NTLM-sasl dispatch.
    signing=False (the four no-layer methods) skips that path entirely and
    every message goes out exactly as BER-encoded."""

    def __init__(self, url: str, dst_ip: Optional[str] = None, signing: bool = False):
        super().__init__(url, dstIp=dst_ip, signing=signing)
        # The base class silently forces __signing=False whenever url
        # starts with "ldaps://" (impacket/ldap/ldap.py), regardless of
        # what was just passed in - on the reasoning that SASL-layer
        # signing is redundant once TLS is already protecting the wire.
        # That's true for security, but it means a caller-requested layer
        # would be silently skipped rather than genuinely attempted: our
        # own send()/recv_raw() overrides gate encrypt()/decrypt() on this
        # exact flag, so a "PASS" under --scheme ldaps was passing because
        # nothing was ever actually sent through the layer, not because
        # the layer worked. Restoring the caller's real intent here makes
        # ldaps behave consistently with starttls (where the base class
        # never forces this off in the first place) - whatever the target
        # actually does with a doubly-layered request (accept, reject, or
        # reset) is the real, worth-reporting answer.
        self._LDAPConnection__signing = signing
        self.layer_strategy: Optional[LayerStrategy] = None
        self._next_message_id = 1

    def upgrade_tls(self, cert_pem: Optional[str] = None, key_pem: Optional[str] = None) -> None:
        """Upgrades the current plaintext socket to TLS in place, with an
        optional client certificate. Used two ways: directly, for a
        ldaps:// connection with a client cert (the base class's own
        ldaps:// handling in __init__ has no client-cert hook at all, so
        open_transport() connects plain to the TLS port and upgrades here
        instead - LDAPS is TLS-from-the-first-byte, no negotiation needed);
        and after start_tls()'s extended request succeeds."""
        from OpenSSL import SSL, crypto

        ctx = SSL.Context(SSL.TLS_METHOD)
        ctx.set_cipher_list(b"ALL:@SECLEVEL=0")
        if cert_pem and key_pem:
            ctx.use_certificate_file(cert_pem, filetype=crypto.FILETYPE_PEM)
            ctx.use_privatekey_file(key_pem, filetype=crypto.FILETYPE_PEM)
        conn = SSL.Connection(ctx, self._socket)
        conn.set_connect_state()
        conn.do_handshake()
        self._socket = conn
        self._SSL = True

    def start_tls(self, cert_pem: Optional[str] = None, key_pem: Optional[str] = None) -> None:
        """RFC 4511 §4.14 StartTLS extended operation over an already-open
        plaintext ldap:// connection, then upgrades the socket."""
        ext_req = ExtendedRequest()
        ext_req["requestName"] = _START_TLS_OID
        resp = self.sendReceive(ext_req)[0]["protocolOp"]["extendedResp"]
        if resp["resultCode"] != ResultCode("success"):
            raise LDAPSessionError(
                error=int(resp["resultCode"]),
                errorString=f"StartTLS failed: {resp['resultCode'].prettyPrint()}",
            )
        self.upgrade_tls(cert_pem, key_pem)

    def send(self, request, controls=None) -> None:
        """Overrides the base class's send(), which assigns each message a
        fresh random messageID (impacket/ldap/ldap.py:
        message['messageID'] = random.randrange(1, 2147483647)) - unlike a
        real LDAP client, which sends a monotonically increasing ID
        starting at 1. Everything else here mirrors the base class
        implementation exactly (private __binded/__signing flags accessed
        the same way mark_bound()/encrypt()/decrypt() already do)."""
        message = LDAPMessage()
        message["messageID"] = self._next_message_id
        self._next_message_id += 1
        message["protocolOp"].setComponentByType(request.getTagSet(), request)
        if controls is not None:
            message["controls"].setComponents(*controls)

        data = encoder.encode(message)
        if self._LDAPConnection__binded and self._LDAPConnection__signing:
            data = self.encrypt(data)
            self.sequenceNumber += 1
        return self._socket.sendall(data)

    def encrypt(self, data: bytes) -> bytes:
        if self.layer_strategy is None:
            raise RuntimeError("LDAPTransport.encrypt called with no active layer strategy")
        wrapped = self.layer_strategy.wrap(data)
        return struct.pack("!I", len(wrapped)) + wrapped

    def decrypt(self, data: bytes) -> bytes:
        if self.layer_strategy is None:
            raise RuntimeError("LDAPTransport.decrypt called with no active layer strategy")
        # recv_raw() has already read the length-prefixed frame in full and
        # hands it over whole, prefix included - only the wrapped body
        # after those 4 bytes needs unwrapping.
        return self.layer_strategy.unwrap(data[4:])

    def mark_bound(self, layer_strategy: Optional[LayerStrategy]) -> None:
        """Called by a bind builder once its handshake succeeds. Sets the
        base class's private __binded flag via its name-mangled attribute
        (_LDAPConnection__binded): the base class only ever sets this as a
        side effect of its own login()/kerberosLogin(), which this package
        deliberately bypasses for full flag control, so there is no public
        setter to call instead."""
        self.layer_strategy = layer_strategy
        self._LDAPConnection__binded = True

    def send_bind(self, bind_request: BindRequest) -> LDAPMessage:
        """Sends a BindRequest built by a mechanism module and returns the
        raw bindResponse protocolOp - always plaintext (pre-bind, no layer
        strategy is active yet regardless of what the constructor's
        signing= was)."""
        return self.sendReceive(bind_request)[0]["protocolOp"]

    def verify_rootdse_namingcontexts(self) -> tuple[bool, str]:
        """Post-bind proof step: a base-scope search for namingContexts on
        the rootDSE, through whatever layer_strategy is currently active
        (or none). Returns (ok, detail) - ok is True iff a result with at
        least one namingContexts value came back, proving the negotiated
        layer (if any) actually works end to end, not just that the bind
        succeeded."""
        try:
            results = self.search(
                searchBase="",
                scope=Scope("baseObject"),
                searchFilter="(objectClass=*)",
                attributes=["namingContexts"],
                sizeLimit=1,
            )
        except LDAPSearchError as exc:
            return False, f"search failed: {exc}"
        except Exception as exc:  # wrap/unwrap errors, malformed responses, etc.
            return False, f"post-bind operation failed: {exc}"

        for entry in results:
            for attr in entry["attributes"]:
                if str(attr["type"]).lower() == "namingcontexts" and len(attr["vals"]) > 0:
                    return True, "namingContexts present"
        return False, "no namingContexts value in response"


@contextlib.contextmanager
def _redirect_getaddrinfo_port(target_port: int):
    """Impacket's LDAPConnection.__init__ hardcodes the port it resolves
    via socket.getaddrinfo() based solely on the URL scheme prefix (389
    for "ldap://", 636 for "ldaps://") - there's no way to give it a
    different port through the public URL interface at all. Used only for
    the ldaps+client-cert path, which deliberately connects via a plain
    "ldap://" URL (to reach the base class's non-SSL connect code, since
    its own ldaps:// SSL.Context has no client-cert hook) but still needs
    the real TLS port (636 by default, or a --port override) rather than
    389. Redirecting getaddrinfo is contained to the single connect call
    below and restored immediately after, synchronously, in a single-
    threaded CLI tool - not a risk of cross-talk with anything else."""
    real_getaddrinfo = socket.getaddrinfo

    def _patched(host, _port, *args, **kwargs):
        return real_getaddrinfo(host, target_port, *args, **kwargs)

    socket.getaddrinfo = _patched
    try:
        yield
    finally:
        socket.getaddrinfo = real_getaddrinfo


def open_transport(
    target: str,
    port: Optional[int],
    scheme: str,
    signing: bool,
    dst_ip: Optional[str] = None,
    cert_pem: Optional[str] = None,
    key_pem: Optional[str] = None,
) -> LDAPTransport:
    """Single place every method family connects through, so --scheme
    (ldap/starttls/ldaps) applies uniformly across the whole matrix rather
    than each mechanism module picking its own URL scheme. A client
    certificate (cert_pem/key_pem) is optional and applies under either
    starttls or ldaps - under plain ldap there's no TLS session for
    SASL EXTERNAL to derive an identity from, which is a legitimate outcome
    to observe, not something to special-case here."""
    # impacket's own LDAPConnection.__init__ never actually parses a port
    # out of the URL - it hardcodes _dstPort per scheme prefix (389/636)
    # and treats everything after "://" as the hostname verbatim, colon
    # included. So a URL only gets a ":port" suffix when --port explicitly
    # overrides the default; appending it unconditionally breaks
    # getaddrinfo() for the common (default-port) case.
    def _url(url_scheme: str, default_port: int) -> str:
        if port and port != default_port:
            return f"{url_scheme}://{target}:{port}"
        return f"{url_scheme}://{target}"

    if scheme == "ldaps":
        if cert_pem and key_pem:
            # Base class's own ldaps:// handling in __init__ has no
            # client-cert hook - connect plain (via a "ldap://" URL, to
            # reach its non-SSL connect path) and upgrade ourselves
            # instead. LDAPS is TLS-from-the-first-byte, no StartTLS
            # negotiation - but that still means reaching the real TLS
            # port (636 by default), which the getaddrinfo redirect below
            # provides since the base class won't take one via the URL.
            with _redirect_getaddrinfo_port(port or 636):
                transport = LDAPTransport("ldap://" + target, dst_ip=dst_ip, signing=signing)
            transport.upgrade_tls(cert_pem, key_pem)
            return transport
        return LDAPTransport(_url("ldaps", 636), dst_ip=dst_ip, signing=signing)

    transport = LDAPTransport(_url("ldap", 389), dst_ip=dst_ip, signing=signing)
    if scheme == "starttls":
        transport.start_tls(cert_pem, key_pem)
    return transport
