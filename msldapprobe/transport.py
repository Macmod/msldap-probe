"""LDAPTransport: thin subclass of impacket's LDAPConnection reusing its
socket/TLS/client-cert/channel-binding setup and send/recv framing, while
replacing its built-in login()/kerberosLogin() (which only ever expose a
single boolean signing flag, confirmed via direct source reading - never a
genuine plain/sign-only/seal-only/sign+seal choice) with this package's own
bind builders and LayerStrategy-based wrap/unwrap.
"""

from __future__ import annotations

import contextlib
import hashlib
import socket
import struct
from typing import Optional

from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import SubstrateUnderrunError

from impacket.ldap.ldap import LDAPConnection, LDAPSearchError, LDAPSessionError
from impacket.ldap.ldapasn1 import (
    BindRequest,
    ExtendedRequest,
    LDAPMessage,
    ResultCode,
    Scope,
)

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
        # Bytes read past the end of the SASL frame currently being consumed;
        # they belong to the next frame. See recv_raw().
        self._sasl_buf = b""

    def upgrade_tls(
        self, cert_pem: Optional[str] = None, key_pem: Optional[str] = None
    ) -> None:
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

    def start_tls(
        self, cert_pem: Optional[str] = None, key_pem: Optional[str] = None
    ) -> None:
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
            raise RuntimeError(
                "LDAPTransport.encrypt called with no active layer strategy"
            )
        wrapped = self.layer_strategy.wrap(data)
        return struct.pack("!I", len(wrapped)) + wrapped

    def decrypt(self, data: bytes) -> bytes:
        if self.layer_strategy is None:
            raise RuntimeError(
                "LDAPTransport.decrypt called with no active layer strategy"
            )
        # recv_raw() has already read the length-prefixed frame in full and
        # hands it over whole, prefix included - only the wrapped body
        # after those 4 bytes needs unwrapping.
        return self.layer_strategy.unwrap(data[4:])

    def channel_binding_token(self) -> bytes:
        """The `tls-server-end-point` channel binding for this connection, or
        b"" when it isn't running over TLS.

        RFC 5929 §4 hashes the server certificate with the hash its own
        signature algorithm uses, except that MD5 and SHA-1 are upgraded to
        SHA-256. That digest becomes the `application_data` of a GSS
        channel-bindings structure (RFC 2744 §3.11, all address fields empty),
        and callers embed the MD5 of that structure - NTLM in an
        `MsvAvChannelBindings` AV_PAIR, Kerberos in the AP-REQ checksum's
        `Bnd` field. Both mechanisms carry the same value.
        """
        get_peer = getattr(self._socket, "get_peer_certificate", None)
        if get_peer is None:
            return b""  # plain socket: no channel to bind to
        cert = get_peer()
        if cert is None:
            return b""

        # The certificate's own signature algorithm picks the hash, e.g.
        # "sha256WithRSAEncryption" -> sha256.
        sig_alg = cert.get_signature_algorithm().decode("ascii", "replace").lower()
        for name in ("sha512", "sha384", "sha256"):
            if name in sig_alg:
                digest_name = name
                break
        else:
            digest_name = "sha256"  # RFC 5929 §4.1: md5/sha1 are upgraded

        from OpenSSL import crypto

        der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        cert_hash = hashlib.new(digest_name, der).digest()
        application_data = b"tls-server-end-point:" + cert_hash

        # gss_channel_bindings_struct with no addresses: five little-endian
        # 32-bit fields, then application_data.
        bindings = struct.pack("<IIIII", 0, 0, 0, 0, len(application_data))
        return hashlib.md5(bindings + application_data).digest()

    _NON_TERMINAL_OPS = ("searchResEntry", "searchResRef")
    # RFC 4511 §4.4.1 Notice of Disconnection.
    _NOTICE_OF_DISCONNECTION = "1.3.6.1.4.1.1466.20036"

    def _disconnect_notice(self, plaintext: bytes) -> Optional[str]:
        """The server's own diagnostic if plaintext carries an unsolicited
        Notice of Disconnection, else None.

        Worth pulling out because it is the most informative thing a DC ever
        says: it explains why it is about to hang up, in its own words. It
        arrives as messageID 0, which no request ever matches, so impacket's
        operation loops don't recognise it - search() keeps waiting for a
        searchResDone that will never come, and the caller ends up with a
        pyasn1 complaint instead of the reason. Reporting it verbatim turns
        a mechanism failure into a readable one (e.g. a sign-only bind that
        sent a cleartext body gets back "Error decrypting ldap message").
        """
        def opt(container, field):
            """An optional ASN.1 field as str, or None if absent. pyasn1
            raises on an unset optional rather than returning something
            testable, so absence has to be caught rather than checked."""
            try:
                value = container[field]
                return str(value) if value.hasValue() else None
            except Exception:
                return None

        data = plaintext
        while data:
            try:
                msg, data = decoder.decode(data, asn1Spec=LDAPMessage())
            except Exception:
                return None
            try:
                if int(msg["messageID"]) != 0:
                    continue
                op = msg["protocolOp"]
                if op.getName() != "extendedResp":
                    continue
                resp = op.getComponent()
                # impacket declares responseName/responseValue as optional
                # fields of LDAPMessage itself, not of ExtendedResponse, and
                # a real notice puts the OID after the extendedResp element
                # in the outer SEQUENCE - so look there first, and fall back
                # to the nested position for servers that use it.
                oid = opt(msg, "responseName") or opt(resp, "responseName")
                if oid != self._NOTICE_OF_DISCONNECTION:
                    continue
                diagnostic = opt(resp, "diagnosticMessage") or ""
                return diagnostic.rstrip("\x00").strip()
            except Exception:
                continue
        return None

    def _fill_sasl_buf(self) -> None:
        chunk = self._socket.recv(8192)
        if not chunk:
            raise LDAPSessionError(
                errorString="connection closed while reading a SASL frame"
            )
        self._sasl_buf += chunk

    @staticmethod
    def _ber_message_length(buf: bytes) -> Optional[int]:
        """Total size (header + body) of the LDAPMessage at the head of buf,
        or None while buf is still too short to tell or doesn't start one."""
        if len(buf) < 2 or buf[0] != 0x30:
            return None
        n = buf[1]
        if n < 0x80:  # short form
            return 2 + n
        count = n & 0x7F  # long form: low 7 bits give the length-octet count
        if count == 0 or count > 4 or len(buf) < 2 + count:
            return None
        return 2 + count + int.from_bytes(buf[2 : 2 + count], "big")

    def _read_plain_ldap_message(self) -> bytes:
        """Reads one *unwrapped* LDAPMessage, sized by its own BER header
        rather than by a SASL length prefix."""
        while True:
            total = self._ber_message_length(self._sasl_buf)
            if total is None:
                if len(self._sasl_buf) >= 6:
                    raise LDAPSessionError(
                        errorString="unwrapped data at the head of the stream "
                        "is not a valid LDAPMessage"
                    )
                self._fill_sasl_buf()
                continue
            if len(self._sasl_buf) >= total:
                msg, self._sasl_buf = self._sasl_buf[:total], self._sasl_buf[total:]
                return msg
            self._fill_sasl_buf()

    def _read_sasl_frame(self) -> bytes:
        """Reads exactly one length-prefixed SASL frame, keeping anything read
        past its end buffered for the next call."""
        while len(self._sasl_buf) < 4:
            self._fill_sasl_buf()
        length = struct.unpack("!I", self._sasl_buf[:4])[0]
        while len(self._sasl_buf) < 4 + length:
            self._fill_sasl_buf()
        end = 4 + length
        frame, self._sasl_buf = self._sasl_buf[:end], self._sasl_buf[end:]
        return frame

    def _batch_is_complete(self, plaintext: bytes) -> bool:
        """True once plaintext decodes to whole LDAPMessages ending in one that
        terminates the operation. Search entries and references don't - their
        searchResDone may still be in a later frame."""
        data = plaintext
        last = None
        while data:
            try:
                last, data = decoder.decode(data, asn1Spec=LDAPMessage())
            except SubstrateUnderrunError:
                return False  # a message straddles the frame boundary
        if last is None:
            return False
        try:
            return last["protocolOp"].getName() not in self._NON_TERMINAL_OPS
        except Exception:
            return True  # unrecognizable shape: hand it up rather than block

    def recv_raw(self) -> bytes:
        """Overrides the base class's recv_raw(), which cannot read a response
        spanning more than one SASL frame.

        impacket sizes the frame from the first 4 bytes and then loops
        `while message_length != len(data) - 4`, an equality test that cannot
        tell an over-read from an under-read: if a single socket read happens
        to contain two frames, len(data)-4 exceeds message_length, the
        condition never clears, and it blocks on recv() forever waiting for
        bytes that will never arrive. Any peer that emits two frames back to
        back triggers it - a DC returning a large result set, for instance.

        Fixing only that would still leave search() broken: it loops on
        sendReceive(), so a batch arriving without its searchResDone makes it
        re-send the whole SearchRequest rather than read the next frame. So
        frames are read one at a time (exactly, with the remainder buffered)
        and their plaintexts concatenated until the batch ends in a message
        that terminates the operation - restoring the "one recv_raw() returns
        the whole response" contract the unsigned path already has.
        """
        if not (self._LDAPConnection__binded and self._LDAPConnection__signing):
            return super().recv_raw()

        plaintext = b""
        while True:
            while not self._sasl_buf:
                self._fill_sasl_buf()
            # A peer can drop the security layer mid-connection: Active
            # Directory sends its Notice of Disconnection unwrapped, as plain
            # BER, while tearing the connection down. Assuming a length prefix
            # regardless reads 30 84 00 00 as a 813MB frame and waits for it,
            # so the server's own explanation is lost and the caller sees only
            # a reset. A leading 0x30 is an unambiguous discriminator: it marks
            # a universal constructed SEQUENCE, and as the top byte of a
            # 32-bit SASL length it would mean a frame far past any server's
            # maxbuf.
            if self._sasl_buf[0] == 0x30:
                plaintext += self._read_plain_ldap_message()
            else:
                plaintext += self.decrypt(self._read_sasl_frame())
            if self._batch_is_complete(plaintext):
                break

        notice = self._disconnect_notice(plaintext)
        if notice is not None:
            raise LDAPSessionError(
                errorString=f"server sent a Notice of Disconnection: {notice}"
            )
        return plaintext

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
            # Bare reason, no prefix - the caller already frames this as the
            # post-bind search failing.
            return False, str(exc)

        for entry in results:
            for attr in entry["attributes"]:
                if (
                    str(attr["type"]).lower() == "namingcontexts"
                    and len(attr["vals"]) > 0
                ):
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
    # ...which also means a ":port" suffix can never work: it lands in the
    # hostname, and getaddrinfo() fails on "localhost:3389". Redirecting
    # getaddrinfo is the only way to reach a non-default port, so --port goes
    # through that for every scheme rather than only for the ldaps+cert path.
    def _connect(url_scheme: str, default_port: int) -> LDAPTransport:
        url = f"{url_scheme}://{target}"
        effective = port or default_port
        if effective == default_port:
            return LDAPTransport(url, dst_ip=dst_ip, signing=signing)
        with _redirect_getaddrinfo_port(effective):
            return LDAPTransport(url, dst_ip=dst_ip, signing=signing)

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
                transport = LDAPTransport(
                    "ldap://" + target, dst_ip=dst_ip, signing=signing
                )
            transport.upgrade_tls(cert_pem, key_pem)
            return transport
        return _connect("ldaps", 636)

    transport = _connect("ldap", 389)
    if scheme == "starttls":
        transport.start_tls(cert_pem, key_pem)
    return transport
