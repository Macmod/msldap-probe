"""SASL DIGEST-MD5 bind (RFC 2831) - all three QOP levels.

DIGEST-MD5 is a challenge-response SASL mechanism defined in RFC 2831
(Historic, obsoleted by RFC 6331).  Active Directory has supported it
since Windows Server 2003 (MS-ADTS §3.1.1.3.4.5.4) and still advertises
it in the current specification revision.

Three QOP (quality-of-protection) levels are registered:

- ``sasl_digest_md5_plain``     — qop=auth     (no security layer)
- ``sasl_digest_md5_signonly``  — qop=auth-int (integrity / HMAC-MD5 MAC)
- ``sasl_digest_md5_signseal``  — qop=auth-conf (integrity + confidentiality via RC4)

DIGEST-MD5 has no "encrypt without integrity" mode, so there is no
``sealonly`` variant (unlike the NTLM family).

The auth-int and auth-conf wire formats (RFC 2831 §2.3-2.4) place the
MAC, a 2-byte message-type hint (0x0001), and a 4-byte big-endian
sequence number *inside* the SASL length-prefixed frame, after the
encoded LDAP message (or its ciphertext).  The MAC is the first 10
bytes of ``HMAC-MD5(signing_key, seqnum ++ message)``.

For auth-conf, AD offers ``3des`` and ``rc4`` ciphers; only RC4 is
implemented here (a stream cipher, so ciphertext length equals
plaintext length, which keeps the framing simple).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import struct
from dataclasses import dataclass

from Cryptodome.Cipher import ARC4, DES, DES3

from impacket.ldap.ldapasn1 import BindRequest, ResultCode

from .methods import BindOutcome, Credentials, Method, bind_failure_detail, register
from .transport import LDAPTransport, open_transport


def _bind_result_code(protocol_op) -> ResultCode:
    return protocol_op["bindResponse"]["resultCode"]


# ---------------------------------------------------------------------------
# Challenge / response parsing and construction (RFC 2831 §2.1)
# ---------------------------------------------------------------------------


def _parse_challenge(challenge_bytes: bytes) -> dict[str, str]:
    """Parse a DIGEST-MD5 server challenge (RFC 2831 §2.1.1) into a dict.

    The challenge is a comma-separated list of ``key=value`` tokens where
    values may be quoted strings (containing escaped characters) or bare
    tokens.  ``nonce`` and ``realm`` are the fields we actually need.
    """
    text = challenge_bytes.decode("utf-8", errors="replace")

    # RFC 2831 §2.1.1 grammar:  key=value where value is either a token
    # (chars except =, comma, and whitespace) or a quoted-string.
    # A simple regex handles both forms and the standard fields.
    pairs: dict[str, str] = {}
    # Match key=value pairs; value is either "..." or unquoted token
    for m in re.finditer(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|([^,]+))', text):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        if val is not None:
            val = val.strip()
        pairs[key] = val
    return pairs


def _md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def _hmac_md5(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.md5).digest()


# ---------------------------------------------------------------------------
# Key derivation (RFC 2831 §2.2.2)
# ---------------------------------------------------------------------------

_KIC_MAGIC = b"Digest session key to client-to-server signing key magic constant"
_KIS_MAGIC = b"Digest session key to server-to-client signing key magic constant"
_KCC_MAGIC = b"Digest H(A1) to client-to-server sealing key magic constant"
_KCS_MAGIC = b"Digest H(A1) to server-to-client sealing key magic constant"


def _derive_keys(a1_hash: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Derive the four per-direction keys from H(A1).

    Kic/Kis are signing keys; Kcc/Kcs are sealing keys (RC4 cipher keys).
    """
    kic = _md5(a1_hash + _KIC_MAGIC)
    kis = _md5(a1_hash + _KIS_MAGIC)
    kcc = _md5(a1_hash + _KCC_MAGIC)
    kcs = _md5(a1_hash + _KCS_MAGIC)
    return kic, kis, kcc, kcs


# ---------------------------------------------------------------------------
# Layer strategies (RFC 2831 §2.3-2.4)
# ---------------------------------------------------------------------------


@dataclass
class DigestMd5IntLayerStrategy:
    """auth-int: HMAC-MD5 integrity wrapping without encryption.

    Wire format inside the 4-byte SASL length frame:
        encoded_message || MAC(10 bytes) || 0x0001(2) || seqnum(4 BE)
    """

    name: str
    client_sign_key: bytes  # Kic
    server_sign_key: bytes  # Kis
    send_seq: int = 0
    recv_seq: int = 0

    def wrap(self, plaintext: bytes) -> bytes:
        seq = struct.pack("!I", self.send_seq)
        mac = _hmac_md5(self.client_sign_key, seq + plaintext)[:10]
        wrapped = plaintext + mac + b"\x00\x01" + seq
        self.send_seq += 1
        return wrapped

    def unwrap(self, wrapped: bytes) -> bytes:
        # Strip trailing 0x0001 (2 bytes) + seqnum (4 bytes), then MAC (10 bytes)
        msg = wrapped[:-16]
        self.recv_seq += 1
        return msg


def _des_expand_key(seven: bytes) -> bytes:
    """Spread a 7-byte (56-bit) string across the 8 bytes of a DES key,
    leaving the low bit of each output byte as the (unused) parity bit.

    RFC 2831 §2.2.2 says only that the DES key is "the first 7 bytes" of
    Kcc/Kcs and never states this expansion, so the bit layout is taken from
    the reference implementation everything interoperates with - Cyrus SASL's
    slidebits() in plugins/digestmd5.c.
    """
    return bytes(
        [
            seven[0] & 0xFF,
            ((seven[0] << 7) | (seven[1] >> 1)) & 0xFF,
            ((seven[1] << 6) | (seven[2] >> 2)) & 0xFF,
            ((seven[2] << 5) | (seven[3] >> 3)) & 0xFF,
            ((seven[3] << 4) | (seven[4] >> 4)) & 0xFF,
            ((seven[4] << 3) | (seven[5] >> 5)) & 0xFF,
            ((seven[5] << 2) | (seven[6] >> 6)) & 0xFF,
            (seven[6] << 1) & 0xFF,
        ]
    )


@dataclass
class DigestMd5ConfLayerStrategy:
    """auth-conf: encryption + HMAC-MD5 integrity.

    Wire format inside the 4-byte SASL length frame, for a stream cipher:
        RC4(encoded_message || MAC(10 bytes)) || 0x0001(2) || seqnum(4 BE)

    and for a block cipher, which additionally pads so the encrypted unit is
    a whole number of blocks:
        CBC(encoded_message || pad || MAC(10)) || 0x0001(2) || seqnum(4 BE)

    The MAC is computed over the unpadded plaintext and travels inside the
    ciphertext; the 0x0001 and seqnum are always cleartext after it.

    `des` and `3des` need three things RFC 2831 does not state, all taken
    from Cyrus SASL: the 7-to-8 byte key expansion (see _des_expand_key),
    two-key EDE for 3des with K1 = slide(Kc[0:7]) and K2 = slide(Kc[7:14]),
    and a CBC IV that starts at Kc[8:16] and then chains from message to
    message rather than restarting.
    """

    name: str
    client_sign_key: bytes  # Kic
    server_sign_key: bytes  # Kis
    client_seal_key: bytes  # Kcc
    server_seal_key: bytes  # Kcs
    cipher: str = "rc4"
    send_seq: int = 0
    recv_seq: int = 0
    _send_cipher: object = None
    _recv_cipher: object = None
    _block_size: int = 0

    def _build(self, seal_key: bytes):
        name = self.cipher.lower()
        if name in ("des", "3des"):
            iv = seal_key[8:16]
            if name == "des":
                key = _des_expand_key(seal_key[0:7])
                return DES.new(key, DES.MODE_CBC, iv), DES.block_size
            k1 = _des_expand_key(seal_key[0:7])
            k2 = _des_expand_key(seal_key[7:14])
            return DES3.new(k1 + k2 + k1, DES3.MODE_CBC, iv), DES3.block_size
        # rc4, rc4-40 and rc4-56 all key RC4 with the whole 16-byte Kcc/Kcs;
        # the reduced variants weaken the derivation, not the key handed over.
        return ARC4.new(seal_key), 0

    def __post_init__(self) -> None:
        # RFC 2831 §2.4 keys ONE cipher per direction for the life of the
        # connection - an RC4 keystream, or a CBC chain, carries over from
        # each message to the next. Building a fresh cipher per call instead
        # restarts it every time, which handles the first message correctly
        # and turns every subsequent one into garbage. With a single wrapped
        # message per connection that never surfaces; it appears the moment a
        # second arrives - a DC bundling results across frames, say.
        self._send_cipher, self._block_size = self._build(self.client_seal_key)
        self._recv_cipher, _ = self._build(self.server_seal_key)

    def wrap(self, plaintext: bytes) -> bytes:
        seq = struct.pack("!I", self.send_seq)
        mac = _hmac_md5(self.client_sign_key, seq + plaintext)[:10]
        body = plaintext + mac
        if self._block_size:
            # Pad between message and MAC so the encrypted unit is a whole
            # number of blocks. Never empty: when the two already align this
            # yields a full block, so the length is always recoverable from
            # the pad's own last byte.
            pad_len = self._block_size - ((len(plaintext) + 10) % self._block_size)
            body = plaintext + bytes([pad_len]) * pad_len + mac
        ciphertext = self._send_cipher.encrypt(body)
        wrapped = ciphertext + b"\x00\x01" + seq
        self.send_seq += 1
        return wrapped

    def unwrap(self, wrapped: bytes) -> bytes:
        # Strip trailing 0x0001 (2 bytes) + seqnum (4 bytes)
        ciphertext = wrapped[:-6]
        decrypted = self._recv_cipher.decrypt(ciphertext)
        msg = decrypted[:-10]
        if self._block_size and msg:
            msg = msg[: -msg[-1]]
        self.recv_seq += 1
        return msg


def _build_response(
    username: str,
    realm: str,
    password: str,
    nonce: str,
    cnonce: str,
    nc: str,
    qop: str,
    digest_uri: str,
    authzid: str = "",
) -> str:
    """Build the client ``response`` value per RFC 2831 §2.1.2.

    A1  = H(username ":" realm ":" password) ":" nonce ":" cnonce [":" authzid]
    A2  = "AUTHENTICATE:" digest_uri [":" authzid]
    response = H(A1) ":" nonce ":" nc ":" cnonce ":" qop ":" H(A2)

    The server's rspauth (for verification) uses the same formula but A2
    starts with ":" instead of "AUTHENTICATE:".
    """
    a1_h = _md5(f"{username}:{realm}:{password}".encode("utf-8"))
    a1 = a1_h + f":{nonce}:{cnonce}".encode("utf-8")
    if authzid:
        a1 += f":{authzid}".encode("utf-8")

    a2_prefix = (
        "AUTHENTICATE:" if not authzid else f"AUTHENTICATE:{digest_uri}:{authzid}"
    )
    if not authzid:
        a2 = f"{a2_prefix}{digest_uri}".encode("utf-8")
    else:
        a2 = a2_prefix.encode("utf-8")

    # RFC 2831 §2.1.2: for auth-int and auth-conf, A2 includes a
    # trailing 32-zero-hex digest (the "00000000000000000000000000000000"
    # placeholder for the message hash that would be present in
    # per-message integrity checks).
    if qop in ("auth-int", "auth-conf"):
        a2 += b":00000000000000000000000000000000"

    # RFC 2831 §2.1.2: response = KD(H(A1), nonce:nc:cnonce:qop:H(A2))
    # where H(A1) and H(A2) in the KD formula are the *hex* representations
    # of the MD5 digest, not the raw bytes (same convention as RFC 2069
    # HTTP Digest).  Using raw bytes here is the classic implementation bug.
    response = _md5(
        b":".join(
            [
                _md5(a1).hex().encode("utf-8"),
                nonce.encode("utf-8"),
                nc.encode("utf-8"),
                cnonce.encode("utf-8"),
                qop.encode("utf-8"),
                _md5(a2).hex().encode("utf-8"),
            ]
        )
    ).hex()

    return response


def _build_response_string(
    username: str,
    realm: str,
    nonce: str,
    cnonce: str,
    nc: str,
    qop: str,
    digest_uri: str,
    response: str,
    cipher: str = "",
    maxbuf: int = 65536,
) -> str:
    """Assemble the full client response string (RFC 2831 §2.1.3).

    All values that could contain special characters are quoted per the
    RFC's quoted-string convention.
    """
    parts = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'cnonce="{cnonce}"',
        f'digest-uri="{digest_uri}"',
        f"qop={qop}",
        f"nc={nc}",
        'charset="utf-8"',
        f'response="{response}"',
    ]
    if cipher:
        parts.append(f'cipher="{cipher}"')
    return ",".join(parts)


# ---------------------------------------------------------------------------
# Bind flow
# ---------------------------------------------------------------------------

# layer name -> (qop value, cipher name, needs signing flag for transport)
_LAYER_PARAMS = {
    "plain": ("auth", "", False),
    "signonly": ("auth-int", "", True),
    "signseal": ("auth-conf", "rc4", True),
}


def _bind_digest_md5(
    transport: LDAPTransport, creds: Credentials, layer: str
) -> BindOutcome:
    """Multi-round SASL DIGEST-MD5 bind supporting all three QOP levels.

    Round 1: empty credentials -> server returns a challenge.
    Round 2: client response (with qop and optional cipher) -> server
    returns success, or saslBindInProgress with rspauth for verification
    followed by a final empty-credentials round.
    """
    qop, cipher, _needs_signing = _LAYER_PARAMS[layer]
    # auth-conf can run under any cipher the server offers; --digest-md5-cipher
    # picks which one to propose. The other QOP levels seal nothing, so the
    # setting is irrelevant to them and their empty cipher stays empty.
    if cipher:
        cipher = creds.digest_md5_cipher

    # Round 1: initial bind with empty credentials to get the challenge.
    req = BindRequest()
    req["version"] = 3
    req["name"] = ""
    req["authentication"]["sasl"]["mechanism"] = "DIGEST-MD5"
    req["authentication"]["sasl"]["credentials"] = b""
    resp = transport.send_bind(req)
    code = _bind_result_code(resp)

    if code == ResultCode("success"):
        transport.mark_bound(None)
        return BindOutcome(True, "bind succeeded (immediate, no challenge)")

    if code != ResultCode("saslBindInProgress"):
        return BindOutcome(
            False, f"challenge request failed: {bind_failure_detail(resp)}"
        )

    challenge_bytes = resp["bindResponse"]["serverSaslCreds"].asOctets()
    challenge = _parse_challenge(challenge_bytes)

    nonce = challenge.get("nonce", "")
    if not nonce:
        return BindOutcome(False, "server challenge missing nonce")

    # AD may provide multiple realm values or none; use the first realm
    # from the challenge, or fall back to the domain argument.
    realm = challenge.get("realm", "")
    if not realm:
        realm = creds.domain

    # The digest-uri for LDAP is "ldap/<host>" (RFC 2831 §3 / RFC 4752).
    # AD validates this against the server's registered SPNs, so the host
    # must match a real LDAP SPN - a bare IP address will be rejected with
    # "The digest-uri does not match any LDAP SPN's registered for this
    # server."  Use spn_host (defaults to target) so the probe can connect
    # via a proxy (target=localhost:3389) while keeping the real hostname
    # in the digest-uri for AD's SPN check.
    digest_uri = f"ldap/{creds.spn_host}"

    # For auth-conf, verify the server offers a cipher we support.
    if cipher:
        server_ciphers = challenge.get("cipher", "")
        if cipher not in server_ciphers.split(","):
            return BindOutcome(
                False,
                f"cipher '{cipher}' not offered by server (server offers: {server_ciphers})",
            )

    cnonce = os.urandom(8).hex()
    nc = "00000001"

    username = creds.username
    password = creds.password

    response = _build_response(
        username=username,
        realm=realm,
        password=password,
        nonce=nonce,
        cnonce=cnonce,
        nc=nc,
        qop=qop,
        digest_uri=digest_uri,
    )

    response_str = _build_response_string(
        username=username,
        realm=realm,
        nonce=nonce,
        cnonce=cnonce,
        nc=nc,
        qop=qop,
        digest_uri=digest_uri,
        response=response,
        cipher=cipher,
    )

    # Round 2: send the response.
    req2 = BindRequest()
    req2["version"] = 3
    req2["name"] = ""
    req2["authentication"]["sasl"]["mechanism"] = "DIGEST-MD5"
    req2["authentication"]["sasl"]["credentials"] = response_str.encode("utf-8")
    resp2 = transport.send_bind(req2)
    code2 = _bind_result_code(resp2)

    if code2 == ResultCode("saslBindInProgress"):
        # Server sent rspauth for verification - send empty response to
        # acknowledge (RFC 2831 §2.1.3: "the client verifies the server's
        # rspauth ... and then sends an empty response").
        server_creds = resp2["bindResponse"]["serverSaslCreds"]
        if server_creds.isValue:
            rspauth_data = server_creds.asOctets().decode("utf-8", errors="replace")
            a1_h = _md5(f"{username}:{realm}:{password}".encode("utf-8"))
            a1 = a1_h + f":{nonce}:{cnonce}".encode("utf-8")
            a2_server = f":{digest_uri}".encode("utf-8")
            if qop in ("auth-int", "auth-conf"):
                a2_server += b":00000000000000000000000000000000"
            expected_rspauth = _md5(
                b":".join(
                    [
                        _md5(a1).hex().encode("utf-8"),
                        nonce.encode("utf-8"),
                        nc.encode("utf-8"),
                        cnonce.encode("utf-8"),
                        qop.encode("utf-8"),
                        _md5(a2_server).hex().encode("utf-8"),
                    ]
                )
            ).hex()

            if f"rspauth={expected_rspauth}" not in rspauth_data:
                return BindOutcome(
                    False, f"server rspauth verification failed: got {rspauth_data!r}"
                )

        req3 = BindRequest()
        req3["version"] = 3
        req3["name"] = ""
        req3["authentication"]["sasl"]["mechanism"] = "DIGEST-MD5"
        req3["authentication"]["sasl"]["credentials"] = b""
        resp3 = transport.send_bind(req3)
        code3 = _bind_result_code(resp3)
        if code3 != ResultCode("success"):
            return BindOutcome(False, f"final ack failed: {bind_failure_detail(resp3)}")
    elif code2 != ResultCode("success"):
        return BindOutcome(False, f"response failed: {bind_failure_detail(resp2)}")

    # Build the layer strategy (if any) and mark the transport as bound.
    if layer == "plain":
        strategy = None
    else:
        a1_h = _md5(f"{username}:{realm}:{password}".encode("utf-8"))
        a1 = a1_h + f":{nonce}:{cnonce}".encode("utf-8")
        a1_hash = _md5(a1)
        kic, kis, kcc, kcs = _derive_keys(a1_hash)
        if layer == "signonly":
            strategy = DigestMd5IntLayerStrategy(
                name=f"digest_md5_{layer}",
                client_sign_key=kic,
                server_sign_key=kis,
            )
        else:  # signseal
            strategy = DigestMd5ConfLayerStrategy(
                name=f"digest_md5_{layer}",
                client_sign_key=kic,
                server_sign_key=kis,
                client_seal_key=kcc,
                server_seal_key=kcs,
                cipher=cipher,
            )

    transport.mark_bound(strategy)
    return BindOutcome(True, f"bind succeeded (qop={qop}, layer={layer})")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

for _layer in ("plain", "signonly", "signseal"):

    def _connect(creds: Credentials, _l=_layer) -> LDAPTransport:
        _, _, needs_signing = _LAYER_PARAMS[_l]
        # When spn_host differs from target (e.g. connecting through a
        # proxy), pass dst_ip so impacket connects to the proxy while the
        # URL hostname (and thus the SPN/digest-uri) stays the real host.
        dst_ip = None
        if creds.spn_host and creds.spn_host != creds.target:
            dst_ip = creds.target
        return open_transport(
            creds.spn_host or creds.target,
            creds.port,
            creds.scheme,
            signing=needs_signing,
            dst_ip=dst_ip,
        )

    def _bind(transport: LDAPTransport, creds: Credentials, _l=_layer) -> BindOutcome:
        return _bind_digest_md5(transport, creds, _l)

    register(
        Method(
            f"sasl_digest_md5_{_layer}",
            requires=["username", "password"],
            connect=_connect,
            bind=_bind,
        )
    )
