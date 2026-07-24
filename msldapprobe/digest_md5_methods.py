"""SASL DIGEST-MD5 bind (RFC 2831) - plain (qop=auth) only.

DIGEST-MD5 is a challenge-response SASL mechanism defined in RFC 2831
(Historic, obsoleted by RFC 6331).  Active Directory has supported it
since Windows Server 2003 (MS-ADTS §3.1.1.3.4.5.4) and still advertises
it in the current specification revision.

This module implements only the ``qop=auth`` flavour (no security layer):
the client proves knowledge of the password by computing a digest
response to the server's challenge, and no per-message wrapping is
performed afterward.  This is the most common real-world usage of
DIGEST-MD5 against AD - integrity (``auth-int``) and confidentiality
(``auth-conf``) layers exist in the RFC but are rarely negotiated in
practice, and would require a separate ``LayerStrategy`` implementation
(HMAC-MD5 MAC and RC4/DES/3DES sealing per RFC 2831 §2.3-2.4).
"""

from __future__ import annotations

import hashlib
import os
import re

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
        f'charset="utf-8"',
        f'response="{response}"',
    ]
    if cipher:
        parts.append(f'cipher="{cipher}"')
    return ",".join(parts)


# ---------------------------------------------------------------------------
# Bind flow
# ---------------------------------------------------------------------------


def _bind_digest_md5_plain(transport: LDAPTransport, creds: Credentials) -> BindOutcome:
    """Two-round SASL DIGEST-MD5 bind with qop=auth (no security layer).

    Round 1: empty credentials -> server returns a challenge.
    Round 2: client response -> server returns success (or rspauth in
    a saslBindInProgress, but AD typically completes in round 2).
    """

    # Round 1: initial bind with empty credentials to get the challenge.
    req = BindRequest()
    req["version"] = 3
    req["name"] = ""
    req["authentication"]["sasl"]["mechanism"] = "DIGEST-MD5"
    req["authentication"]["sasl"]["credentials"] = b""
    resp = transport.send_bind(req)
    code = _bind_result_code(resp)

    if code == ResultCode("success"):
        # Some servers might succeed immediately (unlikely for DIGEST-MD5)
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
    # server."  Use the hostname (resolvable via DNS or hosts file).
    digest_uri = f"ldap/{creds.target}"

    # Generate a client nonce and use nc=00000001 (first request).
    cnonce = os.urandom(8).hex()
    nc = "00000001"
    qop = "auth"

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
            # Verify rspauth if present (best-effort)
            rspauth_data = server_creds.asOctets().decode("utf-8", errors="replace")
            # Expected rspauth = H(A1 ":" nonce ":" nc ":" cnonce ":" qop ":" H(":"
            #   digest_uri))
            a1_h = _md5(f"{username}:{realm}:{password}".encode("utf-8"))
            a1 = a1_h + f":{nonce}:{cnonce}".encode("utf-8")
            a2_server = f":{digest_uri}".encode("utf-8")
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
        transport.mark_bound(None)
        return BindOutcome(True, "bind succeeded (qop=auth, no security layer)")

    if code2 != ResultCode("success"):
        return BindOutcome(False, f"response failed: {bind_failure_detail(resp2)}")

    transport.mark_bound(None)
    return BindOutcome(True, "bind succeeded (qop=auth, no security layer)")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def _connect(creds: Credentials) -> LDAPTransport:
    return open_transport(creds.target, creds.port, creds.scheme, signing=False)


def _bind(transport: LDAPTransport, creds: Credentials) -> BindOutcome:
    return _bind_digest_md5_plain(transport, creds)


register(
    Method(
        "sasl_digest_md5_plain",
        requires=["username", "password"],
        connect=_connect,
        bind=_bind,
    )
)
