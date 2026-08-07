"""Bind-flow construction for the three NTLM-carrying mechanism families:
sicily_ntlm_* (MS-proprietary, non-SASL), sasl_spnego_ntlm_* (SASL
GSS-SPNEGO wrapping NTLM - impacket's own login('sasl') path, extended for
full flag control), and sasl_gssapi_ntlm_* (SASL mechanism literally
"GSSAPI" carrying NTLM - a non-standard Windows SSPI fallback, hand-rolled
since impacket has no reference for it at all).

All three reuse ntlm_layers.py's Type1/Type3/wrap-unwrap logic - per-message
NTLM signing/sealing is identical regardless of which handshake carried it.
"""

from __future__ import annotations

import struct

from Cryptodome.Cipher import ARC4
from impacket.ldap.ldapasn1 import BindRequest, ResultCode
from impacket.ntlm import (
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
    NTLMSSP_NEGOTIATE_SIGN,
    SEALKEY,
    SIGN,
    SIGNKEY,
)
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech

from .methods import BindOutcome, Credentials, Method, bind_failure_detail, register
from .ntlm_layers import (
    build_type1,
    complete_ntlm_handshake,
    finalize_type3,
    seal_key,
)
from .transport import LDAPTransport, open_transport

NTLM_MECH_OID = TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]


def _cbt(transport: LDAPTransport, creds: Credentials) -> bytes:
    """The RFC 5929 channel binding for this connection, or b"" when
    --channel-bindings is off or the connection is not running over TLS."""
    return transport.channel_binding_token() if creds.channel_bindings else b""


def _kxkey_note(strategy) -> str:
    """Names the KXKEY branch the server actually selected, for the NTLMv1
    binds where it varies. Empty for NTLMv2, whose KeyExchangeKey is always
    SessionBaseKey."""
    if not strategy.kxkey or strategy.kxkey == "v2":
        return ""
    return f", kxkey={strategy.kxkey}"


def _bind_result_code(protocol_op) -> ResultCode:
    return protocol_op["bindResponse"]["resultCode"]


# ---------------------------------------------------------------------------
# sicily_ntlm_*
# ---------------------------------------------------------------------------


def _bind_sicily(
    transport: LDAPTransport, creds: Credentials, layer: str
) -> BindOutcome:
    # Round 1: package discovery (unauthenticated probe, confirms NTLM is offered).
    discover = BindRequest()
    discover["version"] = 3
    discover["name"] = creds.username
    discover["authentication"]["sicilyPackageDiscovery"] = ""
    resp = transport.send_bind(discover)
    if _bind_result_code(resp) != ResultCode("success"):
        return BindOutcome(
            False, f"package discovery failed: {bind_failure_detail(resp)}"
        )

    # Round 2: negotiate (Type1 with layer-specific flags). The MIC is
    # supplied here as it is in the other two families: MS-NLMP §3.1.5.1.2
    # conditions it on the CHALLENGE_MESSAGE carrying MsvAvTimestamp, which
    # is a property of the mechanism rather than of the carrier that
    # negotiated it.
    type1 = build_type1(creds, layer)
    negotiate = BindRequest()
    negotiate["version"] = 3
    negotiate["name"] = creds.username
    negotiate["authentication"]["sicilyNegotiate"] = type1.getData()
    resp = transport.send_bind(negotiate)
    if _bind_result_code(resp) != ResultCode("success"):
        return BindOutcome(False, f"negotiate failed: {bind_failure_detail(resp)}")
    # SicilyBindResponse's documented shape is resultCode/serverCreds/
    # errorMessage (no matchedDN) - serverCreds lands in the position the
    # generic BindResponse ASN.1 template calls matchedDN. asOctets() reads
    # the raw bytes regardless of the field's declared utf-8 text encoding -
    # needed since a Type2 challenge is arbitrary binary, not valid UTF-8.
    type2_bytes = resp["bindResponse"]["matchedDN"].asOctets()

    # Round 3: response (Type3).
    type3, strategy, exported_session_key = complete_ntlm_handshake(
        type1, type2_bytes, creds, layer, channel_binding_value=_cbt(transport, creds)
    )
    # Hashed over the challenge as the server sent it, not the copy carrying
    # a --announce-mic declaration.
    type3_bytes = finalize_type3(
        type3, type1, type2_bytes, exported_session_key, creds
    )

    response = BindRequest()
    response["version"] = 3
    response["name"] = creds.username
    response["authentication"]["sicilyResponse"] = type3_bytes
    resp = transport.send_bind(response)
    if _bind_result_code(resp) != ResultCode("success"):
        return BindOutcome(False, f"response failed: {bind_failure_detail(resp)}")

    active_strategy = strategy if layer != "plain" else None
    transport.mark_bound(active_strategy)
    return BindOutcome(True, f"bind succeeded, layer={strategy.name}{_kxkey_note(strategy)}")


def _ntlm_eligible(c: Credentials) -> tuple[bool, str]:
    """NTLM methods accept --password or --hashes, but always need
    --username."""
    if c.username and (c.password or c.nthash):
        return (True, "")
    return (False, "need --username and one of --password/--hashes")


def _register_sicily() -> None:
    for layer in ("plain", "signonly", "sealonly", "signseal"):

        def connect(creds: Credentials, _layer=layer) -> LDAPTransport:
            return open_transport(
                creds.target, creds.port, creds.scheme, signing=(_layer != "plain")
            )

        def bind(
            transport: LDAPTransport, creds: Credentials, _layer=layer
        ) -> BindOutcome:
            return _bind_sicily(transport, creds, _layer)

        register(
            Method(
                f"sicily_ntlm_{layer}",
                requires=["username", "password"],
                connect=connect,
                bind=bind,
                eligible=_ntlm_eligible,
            )
        )


_register_sicily()


# ---------------------------------------------------------------------------
# sasl_spnego_ntlm_* - SASL mechanism "GSS-SPNEGO", NTLM negotiated. Matches
# impacket's own login(authenticationChoice='sasl') wire shape (confirmed by
# reading it directly), extended here for full flag control instead of its
# single boolean.
# ---------------------------------------------------------------------------

# The fixed DER encoding of a MechTypeList containing just the NTLM OID -
# what mechListMIC signs, per RFC 4178 and matching impacket's own login('sasl')
# branch exactly (reused verbatim rather than re-deriving it).
_NTLM_MECH_TYPE_LIST_DER = b"0\x0c\x06\n+\x06\x01\x04\x01\x827\x02\x02\n"


def _bind_spnego_ntlm(
    transport: LDAPTransport, creds: Credentials, layer: str
) -> BindOutcome:
    type1 = build_type1(creds, layer)
    init_blob = SPNEGO_NegTokenInit()
    init_blob["MechTypes"] = [NTLM_MECH_OID]
    init_blob["MechToken"] = type1.getData()

    req = BindRequest()
    req["version"] = 3
    req["name"] = ""
    req["authentication"]["sasl"]["mechanism"] = "GSS-SPNEGO"
    req["authentication"]["sasl"]["credentials"] = init_blob.getData()
    resp = transport.send_bind(req)
    code = _bind_result_code(resp)
    if code not in (ResultCode("success"), ResultCode("saslBindInProgress")):
        return BindOutcome(False, f"negotiate failed: {bind_failure_detail(resp)}")

    resp_blob = SPNEGO_NegTokenResp(resp["bindResponse"]["serverSaslCreds"].asOctets())
    type2_bytes = resp_blob["ResponseToken"]

    type3, strategy, exported_session_key = complete_ntlm_handshake(
        type1, type2_bytes, creds, layer, gss_wrapped=True, channel_binding_value=_cbt(transport, creds)
    )

    # MIC over [Type1 || Type2 || Type3] binds the three messages together
    # (MS-NLMP §3.1.5.1.2) - impacket's own 'sasl' bind path always sets
    # this, so real DCs expect it.
    type3_bytes = finalize_type3(
        type3, type1, type2_bytes, exported_session_key, creds
    )

    resp_blob2 = SPNEGO_NegTokenResp()
    resp_blob2["ResponseToken"] = type3_bytes
    # mechListMIC is RFC 4178/MS-SPNG integrity protection over the
    # MechTypes list. Active Directory rejects the whole exchange
    # (AcceptSecurityContext "data 5") when one arrives without
    # NTLMSSP_NEGOTIATE_SIGN having been negotiated, so sealonly (SEAL
    # without SIGN) omits it.
    #
    # An announced AUTHENTICATE_MESSAGE MIC reverses that: it declares the
    # mechanism as supplying integrity, and the DC then holds the exchange
    # at negState accept-incomplete until it receives a mechListMIC.
    #
    # Extended session security is required too. Without it SIGNKEY yields no
    # key and the legacy MAC runs off the one half-duplex sealing stream
    # (MS-NLMP §3.4), a regime in which Active Directory expects no
    # mechListMIC and numbers post-bind traffic from zero.
    if type3["flags"] & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY and (
        type3["flags"] & NTLMSSP_NEGOTIATE_SIGN or creds.announce_mic
    ):
        # mechListMIC: one throwaway signature over the fixed MechTypes
        # list, using a fresh ARC4 handle (never touched again) rather than
        # strategy's own - keeps strategy's keystream position untouched
        # for the first real post-bind message, mirroring impacket's own
        # SPNEGOCipher(..., reset_cipher=True) exactly.
        if type3["flags"] & NTLMSSP_NEGOTIATE_SIGN:
            mic_sign_key = SIGNKEY(type3["flags"], exported_session_key, mode="Client")
            mic_seal_key = seal_key(type3["flags"], exported_session_key, "Client")
            mic_handle = ARC4.new(mic_seal_key).encrypt
            mech_list_mic = SIGN(
                type3["flags"], mic_sign_key, _NTLM_MECH_TYPE_LIST_DER, 0, mic_handle
            )
            resp_blob2["mechListMIC"] = mech_list_mic.getData()
        else:
            # SEAL without SIGN: MAC() emits a dummy all-zero checksum
            # rather than a computed one, and that is the form Active
            # Directory both sends and accepts here. A real checksum is
            # rejected with SEC_E_MESSAGE_ALTERED (8009030F).
            resp_blob2["mechListMIC"] = (
                struct.pack("<I", 1) + b"\x00" * 8 + struct.pack("<I", 0)
            )
        # impacket's own SPNEGOCipher reference reuses ONE sequence counter
        # across the mechListMIC signature (seqNum 0) and every subsequent
        # message (encrypt() starts from wherever that counter is, never
        # reset alongside the cipher state) - the DC expects the same. The
        # cipher/keystream position stays fresh (separate handle above);
        # only the sequence number itself needs to start post-bind traffic
        # at 1, not 0, to match.
        strategy.send_seq = 1
        strategy.recv_seq = 1

    req2 = BindRequest()
    req2["version"] = 3
    req2["name"] = ""
    req2["authentication"]["sasl"]["mechanism"] = "GSS-SPNEGO"
    req2["authentication"]["sasl"]["credentials"] = resp_blob2.getData()
    resp = transport.send_bind(req2)
    code = _bind_result_code(resp)
    if code != ResultCode("success"):
        return BindOutcome(False, f"authenticate failed: {bind_failure_detail(resp)}")

    active_strategy = strategy if layer != "plain" else None
    transport.mark_bound(active_strategy)
    return BindOutcome(True, f"bind succeeded, layer={strategy.name}{_kxkey_note(strategy)}")


def _register_spnego_ntlm() -> None:
    for layer in ("plain", "signonly", "sealonly", "signseal"):

        def connect(creds: Credentials, _layer=layer) -> LDAPTransport:
            return open_transport(
                creds.target, creds.port, creds.scheme, signing=(_layer != "plain")
            )

        def bind(
            transport: LDAPTransport, creds: Credentials, _layer=layer
        ) -> BindOutcome:
            return _bind_spnego_ntlm(transport, creds, _layer)

        register(
            Method(
                f"sasl_spnego_ntlm_{layer}",
                requires=["username", "password"],
                connect=connect,
                bind=bind,
                eligible=_ntlm_eligible,
            )
        )


_register_spnego_ntlm()


# ---------------------------------------------------------------------------
# sasl_gssapi_ntlm_* - SASL mechanism literally "GSSAPI", NTLM negotiated
# underneath with no SPNEGO envelope at all. A non-standard Windows SSPI
# fallback (observed once GSS-SPNEGO isn't offered) with no impacket
# reference to reuse - built from a real live capture: the client sends
# bare NTLMSSP Type1/Type3 messages
# directly as the SASL credentials field, and the DC wraps its own Type2
# challenge response in an ad-hoc [3]{OCTET STRING "GSSAPI", OCTET STRING
# <ntlm>} shape - not RFC 2743's GSS-API envelope, not SPNEGO. No
# mechListMIC exists in this family at all (that's an SPNEGO-specific
# concept), so - unlike sasl_spnego_ntlm_* - sequence numbers start at 0,
# same as sicily_ntlm_*.
# ---------------------------------------------------------------------------


def _extract_ntlm_message(data: bytes) -> bytes:
    """Bare NTLMSSP signature search, tolerating both a fully bare message
    and one embedded in the DC's ad-hoc wrapper. Searching for the 8-byte
    magic rather than parsing structurally handles both shapes uniformly;
    a collision inside legitimate binary data isn't a realistic concern."""
    idx = data.find(b"NTLMSSP\x00")
    if idx < 0:
        raise ValueError("no NTLMSSP message found in SASL/GSSAPI response")
    return data[idx:]


def _bind_gssapi_ntlm(
    transport: LDAPTransport, creds: Credentials, layer: str
) -> BindOutcome:
    type1 = build_type1(creds, layer)

    req = BindRequest()
    req["version"] = 3
    req["name"] = ""
    req["authentication"]["sasl"]["mechanism"] = "GSSAPI"
    req["authentication"]["sasl"]["credentials"] = type1.getData()
    resp = transport.send_bind(req)
    code = _bind_result_code(resp)
    if code not in (ResultCode("success"), ResultCode("saslBindInProgress")):
        return BindOutcome(False, f"negotiate failed: {bind_failure_detail(resp)}")

    type2_bytes = _extract_ntlm_message(
        resp["bindResponse"]["serverSaslCreds"].asOctets()
    )

    type3, strategy, exported_session_key = complete_ntlm_handshake(
        type1, type2_bytes, creds, layer, gss_wrapped=True, channel_binding_value=_cbt(transport, creds)
    )
    type3_bytes = finalize_type3(
        type3, type1, type2_bytes, exported_session_key, creds
    )

    req2 = BindRequest()
    req2["version"] = 3
    req2["name"] = ""
    req2["authentication"]["sasl"]["mechanism"] = "GSSAPI"
    req2["authentication"]["sasl"]["credentials"] = type3_bytes
    resp = transport.send_bind(req2)
    code = _bind_result_code(resp)
    if code != ResultCode("success"):
        return BindOutcome(False, f"authenticate failed: {bind_failure_detail(resp)}")

    active_strategy = strategy if layer != "plain" else None
    transport.mark_bound(active_strategy)
    return BindOutcome(True, f"bind succeeded, layer={strategy.name}{_kxkey_note(strategy)}")


def _register_gssapi_ntlm() -> None:
    for layer in ("plain", "signonly", "sealonly", "signseal"):

        def connect(creds: Credentials, _layer=layer) -> LDAPTransport:
            return open_transport(
                creds.target, creds.port, creds.scheme, signing=(_layer != "plain")
            )

        def bind(
            transport: LDAPTransport, creds: Credentials, _layer=layer
        ) -> BindOutcome:
            return _bind_gssapi_ntlm(transport, creds, _layer)

        register(
            Method(
                f"sasl_gssapi_ntlm_{layer}",
                requires=["username", "password"],
                connect=connect,
                bind=bind,
                eligible=_ntlm_eligible,
            )
        )


_register_gssapi_ntlm()
