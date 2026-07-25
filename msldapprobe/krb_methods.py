"""Bind-flow construction for the two Kerberos-carrying mechanism families:
sasl_spnego_krb_* (SASL "GSS-SPNEGO" wrapping an AP-REQ) and
sasl_gssapi_krb_* (SASL "GSSAPI", carrying the AP-REQ inside RFC 2743
§3.1's GSS-API "Initial Context Token" envelope, with the RFC 1964 §1
2-byte TOK_ID added after the OID header).

Key architectural points:

* The AP-REQ checksum flags must always request the maximum
  (Integ+Conf+Mutual) regardless of which per-message layer this bind
  will eventually select — the layer choice happens separately in RFC 4752
  §3.3's round-3 bitmask, not here.
* Proposing an AES256 client subkey is necessary to avoid the DC falling
  back to RC4-HMAC for the acceptor subkey even with an AES256 ticket.
* Round 3's SND_SEQ must continue from seq-number 0 (the AP-REQ
  Authenticator's own starting value), not an independent counter.
* The RC4-HMAC path wraps every per-message token in the
  [APPLICATION 0]+OID envelope (a legacy Windows quirk); the AES/CFX path
  sends them bare per RFC 2743 §3.2.
* Post-bind sign-only traffic uses the same unsealed-Wrap-token format
  as round 3, not a separate MIC/GetMIC token.
"""

from __future__ import annotations

from impacket.krb5.constants import EncryptionTypes
from impacket.krb5.crypto import _enctype_table
from impacket.krb5.gssapi import GSSAPI, KRB5_AP_REQ, MechIndepToken
from impacket.ldap.ldapasn1 import BindRequest, ResultCode
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

from .krb_layers import (
    LAYER_BITMASK,
    LAYER_CKSUM_FLAGS,
    acquire_ticket,
    build_ap_req,
    build_kerberos_layer_strategy,
    build_rc4_unsealed_wrap_token,
    build_unsealed_wrap_token,
    decrypt_ap_rep,
    verify_rc4_unsealed_wrap_token,
    verify_unsealed_wrap_token,
)
from .methods import BindOutcome, Credentials, Method, bind_failure_detail, register
from .transport import LDAPTransport, open_transport

KRB5_MECH_OID = TypesMech["MS KRB5 - Microsoft Kerberos 5"]


def _bind_result_code(protocol_op) -> ResultCode:
    return protocol_op["bindResponse"]["resultCode"]


def _gss_initial_context_token(ap_req_bytes: bytes) -> bytes:
    # The outer [APPLICATION 0] length must cover the TOK_ID too, so it's
    # included in what's passed to MechIndepToken rather than appended
    # after to_bytes() has already computed a length without it.
    header, data = MechIndepToken(KRB5_AP_REQ + ap_req_bytes).to_bytes()
    return header + data


def _connect(creds: Credentials, layer: str) -> LDAPTransport:
    return open_transport(
        creds.target, creds.port, creds.scheme, signing=(layer != "plain")
    )


# ---------------------------------------------------------------------------
# sasl_spnego_krb_*
# ---------------------------------------------------------------------------


def _bind_spnego_krb(
    transport: LDAPTransport, creds: Credentials, layer: str
) -> BindOutcome:
    try:
        ticket, cipher, session_key = acquire_ticket(creds, creds.spn_host)
    except Exception as exc:
        return BindOutcome(False, f"ticket acquisition failed: {exc}")

    # Proposing a client subkey (RFC 4120 §5.5.1) is the normal case: the
    # proposed subkey itself - not the ticket session_key - becomes the
    # actual per-message key per RFC 4121 §2 for SPNEGO's single-round
    # bind (which never gets an AP-REP to override it, unlike GSSAPI).
    # creds.propose_subkey selects the etype (or "none" to skip).
    # creds.cksum_flags overrides the AP-REQ checksum flags (int); defaults to the
    # bind's own layer (SPNEGO has no §3.3 round, so the checksum IS the choice).
    ck_flags = (
        creds.cksum_flags if creds.cksum_flags is not None else LAYER_CKSUM_FLAGS[layer]
    )
    ap_req_bytes, subkey_key = build_ap_req(
        ticket,
        cipher,
        session_key,
        creds,
        ck_flags,
        propose_subkey=creds.propose_subkey,
    )
    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = [KRB5_MECH_OID]
    blob["MechToken"] = ap_req_bytes

    req = BindRequest()
    req["version"] = 3
    req["name"] = ""
    req["authentication"]["sasl"]["mechanism"] = "GSS-SPNEGO"
    req["authentication"]["sasl"]["credentials"] = blob.getData()
    resp = transport.send_bind(req)
    code = _bind_result_code(resp)
    if code != ResultCode("success"):
        return BindOutcome(False, f"authenticate failed: {bind_failure_detail(resp)}")

    layer_key = subkey_key if subkey_key is not None else session_key
    strategy = build_kerberos_layer_strategy(layer, cipher, layer_key)
    active_strategy = strategy if layer != "plain" else None
    transport.mark_bound(active_strategy)
    return BindOutcome(True, f"bind succeeded, layer={strategy.name}")


def _register_spnego_krb() -> None:
    for layer in ("plain", "signonly", "signseal"):

        def connect(creds: Credentials, _layer=layer) -> LDAPTransport:
            return _connect(creds, _layer)

        def bind(
            transport: LDAPTransport, creds: Credentials, _layer=layer
        ) -> BindOutcome:
            return _bind_spnego_krb(transport, creds, _layer)

        register(
            Method(
                f"sasl_spnego_krb_{layer}",
                requires=["username", "domain"],
                connect=connect,
                bind=bind,
                eligible=lambda c: (
                    (True, "")
                    if c.domain
                    and (
                        c.ccache
                        or (c.username and (c.password or c.nthash or c.aes_key))
                    )
                    else (
                        False,
                        "need --domain and either --ccache, or --username with "
                        "one of --password/--hashes/--aes-key",
                    )
                ),
            )
        )


_register_spnego_krb()


# ---------------------------------------------------------------------------
# sasl_gssapi_krb_*
# ---------------------------------------------------------------------------


def _gssapi_bind_request(mechanism_credentials: bytes | None) -> BindRequest:
    req = BindRequest()
    req["version"] = 3
    req["name"] = ""
    req["authentication"]["sasl"]["mechanism"] = "GSSAPI"
    if mechanism_credentials is not None:
        req["authentication"]["sasl"]["credentials"] = mechanism_credentials
    return req


def _bind_gssapi_krb(
    transport: LDAPTransport, creds: Credentials, layer: str
) -> BindOutcome:
    try:
        ticket, cipher, session_key = acquire_ticket(creds, creds.spn_host)
    except Exception as exc:
        return BindOutcome(False, f"ticket acquisition failed: {exc}")

    # RFC 4752 §3.1: SASL/GSSAPI always uses mutual authentication - the
    # server proves itself back via an AP-REP before the exchange can
    # continue, which round 2 below verifies.
    #
    # The AP-REQ checksum flags always request "signseal" (Conf+Integ+Mutual)
    # regardless of this bind's own `layer` — a real client's context-
    # establishment request is unconditionally MUTUAL|SEQUENCE|INTEG(+CONF
    # per RFC 4752 and typical SASL security properties). The actual
    # per-message layer is chosen separately in round 3 (LAYER_BITMASK),
    # not here. Requesting less than the maximum here (e.g. no flags at
    # all for a "plain" test) makes the DC only ever offer a reduced
    # round-2 bitmask (0x03, missing the confidentiality bit) instead of
    # the full 0x07 a real client gets.
    #
    # Proposing a client subkey (RFC 4120 §5.5.1) steers the DC toward an
    # acceptor subkey of that etype. Setting propose_subkey="none" lets
    # the AP-REP subkey fall back to whatever msDS-SupportedEncryptionTypes
    # allows, exercising GSSAPI_RC4's sealed GSS_Wrap_LDAP path.
    #
    # creds.cksum_flags (int) overrides the default signseal to probe
    # arbitrary GSS-API checksum flag combinations.
    ck_flags = (
        creds.cksum_flags
        if creds.cksum_flags is not None
        else LAYER_CKSUM_FLAGS["signseal"]
    )
    ap_req_bytes, _ = build_ap_req(
        ticket,
        cipher,
        session_key,
        creds,
        ck_flags,
        mutual_required=True,
        propose_subkey=creds.propose_subkey,
    )
    token = _gss_initial_context_token(ap_req_bytes)

    # Round 1: client's AP-REQ -> server's AP-REP (both inside RFC 2743's
    # Initial Context Token envelope, RFC 1964 §1 TOK_ID-tagged).
    resp = transport.send_bind(_gssapi_bind_request(token))
    code = _bind_result_code(resp)
    if code == ResultCode("success"):
        # Some servers may complete in one round; handle it rather than
        # assume the 3-round shape is mandatory.
        strategy = build_kerberos_layer_strategy(layer, cipher, session_key)
        active_strategy = strategy if layer != "plain" else None
        transport.mark_bound(active_strategy)
        return BindOutcome(True, f"bind succeeded, layer={strategy.name}")
    if code != ResultCode("saslBindInProgress"):
        return BindOutcome(False, f"authenticate failed: {bind_failure_detail(resp)}")

    try:
        gss_key = decrypt_ap_rep(
            bytes(resp["bindResponse"]["serverSaslCreds"]), cipher, session_key
        )
    except Exception as exc:
        return BindOutcome(False, f"AP-REP verification failed: {exc}")

    # The AP-REP subkey (acceptor subkey) becomes the per-message key for
    # ALL subsequent GSS-API calls in BOTH directions (RFC 4121 §2),
    # regardless of whether a client subkey was proposed in the AP-REQ or
    # the DC generated its own.  The AES/CFX path already uses this subkey
    # for everything and works; applying the same rule to the RC4 case
    # (propose_subkey="none") is what the DC expects
    # for verify_rc4_unsealed_wrap_token on round 3 as well.  The SPNEGO
    # path, which never gets an AP-REP and therefore never learns an
    # acceptor subkey, has no such rule to apply — it simply uses whatever
    # key it negotiated (session_key or proposed subkey), which is correct
    # but inapplicable here.
    round2_key = gss_key

    # Round 2: an empty-credentials continuation to request the server's
    # RFC 4752 §3.3 security-layer-negotiation message (it never arrives
    # bundled with the AP-REP).
    resp2 = transport.send_bind(_gssapi_bind_request(None))
    code2 = _bind_result_code(resp2)
    if code2 != ResultCode("saslBindInProgress"):
        return BindOutcome(
            False, f"security-layer negotiation failed: {bind_failure_detail(resp2)}"
        )

    # The AP-REP subkey's etype is independent of the ticket's (RFC 4120
    # §5.5.2) — build_ap_req() proposes a client subkey based on
    # creds.propose_subkey to steer the DC toward an acceptor subkey of
    # that etype (RC4 is the DC's fallback when no client subkey is
    # proposed at all).
    # gss must be built from the negotiated subkey's own etype, not the
    # ticket cipher used for round 1, in case a DC ever ignores the
    # proposal and falls back to RC4 anyway.
    gss = GSSAPI(_enctype_table[gss_key.enctype])
    is_rc4 = gss_key.enctype == EncryptionTypes.rc4_hmac.value

    # Round 2's serverSaslCreds framing differs by subkey etype: the
    # RC4-HMAC path wraps every per-message token in the same
    # [APPLICATION 0]+OID envelope as the AP-REQ/AP-REP (a legacy Windows
    # quirk), but the AES/CFX path sends per-message tokens bare per
    # RFC 2743 §3.2 (only context-establishment tokens carry the OID).
    raw_server_creds = bytes(resp2["bindResponse"]["serverSaslCreds"])
    server_wrap_bytes = (
        MechIndepToken.from_bytes(raw_server_creds).data if is_rc4 else raw_server_creds
    )
    try:
        if is_rc4:
            server_payload = verify_rc4_unsealed_wrap_token(
                gss, round2_key, server_wrap_bytes
            )
        else:
            server_payload = verify_unsealed_wrap_token(gss, gss_key, server_wrap_bytes)
    except Exception as exc:
        return BindOutcome(False, f"security-layer token verification failed: {exc}")

    # Round 3: client picks its layer here (not in the AP-REQ checksum
    # flags) and echoes the server's own max-buffer-size back, per
    # RFC 2222 §7.2.1. The payload may optionally carry an authorization
    # identity (RFC 4752 §3.4's fourth field) after the fixed 4 bytes;
    # this is only appended when a separate authzid is requested
    # (ldapsearch -Y GSSAPI sends exactly 4 bytes).
    max_buf = server_payload[1:4] if len(server_payload) >= 4 else b"\x00\x00\x00"
    reply_payload = bytes([LAYER_BITMASK[layer]]) + max_buf
    # SND_SEQ must continue from the AP-REQ Authenticator's own seq-number
    # field (hardcoded to 0 in build_ap_req). Using an unrelated value here
    # makes the DC silently reject the message with invalidCredentials.
    seq_number = 0
    if is_rc4:
        reply_token = build_rc4_unsealed_wrap_token(
            gss, gss_key, reply_payload, seq_number=seq_number
        )
        # For RC4-HMAC the DC expects ALL GSS-Wrap tokens in SASL
        # credentials (including round 3's security-layer reply, not just
        # the DC's own round-2 message) to be wrapped in the same
        # [APPLICATION 0]+OID envelope — a legacy Windows quirk.
        header, data = MechIndepToken(reply_token).to_bytes()
        reply_token = header + data
    else:
        reply_token = build_unsealed_wrap_token(
            gss, gss_key, reply_payload, seq_number=seq_number
        )
    resp3 = transport.send_bind(_gssapi_bind_request(reply_token))
    code3 = _bind_result_code(resp3)
    if code3 != ResultCode("success"):
        return BindOutcome(False, f"authenticate failed: {bind_failure_detail(resp3)}")

    # Once a subkey is negotiated (RFC 4120 §5.5.2), all further per-message
    # protection uses it in place of the ticket session key. start_seq=1
    # continues from round 3's own SND_SEQ=0 above - starting the first
    # real post-bind message back at 0 desyncs the DC's own sequence
    # tracking.
    strategy = build_kerberos_layer_strategy(layer, cipher, gss_key, start_seq=1)
    active_strategy = strategy if layer != "plain" else None
    transport.mark_bound(active_strategy)
    return BindOutcome(True, f"bind succeeded, layer={strategy.name}")


def _register_gssapi_krb() -> None:
    for layer in ("plain", "signonly", "signseal"):

        def connect(creds: Credentials, _layer=layer) -> LDAPTransport:
            return _connect(creds, _layer)

        def bind(
            transport: LDAPTransport, creds: Credentials, _layer=layer
        ) -> BindOutcome:
            return _bind_gssapi_krb(transport, creds, _layer)

        register(
            Method(
                f"sasl_gssapi_krb_{layer}",
                requires=["username", "domain"],
                connect=connect,
                bind=bind,
                eligible=lambda c: (
                    (True, "")
                    if c.domain
                    and (
                        c.ccache
                        or (c.username and (c.password or c.nthash or c.aes_key))
                    )
                    else (
                        False,
                        "need --domain and either --ccache, or --username with "
                        "one of --password/--hashes/--aes-key",
                    )
                ),
            )
        )


_register_gssapi_krb()
