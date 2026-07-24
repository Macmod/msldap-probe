"""Bind-flow construction for the two Kerberos-carrying mechanism families:
sasl_spnego_krb_* (SASL "GSS-SPNEGO" wrapping an AP-REQ - impacket's own
kerberosLogin() path, extended for full flag control) and sasl_gssapi_krb_*
(SASL mechanism literally "GSSAPI", carrying the AP-REQ inside RFC 2743
§3.1's GSS-API "Initial Context Token" envelope - no SPNEGO layer, just the
generic GSS-API OID header - using impacket.krb5.gssapi.MechIndepToken for
the outer [APPLICATION 0]+OID wrapper, plus RFC 1964 §1's 2-byte TOK_ID
(impacket's own KRB5_AP_REQ constant, b"\\x01\\x00") between the OID and the
AP-REQ itself - the Kerberos-V5-mechanism-specific inner-token marker that
MechIndepToken, being a generic RFC 2743 helper, doesn't know about and
doesn't add on its own.

sasl_gssapi_krb_* now completes end-to-end (PASS across all four layers),
after a multi-stage investigation. In order:

1. Original hard failure (resultCode unavailable) was a missing RFC 1964
   §1 TOK_ID between the GSS-API OID header and the AP-REQ - found by
   building a Go reference client (go-ldap + gokrb5) and diffing its raw
   wire bytes against ours. Fixing it took the DC from a flat rejection
   to a real RFC 4752 §3.1 mutual-auth exchange (AP-REQ -> AP-REP ->
   RFC 4752 §3.3 security-layer negotiation).
2. Round 3 (the client's own reply) then failed uniformly regardless of
   content for a long stretch, which pointed toward "DC/environment
   limitation" - a conclusion that didn't survive scrutiny: a real
   ldapsearch -Y GSSAPI (Cyrus SASL + MIT krb5) bind against the exact
   same DC succeeds completely (SASL SSF: 256), proving the mechanism
   genuinely works and the remaining gap was in this code, not the
   server. Getting a live Wireshark capture of that real bind (not
   source-code inference) surfaced three concrete, previously-invisible
   bugs at once:
     a. The AP-REP's acceptor subkey etype is independent of the
        ticket's (RFC 4120 §5.5.2) and depends on whether the AP-REQ
        Authenticator proposes a client subkey at all - omitting it (as
        this code always had) makes the DC fall back to RC4-HMAC even
        with an AES256 ticket; a real client always proposes one, and
        adding an AES256 client subkey in build_ap_req() gets a real
        AES256 acceptor subkey back, switching the whole exchange onto
        RFC 4121's CFX format instead of RFC 4757's older RC4-HMAC one
        (both are still implemented and dispatched on the negotiated
        subkey's actual etype, since a DC could still fall back).
     b. The AP-REQ checksum flags must always request the maximum
        (Integ+Conf+Mutual, i.e. "signseal") regardless of which layer
        this particular bind will end up choosing - the actual layer
        choice happens separately in round 3's bitmask, not here.
        Requesting less (e.g. no flags for a "plain" test, which this
        code used to do) makes the DC only ever offer a reduced round-2
        bitmask instead of the full set a real client sees.
     c. Round 3's SND_SEQ must continue from the same starting value
        declared in the AP-REQ Authenticator's own seq-number field
        (hardcoded to 0 here) - using an unrelated value (this code
        used a bare 1) silently failed AcceptSecurityContext with the
        same generic error as every other failure mode investigated,
        indistinguishable from a real construction bug without a
        working capture to diff against.
   Also confirmed along the way, independent of the fix itself: the
   RFC 4121/CFX Wrap-token checksum construction (data+checksum,
   RRC=0 for the client's own message; header/EC/RRC zeroed for the
   checksum computation itself) matches MIT krb5's own
   kg_verify_checksum_v3(), and the round 2/round 3 OID-wrapping
   asymmetry between the RC4 and AES paths is real, not a bug - the RC4
   path wraps every per-message token in the OID header (a legacy
   Windows quirk), the AES/CFX path only wraps the AP-REQ/AP-REP per
   strict RFC 2743 §3.2.
3. Bind now succeeded on all four layers, but sign-only's post-bind
   messages still failed - a distinct bug from round 3's, since it's a
   different code path (KerberosLayerStrategy in krb_layers.py, used for
   every real LDAP message once bound, not the security-layer-negotiation
   round). It assumed sign-only used a separate MIC/GetMIC token, which
   was wrong: a live capture of ldapsearch forced to integrity-only
   (-O minssf=1,maxssf=1) showed real per-message sign-only traffic uses
   the exact same unsealed-Wrap-token format as round 3, just carrying
   the whole LDAP message as its payload instead of the 4-byte layer
   negotiation blob. Switching KerberosLayerStrategy's non-sealed path to
   reuse build_unsealed_wrap_token/verify_unsealed_wrap_token (the same
   functions round 3 already used) fixed it - along with two more bugs
   the fix's own regression testing surfaced: build_kerberos_layer_
   strategy was selecting its GSSAPI_* class from the ticket cipher
   instead of the actual negotiated session key's etype (wrong whenever
   they differ, which is exactly the AP-REP-subkey situation above), and
   post-bind messages need to continue sasl_gssapi_krb_*'s own SND_SEQ
   counter from where round 3 left it (1, since round 3 used 0) rather
   than restart at 0.

All four sasl_gssapi_krb_* layers now PASS end-to-end, verified against
the CRETA.LOCAL test DC.
"""

from __future__ import annotations

from impacket.krb5.constants import EncryptionTypes
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.gssapi import GSSAPI, KRB5_AP_REQ, MechIndepToken
from impacket.ldap.ldapasn1 import BindRequest, ResultCode
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

from .krb_layers import (
    LAYER_BITMASK,
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
    ap_req_bytes, subkey_key = build_ap_req(
        ticket, cipher, session_key, creds, layer, propose_subkey=creds.propose_subkey
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
    for layer in ("plain", "signonly", "sealonly", "signseal"):

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
    # The AP-REQ checksum flags below always request "signseal" (Conf+Integ)
    # regardless of this bind's own `layer` - a real client's context-
    # establishment request is unconditionally MUTUAL|SEQUENCE|INTEG(+CONF
    # per RFC 4752 and typical SASL security properties), confirmed against
    # Cyrus SASL's gssapi.c and a live capture: the actual per-message layer
    # is chosen separately in round 3 below (LAYER_BITMASK), not here. Live
    # testing found that requesting less than the maximum here (e.g. no
    # flags at all for a "plain" test) makes the DC only ever offer a
    # reduced round-2 bitmask (0x03, no confidentiality bit) instead of the
    # full 0x07 a real client gets - this was the remaining piece of why
    # round 3 kept failing even after the AES-subkey and framing fixes.
    #
    # Proposing a client subkey (RFC 4120 §5.5.1) steers the DC toward an
    # acceptor subkey of that etype. Setting propose_subkey="none" lets the
    # AP-REP subkey fall back to whatever msDS-SupportedEncryptionTypes
    # allows, exercising GSSAPI_RC4's sealed GSS_Wrap_LDAP path.
    ap_req_bytes, _ = build_ap_req(
        ticket,
        cipher,
        session_key,
        creds,
        "signseal",
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
    # RFC 4752 §3.3 security-layer-negotiation message - it never arrives
    # bundled with the AP-REP (confirmed against a live gokrb5 reference
    # client, which does the same empty round).
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
    # proposed at all, confirmed by diffing against a live capture).
    # gss must be built from the negotiated subkey's own etype, not the
    # ticket cipher used for round 1, in case a DC ever ignores the
    # proposal and falls back to RC4 anyway.
    gss = GSSAPI(_enctype_table[gss_key.enctype])
    is_rc4 = gss_key.enctype == EncryptionTypes.rc4_hmac.value

    # Round 2's serverSaslCreds framing differs by subkey etype: the
    # RC4-HMAC path wraps every per-message token in the same
    # [APPLICATION 0]+OID envelope as the AP-REQ/AP-REP (a legacy Windows
    # quirk), but the AES/CFX path sends per-message tokens bare, per
    # strict RFC 2743 §3.2 (only context-establishment tokens carry the
    # OID) - confirmed against a live capture, where the AES-path
    # server message starts directly with the Wrap token's own TOK_ID.
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
    # flags, which a real client always sets to a fixed Integ+Conf+Mutual
    # regardless of layer - see LAYER_BITMASK in krb_layers.py) and echoes
    # the server's own max-buffer-size back, per RFC 2222 §7.2.1. The
    # payload may optionally carry an authorization identity (RFC 2222
    # §7.2.1 / RFC 4752 §3.4's fourth field) after the fixed 4 bytes - per
    # Cyrus SASL's real gssapi.c client plugin (the library
    # ldapsearch -Y GSSAPI actually uses), this is only appended when a
    # separate authzid was explicitly requested (its "text->user" gate);
    # confirmed against a live capture of a plain ldapsearch -Y GSSAPI
    # bind, whose round-3 payload was exactly 4 bytes with no authzid.
    max_buf = server_payload[1:4] if len(server_payload) >= 4 else b"\x00\x00\x00"
    reply_payload = bytes([LAYER_BITMASK[layer]]) + max_buf
    # RFC 4121 ties per-message sequence numbers to the starting value
    # declared in the AP-REQ Authenticator's own seq-number field
    # (hardcoded to 0 in build_ap_req) - round 3's SND_SEQ must continue
    # from that same value, not an independent counter. Using an
    # unrelated value here (1, or anything else) was the actual final
    # bug: it passed our own checksum self-verification (since our
    # verify function trusts whatever seq_number it's given) but the DC
    # silently rejected it - the same generic invalidCredentials/"data 5"
    # seen throughout this investigation, indistinguishable from a
    # content bug without a live capture to compare against. Found by
    # diffing a real ldapsearch -Y GSSAPI (Cyrus SASL/MIT krb5) capture
    # against this code end-to-end; matching its seq_number=0 here is
    # what finally completes the bind.
    seq_number = 0
    if is_rc4:
        reply_token = build_rc4_unsealed_wrap_token(
            gss, gss_key, reply_payload, seq_number=seq_number
        )
        # For RC4-HMAC the DC expects ALL GSS-Wrap tokens in SASL
        # credentials (including round 3's security-layer reply, not just
        # the DC's own round-2 message) to be wrapped in the same
        # [APPLICATION 0]+OID envelope — a legacy Windows quirk confirmed
        # by KerberosLayerStrategy.wrap() doing the same wrapping for
        # post-bind RC4-unsealed per-message traffic.
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
    # tracking and produces garbage on decrypt (found the same way as the
    # round-3 seq_number bug: by diffing against a live capture).
    strategy = build_kerberos_layer_strategy(layer, cipher, gss_key, start_seq=1)
    active_strategy = strategy if layer != "plain" else None
    transport.mark_bound(active_strategy)
    return BindOutcome(True, f"bind succeeded, layer={strategy.name}")


def _register_gssapi_krb() -> None:
    for layer in ("plain", "signonly", "sealonly", "signseal"):

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
            )
        )


_register_gssapi_krb()
