"""Kerberos ticket acquisition, AP-REQ construction with full checksum-flag
control, and the post-bind GSS-API wrap/unwrap LayerStrategy shared by
sasl_gssapi_krb_* and sasl_spnego_krb_* - per-message GSS protection is
identical regardless of which handshake carried the AP-REQ.
"""

from __future__ import annotations

import datetime
import os
import struct
from dataclasses import dataclass

from pyasn1.codec.ber import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AP_REP,
    AP_REQ,
    Authenticator,
    EncAPRepPart,
    TGS_REP,
    seq_set,
)
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Enctype, Key, _enctype_table, string_to_key
from impacket.krb5.gssapi import (
    GSSAPI,
    GSS_C_CONF_FLAG,
    GSS_C_INTEG_FLAG,
    GSS_C_REPLAY_FLAG,
    GSS_C_SEQUENCE_FLAG,
    KG_USAGE_ACCEPTOR_SEAL,
    KG_USAGE_INITIATOR_SEAL,
    KRB5_AP_REQ,
    MechIndepToken,
)
from impacket.krb5.kerberosv5 import CheckSumField, getKerberosTGS, getKerberosTGT
from impacket.krb5.types import KerberosTime, Principal, Ticket

KRB5_AP_REP = b"\x02\x00"

# RFC 4121 §4.2 Wrap token, TOK_ID for a Wrap token (as opposed to 0x0404
# for a MIC token, which impacket's GSS_GetMIC already builds).
_WRAP_TOK_ID = 0x0504
_WRAP_FILLER = 0xFF

# Layer name -> per-message protection flags.
# build_kerberos_layer_strategy uses this to set wire_seal based on the
# layer under test. --cksum-flags (int) is the mechanism for probing
# arbitrary GSS-API checksum values not covered by a registered layer.
LAYER_CKSUM_FLAGS = {
    "plain": 0,
    "signonly": GSS_C_INTEG_FLAG,
    "signseal": GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG,
}

# RFC 2222 §7.2.1 / RFC 4752 §3.3 security-layer bitmask: the post-auth
# negotiation round selects per-message protection independently of the
# AP-REQ checksum. signseal and the removed sealonly both use the same
# confidentiality value (0x04) since GSS_Wrap with CONF implies integrity.
LAYER_BITMASK = {
    "plain": 0x01,
    "signonly": 0x02,
    "signseal": 0x04,
}


def _ticket_from_tgs_rep(tgs_bytes: bytes):
    """Parses a TGS_REP's encoded bytes into a Ticket."""
    tgs_rep = decoder.decode(tgs_bytes, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs_rep["ticket"])
    return ticket


def acquire_ticket(creds, target_host: str):
    """Returns (ticket, cipher, session_key) for the LDAP service on
    target_host.

    Credential resolution order for the Kerberos ticket:
      1. --ccache (or KRB5CCNAME): use the cached service ticket for
         ldap/<target_host>@REALM directly if present, otherwise use the
         cached TGT to obtain a service ticket via getKerberosTGS. No KDC
         AS-REQ is issued when a cached TGT is available.
      2. --aes-key / --hashes / --password: obtain a fresh TGT in memory
         via getKerberosTGT, then a service ticket via getKerberosTGS.

    NOTE: when only a password is given (no --aes-key, no --hashes), the
    AES256 key is pre-derived here with the standard REALM+username salt
    to avoid impacket's password-only path, which may fall back to RC4-HMAC."""
    spn = f"ldap/{target_host}@{creds.domain.upper()}"

    # Path 1: ccache (explicit --ccache, else KRB5CCNAME if set).
    ccache_path = creds.ccache or os.getenv("KRB5CCNAME")
    if ccache_path:
        ccache = CCache.loadFile(ccache_path)
        if ccache is None:
            raise ValueError(f"could not load ccache: {ccache_path}")
        cred = ccache.getCredential(spn)
        if cred is not None:
            tgs = cred.toTGS(spn)
            return (
                _ticket_from_tgs_rep(tgs["KDC_REP"]),
                tgs["cipher"],
                tgs["sessionKey"],
            )
        # No cached service ticket - fall back to the cached TGT, if any.
        tgt_cred = ccache.getCredential(
            f"krbtgt/{creds.domain.upper()}@{creds.domain.upper()}"
        )
        if tgt_cred is not None:
            tgt = tgt_cred.toTGT()
            server_name = Principal(
                f"ldap/{target_host}",
                type=constants.PrincipalNameType.NT_SRV_INST.value,
            )
            tgs, cipher, _, session_key = getKerberosTGS(
                server_name,
                creds.domain,
                creds.kdc_host,
                tgt["KDC_REP"],
                tgt["cipher"],
                tgt["sessionKey"],
            )
            return _ticket_from_tgs_rep(tgs), cipher, session_key
        raise ValueError(
            f"ccache {ccache_path} has neither a service ticket for {spn} "
            f"nor a TGT to obtain one"
        )

    # Path 2: obtain a fresh TGT in memory from the supplied credential.
    aes_key = creds.aes_key
    if not aes_key and not creds.nthash and creds.password:
        salt = f"{creds.domain.upper()}{creds.username}".encode()
        aes_key = string_to_key(
            Enctype.AES256, creds.password.encode(), salt
        ).contents.hex()

    username = Principal(
        creds.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )
    tgt, cipher, _, session_key = getKerberosTGT(
        username,
        creds.password,
        creds.domain,
        creds.lmhash,
        creds.nthash,
        aes_key,
        creds.kdc_host,
    )
    server_name = Principal(
        f"ldap/{target_host}", type=constants.PrincipalNameType.NT_SRV_INST.value
    )
    tgs, cipher, _, session_key = getKerberosTGS(
        server_name, creds.domain, creds.kdc_host, tgt, cipher, session_key
    )
    return _ticket_from_tgs_rep(tgs), cipher, session_key


def parse_gss_token(token_bytes: bytes) -> tuple[bytes, bytes]:
    """Splits a GSS-API Initial Context Token (RFC 2743 §3.1, the
    [APPLICATION 0]+OID wrapper impacket's MechIndepToken builds) into its
    RFC 1964 §1 TOK_ID (2 bytes - identifies AP-REQ/AP-REP/KRB_ERROR) and
    the Kerberos message that follows it."""
    mech = MechIndepToken.from_bytes(token_bytes)
    return mech.data[:2], mech.data[2:]


def decrypt_ap_rep(ap_rep_token: bytes, cipher, session_key):
    """Verifies the mutual-auth response required by RFC 4752 §3.1 for bare
    SASL/GSSAPI, and returns the key to use for the rest of the exchange:
    the AP-REP's own subkey (RFC 4120 §5.5.2 - the acceptor may supply one
    to move off the ticket session key) if present, otherwise the ticket
    session key unchanged."""
    tok_id, ap_rep_bytes = parse_gss_token(ap_rep_token)
    if tok_id != KRB5_AP_REP:
        raise ValueError(
            f"expected AP-REP token (TOK_ID {KRB5_AP_REP.hex()}), got {tok_id.hex()}"
        )

    ap_rep = decoder.decode(ap_rep_bytes, asn1Spec=AP_REP())[0]
    # Key Usage 12: AP-REP encrypted part, encrypted with the session key
    # (RFC 4120 §5.5.2).
    enc_part_cipher = bytes(ap_rep["enc-part"]["cipher"])
    plaintext = cipher.decrypt(session_key, 12, enc_part_cipher)
    enc_ap_rep_part = decoder.decode(plaintext, asn1Spec=EncAPRepPart())[0]

    if enc_ap_rep_part["subkey"].hasValue():
        subkey_type = int(enc_ap_rep_part["subkey"]["keytype"])
        subkey_bytes = bytes(enc_ap_rep_part["subkey"]["keyvalue"])
        return Key(subkey_type, subkey_bytes)
    return session_key


def _rc4_unsealed_wrap_checksum(
    gss, key_contents: bytes, header8: bytes, confounder: bytes, data: bytes
) -> bytes:
    """RFC 4757 §7.3 Sgn_Cksum for an unsealed Wrap token (sign-type 0x0d,
    computed over header[:8]+Confounder+data, same as the sealed formula)."""
    from impacket.krb5.gssapi import HMAC, MD5

    ksign = HMAC.new(key_contents, b"signaturekey\0", MD5).digest()
    mid = MD5.new(struct.pack("<L", 13) + header8 + confounder + data).digest()
    return HMAC.new(ksign, mid, MD5).digest()[:8]


def verify_rc4_unsealed_wrap_token(gss, key, token_bytes: bytes) -> bytes:
    """Verifies an RFC 4752 §3.3 security-layer-negotiation message wrapped
    with an RC4-HMAC subkey (RFC 4757). Returns the plaintext payload with
    the trailing single-byte marker (matching GSS_Wrap_LDAP's own
    `data += b"\\x01"` convention) stripped."""
    wrap_struct = gss.WRAP(token_bytes[: len(gss.WRAP())])
    if wrap_struct["TOK_ID"] != 0x0102:
        raise ValueError(
            f"expected RC4 Wrap token (TOK_ID 0x0102), got 0x{wrap_struct['TOK_ID']:04x}"
        )
    data = token_bytes[len(gss.WRAP()) :]
    header8 = wrap_struct.getData()[:8]
    expected = _rc4_unsealed_wrap_checksum(
        gss, key.contents, header8, wrap_struct["Confounder"], data
    )
    if expected != wrap_struct["SGN_CKSUM"]:
        raise ValueError("security-layer-negotiation checksum mismatch")
    return data[:-1] if data.endswith(b"\x01") else data


def build_rc4_unsealed_wrap_token(gss, key, payload: bytes, seq_number: int) -> bytes:
    """Builds the client's RFC 4752 §3.3 reply: RC4-HMAC Wrap token
    (TOK_ID 0x0102), SEAL_ALG=0xffff (no confidentiality), SND_SEQ
    encrypted the same way impacket's GSS_Wrap does."""
    from impacket.krb5.gssapi import ARC4, HMAC, MD5

    data = payload + b"\x01"
    token = gss.WRAP()
    token["SGN_ALG"] = 0x11  # GSS_HMAC
    token["SEAL_ALG"] = 0xFFFF  # no confidentiality
    token["SND_SEQ"] = struct.pack(">L", seq_number) + b"\x00" * 4  # direction='init'

    import os

    confounder = os.urandom(8)
    token["Confounder"] = confounder

    header8 = token.getData()[:8]
    checksum = _rc4_unsealed_wrap_checksum(gss, key.contents, header8, confounder, data)
    token["SGN_CKSUM"] = checksum

    kseq = HMAC.new(key.contents, struct.pack("<L", 0), MD5).digest()
    kseq = HMAC.new(kseq, checksum, MD5).digest()
    token["SND_SEQ"] = ARC4.new(kseq).encrypt(token["SND_SEQ"])

    return token.getData() + data


def _cfx_checksum_header(flags: int, seq_number: int) -> bytes:
    """RFC 4121 §4.2.4: the checksum is computed over a 16-byte header with
    EC and RRC fields ZEROED (per MIT krb5's kg_verify_checksum_v3():
    "the EC and RRC fields have the value 0 for the checksum operation,
    regardless of their values in the actual token"). Sequence number
    is a plain 8-byte big-endian value (unlike RFC 4757 RC4-HMAC)."""
    return struct.pack(">HBBI", _WRAP_TOK_ID, flags, _WRAP_FILLER, 0) + struct.pack(
        ">Q", seq_number
    )


def unpack_wrap_token(data: bytes) -> tuple[int, int, int, int, bytes, bytes]:
    """Parses an RFC 4121 §4.2 Wrap token. The canonical body is DATA
    followed by an EC-byte CHECKSUM; RRC (RFC 4121 §4.2.5) rotates the body
    right by RRC bytes on the wire. This function unrotates by the token's
    own RRC field rather than assuming a fixed layout."""
    if len(data) < 16:
        raise ValueError("wrap token shorter than its own header")
    tok_id, flags, filler, ec, rrc = struct.unpack(">HBBHH", data[:8])
    if tok_id != _WRAP_TOK_ID:
        raise ValueError(
            f"expected Wrap token (TOK_ID 0x{_WRAP_TOK_ID:04x}), got 0x{tok_id:04x}"
        )
    seq_number = struct.unpack(">Q", data[8:16])[0]
    body = data[16:]
    if len(body) < ec:
        raise ValueError("wrap token body shorter than its own checksum")
    canonical = body[rrc:] + body[:rrc] if rrc else body
    payload, checksum = canonical[:-ec], canonical[-ec:]
    return flags, ec, seq_number, rrc, checksum, payload


def build_unsealed_wrap_token(gss, key, payload: bytes, seq_number: int) -> bytes:
    """Builds a client RFC 4752 §3.3 reply: an RFC 4121 Wrap token with the
    Sealed flag (bit 1) unset - integrity only, no encryption. Flags 0b100
    (AcceptorSubkey) with RRC=0 (canonical, unrotated DATA+CHECKSUM)."""
    checksum_profile = gss.checkSumProfile()
    ec = checksum_profile.macsize
    flags = 0b100
    header = struct.pack(
        ">HBBHH", _WRAP_TOK_ID, flags, _WRAP_FILLER, ec, 0
    ) + struct.pack(">Q", seq_number)
    checksum = checksum_profile.checksum(
        key, KG_USAGE_INITIATOR_SEAL, payload + _cfx_checksum_header(flags, seq_number)
    )
    return header + payload + checksum


def verify_unsealed_wrap_token(gss, key, token_bytes: bytes) -> bytes:
    """Verifies the server's RFC 4752 §3.3 security-layer-negotiation
    message and returns its plaintext payload (a 4-byte supported-layers
    bitmask + max buffer size, per RFC 2222 §7.2.1)."""
    flags, ec, seq_number, rrc, checksum, payload = unpack_wrap_token(token_bytes)
    checksum_profile = gss.checkSumProfile()
    expected = checksum_profile.checksum(
        key, KG_USAGE_ACCEPTOR_SEAL, payload + _cfx_checksum_header(flags, seq_number)
    )
    if expected != checksum:
        raise ValueError("security-layer-negotiation checksum mismatch")
    return payload


# Subkey etype specifications for build_ap_req's propose_subkey parameter.
# Maps string name -> (etype_value, key_length_bytes) or None for "no subkey".
_SUBKEY_SPECS: dict[str, tuple[int, int] | None] = {
    "none": None,
    "rc4-hmac": (constants.EncryptionTypes.rc4_hmac.value, 16),
    "aes128-cts-hmac-sha1-96": (
        constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
        16,
    ),
    "aes256-cts-hmac-sha1-96": (
        constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
        32,
    ),
}


def build_ap_req(
    ticket: Ticket,
    cipher,
    session_key,
    creds,
    cksum_flags: int,
    channel_binding_value: bytes = b"",
    mutual_required: bool = False,
    propose_subkey: str = "aes256-cts-hmac-sha1-96",
) -> tuple[bytes, Key | None]:
    """mutual_required must be True for bare SASL/GSSAPI (RFC 4752 §3.1:
    "the client MUST set the mutual_state flag to TRUE") - the GSSAPI SASL
    mechanism always uses mutual authentication, unlike SPNEGO's Kerberos."""
    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    opts = [constants.APOptions.mutual_required.value] if mutual_required else []
    ap_req["ap-options"] = constants.encodeFlags(opts)
    seq_set(ap_req, "ticket", ticket.to_asn1)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = creds.domain
    username = Principal(
        creds.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )
    seq_set(authenticator, "cname", username.components_to_asn1)
    now = datetime.datetime.now(datetime.timezone.utc)
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    authenticator["cksum"] = noValue
    authenticator["cksum"]["cksumtype"] = 0x8003
    chk_field = CheckSumField()
    chk_field["Lgth"] = 16
    chk_field["Flags"] = (
        GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG | cksum_flags
    )
    if channel_binding_value:
        chk_field["Bnd"] = channel_binding_value
    authenticator["cksum"]["checksum"] = chk_field.getData()

    # Proposing a client subkey here (RFC 4120 §5.5.1's optional
    # Authenticator subkey field) determines the etype of the AP-REP's own
    # acceptor subkey, *and* — per RFC 4121 §2 — becomes the key used for
    # all further per-message protection whenever no AP-REP ever overrides
    # it (SPNEGO's single-round bind never gets one).  propose_subkey
    # selects the etype as a string keyed into _SUBKEY_SPECS above: "none"
    # omits the subkey entirely (DC picks from msDS-SupportedEncryptionTypes),
    # and the named etypes request a specific cipher.  The returned Key
    # object embeds both the etype and random key material so callers
    # (notably the SPNEGO path) can use it directly rather than guessing
    # the etype from the ticket cipher.
    subkey_spec = _SUBKEY_SPECS.get(propose_subkey)
    if subkey_spec is None:
        subkey_key = None
    else:
        subkey_keytype, subkey_length = subkey_spec
        subkey_bytes = os.urandom(subkey_length)
        subkey_key = Key(subkey_keytype, subkey_bytes)
        authenticator["subkey"] = noValue
        authenticator["subkey"]["keytype"] = subkey_keytype
        authenticator["subkey"]["keyvalue"] = subkey_bytes

    authenticator["seq-number"] = 0
    encoded_authenticator = encoder.encode(authenticator)

    # Key Usage 11: AP-REQ Authenticator, encrypted with the application
    # session key (RFC 4120 §5.5.1).
    encrypted_authenticator = cipher.encrypt(
        session_key, 11, encoded_authenticator, None
    )
    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = encrypted_authenticator
    return encoder.encode(ap_req), subkey_key


@dataclass
class KerberosLayerStrategy:
    """wire_seal chooses GSS_Wrap_LDAP (confidentiality) vs an unsealed
    RFC 4121 Wrap token (sign-only, no encryption) at actual message-wrap
    time - independent of what was negotiated in the AP-REQ checksum.

    Sign-only uses the same unsealed-Wrap-token format (TOK_ID 0x0504,
    Flags=0x04, no Sealed bit) as round 3's security-layer negotiation,
    NOT a separate MIC/GetMIC token."""

    name: str
    gss: object  # GSSAPI_RC4 | GSSAPI_AES, from impacket.krb5.gssapi's GSSAPI(cipher) factory
    session_key: object  # types.EncryptionKey
    wire_seal: bool
    is_rc4: bool = False
    send_seq: int = 0

    def wrap(self, plaintext: bytes) -> bytes:
        if self.wire_seal:
            cipher_text, token = self.gss.GSS_Wrap_LDAP(
                self.session_key, plaintext, self.send_seq
            )
            wrapped = token + cipher_text
        elif self.is_rc4:
            wrapped = build_rc4_unsealed_wrap_token(
                self.gss, self.session_key, plaintext, self.send_seq
            )
            # Per-message RC4-unsealed traffic is OID-wrapped in both
            # directions (unlike round 3's bare negotiation reply).
            header, data = MechIndepToken(wrapped).to_bytes()
            wrapped = header + data
        else:
            wrapped = build_unsealed_wrap_token(
                self.gss, self.session_key, plaintext, self.send_seq
            )
        self.send_seq += 1
        return wrapped

    def unwrap(self, wrapped: bytes) -> bytes:
        if self.wire_seal:
            plain, _ = self.gss.GSS_Unwrap_LDAP(
                self.session_key, wrapped, 0, direction="init"
            )
            return plain
        if self.is_rc4:
            # Per-message RC4-unsealed traffic is [APPLICATION 0]+OID wrapped.
            if wrapped[:1] == b"\x60":
                wrapped = MechIndepToken.from_bytes(wrapped).data
            return verify_rc4_unsealed_wrap_token(self.gss, self.session_key, wrapped)
        return verify_unsealed_wrap_token(self.gss, self.session_key, wrapped)


def build_kerberos_layer_strategy(
    layer: str, cipher, session_key, start_seq: int = 0
) -> KerberosLayerStrategy:
    # Built from session_key's own etype, not the ticket cipher's - they
    # can differ (e.g. the AP-REP acceptor subkey may have a different
    # etype than the ticket). Using the ticket cipher here would select
    # the wrong GSSAPI_* class.
    gss = GSSAPI(_enctype_table[session_key.enctype])
    return KerberosLayerStrategy(
        name=f"krb_{layer}",
        gss=gss,
        session_key=session_key,
        wire_seal=bool(LAYER_CKSUM_FLAGS[layer] & GSS_C_CONF_FLAG),
        is_rc4=session_key.enctype == constants.EncryptionTypes.rc4_hmac.value,
        send_seq=start_seq,
    )
