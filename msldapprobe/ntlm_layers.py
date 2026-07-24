"""NTLM Type1/Type3 construction with full sign/seal flag control, and the
post-bind wrap/unwrap LayerStrategy shared by every NTLM-carrying mechanism
family (sicily_ntlm_*, sasl_gssapi_ntlm_*, sasl_spnego_ntlm_*) - per-message
NTLM signing/sealing is identical regardless of which handshake carried it.

impacket's own getNTLMSSPType1(signingRequired=bool) only ever bundles
NTLMSSP_NEGOTIATE_SIGN and NTLMSSP_NEGOTIATE_SEAL together (confirmed by
reading its source) - build_type1 here replicates it with an explicit
4-way layer choice instead.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from Cryptodome.Cipher import ARC4
from impacket.ntlm import (
    NTLMAuthNegotiate,
    NTLMSSP_NEGOTIATE_128,
    NTLMSSP_NEGOTIATE_56,
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
    NTLMSSP_NEGOTIATE_KEY_EXCH,
    NTLMSSP_NEGOTIATE_NTLM,
    NTLMSSP_NEGOTIATE_SEAL,
    NTLMSSP_NEGOTIATE_SIGN,
    NTLMSSP_NEGOTIATE_TARGET_INFO,
    NTLMSSP_NEGOTIATE_UNICODE,
    NTLMSSP_NEGOTIATE_VERSION,
    NTLMSSP_REQUEST_TARGET,
    SEAL,
    SEALKEY,
    SIGN,
    SIGNKEY,
    VERSION,
    getNTLMSSPType3,
)

NTLM_BASE_FLAGS = (
    NTLMSSP_NEGOTIATE_NTLM
    | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NTLMSSP_NEGOTIATE_UNICODE
    | NTLMSSP_REQUEST_TARGET
    | NTLMSSP_NEGOTIATE_128
    | NTLMSSP_NEGOTIATE_56
    | NTLMSSP_NEGOTIATE_TARGET_INFO
)

# Layer -> extra Type1 flags beyond NTLM_BASE_FLAGS. sealonly deliberately
# requests confidentiality without integrity (SEAL but not SIGN/ALWAYS_SIGN)
# - not how a real Windows client negotiates, but a legitimate edge case for
# checking how strictly a target enforces flag consistency.
LAYER_FLAGS = {
    "plain": 0,
    "signonly": NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_KEY_EXCH,
    "sealonly": NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_NEGOTIATE_KEY_EXCH,
    "signseal": NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_NEGOTIATE_KEY_EXCH,
}


def build_type1(domain: str, layer: str, with_mic: bool = False) -> NTLMAuthNegotiate:
    """with_mic must be True for any caller that will set type3['MIC']
    afterward (sasl_spnego_ntlm_*, sasl_gssapi_ntlm_*): impacket's
    NTLMAuthChallengeResponse.checkMIC only reserves the MIC field's 16
    bytes in its offset layout when NTLMSSP_NEGOTIATE_VERSION is set on the
    message's own flags (confirmed by reading its source) - setting
    type3['MIC'] without this flag silently produces a structurally
    misaligned message the DC rejects with AcceptSecurityContext error
    "data 57" (ERROR_INVALID_PARAMETER), not a credentials problem. Sicily
    never sets a MIC, so its own build_type1 call leaves this off."""
    auth = NTLMAuthNegotiate()
    auth["flags"] = NTLM_BASE_FLAGS | LAYER_FLAGS[layer]
    if with_mic:
        auth["flags"] |= NTLMSSP_NEGOTIATE_VERSION
        version = VERSION()
        version["ProductMajorVersion"], version["ProductMinorVersion"], version["ProductBuild"] = 10, 0, 19041
        auth["os_version"] = version
    auth.setWorkstation("")
    return auth


@dataclass
class NTLMLayerStrategy:
    """Post-bind LDAP message wrap/unwrap for a completed NTLM handshake.
    Four independent RC4 handles (client-send/client-recv share a key but
    are separate keystream positions - same reasoning as ldapx's own Go
    NTLMDirectionCipher: unwrapping and re-sealing are each their own RC4
    stream advance even when both use the same key).

    wire_seal (whether the actual wire framing encrypts, not just signs) is
    deliberately NOT the same thing as whether NTLMSSP_NEGOTIATE_SEAL was
    negotiated: confirmed empirically against a real DC that its LDAP/NTLM
    implementation always uses the sealed wire format once ANY session
    security (sign or seal) is active - "sign but don't encrypt" is a real,
    independent NTLM flag combination, but not one AD's LDAP layer actually
    honors distinctly at the framing level. negotiated_seal is kept
    separately for accurate reporting of what was actually asked for in the
    handshake.

    SEAL-without-SIGN (sasl_*_ntlm_sealonly) uses a different keystream
    discipline (see `datagram`). Cracked from a live DC capture: a real
    Windows DC re-keys its RC4 sealing per message with the connectionless
    formula MD5(SealingKey || le32(seqNum)) - even over connection-oriented
    LDAP - specifically when SEAL is negotiated without SIGN. MS-NLMP §3.4.3
    documents that rekey for connectionless mode only; connection-oriented
    LDAP is supposed to use a single continuous RC4 stream (and does for
    signonly/signseal), but in reality Windows does not for the sealed-only
    case, which no Microsoft spec documents. Without matching it the DC can't
    decrypt our continuously-sealed request and replies with an unsolicited
    "Error decrypting ldap message"."""

    name: str
    flags: int
    negotiated_seal: bool  # NTLMSSP_NEGOTIATE_SEAL bit, as actually negotiated
    wire_seal: bool  # whether wrap/unwrap actually encrypt on the wire
    datagram: bool  # per-message MD5(SealKey||seq) rekey (SEAL without SIGN); else continuous RC4
    client_sign_key: bytes
    client_seal_key: bytes  # base sealing key, client->server
    server_sign_key: bytes
    server_seal_key: bytes  # base sealing key, server->client
    client_seal_handle: object  # continuous ARC4 encrypt method (unused in datagram mode)
    server_seal_handle: object
    send_seq: int = 0
    recv_seq: int = 0

    def _handle(self, base_key: bytes, seq: int, continuous):
        # Datagram mode: fresh RC4 keyed by MD5(SealingKey || le32(seq)) per
        # message. Connection-oriented: the persistent continuous handle.
        if self.datagram:
            rk = hashlib.md5(base_key + struct.pack("<I", seq)).digest()
            return ARC4.new(rk).encrypt
        return continuous

    def wrap(self, plaintext: bytes) -> bytes:
        handle = self._handle(self.client_seal_key, self.send_seq, self.client_seal_handle)
        if self.wire_seal:
            # SEAL's sealingKey parameter is accepted but unused by impacket's
            # own implementation - encryption comes entirely from `handle` -
            # so the signing key is passed for both positions.
            sealed, sig = SEAL(self.flags, self.client_sign_key, self.client_sign_key, plaintext, plaintext,
                                self.send_seq, handle)
        else:
            sig = SIGN(self.flags, self.client_sign_key, plaintext, self.send_seq, handle)
            sealed = plaintext
        self.send_seq += 1
        return sig.getData() + sealed

    def unwrap(self, wrapped: bytes) -> bytes:
        # NTLM's native wrapped-message framing: 16-byte
        # NTLMSSP_MESSAGE_SIGNATURE first, then the (possibly sealed)
        # payload - same order ldapx's own Go code assumes.
        signature, payload = wrapped[:16], wrapped[16:]
        handle = self._handle(self.server_seal_key, self.recv_seq, self.server_seal_handle)
        if self.wire_seal:
            plain = handle(payload)  # RC4 is symmetric: same handle decrypts
        else:
            plain = payload
        del signature  # verification is best-effort/out of scope for this tester
        self.recv_seq += 1
        return plain


def build_ntlm_layer_strategy(layer: str, flags: int, exported_session_key: bytes,
                              gss_wrapped: bool = False) -> NTLMLayerStrategy:
    client_sign_key = SIGNKEY(flags, exported_session_key, mode="Client")
    server_sign_key = SIGNKEY(flags, exported_session_key, mode="Server")
    client_seal_key = SEALKEY(flags, exported_session_key, mode="Client")
    server_seal_key = SEALKEY(flags, exported_session_key, mode="Server")
    # Datagram per-message rekey applies only to GSS-wrapped NTLM (GSSAPI /
    # GSS-SPNEGO) sealed without signing - raw Sicily/SASL NTLM keeps the
    # continuous stream for the same flags (see NTLMLayerStrategy).
    datagram = gss_wrapped and bool(flags & NTLMSSP_NEGOTIATE_SEAL) and not (flags & NTLMSSP_NEGOTIATE_SIGN)
    return NTLMLayerStrategy(
        name=f"ntlm_{layer}",
        flags=flags,
        negotiated_seal=bool(flags & NTLMSSP_NEGOTIATE_SEAL),
        wire_seal=bool(flags & (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL)),
        datagram=datagram,
        client_sign_key=client_sign_key,
        client_seal_key=client_seal_key,
        server_sign_key=server_sign_key,
        server_seal_key=server_seal_key,
        client_seal_handle=ARC4.new(client_seal_key).encrypt,
        server_seal_handle=ARC4.new(server_seal_key).encrypt,
    )


def complete_ntlm_handshake(type1: NTLMAuthNegotiate, type2_bytes: bytes, creds, layer: str,
                            gss_wrapped: bool = False):
    """Runs Type3 construction (reusing impacket's getNTLMSSPType3 as-is -
    it already correctly derives responseFlags as the intersection of what
    Type1 asked for and what the server's Type2 challenge actually granted)
    and builds the matching NTLMLayerStrategy. Returns (type3, strategy,
    exported_session_key) - the session key is exposed separately for
    callers (SPNEGO's mechListMIC) that need one throwaway signature over
    a different value before any real post-bind traffic exists, so they
    can use their own fresh cipher handle rather than pre-consuming
    strategy's keystream position."""
    version = type1["os_version"] if type1["flags"] & NTLMSSP_NEGOTIATE_VERSION else None
    type3, exported_session_key = getNTLMSSPType3(
        type1, type2_bytes, creds.username, creds.password, creds.domain,
        creds.lmhash, creds.nthash, service="ldap", version=version,
    )
    strategy = build_ntlm_layer_strategy(layer, type3["flags"], exported_session_key, gss_wrapped=gss_wrapped)
    return type3, strategy, exported_session_key
