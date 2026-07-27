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
from typing import Optional

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
    "signonly": NTLMSSP_NEGOTIATE_SIGN
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_NEGOTIATE_KEY_EXCH,
    "sealonly": NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_NEGOTIATE_KEY_EXCH,
    "signseal": NTLMSSP_NEGOTIATE_SIGN
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_NEGOTIATE_SEAL
    | NTLMSSP_NEGOTIATE_KEY_EXCH,
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
        (
            version["ProductMajorVersion"],
            version["ProductMinorVersion"],
            version["ProductBuild"],
        ) = 10, 0, 19041
        auth["os_version"] = version
    auth.setWorkstation("")
    return auth


@dataclass
class NTLMLayerStrategy:
    """Post-bind LDAP message wrap/unwrap for a completed NTLM handshake.
    Four independent RC4 handles (client-send/client-recv share a key but
    are separate keystream positions).

    Two behaviours here are not what the spec describes, and both were
    established against a live DC:

    1. Outbound framing (`seal_out`). Defaults to exactly what
       NTLMSSP_NEGOTIATE_SEAL says, so a sign-only negotiation really does
       put a signed cleartext body on the wire, per MS-NLMP §3.4.3, and the
       layer names describe what they actually produce. Active Directory
       will not accept that: a SIGN-without-SEAL bind succeeds, but the DC
       then unseals every post-bind body regardless of the negotiated flags
       and answers a cleartext one with an unsolicited Notice of
       Disconnection before closing the connection.  
       --ntlm-always-seal seals the SIGN-only case too, making the NTLM signonly variant 
       equivalent to the signseal with respect to the post-bind wire format
       (varying only in the negotiation preamble).

    2. Inbound framing (`seal_in`). Detected from the response rather than
       configured, because the DC seals its replies either way - including
       its rejection of a cleartext request. See unwrap().

    Separately, SEAL-without-SIGN (`sasl_*_ntlm_sealonly`) uses a different
    keystream discipline - see `datagram`. A real Windows DC re-keys its RC4
    sealing per message with the connectionless formula
    MD5(SealingKey || le32(seqNum)), even over connection-oriented LDAP.
    MS-NLMP §3.4.3 documents that rekey for connectionless mode only;
    connection-oriented LDAP is supposed to use one continuous stream, and
    does for signonly/signseal. No Microsoft spec documents the exception."""

    name: str
    flags: int
    negotiated_seal: bool  # NTLMSSP_NEGOTIATE_SEAL bit, as actually negotiated
    seal_out: bool  # whether what we send is encrypted
    datagram: bool  # per-message MD5(SealKey||seq) rekey (SEAL without SIGN); else continuous RC4
    client_sign_key: bytes
    client_seal_key: bytes  # base sealing key, client->server
    server_sign_key: bytes
    server_seal_key: bytes  # base sealing key, server->client
    client_seal_handle: (
        object  # continuous ARC4 encrypt method (unused in datagram mode)
    )
    server_seal_handle: object
    send_seq: int = 0
    recv_seq: int = 0
    # Latched on the first response: whether the peer seals what it sends.
    # None until then. See unwrap() for why this is detected, and why it is
    # decided once rather than per message.
    seal_in: Optional[bool] = None

    def _handle(self, base_key: bytes, seq: int, continuous):
        # Datagram mode: fresh RC4 keyed by MD5(SealingKey || le32(seq)) per
        # message. Connection-oriented: the persistent continuous handle.
        if self.datagram:
            rk = hashlib.md5(base_key + struct.pack("<I", seq)).digest()
            return ARC4.new(rk).encrypt
        return continuous

    def wrap(self, plaintext: bytes) -> bytes:
        handle = self._handle(
            self.client_seal_key, self.send_seq, self.client_seal_handle
        )
        if self.seal_out:
            # SEAL's sealingKey parameter is accepted but unused by impacket's
            # own implementation - encryption comes entirely from `handle` -
            # so the signing key is passed for both positions.
            sealed, sig = SEAL(
                self.flags,
                self.client_sign_key,
                self.client_sign_key,
                plaintext,
                plaintext,
                self.send_seq,
                handle,
            )
        else:
            sig = SIGN(
                self.flags, self.client_sign_key, plaintext, self.send_seq, handle
            )
            sealed = plaintext
        self.send_seq += 1
        return sig.getData() + sealed

    def unwrap(self, wrapped: bytes) -> bytes:
        # NTLM's native wrapped-message framing: 16-byte
        # NTLMSSP_MESSAGE_SIGNATURE first, then the (possibly sealed)
        # payload - the opposite order from RFC 4752's GSS_Wrap convention,
        # which puts the trailing MIC after the payload.
        signature, payload = wrapped[:16], wrapped[16:]
        handle = self._handle(
            self.server_seal_key, self.recv_seq, self.server_seal_handle
        )
        # Inbound framing is detected, not assumed: the DC seals its replies
        # whenever any security layer is active, even when it agreed to
        # SIGN-without-SEAL and even when what we sent was cleartext. Reading
        # it off the wire keeps sign-only usable in both directions and lets
        # the DC's own error reach the caller instead of arriving as noise.
        #
        # Decided once and latched, because guessing wrong costs the whole
        # connection: a body we decline to decrypt leaves the RC4 handle
        # len(payload) bytes behind where the sender left it, and every later
        # message decrypts to garbage. The framing cannot change mid-session,
        # so one strong check beats re-guessing per message.
        if self.seal_in is None:
            self.seal_in = not _looks_like_cleartext_ldap(payload)
        if self.seal_in:
            plain = handle(payload)  # RC4 is symmetric: same handle decrypts
        else:
            plain = payload
        # MS-NLMP §3.4.4: MAC() always runs its 8-byte checksum through the
        # same RC4 handle, whether or not the body itself was sealed - the
        # sender did (impacket's SEAL()/SIGN() both consume it), so a receiver
        # that skips it leaves this handle 8 bytes behind the sender's for
        # every message. With a single wrapped message per connection that
        # never surfaces; the moment a second one arrives - a DC bundling
        # results across frames, say - it decrypts to garbage. Consumed
        # here rather than verified, keeping signature
        # checking out of scope while still tracking the keystream correctly.
        handle(b"\x00" * 8)
        del signature  # signature verification is out of scope for this tester
        self.recv_seq += 1
        return plain


def _looks_like_cleartext_ldap(payload: bytes) -> bool:
    """Whether payload is an unencrypted LDAPMessage rather than ciphertext.

    Checking only for a leading 0x30 would misfire on roughly 1 in 256 sealed
    bodies, and a single misfire desynchronises the RC4 stream for the rest of
    the connection. So the BER length header is decoded as well and required
    to account for the payload exactly (a single message) or to fit inside it
    (a bundle) - which random ciphertext will essentially never satisfy.
    """
    if len(payload) < 2 or payload[0] != 0x30:
        return False
    n = payload[1]
    if n < 0x80:  # short form
        total, body_len = 2, n
    else:  # long form: low 7 bits give the number of length octets
        count = n & 0x7F
        if count == 0 or count > 4 or len(payload) < 2 + count:
            return False
        total, body_len = 2 + count, int.from_bytes(payload[2 : 2 + count], "big")
    return total + body_len <= len(payload)


def build_ntlm_layer_strategy(
    layer: str,
    flags: int,
    exported_session_key: bytes,
    gss_wrapped: bool = False,
    always_seal: bool = False,
) -> NTLMLayerStrategy:
    client_sign_key = SIGNKEY(flags, exported_session_key, mode="Client")
    server_sign_key = SIGNKEY(flags, exported_session_key, mode="Server")
    client_seal_key = SEALKEY(flags, exported_session_key, mode="Client")
    server_seal_key = SEALKEY(flags, exported_session_key, mode="Server")
    # Datagram per-message rekey applies only to GSS-wrapped NTLM (GSSAPI /
    # GSS-SPNEGO) sealed without signing - raw Sicily/SASL NTLM keeps the
    # continuous stream for the same flags (see NTLMLayerStrategy).
    datagram = (
        gss_wrapped
        and bool(flags & NTLMSSP_NEGOTIATE_SEAL)
        and not (flags & NTLMSSP_NEGOTIATE_SIGN)
    )
    return NTLMLayerStrategy(
        name=f"ntlm_{layer}",
        flags=flags,
        negotiated_seal=bool(flags & NTLMSSP_NEGOTIATE_SEAL),
        # Honest by default: encrypt only what SEAL was negotiated for. With
        # --ntlm-always-seal, a SIGN-only negotiation seals too, which is what
        # Active Directory requires (see the class docstring).
        seal_out=bool(
            flags
            & (
                (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL)
                if always_seal
                else NTLMSSP_NEGOTIATE_SEAL
            )
        ),
        datagram=datagram,
        client_sign_key=client_sign_key,
        client_seal_key=client_seal_key,
        server_sign_key=server_sign_key,
        server_seal_key=server_seal_key,
        client_seal_handle=ARC4.new(client_seal_key).encrypt,
        server_seal_handle=ARC4.new(server_seal_key).encrypt,
    )


def complete_ntlm_handshake(
    type1: NTLMAuthNegotiate,
    type2_bytes: bytes,
    creds,
    layer: str,
    gss_wrapped: bool = False,
    channel_binding_value: bytes = b"",
):
    """Runs Type3 construction (reusing impacket's getNTLMSSPType3 as-is -
    it already correctly derives responseFlags as the intersection of what
    Type1 asked for and what the server's Type2 challenge actually granted)
    and builds the matching NTLMLayerStrategy. Returns (type3, strategy,
    exported_session_key) - the session key is exposed separately for
    callers (SPNEGO's mechListMIC) that need one throwaway signature over
    a different value before any real post-bind traffic exists, so they
    can use their own fresh cipher handle rather than pre-consuming
    strategy's keystream position."""
    version = (
        type1["os_version"] if type1["flags"] & NTLMSSP_NEGOTIATE_VERSION else None
    )
    # impacket's NTOWFv2 checks `if hash != ''` to decide whether a hash was
    # explicitly provided — if not, it computes the NTLM hash from the password.
    # Our Credentials stores hashes as `bytes`, so b"" (empty, no hashes) is the
    # default.  But in Python 3, b"" != '' is True (different types, never equal),
    # so impacket would treat an empty-bytes nthash as "hash IS provided" and use
    # a zero-length HMAC key, producing a garbage response that the DC rejects
    # with data 52e (STATUS_LOGON_FAILURE).  Converting to "" when the hashes are
    # falsy gives impacket the sentinel it expects.
    lmhash = creds.lmhash if creds.lmhash else ""
    nthash = creds.nthash if creds.nthash else ""
    type3, exported_session_key = getNTLMSSPType3(
        type1,
        type2_bytes,
        creds.username,
        creds.password,
        creds.domain,
        lmhash,
        nthash,
        service="ldap",
        version=version,
        # impacket places this in the MsvAvChannelBindings AV_PAIR
        # (NTLMSSP_AV_CHANNEL_BINDINGS, 0x0a) and recomputes NTProofStr over
        # the modified TargetInfo, so passing it here is all that is needed.
        channel_binding_value=channel_binding_value,
    )
    strategy = build_ntlm_layer_strategy(
        layer,
        type3["flags"],
        exported_session_key,
        gss_wrapped=gss_wrapped,
        always_seal=creds.ntlm_always_seal,
    )
    return type3, strategy, exported_session_key
