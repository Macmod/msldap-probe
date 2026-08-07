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
    AV_PAIRS,
    NTLMAuthChallenge,
    NTLMAuthNegotiate,
    NTLMSSP_NEGOTIATE_128,
    NTLMSSP_NEGOTIATE_56,
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    NTLMSSP_NEGOTIATE_DATAGRAM,
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
    NTLMSSP_NEGOTIATE_KEY_EXCH,
    NTLMSSP_NEGOTIATE_LM_KEY,
    NTLMSSP_NEGOTIATE_NTLM,
    NTLMSSP_NEGOTIATE_SEAL,
    NTLMSSP_NEGOTIATE_SIGN,
    NTLMSSP_NEGOTIATE_TARGET_INFO,
    NTLMSSP_NEGOTIATE_UNICODE,
    NTLMSSP_NEGOTIATE_VERSION,
    NTLMSSP_REQUEST_NON_NT_SESSION_KEY,
    NTLMSSP_REQUEST_TARGET,
    MAC,
    SEALKEY,
    SIGNKEY,
    VERSION,
    getNTLMSSPType3,
    hmac_md5,
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
#
# plain carries NTLMSSP_NEGOTIATE_ALWAYS_SIGN, which requests a signature
# block without negotiating session security (MS-NLMP §2.2.2.5); a Windows
# client sets it in every NEGOTIATE_MESSAGE. Neither SIGN nor SEAL is set, so
# no security layer becomes active and the connection stays in the clear.
# Active Directory does not validate a declared AUTHENTICATE_MESSAGE MIC
# unless it is negotiated.
LAYER_FLAGS = {
    "plain": NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    "signonly": NTLMSSP_NEGOTIATE_SIGN
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_NEGOTIATE_KEY_EXCH,
    "sealonly": NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_NEGOTIATE_KEY_EXCH,
    "signseal": NTLMSSP_NEGOTIATE_SIGN
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_NEGOTIATE_SEAL
    | NTLMSSP_NEGOTIATE_KEY_EXCH,
}




def kxkey_branch(challenge_flags: int, ntlmv1: bool) -> str:
    """Which KXKEY branch (MS-NLMP §3.4.5.1) the challenge's flags select.

    The branch follows the flags the *server* returned rather than the ones
    the Type 1 asked for, so this reports what was granted. Mirrors
    impacket's own condition order in KXKEY.
    """
    if not ntlmv1:
        return "v2"
    if challenge_flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
        return "ess"
    if challenge_flags & NTLMSSP_NEGOTIATE_LM_KEY:
        return "lm"
    if challenge_flags & NTLMSSP_REQUEST_NON_NT_SESSION_KEY:
        return "nonnt"
    return "nt"


def build_type1(creds, layer: str) -> NTLMAuthNegotiate:
    """NTLMSSP_NEGOTIATE_VERSION governs the MIC field as well as the Version
    field. Neither has a presence flag of its own: MS-NLMP §2.2.1.3 lays the
    AUTHENTICATE_MESSAGE out as a fixed 64-byte header, then Version, then
    MIC, then the payload, so a receiver takes both to be present exactly when
    that flag is set. The two therefore have to be emitted or omitted
    together - a message carrying one without the other places its payload
    where the receiver does not expect it. Suppressing the flag means
    clearing os_version as well, since NTLMAuthNegotiate.getData() re-sets it
    whenever that field is populated."""
    flags = NTLM_BASE_FLAGS | LAYER_FLAGS[layer]
    if creds.mic != "drop":
        flags |= NTLMSSP_NEGOTIATE_VERSION
    if creds.ntlmv1 and creds.no_ess:
        # The legacy signing and sealing regime applies only where extended
        # session security is absent, so reaching it means not negotiating it.
        flags &= ~NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY

    auth = NTLMAuthNegotiate()
    auth["flags"] = flags
    if creds.mic == "drop":
        auth["os_version"] = b""
    else:
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
    keystream discipline - see `datagram`. A real Windows DC reinitialises
    its RC4 sealing per message there, as MS-NLMP §3.4.3 has it for
    connectionless mode, even over connection-oriented LDAP; the same flags
    over signonly/signseal keep the one continuous stream that
    connection-oriented LDAP calls for. No Microsoft spec documents the
    exception.

    What the reinitialisation does then depends on extended session
    security:

    - with it, the key is re-derived per message as
      MD5(SealingKey || le32(seqNum)), and the signature continues the same
      handle the body was sealed from;
    - without it, measured only, the key stays the SealingKey and the
      signature gets a handle of its own, so body and signature each start
      that keystream from offset zero.

    The second has no specification behind it in either direction: §3.4.3
    states that message confidentiality exists in connectionless mode only
    when extended session security is configured, so it describes no non-ESS
    form of any of this. Nor is the result something to rely on - one key,
    restarted per message, means every message reuses one keystream."""

    name: str
    flags: int
    negotiated_seal: bool  # NTLMSSP_NEGOTIATE_SEAL bit, as actually negotiated
    seal_out: bool  # whether what we send is encrypted
    datagram: bool  # per-message RC4 reinitialisation (SEAL without SIGN); else continuous RC4
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
    # Which KXKEY branch the server's flags selected, for reporting.
    # See kxkey_branch().
    kxkey: str = ""

    def _shares_sequence(self) -> bool:
        """Whether one sequence number serves both directions.

        MS-NLMP §3.4 gives a session without extended session security a
        single sealing key used half-duplex, and the sequence number goes with
        it: Samba's legacy path keeps one seq_num alongside the one seal state
        for both directions (auth/ntlmssp/ntlmssp_sign.c), so a reply advances
        the number the next request carries. Extended session security numbers
        each direction separately, and datagram mode numbers per message.
        """
        return not (
            self.flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        ) and not self.datagram

    def _handle(self, base_key: bytes, seq: int, continuous):
        # Datagram mode reinitialises the RC4 handle for every message;
        # connection-oriented keeps the persistent continuous one.
        #
        # The per-message MD5(SealingKey || le32(seq)) rekey is applied only
        # under extended session security. MS-NLMP specifies no rekey for the
        # other case: §3.4.3 states that message confidentiality exists in
        # connectionless mode only when extended session security is
        # configured, so it defines no non-ESS behaviour here to follow.
        # What a Windows DC does instead, measured, is reinitialise from the
        # sealing key unchanged, leaving every message restarting the same
        # keystream at offset zero - which is presumably why the
        # specification declines to offer the combination.
        if self.datagram:
            key = base_key
            if self.flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                key = hashlib.md5(key + struct.pack("<I", seq)).digest()
            return ARC4.new(key).encrypt
        return continuous

    def wrap(self, plaintext: bytes) -> bytes:
        handle = self._handle(
            self.client_seal_key, self.send_seq, self.client_seal_handle
        )
        sealed = handle(plaintext) if self.seal_out else plaintext
        # MS-NLMP §3.4.2 and §3.4.3 both hand MAC() the same Handle the body
        # was sealed from, so the signature continues that one keystream.
        # Datagram mode without extended session security is the exception: a
        # Windows DC reinitialises there, masking the signature from offset
        # zero of a handle of its own, and rejects a message signed off the
        # continuing keystream with "Error decrypting ldap message".
        mac_handle = handle
        if self.datagram and not (
            self.flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        ):
            mac_handle = self._handle(
                self.client_seal_key, self.send_seq, self.client_seal_handle
            )
        sig = MAC(
            self.flags,
            mac_handle,
            self.client_sign_key,
            self.send_seq,
            plaintext,
        )
        self.send_seq += 1
        if self._shares_sequence():
            self.recv_seq = self.send_seq
        return sig.getData() + sealed

    def unwrap(self, wrapped: bytes) -> bytes:
        # NTLM's native wrapped-message framing: 16-byte
        # NTLMSSP_MESSAGE_SIGNATURE first, then the (possibly sealed)
        # payload - the opposite order from RFC 4752's GSS_Wrap convention,
        # which puts the trailing MIC after the payload.
        signature, payload = wrapped[:16], wrapped[16:]
        # Datagram mode keys each message independently off a sequence
        # number, so the receiver has to use the one the *sender* used
        # rather than its own count of messages seen. MS-NLMP §3.4.4 puts
        # that number in the signature's last 4 bytes (Version(4) ||
        # Checksum(8) || SeqNum(4)) precisely so it need not be inferred,
        # and a Windows DC does not increment it for its own replies here:
        # it stays at 0 while a local counter climbs, so every message
        # after the first decrypts under the wrong key.
        #
        # That reading applies to the extended-session-security signature,
        # which carries the number in the clear. The legacy signature
        # (§3.4.4.1) masks the same field with the sealing keystream, and no
        # number is needed there because the handle does not derive from one.
        if self.datagram and self.flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            self.recv_seq = struct.unpack("<I", signature[12:16])[0]
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
        # MS-NLMP §3.4.4: MAC() runs part of the signature through the same
        # RC4 handle, whether or not the body itself was sealed, so a
        # receiver that skips it falls behind the sender's keystream by that
        # much on every message. With a single wrapped message per
        # connection that never surfaces; the moment a second one arrives -
        # a DC bundling results across frames, say - it decrypts to garbage.
        #
        # How much differs by regime. With extended session security
        # (§3.4.4.1) it is the 8-byte HMAC checksum. Without it (§3.4.4.2)
        # the signature is RandomPad, Checksum and SeqNum, each 4 bytes and
        # each passed through the handle, for 12. Consumed rather than
        # verified, keeping signature checking out of scope while still
        # tracking the keystream correctly.
        if self.flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            handle(b"\x00" * 8)
        else:
            handle(b"\x00" * 12)
        del signature  # signature verification is out of scope for this tester
        self.recv_seq += 1
        if self._shares_sequence():
            self.send_seq = self.recv_seq
        return plain


def _looks_like_cleartext_ldap(payload: bytes) -> bool:
    """Whether payload is an unencrypted LDAPMessage rather than ciphertext.

    A sealed body is indistinguishable from random bytes, so the answer has to
    come from structure alone, and one wrong answer desynchronises the RC4
    stream for the rest of the connection. Three things are therefore required
    together, each cutting the odds of a sealed body passing by chance:

    - the universal SEQUENCE tag every LDAPMessage opens with;
    - a BER length accounting for the payload exactly (a single message) or
      fitting inside it (a bundle);
    - the messageID that RFC 4511 §4.1.1 places first inside that SEQUENCE,
      which narrows the byte after the header to a single tag value.
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
    if total + body_len > len(payload):
        return False
    # messageID is a universal INTEGER, and RFC 4511 §4.1.1 bounds it by maxInt
    # (2^31 - 1), so its contents occupy five octets at most - four, plus a
    # possible leading zero keeping the sign bit clear.
    if len(payload) < total + 2 or payload[total] != 0x02:
        return False
    id_len = payload[total + 1]
    return 1 <= id_len <= 5 and 2 + id_len <= body_len


def _legacy_seal_key(flags: int, exported_session_key: bytes) -> bytes:
    """SEALKEY's branches for when extended session security is absent
    (MS-NLMP §3.4.5.3).

    The truncation to 56 or 40 bits applies only when NTLMSSP_NEGOTIATE_LM_KEY
    or NTLMSSP_NEGOTIATE_DATAGRAM is set; otherwise the sealing key is the
    ExportedSessionKey unchanged. impacket's SEALKEY truncates whenever
    extended session security is absent, which yields a key a DC does not
    agree with for a plain NTLMv1 bind, so this is computed here instead of
    calling it.

    The specification additionally conditions the DATAGRAM case on
    NTLMRevisionCurrent >= NTLMSSP_REVISION_W2K3; that is not checked here,
    since nothing in this tool negotiates datagram mode.
    """
    if flags & (NTLMSSP_NEGOTIATE_LM_KEY | NTLMSSP_NEGOTIATE_DATAGRAM):
        if flags & NTLMSSP_NEGOTIATE_56:
            return exported_session_key[:7] + b"\xa0"
        return exported_session_key[:5] + b"\xe5\x38\xb0"
    return exported_session_key


def seal_key(flags: int, exported_session_key: bytes, mode: str) -> bytes:
    """The sealing key for one direction, by regime. Extended session
    security derives a distinct key per direction; without it there is a
    single key shared by both (MS-NLMP §3.4)."""
    if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
        return SEALKEY(flags, exported_session_key, mode=mode)
    return _legacy_seal_key(flags, exported_session_key)


def build_ntlm_layer_strategy(
    layer: str,
    flags: int,
    exported_session_key: bytes,
    gss_wrapped: bool = False,
    always_seal: bool = False,
) -> NTLMLayerStrategy:
    client_sign_key = SIGNKEY(flags, exported_session_key, mode="Client")
    server_sign_key = SIGNKEY(flags, exported_session_key, mode="Server")
    client_seal_key = seal_key(flags, exported_session_key, "Client")
    server_seal_key = seal_key(flags, exported_session_key, "Server")

    # MS-NLMP §3.4: without NTLM v2 "only one key is used for sealing. As a
    # result, operations are performed in a half-duplex mode" - one RC4
    # stream carries both directions, advancing across the alternating
    # request and response. Extended session security has a key per
    # direction and so a stream per direction.
    if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
        client_seal_handle = ARC4.new(client_seal_key).encrypt
        server_seal_handle = ARC4.new(server_seal_key).encrypt
    else:
        client_seal_handle = server_seal_handle = ARC4.new(client_seal_key).encrypt
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
        client_seal_handle=client_seal_handle,
        server_seal_handle=server_seal_handle,
    )


# MsvAvFlags (MS-NLMP §2.2.2.1) and the bit within it by which a client
# declares it "is providing message integrity in the MIC field".
NTLMSSP_AV_FLAGS = 0x0006
MSV_AV_FLAG_MIC = 0x00000002


def declare_mic_in_challenge(type2_bytes: bytes) -> bytes:
    """Returns the CHALLENGE_MESSAGE with MsvAvFlags bit 0x2 set in its
    TargetInfo, so that the client's own NTLMv2 blob ends up carrying that
    declaration.

    MS-NLMP §3.1.5.1.2 requires a client supplying a MIC to say so through
    that bit, and the blob's AV_PAIR list is where the statement lives.
    Because the list is covered by NTProofStr, the pair has to be present
    before the response is computed rather than added afterwards - and
    impacket's getNTLMSSPType3 offers no hook for that, seeding its AV_PAIRS
    from the challenge it is handed. Setting it here therefore reaches the
    same wire bytes a client produces by adding the pair itself.

    Only the copy fed to response construction is modified. The MIC is
    computed over the messages as they were exchanged, so callers must keep
    hashing the challenge the server actually sent.
    """
    challenge = NTLMAuthChallenge(type2_bytes)
    av_pairs = AV_PAIRS(challenge["TargetInfoFields"])

    existing = av_pairs[NTLMSSP_AV_FLAGS]
    value = struct.unpack("<I", existing[1])[0] if existing is not None else 0
    av_pairs[NTLMSSP_AV_FLAGS] = struct.pack("<I", value | MSV_AV_FLAG_MIC)

    target_info = av_pairs.getData()
    challenge["TargetInfoFields"] = target_info
    challenge["TargetInfoFields_len"] = len(target_info)
    challenge["TargetInfoFields_max_len"] = len(target_info)
    return challenge.getData()


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
    # --announce-mic only alters the challenge handed to response construction,
    # so that the declaration lands inside the blob NTProofStr covers. The
    # caller still hashes the challenge as received when it computes the MIC.
    challenge_for_response = (
        declare_mic_in_challenge(type2_bytes)
        if creds.announce_mic
        else type2_bytes
    )
    type3, exported_session_key = getNTLMSSPType3(
        type1,
        challenge_for_response,
        creds.username,
        creds.password,
        creds.domain,
        lmhash,
        nthash,
        service="ldap",
        version=version,
        use_ntlmv2=not creds.ntlmv1,
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
    # Recorded from the challenge, which is what impacket's KXKEY consults -
    # what the Type 1 requested may not be what the server granted.
    strategy.kxkey = kxkey_branch(
        NTLMAuthChallenge(type2_bytes)["flags"], creds.ntlmv1
    )
    return type3, strategy, exported_session_key


def finalize_type3(
    type3,
    type1: NTLMAuthNegotiate,
    type2_bytes: bytes,
    exported_session_key: bytes,
    creds,
) -> bytes:
    """Returns the AUTHENTICATE_MESSAGE bytes to put on the wire, carrying the
    MIC that creds.mic selects.

    MS-NLMP §3.1.5.1.2 computes the MIC over the concatenated three messages
    with the field itself zeroed, since the message being hashed is the one
    that will carry the result.

    Dropping it needs nothing structural here beyond leaving the field unset:
    the Type 1 then carried no NTLMSSP_NEGOTIATE_VERSION, so impacket reserves
    no space for either Version or MIC and the payload starts at offset 64.
    """
    if creds.mic == "drop":
        return type3.getData()
    type3["MIC"] = b"\x00" * 16
    if creds.mic == "empty":
        return type3.getData()
    type3["MIC"] = hmac_md5(
        exported_session_key,
        type1.getData() + NTLMAuthChallenge(type2_bytes).getData() + type3.getData(),
    )
    return type3.getData()
