<p align="center">
  <h1 align="center"><b>msldap-probe</b></h1>
  <p align="center"><i>Probe all authentication methods against MSLDAP services for troubleshooting/research/study purposes.</i></p>
  <p align="center">
    <img src="https://img.shields.io/github/languages/code-size/Macmod/msldap-probe" alt="">
    <img src="https://img.shields.io/github/license/Macmod/msldap-probe" alt="">
    <a href="https://twitter.com/MacmodSec"><img src="https://img.shields.io/twitter/follow/MacmodSec?style=for-the-badge&logo=X&color=blue" alt="Twitter Follow"></a>
  </p>
</p>

LDAP/AD authentication-method matrix tester.

Tests every requested combination of LDAP bind mechanism and security layer against a target, verifies each one with a real post-bind operation (a rootDSE `namingContexts` search), and reports PASS / PARTIAL / FAIL per method.

<img width="1282" height="585" alt="image" src="https://github.com/user-attachments/assets/50f4c469-ac9c-44dd-be2d-75797188bc5b" />

- **PASS**: bind succeeded and a post-bind rootDSE search returned `namingContexts`.
- **PARTIAL**: bind succeeded, but the post-bind search failed.
- **FAIL**: bind or post-bind search failed.
- **SKIP**: method was not run because required credentials were missing.

## Purpose

Use this tool to enumerate which LDAP authentication methods and signing/sealing layers a domain controller actually accepts and supports end-to-end. It is useful for checking protocol compatibility, verifying hardening, or comparing behavior across DC versions.

## Supported methods

Methods are registered in `msldapprobe/methods.py` and grouped by mechanism family:

| Family | Names |
|--------|-------|
| Simple (anonymous) / Simple (with creds) / No bind | `anonymous_bind`, `simple_bind`, `no_bind` |
| Sicily (NTLM) | `sicily_ntlm_plain`, `sicily_ntlm_signonly`, `sicily_ntlm_sealonly`, `sicily_ntlm_signseal` |
| SASL/GSS-SPNEGO (NTLM) | `sasl_spnego_ntlm_plain`, `sasl_spnego_ntlm_signonly`, `sasl_spnego_ntlm_sealonly`, `sasl_spnego_ntlm_signseal` |
| SASL/GSSAPI (NTLM) | `sasl_gssapi_ntlm_plain`, `sasl_gssapi_ntlm_signonly`, `sasl_gssapi_ntlm_sealonly`, `sasl_gssapi_ntlm_signseal` |
| SASL/GSS-SPNEGO (Kerberos) | `sasl_spnego_krb_plain`, `sasl_spnego_krb_signonly`, `sasl_spnego_krb_signseal` |
| SASL/GSSAPI (Kerberos) | `sasl_gssapi_krb_plain`, `sasl_gssapi_krb_signonly`, `sasl_gssapi_krb_signseal` |
| SASL/DIGEST-MD5 | `sasl_digest_md5_plain`, `sasl_digest_md5_signonly`, `sasl_digest_md5_signseal` |
| SASL/EXTERNAL | `sasl_external` |

Each NTLM family tests four security layers: plain, sign-only, seal-only, and sign+seal. Kerberos and DIGEST-MD5 have three: plain, sign-only, and sign+seal - in Kerberos/GSSAPI, the "seal-only" wire state is not defined (`GSS_Wrap` with CONF already implies integrity), and DIGEST-MD5 always combines integrity and confidentiality per RFC 2831.

### About Kerberos

**Subkeys & etypes**

For Kerberos methods, the AP-REQ subkey etype proposal is controlled by `--propose-subkey` (see below) rather than provided in separate method variants. The subkey governs per-message protection per RFC 4121 §2: `aes256-cts-hmac-sha1-96` (default) steers the DC toward an AES256 acceptor subkey; `none` lets the DC pick from its `msDS-SupportedEncryptionTypes` (typically RC4-HMAC on a default-configured DC); `rc4-hmac` and `aes128-cts-hmac-sha1-96` propose those etypes explicitly.

**Automatic ticket requests**

When no Kerberos-specific credential (`--ccache` or `--aes-key`) is supplied but Kerberos methods are selected and a **password** or **NT hash** is present, a TGT and a ST are obtained in memory from that credential.

**Mutual authentication**

`--mutual-auth` decides whether the Kerberos AP-REQ sets the `mutual-required` ap-options bit (RFC 4120 §5.5.1), which asks the server to prove itself with an AP-REP. Both carriers require it by default, which is what a real client sends; the AP-REP's acceptor subkey then governs per-message protection on either one, and `--propose-subkey` steers the etype the DC picks for it.

For a SASL/GSSAPI bind it also decides the shape of the exchange, because the AP-REP is a second context token and SASL strictly alternates challenge and response. With mutual authentication it is six messages: AP-REQ, AP-REP, an **empty** client response (the context is complete and `GSS_Init_sec_context` has no output token left, but the client still owes a turn), the server's wrapped security-layer offer, the client's wrapped reply, success. RFC 4752 §3.2 has a server that produced no output token send its §3.3 offer straight away, which would make the bind four messages - but a DC does not: it answers an **empty challenge** where the AP-REP would have been and keeps the six-message shape. Both are accepted here.

RFC 4752 §3.1 only mandates mutual authentication when the client will be requesting a security layer - integrity is the unconditional requirement there - so `none` is within spec for `plain` and a deliberate deviation for `signonly`/`signseal`. A DC accepts it in all three: the security-layer offer still comes back as `0x07` (all three layers, 10 MiB buffer), and post-bind signing and sealing work, keyed with the subkey the AP-REQ proposed since no acceptor subkey was ever issued.

On GSS-SPNEGO the AP-REP arrives inside the `negTokenResp`, which is what a Windows/SSPI client gets. SPNEGO needs no extra round for it - the AP-REP rides on the same reply that carries `accept-completed` - so the bind stays a single round trip either way, and `--mutual-auth none` only costs it the server authentication and moves the per-message key back to the proposed subkey.

A DC also checks the two mutual signals against each other. Mutual authentication is requested twice in an AP-REQ: the `mutual-required` ap-options bit, and `GSS_C_MUTUAL_FLAG` (0x02) in the authenticator's GSS-API checksum (RFC 4121 §4.1.1.1). Setting the checksum bit with `--cksum-flags` while `--mutual-auth none` clears the ap-options bit is refused with `invalidCredentials` and no `serverSaslCreds` at all; the reverse asymmetry - ap-options set, checksum bit absent, which is what this tool sends by default - is accepted.

**Optimistic vs deferred mechToken (SPNEGO)**

A SPNEGO NegTokenInit carries two separate things: `mechTypes`, the list of mechanism OIDs the client supports, and `mechToken`, the first context token of the first one - the *optimistic* token of RFC 4178 §4.2.1, sent on the guess that the server will pick that mechanism. `--spnego-mech-token deferred` omits it and sends the AP-REQ in the next round's `responseToken` instead.

Against a DC that is the difference between one round trip and three:

| | `optimistic` | `deferred` |
|---|---|---|
| 1 | `NegTokenInit{mechTypes, mechToken=AP-REQ}` → `success` + `AP-REP` | `NegTokenInit{mechTypes}` → `accept-incomplete`, `supportedMech=Kerberos` |
| 2 | | `NegTokenResp{responseToken=AP-REQ}` → `AP-REP` |
| 3 | | `NegTokenResp{}` (empty) → `success` |

The third round exists for the same reason bare SASL/GSSAPI has one: the AP-REP is a server token and SASL alternates strictly, so the client has to return the turn before the server can conclude.

**PKINIT**

PKINIT is not implemented as it's more related to the KDC than to the LDAP service itself. To test flows related to PKINIT first perform PKINIT manually to obtain a TGT, then test Kerberos-related methods by providing it via `--ccache` or the KRB5CCNAME environment variable.

### About NTLM

**NTLM carried by SASL/GSSAPI**

For some reason all Microsoft specs (such as `MS-ADTS`) state that their implementation of the SASL/GSSAPI mech (without SPNEGO) is for Kerberos only (which would seem correct per RFC4752), but Microsoft's own clients such as ADExplorer often issue SASL/GSSAPI carrying NTLM, and DCs accept it just fine.

**NTLM "signonly"**

A DC accepts a `NTLMSSP_NEGOTIATE_SIGN`-without-`SEAL` bind, but still expects every post-bind body to be **sealed**. Send it a signed cleartext body - which is what MS-NLMP §3.4.3 describes - and it answers with an unsolicited Notice of Disconnection carrying `Error decrypting ldap message`, then hangs up.

By default this tool sends what the negotiated flags actually describe, so the wire matches the method name. Against a DC that means every `*_ntlm_signonly` method reports `PARTIAL`, with the server's own explanation as the detail. Pass `--ntlm-always-seal` to seal the sign-only case too, which is what a DC requires and what makes those methods `PASS`.

**NTLMv1**

`--ntlmv1` computes an NTLMv1 response instead of NTLMv2, for targets whose LAN Manager authentication level still permits it.

NTLMv1 carries no `AV_PAIR` list, so channel bindings and the MIC declaration would have nowhere to go - `--channel-bindings` and `--announce-mic` are not accepted if `--ntlmv1` is enabled.

`--ntlmv1` negotiates extended session security. If `--no-ess` is passed it is suppressed and the legacy signing and sealing regime is used instead. The key exchange is NT-keyed: no option requests the legacy LM-keyed branches.

Under `--no-ess`, `sasl_gssapi_ntlm_sealonly` and `sasl_spnego_ntlm_sealonly` reuse one RC4 keystream for every message, so their sealing provides no meaningful confidentiality.

The legacy regime also shares one sequence number between the two directions, as it shares the sealing key: a reply advances the number the next request carries. Extended session security numbers each direction separately.

**Message Integrity Code (MIC)**

`--mic` selects what the Type 3 MIC field carries: `computed` (the default), `empty` for a field present but all zero, or `drop` for no field at all. `--announce-mic` is separate and decides only whether a populated field is *declared*.

*Presence is tied to the Version field.* MS-NLMP §2.2.1.3 lays the `AUTHENTICATE_MESSAGE` out as a fixed 64-byte header, then Version, then MIC, then the payload, and gives neither Version nor MIC a presence flag of its own. A receiver takes both to be present exactly when `NTLMSSP_NEGOTIATE_VERSION` is set, so it seems the two have to be emitted or omitted together - which is why `drop` also drops Version and that flag. 

*An undeclared MIC is not checked.* `computed` and `empty` are both accepted, so by default the field is structural only and provides no integrity protection. `--announce-mic` declares it through `MsvAvFlags` bit 0x2, which MS-NLMP §3.1.5.1.2 requires of a client supplying one. The declaration lands in the NTLMv2 blob before `NTProofStr` covers it, so the MIC becomes one the server is told to check - and then the value matters. On its own, `--announce-mic` declares the computed MIC and a DC accepts it. `--mic empty --announce-mic` declares a field left all zero, and a DC rejects it with `data 57` - which is what shows the value is genuinely verified once declared, rather than merely required to be present.

A declared MIC is only validated when `NTLMSSP_NEGOTIATE_ALWAYS_SIGN` was negotiated. Without it a DC answers `data 57` however correct the MIC is, and neither the key exchange nor the security layer makes any difference. Every method here negotiates that flag, including the `*_ntlm_plain` ones: MS-NLMP §2.2.2.5 has it request a signature block without negotiating session security, which is why it does not turn `plain` into a signed method - a Windows client sets it in every `NEGOTIATE_MESSAGE` regardless of the layer it goes on to use.

*A declaration with no field behind it is refused.* `--mic drop --announce-mic` sends a blob declaring a MIC in a message that carries none, and a DC rejects all twelve methods with `data 57`; `--mic drop` on its own passes all twelve, so the declaration bit is the only difference and the DC is enforcing presence rather than reacting to the missing field. That pairing is not merely a misconfiguration: `MsvAvFlags` lives inside the blob that `NTProofStr` covers, so a declaration cannot be withdrawn once the response is computed, and stripping the MIC field while the declaration stands is reachable without the client's cooperation. A server that accepted it would be honouring a declaration it never checked.

### About TLS

**Channel bindings**

`--channel-bindings` makes NTLM and Kerberos SASL binds carry an RFC 5929 `tls-server-end-point` token, tying the authentication to the TLS certificate the connection runs on. It is what a DC with `LdapEnforceChannelBinding=1` validates and what one set to `2` requires. It only does anything under `-s ldaps` or `-s starttls` - on a plaintext connection there is no channel to bind, so the token is omitted and the flag is a no-op.

`-m plain` is the natural selection for testing it: no SASL security layer can be in effect over TLS anyway (see the note under LDAPS/StartTLS below), and the plain layer covers both authentication families across all three carriers plus DIGEST-MD5.

```bash
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -p password -m plain -s ldaps --channel-bindings
```

Against a DC set to `2`, omitting the flag fails every method with `data 80090346` (`SEC_E_BAD_BINDINGS`), which is reported as `invalidCredentials` even though the credentials were fine - so the output appends a short hint saying so. Adding the flag makes the NTLM and Kerberos methods pass.

`sasl_digest_md5_plain` fails either way, and cannot be made to pass: RFC 2831 predates channel bindings and has no field to carry one, so DIGEST-MD5 is unusable over TLS against a DC that requires them. Simple binds and SASL EXTERNAL are unaffected - neither is a SASL mechanism that carries a binding.

**"Pass the cert"**

The technique informally known as "pass the cert" can apparently flow through the wire in the following "settings" only:

1) StartTLS with the client certificate used during the handshake over a plain LDAP port, then a SASL/EXTERNAL bind (`-s starttls -m sasl_external --cert-pem <certfile> --key-pem <keyfile>`)

2) LDAPS with the client certificate used during the handshake to the secure LDAP port, *without a SASL/EXTERNAL* bind (`-s ldaps -m no_bind --cert-pem <certfile> --key-pem <keyfile>`)

### About DIGEST-MD5 ciphers

`auth-conf` negotiates a cipher of its own. AD may offer `3des,rc4`; `rc4` is the default and `--digest-md5-cipher` selects another. `des`, `rc4-40` and `rc4-56` are implemented and accepted by the flag - if AD does not offer them, requesting one fails the bind up front and reports the list the server did offer.

## Requirements

- Python 3
- `impacket==0.13.1`
- `pyasn1==0.6.3`
- `pyasn1_modules==0.4.2`
- `pycryptodomex==3.23.0`

Install with:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python msldap_probe.py -t <target> [options]
```

### Common examples

Test all methods against a host:

```bash
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -p password
```

Run only NTLM methods (and let sign-only reach the DC's expectations):

```bash
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -p password -m ntlm --ntlm-always-seal
```

Compare one security layer across every mechanism that offers it:

```bash
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -p password -m signseal
```

Test DIGEST-MD5 confidentiality under 3DES instead of RC4:

```bash
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -p password -m sasl_digest_md5_signseal --digest-md5-cipher 3des
```

Use NTLM hashes instead of a password:

```bash
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -H "LMHASH:NTHASH"
```

Run Kerberos methods with an AES key:

```bash
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -A AES256KEY -K kdc.creta.local --spn-host dc.creta.local
```

Use a Kerberos credentials cache:

```bash
python msldap_probe.py -t dc.creta.local -d creta.local --ccache /tmp/krb5cc_1000 -m sasl_gssapi_krb --spn-host dc.creta.local
```

When `--ccache` is set, no TGT is requested from the KDC - the cached service ticket for `ldap/<spn-host>` is used directly, or the cached TGT is used to obtain one. `KRB5CCNAME` is honored as a fallback when `--ccache` is not given.

Test Kerberos with RC4 subkey fallback (DC picks the etype):

```bash
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -H "LMHASH:NTHASH" -m sasl_gssapi_krb --propose-subkey none
```

Test Kerberos with an explicit RC4-HMAC subkey proposal:

```bash
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -p password -m sasl_spnego_krb_signseal --propose-subkey rc4-hmac
```

Use LDAPS or StartTLS:

```bash
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -p password -s ldaps
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -p password -s starttls
```

> [!IMPORTANT]
> Per MS-ADTS §5.1.1.1.2, Active Directory permits a SASL bind on a TLS-protected connection but **does not permit a SASL security layer on one**. So under `-s ldaps` or `-s starttls`, only the `*_plain` methods (plus `simple_bind` and `sasl_external`) can pass - every signing or sealing variant either gets an `unwillingToPerform`/`inappropriateAuthentication`, or binds successfully and is then torn down on its first wrapped message, reporting `PARTIAL` with `Error decoding ldap message`. That is the DC enforcing the restriction, not a client failure. Note that impacket silently drops the SASL layer under `ldaps://`, so this tool deliberately restores it in order to test the combination rather than skip it.

### Options

**Target and transport**

- `-t`, `--target` - target host or IP (required).
- `-P`, `--port` - override the default port for the chosen scheme.
- `-s`, `--scheme` - transport: `ldap` (default), `starttls`, or `ldaps`.

**Credentials**

- `-d`, `--domain` - domain FQDN or NetBIOS name.
- `-u`, `--username` - username.
- `-p`, `--password` - password.
- `-H`, `--hashes` - `LM:NT` hash pair.
- `-A`, `--aes-key` - AES key for Kerberos (AES256 or AES128).
- `--ccache` - path to a Kerberos credentials cache. Overrides `KRB5CCNAME`. When set, no TGT is requested from the KDC: the cached service ticket is used directly, or a cached TGT is used to obtain one.
- `-C`, `--cert-pem` - client certificate PEM for `sasl_external`.
- `-k`, `--key-pem` - client private key PEM for `sasl_external`.

**Kerberos tuning** (ignored by other methods)

- `-K`, `--kdc-host` - KDC hostname/IP (defaults to `--domain`).
- `-S`, `--spn-host` - real hostname for the `ldap/<host>` SPN when `--target` is an IP.
- `--propose-subkey` - AP-REQ subkey etype: `none` (DC picks), `rc4-hmac`, `aes128-cts-hmac-sha1-96`, or `aes256-cts-hmac-sha1-96` (default).
- `--cksum-flags` - override the AP-REQ GSS-API checksum flags (int bitmask of `GSS_C_INTEG_FLAG` 0x20 and `GSS_C_CONF_FLAG` 0x10, RFC 4121 §4.1.1.1). Default: 0x03 for GSSAPI, derived from the bind's layer for SPNEGO.
- `--mutual-auth` - `required` (default, both Kerberos carriers) or `none` for the AP-REQ's `mutual-required` ap-options bit (RFC 4120 §5.5.1). `none` drops the AP-REP, moving per-message protection onto the proposed subkey (see [About mutual authentication](#about-mutual-authentication)).
- `--spnego-mech-token` - `optimistic` (default) or `deferred` for the AP-REQ's placement in a `sasl_spnego_krb_*` bind: the NegTokenInit's optimistic mechToken, or a later round's responseToken (see [About the optimistic mechToken](#about-the-optimistic-mechtoken)).

**SASL behaviour**

- `--channel-bindings` - send an RFC 5929 `tls-server-end-point` binding with NTLM and Kerberos binds. Only meaningful under `-s ldaps`/`-s starttls`; required by a DC with `LdapEnforceChannelBinding=2` (see [About channel bindings](#about-channel-bindings)).
- `--ntlm-always-seal` - seal outgoing NTLM traffic even when only `NTLMSSP_NEGOTIATE_SIGN` was negotiated. Off by default; required for the `*_ntlm_signonly` methods to pass against a DC (see [About NTLM "signonly"](#about-ntlm-signonly)).
- `--digest-md5-cipher` - cipher to propose for a DIGEST-MD5 `auth-conf` bind: `rc4` (default), `rc4-40`, `rc4-56`, `des`, or `3des`.

**NTLM behaviour**

- `--ntlmv1` - compute an NTLMv1 response instead of NTLMv2, negotiating extended session security (see [About NTLMv1](#about-ntlmv1)).
- `--no-ess` - suppress extended session security, putting the legacy regime on the wire. Requires `--ntlmv1`.
- `--announce-mic` - declare the Type 3 MIC through `MsvAvFlags` bit 0x2, so a server verifies it (see [About the MIC](#about-the-authenticate_message-mic)).
- `--mic` - what the Type 3 MIC field carries: `computed` (default), `empty` (present, all zero), or `drop` (omitted, along with the Version field).

**Selection and output**

- `-m`, `--methods` - comma-separated method names, prefixes or aliases, or `all` (the default).
- `-D`, `--debug` - show full error details.
- `-Z`, `--no-color` - disable colored output.

### Selecting methods

A method name encodes three dimensions in a fixed order - SASL carrier, authentication family, security layer - so a **prefix** only ever slices the first: `sasl_gssapi_krb` selects all three `sasl_gssapi_krb_*` layers.

**Aliases** slice along the other two:

| Alias | Selects |
|---|---|
| `gssapi`, `spnego` | every method on that SASL carrier (`sicily` needs no alias - it already leads its names) |
| `kerberos`, `ntlm` | every method of that authentication family |
| `plain`, `signonly`, `sealonly`, `signseal` | every method negotiating that security layer |

Entries combine as a union, so `-m spnego,sealonly` runs both sets. `anonymous_bind`, `simple_bind` and `sasl_external` match no alias - they negotiate no layer and belong to no family - and are reachable by name or `all`.

## Output

FAIL/PARTIAL details are hidden unless `--debug` is used, to keep the default output a clean matrix.

## Implementation notes

* Built on top of `impacket`'s `LDAPConnection`, but replaces its built-in `login()` / `kerberosLogin()` paths to gain independent control over signing and sealing flags.
* `--scheme` applies uniformly to every method; the security layer (if any) is negotiated on top of that transport.
* Kerberos methods require a resolvable SPN. If `--target` is an IP, use `--spn-host` to supply the real hostname for `ldap/<spn-host>`.
* `sasl_external` does not require credentials; it reports what the server does when an EXTERNAL bind is attempted with or without a TLS client certificate.
* For some reason a Sicily-style rebind after a SASL layer has been established **does not seem to work** and the connection is reset. I could not figure out why.
* Impacket still includes some old Python2 code that raises exceptions in Python3 regarding the NTLMv1 LM path - which is not a big problem, as supporting LM paths is a bit overkill even for this project's goals.
* The receive path reads one SASL frame at a time and coalesces frames until a response is complete, so a reply spanning several frames is handled. It also accepts an unwrapped `LDAPMessage` mid-connection, which is how a DC delivers a Notice of Disconnection while tearing a session down - that server-side explanation is surfaced verbatim instead of appearing as a connection reset.

## License

MIT License

Copyright (c) 2026 Artur Henrique Marzano Gonzaga

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
