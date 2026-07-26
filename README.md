# msldap-probe

LDAP/AD authentication-method matrix tester.

Tests every requested combination of LDAP bind mechanism and security layer against a target, verifies each one with a real post-bind operation (a rootDSE `namingContexts` search), and reports PASS / PARTIAL / FAIL per method.

<img width="1282" height="585" alt="image" src="https://github.com/user-attachments/assets/50f4c469-ac9c-44dd-be2d-75797188bc5b" />

- **PASS**: bind succeeded and a post-bind rootDSE search returned `namingContexts`.
- **PARTIAL**: bind succeeded, but the post-bind operation failed (a real finding, not a clean pass).
- **FAIL**: bind or post-bind operation failed.
- **SKIP**: method was not run because required credentials were missing.

## Purpose

Use this tool to enumerate which LDAP authentication methods and signing/sealing layers a domain controller actually accepts and supports end-to-end. It is useful for checking protocol compatibility, verifying hardening, or comparing behavior across DC versions.

## Supported methods

Methods are registered in `msldapprobe/methods.py` and grouped by mechanism family:

| Family | Names |
|--------|-------|
| Simple (anonymous) / Simple (with creds) / SASL EXTERNAL | `anonymous_bind`, `simple_bind`, `sasl_external` |
| Sicily (NTLM) | `sicily_ntlm_plain`, `sicily_ntlm_signonly`, `sicily_ntlm_sealonly`, `sicily_ntlm_signseal` |
| SASL/GSS-SPNEGO (NTLM) | `sasl_spnego_ntlm_plain`, `sasl_spnego_ntlm_signonly`, `sasl_spnego_ntlm_sealonly`, `sasl_spnego_ntlm_signseal` |
| SASL/GSSAPI (NTLM) | `sasl_gssapi_ntlm_plain`, `sasl_gssapi_ntlm_signonly`, `sasl_gssapi_ntlm_sealonly`, `sasl_gssapi_ntlm_signseal` |
| SASL/GSS-SPNEGO (Kerberos) | `sasl_spnego_krb_plain`, `sasl_spnego_krb_signonly`, `sasl_spnego_krb_signseal` |
| SASL/GSSAPI (Kerberos) | `sasl_gssapi_krb_plain`, `sasl_gssapi_krb_signonly`, `sasl_gssapi_krb_signseal` |
| SASL/DIGEST-MD5 | `sasl_digest_md5_plain`, `sasl_digest_md5_signonly`, `sasl_digest_md5_signseal` |

Each NTLM family tests four security layers: plain, sign-only, seal-only, and sign+seal. Kerberos and DIGEST-MD5 have three: plain, sign-only, and sign+seal - in Kerberos/GSSAPI, the "seal-only" wire state is not defined (`GSS_Wrap` with CONF already implies integrity), and DIGEST-MD5 always combines integrity and confidentiality per RFC 2831.

### About Kerberos

For Kerberos methods, the AP-REQ subkey etype proposal is controlled by `--propose-subkey` (see below) rather than provided in separate method variants. The subkey governs per-message protection per RFC 4121 §2: `aes256-cts-hmac-sha1-96` (default) steers the DC toward an AES256 acceptor subkey; `none` lets the DC pick from its `msDS-SupportedEncryptionTypes` (typically RC4-HMAC on a default-configured DC); `rc4-hmac` and `aes128-cts-hmac-sha1-96` propose those etypes explicitly.

PKINIT is not implemented as it's more related to the KDC than to the LDAP service itself. To test flows related to PKINIT first perform PKINIT manually to obtain a TGT, then test Kerberos-related methods by providing it via `--ccache` or the KRB5CCNAME environment variable.

> [!NOTE]
> When no Kerberos-specific credential (`--ccache`, `--aes-key`, `--keytab`) is supplied but Kerberos methods are selected and a **password** or **NT hash** is present, a TGT and a ST are obtained in memory from that credential.

### About NTLM "signonly"

It seems a real DC won't perform signing without sealing - even if **only signing was negotiated** (and accepted by the DC) it seems it always expects a sealed payload. That's why all `NTLM` + `signonly` variants always result `PARTIAL` unless `--ntlm-always-seal` is set.

### About GSSAPI and NTLM

For some reason all Microsoft specs (such as `MS-ADTS`) state that their implementation of the SASL/GSSAPI mech (without SPNEGO) is for Kerberos only (which would seem correct per RFC4752), but Microsoft's own clients such as ADExplorer often issue SASL/GSSAPI carrying NTLM, and DCs accept it just fine.

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

Run only NTLM methods:

```bash
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -p password -m sicily_ntlm,sasl_spnego_ntlm,sasl_gssapi_ntlm
```

Use NTLM hashes instead of a password:

```bash
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -H "LMHASH:NTHASH"
```

Run Kerberos methods with an AES key:

```bash
python msldap_probe.py -t dc.creta.local -d creta.local -u alice -A AES256KEY -K kdc.creta.local --spn-host dc.creta.local
```

Use a Kerberos credentials cache (e.g. after `kinit` or PKINIT):

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

### Options

| Option | Description |
|--------|-------------|
| `-t`, `--target` | Target host or IP (required) |
| `-P`, `--port` | Override the default port for the method |
| `-d`, `--domain` | Domain FQDN or NetBIOS name |
| `-u`, `--username` | Username |
| `-p`, `--password` | Password |
| `-H`, `--hashes` | `LM:NT` hash pair |
| `-A`, `--aes-key` | AES key for Kerberos (AES256 or AES128) |
| `--ccache` | Path to a Kerberos credentials cache file for Kerberos methods. Overrides `KRB5CCNAME`. When set, no TGT is requested from the KDC - the cached service ticket (or TGT, used to obtain one) is used directly |
| `-K`, `--kdc-host` | KDC hostname/IP for Kerberos methods (defaults to `--domain`) |
| `-S`, `--spn-host` | Real hostname for the `ldap/<host>` SPN when `--target` is an IP |
| `--propose-subkey` | Kerberos AP-REQ subkey etype: `none` (DC picks), `rc4-hmac`, `aes128-cts-hmac-sha1-96`, or `aes256-cts-hmac-sha1-96` (default). Ignored by non-Kerberos methods |
| `--cksum-flags` | Override the AP-REQ GSS-API checksum flags (int bitmask of `GSS_C_INTEG_FLAG` 0x20 and `GSS_C_CONF_FLAG` 0x10, RFC 4121 §4.1.1.1). Default: 0x03 for GSSAPI, derived from the bind's layer for SPNEGO. Ignored by non-Kerberos methods |
| `-C`, `--cert-pem` | Client certificate PEM for `sasl_external` |
| `-k`, `--key-pem` | Client private key PEM for `sasl_external` |
| `-s`, `--scheme` | Transport scheme: `ldap` (default), `starttls`, or `ldaps` |
| `-m`, `--methods` | Comma-separated method names or prefixes, or `all` |
| `-D`, `--debug` | Show full error details |
| `-Z`, `--no-color` | Disable colored output |

The `--methods` argument matches prefixes, so `sasl_gssapi_krb` selects all three `sasl_gssapi_krb_*` layers.

## Output

FAIL/PARTIAL details are hidden unless `--debug` is used, to keep the default output a clean matrix.

## Implementation notes

- Built on top of `impacket`'s `LDAPConnection`, but replaces its built-in `login()` / `kerberosLogin()` paths to gain independent control over signing and sealing flags.
- `--scheme` applies uniformly to every method; the security layer (if any) is negotiated on top of that transport.
- Per-message wrap/unwrap is implemented separately for NTLM and Kerberos in `msldapprobe/ntlm_layers.py` and `msldapprobe/krb_layers.py`.
- Kerberos methods require a resolvable SPN. If `--target` is an IP, use `--spn-host` to supply the real hostname for `ldap/<spn-host>`.
- `sasl_external` does not require credentials; it reports what the server does when an EXTERNAL bind is attempted with or without a TLS client certificate.
