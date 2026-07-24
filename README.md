# msldap-probe

LDAP/AD authentication-method matrix tester.

Tests every requested combination of LDAP bind mechanism and security layer against a target, verifies each one with a real post-bind operation (a rootDSE `namingContexts` search), and reports PASS / PARTIAL / FAIL per method.

## Purpose

Use this tool to enumerate which LDAP authentication methods and signing/sealing layers a domain controller actually accepts and supports end-to-end. It is useful for checking protocol compatibility, verifying hardening, or comparing behavior across DC versions.

## Supported methods

Methods are registered in `msldapprobe/methods.py` and grouped by mechanism family:

| Family | Names |
|--------|-------|
| Anonymous / simple / SASL EXTERNAL | `anonymous_bind`, `simple_bind`, `sasl_external` |
| Sicily NTLM | `sicily_ntlm_plain`, `sicily_ntlm_signonly`, `sicily_ntlm_sealonly`, `sicily_ntlm_signseal` |
| SASL GSS-SPNEGO wrapping NTLM | `sasl_spnego_ntlm_plain`, `sasl_spnego_ntlm_signonly`, `sasl_spnego_ntlm_sealonly`, `sasl_spnego_ntlm_signseal` |
| SASL GSSAPI carrying NTLM | `sasl_gssapi_ntlm_plain`, `sasl_gssapi_ntlm_signonly`, `sasl_gssapi_ntlm_sealonly`, `sasl_gssapi_ntlm_signseal` |
| SASL GSS-SPNEGO wrapping Kerberos | `sasl_spnego_krb_plain`, `sasl_spnego_krb_signonly`, `sasl_spnego_krb_sealonly`, `sasl_spnego_krb_signseal` |
| SASL GSSAPI carrying Kerberos | `sasl_gssapi_krb_plain`, `sasl_gssapi_krb_signonly`, `sasl_gssapi_krb_sealonly`, `sasl_gssapi_krb_signseal` |
| SASL DIGEST-MD5 | `sasl_digest_md5_plain` |

Each NTLM/Kerberos family tests four security layers: plain (no per-message protection), sign-only, seal-only, and sign+seal.

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
| `-K`, `--kdc-host` | KDC hostname/IP for Kerberos methods (defaults to `--domain`) |
| `-S`, `--spn-host` | Real hostname for the `ldap/<host>` SPN when `--target` is an IP |
| `-C`, `--cert-pem` | Client certificate PEM for `sasl_external` |
| `-k`, `--key-pem` | Client private key PEM for `sasl_external` |
| `-s`, `--scheme` | Transport scheme: `ldap` (default), `starttls`, or `ldaps` |
| `-m`, `--methods` | Comma-separated method names or prefixes, or `all` |
| `-D`, `--debug` | Show full error details |
| `-n`, `--no-color` | Disable colored output |

The `--methods` argument matches prefixes, so `sasl_gssapi_krb` selects all four `sasl_gssapi_krb_*` layers.

## Output

Each method prints one line:

```
PASS     sasl_gssapi_krb_signseal
PARTIAL  sasl_spnego_ntlm_sealonly
FAIL     sasl_gssapi_ntlm_signonly
SKIP     sasl_external
```

- **PASS** — bind succeeded and a post-bind rootDSE search returned `namingContexts`.
- **PARTIAL** — bind succeeded, but the post-bind operation failed (a real finding, not a clean pass).
- **FAIL** — bind or post-bind operation failed.
- **SKIP** — method was not run because required credentials were missing.

FAIL/PARTIAL details are hidden unless `--debug` is used, to keep the default output a clean matrix.

## Implementation notes

- Built on top of `impacket`'s `LDAPConnection`, but replaces its built-in `login()` / `kerberosLogin()` paths to gain independent control over signing and sealing flags.
- `--scheme` applies uniformly to every method; the security layer (if any) is negotiated on top of that transport.
- Per-message wrap/unwrap is implemented separately for NTLM and Kerberos in `msldapprobe/ntlm_layers.py` and `msldapprobe/krb_layers.py`.
- Kerberos methods require a resolvable SPN. If `--target` is an IP, use `--spn-host` to supply the real hostname for `ldap/<spn-host>`.
- `sasl_external` does not require credentials; it reports what the server does when an EXTERNAL bind is attempted with or without a TLS client certificate.