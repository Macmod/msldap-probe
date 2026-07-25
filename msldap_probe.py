#!/usr/bin/env python3
"""LDAP auth-method matrix tester.

Authenticates to an LDAP/AD target using every requested combination of
bind mechanism and security layer, verifying each one with a real post-bind
operation (not just a successful bind), and reports PASS/PARTIAL/FAIL per
method. See msldapprobe/methods.py for the full method registry.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0] if "/" in __file__ else ".")

from msldapprobe.methods import REGISTRY, Credentials  # noqa: E402
from msldapprobe import ntlm_methods  # noqa: E402,F401 - populates REGISTRY as a side effect
from msldapprobe import krb_methods  # noqa: E402,F401 - populates REGISTRY as a side effect
from msldapprobe import digest_md5_methods  # noqa: E402,F401 - populates REGISTRY as a side effect


# Same red/yellow/green/cyan-for-info convention ldapx (this repo's own Go
# tool) already uses - PASS=green, PARTIAL=yellow (a real finding, not a
# clean pass), FAIL=red, SKIP=cyan (neutral/informational, not an error).
_ANSI = {
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}
_STATUS_COLOR = {"PASS": "green", "PARTIAL": "yellow", "FAIL": "red", "SKIP": "cyan"}


def _colors_enabled(no_color_flag: bool) -> bool:
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _paint(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_ANSI[color]}{text}{_ANSI['reset']}"


# Set by main() once args are parsed, read by _truncate - module-level
# rather than threaded through every call site, since this only affects
# how much of an already-built detail string gets displayed, not any
# actual control flow.
_COLOR = True
_DEBUG = False


def _truncate(detail: str, limit: int = 300) -> str:
    if _DEBUG or len(detail) <= limit:
        return detail
    return (
        detail[:limit]
        + f" ... ({len(detail) - limit} more chars, use --debug for full output)"
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("-t", "--target", required=True, help="Target host or IP")
    p.add_argument(
        "-P",
        "--port",
        type=int,
        default=None,
        help="Override the default port for the chosen method",
    )
    p.add_argument(
        "-d",
        "--domain",
        default="",
        help="Domain (FQDN, e.g. creta.local, or NetBIOS name)",
    )
    p.add_argument("-u", "--username", default="")
    p.add_argument("-p", "--password", default="")
    p.add_argument("-H", "--hashes", default="", help="LM:NT hash pair")
    p.add_argument(
        "-A", "--aes-key", default="", help="AES key for Kerberos (aes256 or aes128)"
    )
    p.add_argument(
        "--ccache",
        default=None,
        help="Path to a Kerberos credentials cache file to use for Kerberos methods. "
        "Overrides KRB5CCNAME. When set, no TGT is requested from the KDC - the "
        "cached service ticket (or TGT, used to obtain one) is used directly.",
    )
    p.add_argument(
        "-K",
        "--kdc-host",
        default=None,
        help="KDC hostname/IP for Kerberos methods (defaults to --domain)",
    )
    p.add_argument(
        "-S",
        "--spn-host",
        default=None,
        help="LDAP service's real hostname for Kerberos SPN construction (ldap/<spn-host>) - "
        "required for the Kerberos methods when --target is a bare IP, since AD doesn't register SPNs against IPs",
    )
    p.add_argument(
        "--propose-subkey",
        default="aes256-cts-hmac-sha1-96",
        choices=[
            "none",
            "rc4-hmac",
            "aes128-cts-hmac-sha1-96",
            "aes256-cts-hmac-sha1-96",
        ],
        help="Kerberos AP-REQ subkey etype proposal: 'none' (DC picks), 'rc4-hmac', "
        "'aes128-cts-hmac-sha1-96', or 'aes256-cts-hmac-sha1-96' (default). "
        "The subkey governs per-message protection per RFC 4121 §2. Ignored by non-Kerberos methods.",
    )
    p.add_argument(
        "--cksum-flags",
        default=None,
        type=int,
        help="Override the AP-REQ GSS-API checksum flags (int) for Kerberos methods. "
        "Bitmask of GSS_C_INTEG_FLAG (0x20) and GSS_C_CONF_FLAG (0x10) "
        "per RFC 4121 §4.1.1.1 combined with the mandatory GSS_C_SEQUENCE_FLAG "
        "and GSS_C_REPLAY_FLAG. When set, Kerberos methods use these bits "
        "instead of the default (GSSAPI: 0x03, SPNEGO: derived from the "
        "bind's own layer). Ignored by non-Kerberos methods.",
    )
    p.add_argument(
        "-C", "--cert-pem", default=None, help="Client certificate PEM (sasl_external)"
    )
    p.add_argument(
        "-k", "--key-pem", default=None, help="Client private key PEM (sasl_external)"
    )
    p.add_argument(
        "-s",
        "--scheme",
        choices=["ldap", "starttls", "ldaps"],
        default="ldap",
        help="Transport scheme for every method's connection: ldap (default, no transport-level TLS), "
        "starttls (RFC 4511 StartTLS), or ldaps (implicit TLS)",
    )
    p.add_argument(
        "-m",
        "--methods",
        default="all",
        help="Comma-separated method names or prefixes, or 'all' (see methods.py REGISTRY for the full list). "
        "Each entry matches every registered method whose name starts with it, e.g. 'sasl_gssapi_krb' selects "
        "all three sasl_gssapi_krb_* layers.",
    )
    p.add_argument(
        "-D",
        "--debug",
        action="store_true",
        help="Show full error details (raw pyasn1 dumps etc. can be very long) - hidden entirely otherwise",
    )
    p.add_argument(
        "-Z", "--no-color", action="store_true", help="Disable colored output"
    )
    return p.parse_args()


def build_credentials(args: argparse.Namespace) -> Credentials:
    lmhash, nthash = b"", b""
    if args.hashes:
        if ":" in args.hashes:
            lmhash_str, nthash_str = args.hashes.split(":", 1)
            lmhash = bytes.fromhex(lmhash_str) if lmhash_str else b""
            nthash = bytes.fromhex(nthash_str) if nthash_str else b""
        else:
            nthash = bytes.fromhex(args.hashes)
    return Credentials(
        target=args.target,
        port=args.port,
        domain=args.domain,
        username=args.username,
        password=args.password,
        lmhash=lmhash,
        nthash=nthash,
        aes_key=args.aes_key,
        ccache=args.ccache,
        kdc_host=args.kdc_host or args.domain or None,
        cert_pem=args.cert_pem,
        key_pem=args.key_pem,
        spn_host=args.spn_host,
        propose_subkey=args.propose_subkey,
        cksum_flags=args.cksum_flags,
        scheme=args.scheme,
    )


def selected_method_names(spec: str) -> list[str]:
    """Each comma-separated entry is a prefix match against REGISTRY, not
    just an exact name - 'sasl_gssapi_krb' selects all three
    sasl_gssapi_krb_* layers, and a full method name still matches (it's
    a prefix of itself). Results are deduplicated but not sorted here -
    main() sorts the final selection alphabetically for display."""
    if spec.strip().lower() == "all":
        return list(REGISTRY.keys())
    tokens = [t.strip() for t in spec.split(",") if t.strip()]
    selected: list[str] = []
    seen: set[str] = set()
    unmatched = []
    for token in tokens:
        matches = [name for name in REGISTRY if name.startswith(token)]
        if not matches:
            unmatched.append(token)
            continue
        for name in matches:
            if name not in seen:
                seen.add(name)
                selected.append(name)
    if unmatched:
        raise SystemExit(
            f"no method matches prefix(es): {', '.join(unmatched)}\navailable: {', '.join(sorted(REGISTRY))}"
        )
    return selected


def run_method(name: str, creds: Credentials) -> tuple[str, str]:
    method = REGISTRY[name]
    if method.eligible is not None:
        ok, reason = method.eligible(creds)
        if not ok:
            return "SKIP", reason
    else:
        missing = [f for f in method.requires if not getattr(creds, f)]
        if missing:
            return "SKIP", f"missing required field(s): {', '.join(missing)}"

    try:
        transport = method.connect(creds)
    except Exception as exc:
        return "FAIL", f"connect failed: {exc}"

    try:
        outcome = method.bind(transport, creds)
        if not outcome.ok:
            return "FAIL", outcome.detail

        ok, detail = transport.verify_rootdse_namingcontexts()
        if ok:
            return "PASS", outcome.detail
        return "PARTIAL", f"bind ok, post-bind operation failed: {detail}"
    except Exception as exc:
        return "FAIL", f"exception: {exc}"
    finally:
        try:
            transport.close()
        except Exception:
            pass


def main() -> int:
    global _COLOR, _DEBUG

    args = parse_args()
    _DEBUG = args.debug
    _COLOR = _colors_enabled(args.no_color)

    creds = build_credentials(args)
    names = sorted(selected_method_names(args.methods))

    results: list[tuple[str, str, str]] = []
    for name in names:
        status, detail = run_method(name, creds)
        results.append((name, status, detail))
        status_text = _paint(f"{status:8}", _STATUS_COLOR[status], _COLOR)
        # FAIL/PARTIAL detail is error-shaped output (exception text, raw
        # pyasn1 dumps) - hidden entirely without --debug, not even
        # truncated, so a plain run stays a clean pass/fail table. PASS's
        # own detail (e.g. "bind succeeded, layer=...") and SKIP's reason
        # aren't error messages and still show either way.
        if status in ("FAIL", "PARTIAL") and not _DEBUG:
            print(f"{status_text} {name:36}")
        else:
            print(f"{status_text} {name:36} {_truncate(detail)}")

    failed = sum(1 for _, status, _ in results if status == "FAIL")
    partial = sum(1 for _, status, _ in results if status == "PARTIAL")
    skipped = sum(1 for _, status, _ in results if status == "SKIP")
    passed = len(results) - failed - partial - skipped
    summary = f"{len(results)} methods run: {passed} PASS, {partial} PARTIAL, {failed} FAIL, {skipped} SKIP"
    print(f"\n{_paint(summary, 'bold', _COLOR)}")
    return 1 if failed or partial else 0


if __name__ == "__main__":
    raise SystemExit(main())
