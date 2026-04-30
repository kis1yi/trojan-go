---
title: "Advanced TLS Settings: Fingerprints, ALPN, and ECH"
draft: false
weight: 11
---

This page documents the TLS-layer knobs that affect how a trojan-go **client**
talks to a remote endpoint: the spoofed Client Hello fingerprint, the ALPN
list, and the ECH (Encrypted Client Hello) modes. The corresponding
configuration fields live under the `ssl` block — see
[Complete Configuration File](../../basic/full-config) for the full schema.

The behaviour described here is exercised by the `tunnel/tls` regression
tests; in particular, the default fingerprint is locked by
`TestDefaultFingerprintIsChrome`, so it will not change silently between
releases.

### Default fingerprint

Trojan-go uses [utls](https://github.com/refraction-networking/utls) to forge
a browser-shaped TLS Client Hello. The fingerprint controls the cipher list,
extension order, supported groups, and other observable bytes that censors
use to single out non-browser TLS clients.

| `fingerprint` value | utls ClientHelloID    | Notes                                   |
|---------------------|-----------------------|-----------------------------------------|
| `""` (default)      | `HelloChrome_Auto`    | Resolves to `chrome`. Stable since 2024.|
| `"chrome"`          | `HelloChrome_Auto`    | Default.                                |
| `"firefox"`         | `HelloFirefox_Auto`   |                                         |
| `"ios"`             | `HelloIOS_Auto`       |                                         |
| `"edge"`            | `HelloEdge_Auto`      |                                         |
| `"safari"`          | `HelloSafari_Auto`    |                                         |
| `"360browser"`      | `Hello360_Auto`       |                                         |
| `"qqbrowser"`       | `HelloQQ_Auto`        |                                         |

Names are case-insensitive. Any other value is rejected at startup with a
descriptive error.

When a fingerprint is selected, the `cipher`, `curves`, `alpn`, and
`session_ticket` fields are overwritten with the fingerprint's canonical
values — do not try to mix and match. If you need to override one of those
fields, leave `fingerprint` empty and set every related field by hand;
expect the resulting handshake to be detectable as non-browser traffic.

### ECH GREASE vs. full ECH

`ech` enables Encrypted Client Hello. There are two distinct modes, and they
have very different threat models:

* **GREASE ECH** (`ech: true`, `ech_config: ""`):
  trojan-go injects a syntactically valid but cryptographically meaningless
  ECH extension into the Client Hello. The real SNI is **not** encrypted;
  it still travels in plaintext in the outer Client Hello. The point is to
  make the trojan-go handshake indistinguishable from Chrome with ECH
  enabled, defeating fingerprinters that flag "no ECH extension" as a
  signal. Use this mode when the destination is a normal HTTPS origin that
  does not advertise ECH.

* **Full ECH** (`ech: true`, `ech_config: "<base64 ECHConfigList>"`):
  trojan-go performs a real ECH handshake. The inner Client Hello (with
  the real SNI) is encrypted to the public key in the ECHConfigList and
  embedded in the outer Client Hello, whose SNI is the public name from
  the ECHConfigList. Use this mode only when the destination explicitly
  publishes an ECHConfigList (typically via the HTTPS DNS record).

If `ech_config` is set but `ech` is `false`, the config is silently ignored
with a `WARN` at startup; this is an operator mistake, not a feature.

#### CDN and ALPN caveats

* CDNs do not, in general, support ECH. With most CDN deployments, full ECH
  will fail the handshake or land you on the wrong virtual host. Stick to
  GREASE ECH (or no ECH) when fronting through a CDN.
* The `alpn` list is purely cosmetic at the TLS layer — trojan-go does not
  multiplex on the negotiated protocol. However, **CDNs do honour ALPN**:
  if the configured ALPN does not match what the CDN expects (typically
  `["h2", "http/1.1"]`), the CDN may upgrade or downgrade the inner
  protocol and break the trojan tunnel. When using a fingerprint, the
  fingerprint's canonical ALPN already matches the impersonated browser;
  leaving `alpn` unset is the safe choice.
* ECH GREASE only changes the Client Hello shape; it does not improve
  confidentiality of the SNI through a plain TLS terminator. If your
  threat model requires SNI confidentiality, use full ECH against an
  ECH-aware origin or an in-network rendezvous (out of scope for this
  document).

### Single source of truth

The list of supported fingerprint names lives in
`tunnel/tls/client.go` (`resolveFingerprint`). When adding or removing a
value, update:

1. The `resolveFingerprint` switch.
2. The error message returned by `resolveFingerprint` for unknown values.
3. The table in this document.
4. The list under `fingerprint` in
   [Complete Configuration File](../../basic/full-config).
5. The `TestResolveFingerprintKnownNames` test in
   `tunnel/tls/fingerprint_default_test.go`.
