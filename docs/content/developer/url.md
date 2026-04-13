---
title: "URL Scheme (Draft)"
draft: false
weight: 200
---

## Changelog

- `encryption` format changed to `ss;method:password`

## Overview

Thanks to @DuckSoft, @StudentMain, and @phlinhng for their discussion and contributions to the Trojan-Go URL scheme. **The URL scheme is currently a draft and requires more practice and discussion.**

The Trojan-Go **client** can accept URLs to locate server resources. The principles are:

- Follow URL format specifications

- Ensure human readability and machine friendliness

- The purpose of a URL is to locate Trojan-Go node resources and facilitate resource sharing

Note: for human readability reasons, embedding base64-encoded data in URLs is prohibited. First, base64 encoding does not guarantee transmission security; its purpose is to transmit non-ASCII data over ASCII channels. Second, if transmission security is needed when sharing a URL, encrypt the plaintext URL instead of modifying the URL format.

## Format

The basic format is as follows. `$()` indicates the content must be `encodeURIComponent`-encoded.

```text
trojan-go://
    $(trojan-password)
    @
    trojan-host
    :
    port
/?
    sni=$(tls-sni.com)&
    type=$(original|ws|h2|h2+ws)&
        host=$(websocket-host.com)&
        path=$(/websocket/path)&
    encryption=$(ss;aes-256-gcm;ss-password)&
    plugin=$(...)
#$(descriptive-text)
```

For example

```text
trojan-go://password1234@google.com/?sni=microsoft.com&type=ws&host=youtube.com&path=%2Fgo&encryption=ss%3Baes-256-gcm%3Afuckgfw
```

Since Trojan-Go is compatible with Trojan, the Trojan URL scheme

```text
trojan://password@remote_host:remote_port
```

can be accepted compatibly. It is equivalent to

```text
trojan-go://password@remote_host:remote_port
```

Note that once the server uses features that are not Trojan-compatible, `trojan-go://` must be used to locate the server. This design prevents Trojan-Go URLs from being incorrectly accepted by original Trojan, avoiding contamination of Trojan users' URL sharing. At the same time, Trojan-Go ensures backward compatibility with Trojan URLs.

## Details

Note: all parameter names and constant strings are case-sensitive.

### `trojan-password`

The Trojan password.
Cannot be omitted, cannot be an empty string; non-ASCII printable characters are not recommended.
Must be encoded with `encodeURIComponent`.

### `trojan-host`

Node IP / domain name.
Cannot be omitted, cannot be an empty string.
IPv6 addresses must be enclosed in square brackets.
IDN domains (e.g., "百度.cn") must use the `xn--xxxxxx` format.

### `port`

Node port.
Defaults to `443` when omitted.
Must be an integer in `[1,65535]`.

### `tls` or `allowInsecure`

This field does not exist.
TLS is always enabled by default unless a transport plugin disables it.
TLS authentication must be enabled. Nodes that cannot verify server identity via a root CA are not suitable for sharing.

### `sni`

Custom TLS SNI.
Defaults to the same value as `trojan-host` when omitted. Must not be an empty string.

Must be encoded with `encodeURIComponent`.

### `type`

Transport type.
Defaults to `original` when omitted; must not be an empty string.
Currently the only valid values are `original` and `ws`; future values may include `h2`, `h2+ws`, etc.

When set to `original`, the original Trojan transport is used, which cannot conveniently pass through a CDN.
When set to `ws`, WebSocket over TLS transport is used.

### `host`

Custom HTTP `Host` header.
Can be omitted; defaults to the same value as `trojan-host`.
Can be an empty string, but this may cause unexpected behavior.

Warning: if your port is non-standard (not 80/443), RFC standards require that `Host` include the port number after the hostname, e.g., `example.com:44333`. Whether to comply is at your discretion.

Must be encoded with `encodeURIComponent`.

### `path`

Valid when `type` is `ws`, `h2`, or `h2+ws`.
Cannot be omitted, cannot be empty.
Must start with `/`.
May contain `&`, `#`, `?` and other URL characters, but must be a valid URL path.

Must be encoded with `encodeURIComponent`.

### `mux`

This field does not exist.
The current server always supports `mux` by default.
Whether to enable `mux` has trade-offs; it should be decided by the client. The purpose of a URL is to locate server resources, not to dictate user preferences.

### `encryption`

The encryption layer used to ensure cryptographic security of Trojan traffic.
Can be omitted; defaults to `none`, meaning no encryption.
Must not be an empty string.

Must be encoded with `encodeURIComponent`.

When using Shadowsocks for traffic encryption, the format is:

```text
ss;method:password
```

Where `ss` is a fixed string, `method` is the encryption method, which must be one of:

- `aes-128-gcm`
- `aes-256-gcm`
- `chacha20-ietf-poly1305`

Where `password` is the Shadowsocks password; it must not be an empty string.
If `password` contains a semicolon, no escaping is needed.
`password` should consist of printable ASCII characters.

Other encryption schemes are to be determined.

### `plugin`

Additional plugin options. This field is reserved.
Can be omitted, but must not be an empty string.

### URL Fragment (content after #)

Node description.
It is not recommended to omit it or leave it as an empty string.

Must be encoded with `encodeURIComponent`.
