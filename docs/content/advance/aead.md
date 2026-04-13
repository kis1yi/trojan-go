---
title: "Secondary Encryption with Shadowsocks AEAD"
draft: false
weight: 8
---

### Note: Trojan does not support this feature

The Trojan protocol itself has no encryption; its security depends on the underlying TLS. Under normal circumstances, TLS security is good and there is no need to encrypt Trojan traffic again. However, in some scenarios, you may not be able to guarantee the security of the TLS tunnel:

- You use WebSocket, relayed through an untrusted CDN (such as a domestic CDN)

- Your connection to the server has been subjected to a GFW man-in-the-middle attack targeting TLS

- Your certificate has expired and certificate validity cannot be verified

- You have used a pluggable transport layer that cannot guarantee cryptographic security

Etc.

Trojan-Go supports encrypting Trojan-Go traffic using Shadowsocks AEAD. The essence is adding a Shadowsocks AEAD encryption layer below the Trojan protocol. Both server and client must enable it simultaneously, and the password and encryption method must be identical, otherwise communication is impossible.

To enable AEAD encryption, simply add a `shadowsocks` option:

```json
...
"shadowsocks": {
    "enabled": true,
    "method": "AES-128-GCM",
    "password": "1234567890"
}
```

If `method` is omitted, AES-128-GCM is used by default. For more information, see the "Complete Configuration File" section.
