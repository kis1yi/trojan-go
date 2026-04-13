---
title: "WebSocket"
draft: false
weight: 40
---

When using CDN relay, HTTPS is transparent to the CDN, which can inspect the WebSocket transmission content. Since the Trojan protocol itself transmits in plaintext, a Shadowsocks AEAD encryption layer can be added to obfuscate traffic characteristics and ensure security.

**If you are using a CDN provided by a carrier in mainland China, you must enable AEAD encryption**

After enabling AEAD encryption, the traffic carried via WebSocket will be encrypted with Shadowsocks AEAD. For the specific header format, refer to the Shadowsocks whitepaper.

After enabling WebSocket support, the protocol stack is as follows:

| Protocol    | Note                        |
| ----------- | ---------------- |
| Real Traffic    |                  |
| SimpleSocks | If multiplexing is enabled |
| smux        | If multiplexing is enabled |
| Trojan      |                  |
| Shadowsocks | If encryption is enabled     |
| WebSocket   |                  |
| Transport Layer Protocol  |                  |
