---
title: "Basic Principles of Trojan"
draft: false
weight: 21
---

This page briefly describes the basic working principles of the Trojan protocol. If you are not interested in how GFW and Trojan work, you can skip this section. However, for better protection of your communication security and node concealment, I still recommend reading it.

## Why Shadowsocks (with stream ciphers) is Easily Blocked

In its early days, the firewall only intercepted and inspected outbound traffic — what is called **passive detection**. The encryption protocol design of Shadowsocks made the transmitted data packets themselves have almost no distinguishing features, looking like a completely random bitstream, which was indeed effective at bypassing the GFW in the early days.

The current GFW has started using **active probing**. Specifically, when the GFW discovers a suspicious unrecognized connection (large traffic, random byte streams, high-numbered ports, etc.), it will **actively connect** to the server's port and replay previously captured traffic (or replay it after some careful modifications). The Shadowsocks server detects the abnormal connection and closes it. This abnormal traffic and connection-closing behavior is regarded as a characteristic of a suspicious Shadowsocks server, and the server is added to the GFW's suspect list. This list may not immediately take effect, but during some special sensitive periods, servers on the suspect list may be temporarily or permanently blocked. Whether this list is blocked may be determined by human factors.

If you want to learn more, please refer to [this article](https://gfw.report/blog/gfw_shadowsocks/).

## How Trojan Bypasses the GFW

Unlike Shadowsocks, Trojan does not use a custom encryption protocol to hide itself. Instead, it uses TLS (TLS/SSL) — a protocol with obvious characteristics — making traffic look the same as a normal HTTPS website. TLS is a mature encryption system; HTTPS uses TLS to carry HTTP traffic. Using a **correctly configured** encrypted TLS tunnel guarantees:

- Confidentiality (GFW cannot learn the content of transmission)
- Integrity (once GFW attempts to tamper with the encrypted ciphertext, both communicating parties will detect it)
- Non-repudiation (GFW cannot forge identities to impersonate the server or client)
- Forward secrecy (even if the key is leaked, GFW cannot decrypt previously encrypted traffic)

For passive detection, Trojan protocol traffic has exactly the same characteristics and behavior as HTTPS traffic. HTTPS traffic accounts for more than half of current internet traffic, and once the TLS handshake succeeds all traffic is encrypted ciphertext, making it practically infeasible to distinguish Trojan protocol traffic from it.

For active detection, when the firewall actively connects to the Trojan server for detection, Trojan can correctly identify non-Trojan protocol traffic. Unlike Shadowsocks and other proxies, at this point Trojan does not close the connection but instead proxies this connection to a normal web server. From GFW's perspective, the server's behavior is exactly the same as a normal HTTPS website, making it impossible to determine whether it is a Trojan proxy node. This is also why Trojan recommends using a legitimate domain name and an HTTPS certificate signed by an authoritative CA: it makes your server completely undetectable as a Trojan server by GFW using active probing.

Therefore, at the present time, to identify and block Trojan connections, one can only use indiscriminate blocking (blocking an IP segment, a class of certificates, a class of domain names, or even blocking all outbound HTTPS connections) or launch large-scale man-in-the-middle attacks (hijacking all TLS traffic and certificates to inspect content). For man-in-the-middle attacks, dual TLS via WebSocket can be used as a countermeasure, as explained in detail in the advanced configuration section.
