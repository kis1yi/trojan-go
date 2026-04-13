---
title: "Pluggable Transport Layer Plugin Development"
draft: false
weight: 150
---

Trojan-Go encourages the development of transport layer plugins to enrich protocol diversity and increase the strategic depth of confrontation with the GFW.

The role of a transport layer plugin is to replace the TLS in the transport tunnel for transmission encryption and obfuscation.

Plugins communicate with Trojan-Go via TCP sockets, with no coupling to Trojan-Go itself. You can develop using any language and design pattern you prefer. We recommend following the [SIP003](https://shadowsocks.org/en/spec/Plugin.html) standard. Plugins developed this way can be used with both Trojan-Go and Shadowsocks.

After enabling the plugin functionality, Trojan-Go only uses TCP for transmission (plaintext). Your plugin only needs to handle inbound TCP requests. You can convert these TCP streams into any traffic format you like, such as QUIC, HTTP, or even ICMP.

The Trojan-Go plugin design principles differ slightly from those of Shadowsocks:

1. The plugin itself can perform encryption, obfuscation, integrity verification, and replay attack resistance on transmitted content.

2. The plugin should impersonate an existing, commonly used service (call it Service X) and its traffic, embedding encrypted content within it.

3. The server-side plugin, upon detecting tampered or replayed content, **must hand the connection over to Trojan-Go for processing**. The specific steps are: forward all already-read and unread content to Trojan-Go and establish a bidirectional connection, rather than dropping it directly. Trojan-Go will then connect to a real Service X server, causing the attacker to interact directly with the real Service X server.

The explanation is as follows:

The first principle exists because the Trojan protocol itself is not encrypted. When TLS is replaced by a transport plugin, **full trust is placed in the security of the plugin**.

The second principle inherits the spirit of Trojan. The best place to hide a tree is a forest.

The third principle is to fully leverage Trojan-Go's anti-active-probing capability. Even if the GFW actively probes your server, the server will behave consistently with Service X, leaving no other distinguishable characteristics.

For clarity, here is an example:

1. Suppose your plugin disguises itself as MySQL traffic. The firewall detects unusually high MySQL traffic through traffic sniffing and decides to actively connect to your server for probing.

2. The firewall connects to your server and sends a probe payload. Your Trojan-Go server-side plugin, after verification, determines the abnormal connection is not proxy traffic, and hands the connection over to Trojan-Go.

3. Trojan-Go detects the abnormal connection and redirects it to a real MySQL server. The firewall then interacts with the real MySQL server, finds its behavior indistinguishable from a genuine MySQL server, and is unable to block the service.

Additionally, even if your protocol and plugin do not satisfy principles 2 and 3, or even do not fully satisfy principle 1, we still encourage development. Since the GFW only audits and blocks popular protocols, such protocols (homemade cryptography / homemade protocols), as long as they are not publicly published, can maintain very strong vitality.
