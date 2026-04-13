---
title: "SimpleSocks Protocol"
draft: false
weight: 50
---

SimpleSocks is a simple proxy protocol without an authentication mechanism; it is essentially the Trojan protocol with sha224 removed. The purpose of this protocol is to reduce overhead during multiplexing.

This protocol is only used for multiplexed connections when multiplexing is enabled. That is, SimpleSocks is always carried by SMux.

SimpleSocks is even simpler than Socks5. Below is the header structure.

```text
+-----+------+----------+----------+-----------+
| CMD | ATYP | DST.ADDR | DST.PORT |  Payload  |
+-----+------+----------+----------+-----------+
|  1  |  1   | Variable |    2     |  Variable |
+-----+------+----------+----------+-----------+
```

The field definitions are the same as the Trojan protocol and will not be repeated here.
