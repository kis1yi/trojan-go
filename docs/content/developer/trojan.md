---
title: "Trojan Protocol"
draft: false
weight: 20
---

Trojan-Go follows the original Trojan protocol. For the specific format, please refer to the [Trojan documentation](https://trojan-gfw.github.io/trojan/protocol); it will not be repeated here.

By default, the Trojan protocol is carried by TLS. The protocol stack is as follows:

| Protocol   |
| ---------- |
| Real Traffic |
| Trojan     |
| TLS        |
| TCP        |
