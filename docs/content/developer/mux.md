---
title: "Multiplexing"
draft: false
weight: 30
---

Trojan-Go uses [smux](https://github.com/xtaci/smux) to implement multiplexing. It also implements the simplesocks protocol for proxy transport.

When multiplexing is enabled, the client first initiates a TLS connection using the normal Trojan protocol format, but fills the Command field with 0x7f (protocol.Mux) to identify the connection as a multiplexed one (similar to HTTP's upgrade). The connection is then handed over to the smux client for management. After the server receives the request header, the smux server parses all traffic on that connection. On each demultiplexed smux connection, the simplesocks protocol (Trojan protocol with authentication removed) is used to identify the proxy destination. The top-down protocol stack is as follows:

| Protocol            | Note               |
| ----------- | -------- |
| Real Traffic        |
| SimpleSocks |
| smux        |
| Trojan      | For Authentication |
| Underlying Protocol |                  |
