---
title: "Customizing the Protocol Stack"
draft: false
weight: 8
---

### Note: Trojan does not support this feature

Trojan-Go allows advanced users to customize the protocol stack. In custom mode, Trojan-Go relinquishes control of the protocol stack, allowing users to operate the underlying protocol stack combinations. For example:

- Building one or more additional TLS encryption layers on top of a TLS layer

- Using TLS to carry WebSocket traffic, then establishing another TLS on the WebSocket layer, then using Shadowsocks AEAD for encrypted transport on the second TLS layer

- Using Shadowsocks AEAD encrypted transport of Trojan protocol over a TCP connection

- Unwrapping inbound Trojan TLS traffic and re-wrapping it as new outbound Trojan TLS traffic

Etc.

**If you are not familiar with networking concepts, please do not try to use this feature. Incorrect configuration may cause Trojan-Go to malfunction, or cause performance and security issues.**

Trojan-Go abstracts all protocols (including routing functions, etc.) as tunnels. Each tunnel may provide a client (for sending) and/or a server (for receiving). The custom protocol stack customizes how tunnels are stacked.

### Before continuing, please first read the "Introduction" section in the Developer Guide to ensure you understand how Trojan-Go works.

Below are the tunnels supported by Trojan-Go and their properties:

| Tunnel      | Requires stream from below | Requires packet from below | Provides stream above | Provides packet above | Can be inbound | Can be outbound |
| ----------- | -------------------------- | -------------------------- | --------------------- | --------------------- | -------------- | --------------- |
| transport   | n                          | n                          | y                     | y                     | y              | y               |
| dokodemo    | n                          | n                          | y                     | y                     | y              | n               |
| tproxy      | n                          | n                          | y                     | y                     | y              | n               |
| tls         | y                          | n                          | y                     | n                     | y              | y               |
| trojan      | y                          | n                          | y                     | y                     | y              | y               |
| mux         | y                          | n                          | y                     | n                     | y              | y               |
| simplesocks | y                          | n                          | y                     | y                     | y              | y               |
| shadowsocks | y                          | n                          | y                     | n                     | y              | y               |
| websocket   | y                          | n                          | y                     | n                     | y              | y               |
| freedom     | n                          | n                          | y                     | y                     | n              | y               |
| socks       | y                          | y                          | y                     | y                     | y              | n               |
| http        | y                          | n                          | y                     | n                     | y              | n               |
| router      | y                          | y                          | y                     | y                     | n              | y               |
| adapter     | n                          | n                          | y                     | y                     | y              | n               |

The custom protocol stack works by defining tree/chain nodes, naming them with tags and adding configuration, then using tag-composed directed paths to describe the tree/chain. For example, for a typical Trojan-Go server, it can be described as follows:

Inbound, two paths in total. The tls node automatically identifies and dispatches trojan and websocket traffic:

- transport->tls->trojan

- transport->tls->websocket->trojan

Outbound, only one path is allowed:

- router->freedom

For inbound, describe multiple paths starting from the root to form a **multi-way tree** (can also degenerate to a single chain). A graph that does not satisfy tree properties will lead to undefined behavior. For outbound, a single **chain** must be described.

Each path must meet the following conditions:

1. Must begin with a tunnel that **does not require stream or packet from below** (transport/adapter/tproxy/dokodemo, etc.)

2. Must end with a tunnel that **can provide both packets and streams to the layer above** (trojan/simplesocks/freedom, etc.)

3. On the outbound single chain, all tunnels must be able to act as outbound. On all inbound paths, all tunnels must be able to act as inbound.

To enable the custom protocol stack, set `run_type` to `custom`. At this point, all options other than `inbound` and `outbound` will be ignored.

Below is an example. You can insert or remove protocol nodes on this basis. For conciseness, the configuration file uses YAML; you can also use JSON, the effect is equivalent modulo format differences.

Client `client.yaml`:

```yaml
run-type: custom

inbound:
  node:
    - protocol: adapter
      tag: adapter
      config:
        local-addr: 127.0.0.1
        local-port: 1080
    - protocol: socks
      tag: socks
      config:
        local-addr: 127.0.0.1
        local-port: 1080
  path:
    -
      - adapter
      - socks

outbound:
  node:
    - protocol: transport
      tag: transport
      config:
        remote-addr: you_server
        remote-port: 443

    - protocol: tls
      tag: tls
      config:
        ssl:
          sni: localhost
          key: server.key
          cert: server.crt

    - protocol: trojan
      tag: trojan
      config:
        password:
          - 12345678

  path:
    -
      - transport
      - tls
      - trojan

```

Server `server.yaml`:

```yaml
run-type: custom

inbound:
  node:
    - protocol: websocket
      tag: websocket
      config:
        websocket:
            enabled: true
            hostname: example.com
            path: /ws

    - protocol: transport
      tag: transport
      config:
        local-addr: 0.0.0.0
        local-port: 443
        remote-addr: 127.0.0.1
        remote-port: 80

    - protocol: tls
      tag: tls
      config:
        remote-addr: 127.0.0.1
        remote-port: 80
        ssl:
          sni: localhost
          key: server.key
          cert: server.crt

    - protocol: trojan
      tag: trojan1
      config:
        remote-addr: 127.0.0.1
        remote-port: 80
        password:
          - 12345678

    - protocol: trojan
      tag: trojan2
      config:
        remote-addr: 127.0.0.1
        remote-port: 80
        password:
          - 87654321

  path:
    -
      - transport
      - tls
      - trojan1
    -
      - transport
      - tls
      - websocket
      - trojan2

outbound:
  node:
    - protocol: freedom
      tag: freedom

  path:
    -
      - freedom
```
