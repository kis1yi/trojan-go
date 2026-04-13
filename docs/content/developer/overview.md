---
title: "Overview"
draft: false
weight: 1
---

The core components of Trojan-Go are:

- tunnel — concrete implementations of each protocol

- proxy — proxy core

- config — configuration registration and parsing module

- redirector — active detection spoofing module

- statistics — user authentication and statistics module

Source code can be found in the corresponding folders.

## tunnel.Tunnel

Trojan-Go abstracts all protocols (including routing functionality, etc.) as tunnels (the `tunnel.Tunnel` interface). Each tunnel can open a server side (`tunnel.Server` interface) and a client side (`tunnel.Client`). Each server can strip and accept streams (`tunnel.Conn`) and packets (`tunnel.PacketConn`) from its underlying tunnel. A client can create streams and packets towards the underlying tunnel.

Each tunnel does not care what tunnel lies below it, but each tunnel clearly knows information about the other tunnels above it.

All tunnels require the lower layer to provide stream or packet transport support, or both. All tunnels must provide stream transport support to the upper layer, but do not necessarily need to provide packet transport.

A tunnel may have only a server side, only a client side, or both. A tunnel with both sides can be used as the transport tunnel between Trojan-Go client and server.

Note: please distinguish between Trojan-Go's server/client and the tunnel's server/client. Below is an illustrative diagram.

```text

  Inbound                           GFW                                 Outbound
-------->Tunnel A Server->Tunnel B Client ----------------> Tunnel B Server->Tunnel C Client----------->
           (Trojan-Go Client)                                (Trojan-Go Server)

```

The bottommost tunnel is the transport layer — i.e., a tunnel that does not obtain or create streams and packets from other tunnels, playing the role of Tunnel A or C in the diagram above.

- transport — pluggable transport layer

- socks — socks5 proxy, tunnel server only
  
- tproxy — transparent proxy, tunnel server only

- dokodemo — reverse proxy, tunnel server only

- freedom — free outbound, tunnel client only

These tunnels create streams and packets directly from TCP/UDP sockets, and do not accept any underlying tunnels.

Other tunnels can in principle be combined and stacked in any manner and number, as long as the lower layer satisfies the upper layer's requirements for stream and packet transport. These tunnels play the role of Tunnel B in the diagram above:

- trojan

- websocket

- mux

- simplesocks

- tls

- router — routing functionality, tunnel client only

None of them care about their underlying tunnel implementation, but can distribute incoming streams and packets to upper-layer tunnels.

For example, in this diagram, a typical Trojan-Go client and server have tunnels stacked from bottom to top as:

- Tunnel A: transport->socks

- Tunnel B: transport->tls->trojan

- Tunnel C: freedom

In practice the actual tunnel stacking will be somewhat more complex than this. Typically, the inbound tunnel forms a multi-child tree rather than a single chain. For a detailed explanation, see below.

## proxy.Proxy — The Proxy Core

The role of the proxy core is to listen on the protocol stack formed by combining and stacking the tunnels described above, extract streams and packets (along with their metadata) from all inbound protocol stacks (the leaf nodes of multiple tunnel servers, described below), and forward them to the outbound protocol stack (a single tunnel client).

Note that there can be multiple inbound protocol stacks here. For example, the client can simultaneously extract streams and packets from both Socks5 and HTTP protocol stacks; the server can simultaneously extract streams and packets from both WebSocket-based Trojan protocol and TLS-based Trojan protocol. However, there can only be one outbound protocol stack, such as TLS-based Trojan protocol for outbound traffic.

To describe how inbound protocol stacks (tunnel servers) are combined and stacked, a multi-child tree is used to describe all protocol stacks. You can see the tree-building process in the components in the proxy folder.

The outbound protocol stack is simpler and can be described with a simple list.

So in practice, for a typical client/server with both WebSocket and Mux enabled, the tunnel stacking model from the diagram above is:

Client

- Inbound (tree)
  - transport (root)
    - adapter — can identify HTTP and Socks traffic and distribute to upper-layer protocols
      - http (leaf node)
      - socks (leaf node)

- Outbound (chain)
  - transport (root)
  - tls
  - websocket
  - trojan
  - mux
  - simplesocks

Server

- Inbound (tree)
  - transport (root)
    - tls — can identify HTTP and non-HTTP traffic and distribute
      - websocket
        - trojan (leaf node)
          - mux
            - simplesocks (leaf node)
      - trojan — can identify mux and regular trojan traffic and distribute (leaf node)
        - mux
          - simplesocks (leaf node)

- Outbound (chain)
  - freedom

Note that the proxy core only extracts streams and packets from the leaf nodes of the tunnel tree, and forwards them to the single outbound. The purpose of having multiple leaf nodes is to make Trojan-Go simultaneously compatible with WebSocket and Trojan protocol inbound, inbound connections with/without Mux enabled, and HTTP/Socks5 auto-detection. Each tree node with multiple children has the ability to precisely identify and distribute streams and packets to different child nodes. This aligns with our assumption that each protocol knows about the upper-layer protocols it carries.
