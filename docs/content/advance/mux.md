---
title: "Enable Multiplexing to Improve Network Concurrency Performance"
draft: false
weight: 1
---

### Note: Trojan does not support this feature

Trojan-Go supports using multiplexing to improve network concurrency performance.

The Trojan protocol is based on TLS. Before a TLS secure connection is established, both parties need to perform key negotiation and exchange steps to ensure the security of subsequent communication. This process is the TLS handshake.

Currently the GFW inspects and interferes with TLS handshakes. Combined with congestion on egress networks, a regular TLS handshake often takes close to a second or more to complete. This can increase latency when browsing websites and watching videos.

Trojan-Go uses multiplexing to solve this problem. Each established TLS connection carries multiple TCP connections. When a new proxy request arrives, instead of performing a new TLS handshake to establish a new TLS connection with the server, existing TLS connections are reused as much as possible. This reduces the latency caused by repeated TLS and TCP handshakes.

Enabling multiplexing will not increase your link speed (it may even decrease it), and may increase the computational load on both server and client. It can be roughly understood as: multiplexing trades network throughput and CPU power for lower latency. In high-concurrency scenarios, such as browsing web pages with many images or sending large numbers of UDP requests, it can improve the experience.

To activate the `mux` module, simply set the `enabled` field in the `mux` option to `true`. Here is a client example:

```json
...
"mux" :{
    "enabled": true
}
```

Only the client needs to be configured; the server adapts automatically without needing to configure the `mux` option.

The complete mux configuration is as follows:

```json
"mux": {
    "enabled": false,
    "concurrency": 8,
    "idle_timeout": 60,
    "stream_buffer": 4194304,
    "receive_buffer": 4194304
}
```

`concurrency` is the maximum number of TCP connections each TLS connection can carry. The larger this value, the lower the handshake latency when multiple connections are concurrent, but the server and client will be under more computational load, which may decrease your network throughput. If your line's TLS handshake is extremely slow, you can set this to `-1`, meaning Trojan-Go will only perform one TLS handshake and use only one single TLS connection for all transmission.

`idle_timeout` specifies how long each TLS connection should remain idle before being closed. Setting a timeout **may** help reduce unnecessary keepalive traffic that could trigger GFW probing. You can set this to `-1`, which means TLS connections will be closed immediately when idle.

`stream_buffer` specifies the maximum buffer size in bytes per multiplexed stream (smux flow control window). The default is 4194304 (4 MB). Increasing this value allows higher throughput per stream at the cost of more memory usage. If customized, the value must match on both client and server.

`receive_buffer` specifies the maximum total receive buffer size in bytes per smux session. The default is 4194304 (4 MB). This value must be greater than or equal to `stream_buffer`. If customized, the value must match on both client and server.
