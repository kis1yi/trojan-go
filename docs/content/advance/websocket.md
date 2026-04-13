---
title: "Using WebSocket for CDN Relay and Resistance Against Man-in-the-Middle Attacks"
draft: false
weight: 2
---

### Note: Trojan does not support this feature

Trojan-Go supports using TLS+WebSocket to carry the Trojan protocol, making it possible to relay traffic through a CDN.

The Trojan protocol itself does not include encryption; its security depends on the outer TLS layer. However, once traffic passes through a CDN, TLS is transparent to the CDN. The service provider can inspect the plaintext content of TLS traffic. **If you are using an untrusted CDN (any CDN service registered in mainland China should be considered untrusted), you must enable Shadowsocks AEAD to encrypt WebSocket traffic to avoid identification and censorship.**

Add the websocket option to both the server and client configuration files, set its `enabled` field to `true`, and fill in the `path` and `host` fields to enable WebSocket support. Here is a complete WebSocket option example:

```json
"websocket": {
    "enabled": true,
    "path": "/your-websocket-path",
    "host": "example.com"
}
```

`host` is the hostname, typically the domain name. The client `host` is optional; fill in your domain name. If left empty, `remote_addr` will be used.

`path` refers to the URL path where the WebSocket resides, and must start with a slash ("/"). There are no special requirements for the path as long as it follows the basic URL format, but the `path` must be consistent between client and server. The `path` should be a relatively long string to avoid direct active probing by the GFW.

The client `host` will be included in the WebSocket handshake HTTP request sent to the CDN server and must be valid; the server and client `path` must match, otherwise the WebSocket handshake cannot proceed.

Here is an example client configuration file

```json
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "www.your_awesome_domain_name.com",
    "remote_port": 443,
    "password": [
        "your_password"
    ],
    "websocket": {
        "enabled": true,
        "path": "/your-websocket-path",
        "host": "example.com"
    },
    "shadowsocks": {
        "enabled": true,
        "password": "12345678"
    }
}
```
