## Since the original project author is no longer maintaining it and cannot accept PRs, and the original project has many issues and bugs, this fork is maintained as a personal project.
## Other bugs or feature requests can be submitted as Issues
### Changes from the original version
- [x] Fixed multiple data race risks
- [x] Fixed the issue where adding users on the server side causes WebSocket access to become invalid
- [x] Server supports user data persistence using SQLite (Linux only)
- [x] Support specifying forwarding buffer size and count limits for better memory usage control
- [x] Fixed the issue where server-side upload rate limiting is ineffective
- [x] Fix the issue where blocking during connection forwarding may cause goroutine leaks

# Trojan-Go [![Go Report Card](https://goreportcard.com/badge/github.com/kis1yi/trojan-go)](https://goreportcard.com/report/github.com/kis1yi/trojan-go) [![Downloads](https://img.shields.io/github/downloads/kis1yi/trojan-go/total?label=downloads&logo=github&style=flat-square)](https://img.shields.io/github/downloads/kis1yi/trojan-go/total?label=downloads&logo=github&style=flat-square)

A complete Trojan proxy implemented in Go, compatible with the original Trojan protocol and configuration file format. Secure, efficient, lightweight, and easy to use.

Trojan-Go supports [multiplexing](#multiplexing) to improve concurrent performance; uses a [routing module](#routing-module) for domestic/overseas traffic splitting; supports [CDN traffic relay](#websocket) (based on WebSocket over TLS); supports [secondary encryption](#aead-encryption) of Trojan traffic using AEAD (based on Shadowsocks AEAD); supports pluggable [transport layer plugins](#transport-layer-plugins), allowing TLS to be replaced with other encrypted tunnels for Trojan protocol traffic.

Pre-compiled binary executables can be downloaded from the [Release page](https://github.com/kis1yi/trojan-go/releases). They can be run directly after extraction, with no other component dependencies.

If you encounter configuration and usage issues, find bugs, or have better ideas, you are welcome to join the [Telegram discussion group](https://t.me/trojan_go_chat).

## Introduction

**For a complete introduction and configuration tutorial, refer to the [Trojan-Go Documentation](https://kis1yi.github.io/trojan-go).**

Trojan-Go is compatible with most features of the original Trojan, including but not limited to:

- TLS tunneled transport
- UDP proxy
- Transparent proxy (NAT mode, iptables setup reference [here](https://github.com/shadowsocks/shadowsocks-libev/tree/v3.3.1#transparent-proxy))
- Mechanisms against GFW passive detection / active probing
- MySQL data persistence
- MySQL user permission authentication
- Per-user speed limits and IP limits persisted in MySQL, polled and applied at runtime
- User traffic statistics and quota limits
- Per-user quota management via CLI and gRPC API

Additionally, Trojan-Go also implements more efficient and easy-to-use features:

- "Easy mode" for quick deployment
- Automatic Socks5 / HTTP proxy detection
- TProxy-based transparent proxy (TCP / UDP)
- Full platform support, no special dependencies
- Multiplexing (smux) to reduce latency and improve concurrent performance
- Custom routing module for domestic/overseas traffic splitting / ad blocking, etc.
- WebSocket transport support for CDN traffic relay (WebSocket over TLS) and resistance against GFW man-in-the-middle attacks
- TLS fingerprint spoofing to resist GFW's TLS Client Hello fingerprint detection
- Encrypted Client Hello (ECH) support via uTLS, with GREASE ECH mode (fingerprint authenticity) and full ECH mode (real SNI encryption)
- gRPC-based API support for user management and speed limiting
- Pluggable transport layer to replace TLS with other protocols or plaintext, with full Shadowsocks obfuscation plugin support
- Support for the more user-friendly YAML configuration file format

## GUI Clients

Trojan-Go server is compatible with all original Trojan clients such as Igniter and ShadowRocket. The following clients support Trojan-Go extended features (WebSocket / Mux, etc.):

- [Qv2ray](https://github.com/Qv2ray/Qv2ray): Cross-platform client, supports Windows / macOS / Linux, uses the Trojan-Go core, supports all Trojan-Go extended features.
- [Igniter-Go](https://github.com/kis1yi/trojan-go-android): Android client, forked from Igniter with the core replaced by Trojan-Go and some modifications, supports all Trojan-Go extended features.

## Usage

1. Quick start server and client (Easy mode)

    - Server

        ```shell
        sudo ./trojan-go -server -remote 127.0.0.1:80 -local 0.0.0.0:443 -key ./your_key.key -cert ./your_cert.crt -password your_password
        ```

    - Client

        ```shell
        ./trojan-go -client -remote example.com:443 -local 127.0.0.1:1080 -password your_password
        ```

2. Start client / server / transparent proxy / relay using a config file (Normal mode)

    ```shell
    ./trojan-go -config config.json
    ```

3. Start client using a URL (format see documentation)

    ```shell
    ./trojan-go -url 'trojan-go://password@cloudflare.com/?type=ws&path=%2Fpath&host=your-site.com'
    ```

4. Deploy using Docker

    ```shell
    docker run \
        --name trojan-go \
        -d \
        -v /etc/trojan-go/:/etc/trojan-go \
        --network host \
        kis1yi/trojan-go
    ```

   or

    ```shell
    docker run \
        --name trojan-go \
        -d \
        -v /path/to/host/config:/path/in/container \
        --network host \
        kis1yi/trojan-go \
        /path/in/container/config.json
    ```

## Features

In general, Trojan-Go and Trojan are mutually compatible, but once you use the extended features described below (such as multiplexing, WebSocket, etc.), they become incompatible.

### Portability

The compiled Trojan-Go single executable does not depend on any other components. You can conveniently compile (or cross-compile) Trojan-Go and deploy it on your server, PC, Raspberry Pi, or even a router. Build tags can be used to remove modules to reduce the executable file size.

For example, to cross-compile a Trojan-Go for a mips processor, Linux OS, with client-only functionality, just run the command below, and the resulting executable can run directly on the target platform:

```shell
CGO_ENABLED=0 GOOS=linux GOARCH=mips go build -tags "client" -trimpath -ldflags "-s -w -buildid="
```

For a complete list of tag descriptions, refer to the [Trojan-Go Documentation](https://kis1yi.github.io/trojan-go).

### Ease of Use

The configuration file format is compatible with the original Trojan, but greatly simplified. Unspecified fields are assigned default values, making it more convenient to deploy servers and clients. Here is a simple example; for the complete configuration file see [here](https://kis1yi.github.io/trojan-go).

Server configuration file `server.json`:

```json
{
  "run_type": "server",
  "local_addr": "0.0.0.0",
  "local_port": 443,
  "remote_addr": "127.0.0.1",
  "remote_port": 80,
  "password": ["your_awesome_password"],
  "ssl": {
    "cert": "your_cert.crt",
    "key": "your_key.key",
    "sni": "www.your-awesome-domain-name.com"
  }
}
```

Client configuration file `client.json`:

```json
{
  "run_type": "client",
  "local_addr": "127.0.0.1",
  "local_port": 1080,
  "remote_addr": "www.your-awesome-domain-name.com",
  "remote_port": 443,
  "password": ["your_awesome_password"]
}
```

You can also use the more concise and readable YAML syntax. Here is a client example equivalent to the `client.json` above:

Client configuration file `client.yaml`:

```yaml
run-type: client
local-addr: 127.0.0.1
local-port: 1080
remote-addr: www.your-awesome-domain_name.com
remote-port: 443
password:
  - your_awesome_password
```

### WebSocket

Trojan-Go supports using TLS + WebSocket to carry the Trojan protocol, making it possible to relay traffic through CDNs.

Add the `websocket` option to both server and client configuration files to enable WebSocket support, for example:

```json
"websocket": {
    "enabled": true,
    "path": "/your-websocket-path",
    "hostname": "www.your-awesome-domain-name.com"
}
```

For a complete description of options, refer to the [Trojan-Go Documentation](https://kis1yi.github.io/trojan-go).

`hostname` can be omitted, but the `path` must be consistent between server and client. Once the server enables WebSocket support, it can simultaneously support both WebSocket and regular Trojan traffic. Clients without the WebSocket option configured can still use the service normally.

Since Trojan does not support WebSocket, although a Trojan-Go server with WebSocket support enabled can be compatible with all clients, if you want to use WebSocket to carry traffic, please ensure both sides use Trojan-Go.

### Multiplexing

Under very poor network conditions, a single TLS handshake can take a lot of time. Trojan-Go supports multiplexing (based on [smux](https://github.com/xtaci/smux)), carrying multiple TCP connections over a single TLS tunnel, reducing the latency caused by repeated TCP and TLS handshakes to improve performance in high-concurrency scenarios.

> Enabling multiplexing does not improve the link speed measured by speed tests (it may even decrease it), but it reduces latency and improves network experience for large numbers of concurrent requests, such as browsing web pages with many images.

You can enable it by setting the `enabled` field in the client's `mux` option:

```json
"mux": {
    "enabled": true
}
```

The `stream_buffer` and `receive_buffer` options (default 4 MB each) control the smux flow control window size. Larger values improve per-stream throughput on high-latency links. If customized, the values must match on both client and server.

The `protocol` option (default `2`) selects the smux wire protocol version. Set `protocol` to `1` for compatibility with the original trojan-go (p4gefau1t) and iOS clients such as Shadowrocket. Both client and server must use the same protocol version.

Only the client needs to enable mux; the server adapts automatically. For a complete description of options, refer to the [Trojan-Go Documentation](https://kis1yi.github.io/trojan-go).

### Routing Module

The Trojan-Go client has a built-in simple and practical routing module to conveniently implement custom routing functions such as direct connection for domestic traffic and proxy for overseas traffic.

There are three routing policies:

- `Proxy`: Route the request through the TLS tunnel, with the Trojan server connecting to the destination.
- `Bypass`: Connect directly to the destination using the local device.
- `Block`: Do not send the request, close the connection directly.

To activate the routing module, add the `router` option in the configuration file and set the `enabled` field to `true`:

```json
"router": {
    "enabled": true,
    "bypass": [
        "geoip:cn",
        "geoip:private",
        "full:localhost"
    ],
    "block": [
        "cidr:192.168.1.1/24",
    ],
    "proxy": [
        "domain:google.com",
    ],
    "default_policy": "proxy"
}
```

For a complete description of options, refer to the [Trojan-Go Documentation](https://kis1yi.github.io/trojan-go).

### AEAD Encryption

Trojan-Go supports secondary encryption of Trojan protocol traffic based on Shadowsocks AEAD, ensuring that WebSocket traffic cannot be identified and censored by untrusted CDNs:

```json
"shadowsocks": {
    "enabled": true,
    "password": "my-password"
}
```

To enable this, both server and client must enable it simultaneously with the same password.

### Transport Layer Plugins

Trojan-Go supports pluggable transport layer plugins and is compatible with Shadowsocks [SIP003](https://shadowsocks.org/en/wiki/Plugin.html) standard obfuscation plugins. Here is an example using `v2ray-plugin`:

> **This configuration is not secure, for demonstration purposes only**

Server configuration:

```json
"transport_plugin": {
    "enabled": true,
    "type": "shadowsocks",
    "command": "./v2ray-plugin",
    "arg": ["-server", "-host", "www.baidu.com"]
}
```

Client configuration:

```json
"transport_plugin": {
    "enabled": true,
    "type": "shadowsocks",
    "command": "./v2ray-plugin",
    "arg": ["-host", "www.baidu.com"]
}
```

For a complete description of options, refer to the [Trojan-Go Documentation](https://kis1yi.github.io/trojan-go).

## Build

> Please ensure Go version >= 1.26

Build using `make`:

```shell
git clone https://github.com/kis1yi/trojan-go.git
cd trojan-go
make
make install # Install systemd service, etc. (optional)
```

Or build using Go directly:

```shell
go build -tags "full"
```

Go supports cross-compilation by setting environment variables, for example:

Compile executable for 64-bit Windows:

```shell
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags "full"
```

Compile executable for Apple Silicon:

```shell
CGO_ENABLED=0 GOOS=macos GOARCH=arm64 go build -tags "full"
```

Compile executable for 64-bit Linux:

```shell
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags "full"
```

## Acknowledgements

- [Trojan](https://github.com/trojan-gfw/trojan)
- [V2Fly](https://github.com/v2fly)
- [utls](https://github.com/refraction-networking/utls)
- [smux](https://github.com/xtaci/smux)
- [go-tproxy](https://github.com/LiamHaworth/go-tproxy)

## Stargazers over time

[![Stargazers over time](https://starchart.cc/kis1yi/trojan-go.svg)](https://starchart.cc/kis1yi/trojan-go)
