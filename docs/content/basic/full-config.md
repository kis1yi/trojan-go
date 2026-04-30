---
title: "Complete Configuration File"
draft: false
weight: 30
---

Below is a complete configuration file. The required fields are:

- ```run_type```

- ```local_addr```

- ```local_port```

- ```remote_addr```

- ```remote_port```

For the server ```server```, ```key``` and ```cert``` are required.

For the client ```client```, the reverse proxy tunnel ```forward```, and the transparent proxy ```nat```, ```password``` is required.

All other unspecified options will be filled with the values given below.

*Trojan-Go supports the more human-friendly YAML syntax. The basic structure of the configuration file is the same as JSON and yields equivalent results. However, to follow YAML naming conventions, you need to convert underscores ("_") to hyphens ("-"), e.g. `remote_addr` becomes `remote-addr` in YAML files.*

```json
{
  "run_type": *required*,
  "local_addr": *required*,
  "local_port": *required*,
  "remote_addr": *required*,
  "remote_port": *required*,
  "log_level": 1,
  "log_file": "",
  "password": [],
  "disable_http_check": false,
  "udp_timeout": 60,
  "ssl": {
    "verify": true,
    "verify_hostname": true,
    "cert": *required*,
    "key": *required*,
    "key_password": "",
    "cipher": "",
    "curves": "",
    "prefer_server_cipher": false,
    "sni": "",
    "alpn": [
      "http/1.1"
    ],
    "session_ticket": true,
    "reuse_session": true,
    "plain_http_response": "",
    "fallback_addr": "",
    "fallback_port": 0,
    "fingerprint": "",
    "ech": false,
    "ech_config": ""
  },
  "tcp": {
    "no_delay": true,
    "keep_alive": true,
    "prefer_ipv4": false,
    "proxy_protocol": false
  },
  "mux": {
    "enabled": false,
    "concurrency": 8,
    "idle_timeout": 60,
    "stream_buffer": 4194304,
    "receive_buffer": 4194304,
    "protocol": 2
  },
  "router": {
    "enabled": false,
    "bypass": [],
    "proxy": [],
    "block": [],
    "default_policy": "proxy",
    "domain_strategy": "as_is",
    "geoip": "$PROGRAM_DIR$/geoip.dat",
    "geosite": "$PROGRAM_DIR$/geosite.dat"
  },
  "websocket": {
    "enabled": false,
    "path": "",
    "host": ""
  },
  "shadowsocks": {
    "enabled": false,
    "method": "AES-128-GCM",
    "password": ""
  },
  "transport_plugin": {
    "enabled": false,
    "type": "",
    "command": "",
    "option": "",
    "arg": [],
    "env": []
  },
  "forward_proxy": {
    "enabled": false,
    "proxy_addr": "",
    "proxy_port": 0,
    "username": "",
    "password": ""
  },
  "mysql": {
    "enabled": false,
    "server_addr": "localhost",
    "server_port": 3306,
    "database": "",
    "username": "",
    "password": "",
    "check_rate": 60
  },
  "api": {
    "enabled": false,
    "api_addr": "",
    "api_port": 0,
    "ssl": {
      "enabled": false,
      "key": "",
      "cert": "",
      "verify_client": false,
      "client_cert": []
    }
  }
}
```

## Description

### General Options

For client/nat/forward, `remote_xxxx` should contain your Trojan server address and port, while `local_xxxx` corresponds to the locally open Socks5/HTTP proxy address (auto-detected).

For server, `local_xxxx` corresponds to the Trojan server listening address (port 443 is strongly recommended), and `remote_xxxx` contains the HTTP service address to proxy to when non-Trojan traffic is detected, usually local port 80.

`log_level` specifies the log level. The higher the level, the less information is output. Valid values are:

- 0 Output Debug and above logs (all logs)

- 1 Output Info and above logs

- 2 Output Warning and above logs

- 3 Output Error and above logs

- 4 Output Fatal and above logs

- 5 No log output at all

`log_file` specifies the log output file path. If not specified, standard output is used.

`password` can contain multiple passwords. In addition to configuring passwords via the config file, trojan-go also supports configuring passwords via MySQL, see below. The client password must match a password in the server's configuration file or database records to pass server validation and use the proxy service normally.

`disable_http_check` whether to disable the HTTP camouflage server availability check.

`udp_timeout` UDP session timeout.

### ```ssl``` Options

`verify` indicates whether the client (client/nat/forward) verifies the validity of the server's certificate. Enabled by default. For security reasons, this option should not be set to false in real scenarios, as it may expose you to man-in-the-middle attacks. If using self-signed or self-issued certificates, enabling `verify` will cause validation to fail. In this case, keep `verify` enabled and fill in the server's certificate in `cert` to connect normally.

`verify_hostname` indicates whether the server verifies that the SNI provided by the client is consistent with the server's setting. If the server SNI field is left blank, authentication is forcibly disabled.

The server must fill in `cert` and `key`, corresponding to the server's certificate and private key files. Please check whether the certificate is valid/expired. If using a certificate signed by an authoritative CA, the client (client/nat/forward) does not need to fill in `cert`. If using self-signed or self-issued certificates, fill in the server certificate file at `cert`, otherwise validation may fail.

`sni` refers to the server name field in the TLS client request, generally the same as the certificate's Common Name. If you are using a certificate issued by Let's Encrypt etc., fill in your domain name here. For the client, if this field is not filled in, `remote_addr` will be used. You should specify a valid SNI (consistent with the remote certificate CN), otherwise the client may not be able to verify the remote certificate's validity and fail to connect. For the server, if this field is not filled in, the Common Name in the certificate is used as the SNI validation basis, supporting wildcards such as `*.example.com`.

`fingerprint` is used to specify the client TLS Client Hello fingerprint spoofing type, to resist GFW's fingerprint recognition and blocking of TLS Client Hello. trojan-go uses [utls](https://github.com/refraction-networking/utls) for fingerprint spoofing, and **by default spoofs the Chrome fingerprint** (an empty or unset value resolves to `chrome`). Valid values are:

- `""`, use the default fingerprint (currently `chrome`)

- `"chrome"`, spoof Chrome fingerprint (default)

- `"firefox"`, spoof Firefox fingerprint

- `"ios"`, spoof iOS fingerprint

- `"edge"`, spoof Microsoft Edge fingerprint

- `"safari"`, spoof Safari fingerprint

- `"360browser"`, spoof 360 Browser fingerprint

- `"qqbrowser"`, spoof QQ Browser fingerprint

The default is enforced by the `TestDefaultFingerprintIsChrome` regression test in `tunnel/tls`; the value will not change silently across releases. See [Advanced TLS settings](../../advance/tls) for ECH/ALPN interactions.

Once the fingerprint value is set, the client's `cipher`, `curves`, `alpn`, `session_ticket` and other fields that may affect the fingerprint will be overwritten with the specific settings of that fingerprint.

`ech` whether to enable Encrypted Client Hello (ECH). When enabled, the client will hide the real SNI during the TLS handshake. Two modes are supported:

- When `ech` is set to `true` and `ech_config` is empty, **GREASE ECH** mode is used: trojan-go adds a fake ECH extension to the Client Hello to mimic the behaviour of browsers like Chrome. The real SNI is **not** encrypted in this mode — it still travels in plaintext in the outer Client Hello. The point is fingerprint authenticity, not confidentiality.
- When `ech` is set to `true` and `ech_config` is non-empty, **full ECH** mode is used, and the real SNI will be transmitted in encrypted form to the ECH-enabled origin. The outer SNI is taken from the ECHConfigList, so a correct, up-to-date `ech_config` is required.

`ech_config` The ECHConfigList used in full ECH mode, base64-encoded, typically obtained by querying the HTTPS record of the target domain via a trusted DNS resolver. If `ech` is `false`, this field is ignored (a `WARN` is logged at startup).

`alpn` specifies the application-layer protocol negotiation for TLS. It is transmitted in the TLS Client/Server Hello and negotiates the application-layer protocol to use. This is only used for fingerprint spoofing and has no practical effect. **If using a CDN, an incorrect alpn field may cause the CDN to negotiate an incorrect application layer protocol.**

`prefer_server_cipher` whether the client prefers the cipher suite provided by the server during negotiation.

`cipher` The TLS cipher suite. The `cipher13` field is merged with this field. You should only fill this in if you clearly know what you are doing. **In normal circumstances, you should leave this empty or not fill it in.** trojan-go will automatically select the most appropriate encryption algorithm based on the current hardware platform and remote conditions to improve performance and security. If you need to fill it in, cipher suite names are separated by semicolons (":") in priority order. Go's TLS library has deprecated some insecure TLS 1.2 cipher suites and fully supports TLS 1.3. By default, trojan-go will prefer the more secure TLS 1.3.

`curves` specifies the elliptic curves that TLS prefers to use in ECDHE. Only fill this in if you clearly know what you are doing. Curve names are separated by semicolons (":") in priority order.

`plain_http_response` refers to the raw data (raw TCP data) that the server sends in plaintext when TLS handshake fails. Fill in the file path for this field. It is recommended to use `fallback_port` instead of this field.

`fallback_addr` and `fallback_port` specify the address to which trojan-go redirects the connection when the server TLS handshake fails. This is a trojan-go feature to better hide the server and resist GFW's active probing, making the server's port 443 behave exactly like a normal server when probed with non-TLS protocols. When the server accepts a connection but cannot perform TLS handshake, if `fallback_port` is non-empty, the traffic will be proxied to `fallback_addr:fallback_port`. If `fallback_addr` is empty, `remote_addr` is used. For example, you can run an HTTPS service locally with nginx, and when your server's port 443 receives a non-TLS protocol request (such as an HTTP request), trojan-go will proxy it to the local HTTPS server, and nginx will return a 400 Bad Request page in plaintext HTTP. You can verify this by using a browser to access `http://your-domain-name.com:443`.

`key_log` The file path for the TLS key log. If filled in, key logging is enabled. **Recording keys breaks TLS security and this option should not be used for any purpose other than debugging.**

### ```mux``` Multiplexing Options

Multiplexing is a trojan-go feature. If both server and client use trojan-go, you can enable mux multiplexing to reduce latency in high-concurrency scenarios (only the client needs to enable this option; the server adapts automatically).

Note that the significance of multiplexing is to reduce handshake latency, not to improve link speed. On the contrary, it increases CPU and memory consumption on both client and server, which may cause speed reduction.

`enabled` whether to enable multiplexing.

`concurrency` specifies the maximum number of connections a single TLS tunnel can carry, defaulting to 8. The larger this value, the lower the latency caused by TLS handshakes when many connections are concurrent, but network throughput may decrease. A negative number or 0 means all connections use only one TLS tunnel.

`idle_timeout` idle timeout. Specifies how long after the TLS tunnel is idle before it is closed, in seconds. If the value is negative or 0, the TLS tunnel is closed immediately when idle.

`stream_buffer` specifies the maximum buffer size in bytes per multiplexed stream (smux flow control window). The default is 4194304 (4 MB). Increasing this value allows higher throughput per stream at the cost of more memory usage. If customized, the value must match on both client and server.

`receive_buffer` specifies the maximum total receive buffer size in bytes per smux session. The default is 4194304 (4 MB). This value must be greater than or equal to `stream_buffer`. If customized, the value must match on both client and server.

`protocol` the smux wire protocol version (`1` or `2`, default `2`). Set to `1` for compatibility with the original trojan-go and iOS clients such as Shadowrocket. Both client and server must use the same protocol version.

### ```router``` Routing Options

The routing function is a trojan-go feature. trojan-go has three routing policies:

- Proxy. Route the request through the TLS tunnel; trojan server connects to the destination.

- Bypass. Connect directly to the destination locally.

- Block. Do not proxy the request, directly close the connection.

Fill in the corresponding geoip/geosite or routing rules in the `proxy`, `bypass`, `block` fields, and trojan-go will execute the corresponding routing policy according to the IP (CIDR) or domain names in the lists. The client can configure three policies; the server can only configure the block policy.

`enabled` whether to enable the routing module.

`default_policy` refers to the default policy used when all three list matches fail, defaulting to "proxy" (i.e., proxy the connection). Valid values are:

- "proxy"

- "bypass"

- "block"

Same meaning as above.

`domain_strategy` Domain name resolution strategy, default "as_is". Valid values are:

- "as_is", only match within the domain name rules in each list.

- "ip_if_non_match", first match within the domain name rules in each list; if no match, resolve to IP and match within the IP address rules in each list. This strategy may cause DNS leaks or DNS poisoning.

- "ip_on_demand", first resolve to IP and match within the IP address rules in each list; if no match, match within the domain name rules in each list. This strategy may cause DNS leaks or DNS poisoning.

The `geoip` and `geosite` fields specify the paths to the geoip and geosite database files, defaulting to geoip.dat and geosite.dat in the program directory. You can also specify the working directory via the environment variable TROJAN_GO_LOCATION_ASSET.

### ```websocket``` Options

WebSocket transport is a trojan-go feature. **Under normal direct proxy node connection conditions**, enabling this option will not improve your link speed (it may even decrease it), nor will it improve your connection security. You should only use WebSocket when you need to use CDN relay, or when distributing traffic by path using nginx or similar servers.

`enabled` indicates whether to enable WebSocket to carry traffic. When enabled on the server, it supports both regular Trojan protocol and WebSocket-based Trojan protocol simultaneously. When enabled on the client, it will only use WebSocket to carry all Trojan protocol traffic.

`path` refers to the URL path used by WebSocket, must start with a slash ("/"), such as "/longlongwebsocketpath", and must be consistent between server and client.

`host` The hostname used in the HTTP request during WebSocket handshake. If left empty on the client, `remote_addr` is used. If using a CDN, this option generally contains the domain name. An incorrect `host` may prevent the CDN from forwarding requests.

### ```shadowsocks``` AEAD Encryption Options

This option is used to replace the deprecated obfuscation encryption and dual TLS. If this option is enabled, a Shadowsocks AEAD encryption layer will be inserted below the Trojan protocol layer. That is, within the (already encrypted) TLS tunnel, all Trojan protocols will be further encrypted using AEAD. Note that this option is independent of whether WebSocket is enabled. Whether or not WebSocket is enabled, all Trojan traffic will be additionally encrypted.

Note that enabling this option may reduce transmission performance. You should only enable this option when you do not trust the transmission channel carrying the Trojan protocol. For example:

- You use WebSocket, relayed through an untrusted CDN (such as a domestic CDN)

- Your connection to the server has been subjected to a GFW man-in-the-middle attack targeting TLS

- Your certificate has expired and certificate validity cannot be verified

- You have used a pluggable transport layer that cannot guarantee cryptographic security

Etc.

Since AEAD is used, trojan-go can correctly determine whether a request is valid or whether it has been actively probed, and respond accordingly.

`enabled` whether to enable Shadowsocks AEAD encryption of the Trojan protocol layer.

`method` Encryption method. Valid values are:

- "CHACHA20-IETF-POLY1305"

- "AES-128-GCM" (default)

- "AES-256-GCM"

`password` The password used to generate the master key. If AEAD encryption is enabled, this must be consistent between client and server.

### ```transport_plugin``` Transport Layer Plugin Options

`enabled` whether to enable the transport layer plugin to replace TLS transport. Once transport layer plugin support is enabled, trojan-go will **pass unencrypted trojan protocol traffic in plaintext to the plugin**, allowing users to apply custom obfuscation and encryption to the traffic.

`type` Plugin type. Currently supported types are:

- "shadowsocks", supports Shadowsocks obfuscation plugins conforming to the [SIP003](https://shadowsocks.org/en/spec/Plugin.html) standard. trojan-go will replace environment variables and modify its own configuration (`remote_addr/remote_port/local_addr/local_port`) at startup according to the SIP003 standard, allowing the plugin to communicate directly with the remote end, while trojan-go only listens to/connects to the plugin.

- "plaintext", uses plaintext transport. Selecting this option, trojan-go will not modify any address configuration (`remote_addr/remote_port/local_addr/local_port`), will not start the plugin in `command`, and only removes the bottom-level TLS transport layer and uses TCP plaintext transport. This option is intended to support nginx and other tools that take over TLS and perform traffic splitting, as well as for advanced users for debugging and testing. **Do not use plaintext transport mode directly to penetrate firewalls.**

- "other", other plugins. Selecting this option, trojan-go will not modify any address configuration (`remote_addr/remote_port/local_addr/local_port`), but will start the plugin in `command` and pass parameters and environment variables.

`command` Path to the transport layer plugin executable. trojan-go will execute it when starting.

`arg` Transport layer plugin startup parameters. This is a list, such as `["-config", "test.json"]`.

`env` Transport layer plugin environment variables. This is a list, such as `["VAR1=foo", "VAR2=bar"]`.

`option` Transport layer plugin configuration (SIP003). For example, `"obfs=http;obfs-host=www.baidu.com"`.

### ```tcp``` Options

`no_delay` whether TCP packets are sent immediately without waiting for the buffer to fill.

`keep_alive` whether to enable TCP keepalive detection.

`prefer_ipv4` whether to prefer IPv4 addresses.

`proxy_protocol` (server only) whether to enable [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) (v1/v2) support. When trojan-go runs behind a reverse proxy such as nginx, all connections appear to originate from the loopback address (e.g. `127.0.0.1`), which makes features like `ip_limit` ineffective. Enabling this option allows trojan-go to read the real client IP from the PROXY protocol header sent by the upstream proxy. **Only enable this when the upstream proxy is configured to send PROXY protocol headers** (e.g. `proxy_protocol on;` in nginx stream). Accepting PROXY protocol from untrusted sources may allow IP spoofing.

### ```mysql``` Database Options

trojan-go is compatible with Trojan's MySQL-based user management, but the more recommended approach is to use the API.

`enabled` indicates whether to use a MySQL database for user authentication.

`check_rate` is the interval in seconds at which trojan-go fetches user data from MySQL and updates the cache.

Other options are self-explanatory and will not be elaborated on further.

The users table structure is consistent with the Trojan version definition. Below is an example of creating the users table. Note that the password here refers to the SHA224 hash of the password (a string), and the units of traffic download, upload, quota are bytes. You can add and delete users, or specify users' traffic quotas by modifying the user record in the database's users table. trojan-go will automatically update the currently valid user list based on all users' traffic quotas. If download+upload>quota, the trojan-go server will reject that user's connection.

```mysql
CREATE TABLE users (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(64) NOT NULL,
    password CHAR(56) NOT NULL,
    quota BIGINT NOT NULL DEFAULT 0,
    download BIGINT UNSIGNED NOT NULL DEFAULT 0,
    upload BIGINT UNSIGNED NOT NULL DEFAULT 0,
    speed_limit_up BIGINT NOT NULL DEFAULT 0,
    speed_limit_down BIGINT NOT NULL DEFAULT 0,
    ip_limit INT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    INDEX (password)
);
```

Column descriptions for the additional fields:

- `quota`: Traffic quota in bytes. Negative value means unlimited. `0` means the user is disabled (no traffic allowed). Positive value means a byte limit: if `download + upload >= quota`, the server rejects the user's connection. (Already described above.)
- `speed_limit_up` / `speed_limit_down`: Per-user upload and download speed limits in bytes/sec. `0` or a negative value means no limit. Trojan-go reads these values on each polling cycle (`check_rate`) and applies them to connected users in real time.
- `ip_limit`: Maximum number of concurrent IP connections for the user. `0` or a negative value means no limit.

### ```forward_proxy``` Upstream Proxy Options

The upstream proxy option allows using another proxy to carry trojan-go's traffic.

`enabled` whether to enable the upstream proxy (socks5).

`proxy_addr` the host address of the upstream proxy.

`proxy_port` the port of the upstream proxy.

`username` `password` proxy username and password; if left empty, no authentication is used.

### ```api``` Options

trojan-go provides an API based on gRPC to support management and statistics for both server and client. It can provide client traffic and speed statistics, per-user traffic and speed statistics on the server, dynamic user add/delete and speed limiting, etc.

`enabled` whether to enable the API feature.

`api_addr` the address gRPC listens on.

`api_port` the port gRPC listens on.

`ssl` TLS-related settings.

- `enabled` whether to use TLS to transport gRPC traffic.

- `key`, `cert` server private key and certificate.

- `verify_client` whether to authenticate client certificates.

- `client_cert` if client authentication is enabled, fill in the list of authenticated client certificates here.

Warning: **Do not expose an API service without mutual TLS authentication directly to the internet, as it may lead to various security issues.**
