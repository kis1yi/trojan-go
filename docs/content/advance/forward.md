---
title: "Tunneling and Reverse Proxy"
draft: false
weight: 5
---

You can use Trojan-Go to establish a tunnel. A typical application is to use Trojan-Go locally to set up a non-polluted DNS server. Here is an example configuration:

```json
{
    "run_type": "forward",
    "local_addr": "127.0.0.1",
    "local_port": 53,
    "remote_addr": "your_awesome_server",
    "remote_port": 443,
    "target_addr": "8.8.8.8",
    "target_port": 53,
    "password": [
        "your_awesome_password"
    ]
}
```

forward is essentially a client, but you need to fill in the `target_addr` and `target_port` fields to specify the reverse proxy target.

With this configuration file, TCP and UDP port 53 locally will be listened on. All TCP or UDP data sent to local port 53 will be forwarded through the TLS tunnel to the remote server `your_awesome_server`. After the remote server receives the response, the data will be returned through the tunnel to local port 53. That is, you can use 127.0.0.1 as a DNS server, and the local query results will match those of the remote server query. You can use this configuration to avoid DNS pollution.

By the same principle, you can set up a local mirror of Google:

```json
{
    "run_type": "forward",
    "local_addr": "127.0.0.1",
    "local_port": 443,
    "remote_addr": "your_awesome_server",
    "remote_port": 443,
    "target_addr": "www.google.com",
    "target_port": 443,
    "password": [
        "your_awesome_password"
    ]
}
```

Visiting `https://127.0.0.1` will let you access Google's homepage. However, note that since Google's server provides an HTTPS certificate for `google.com` while the current domain is `127.0.0.1`, the browser will trigger a certificate error warning.

Similarly, forward can be used to carry other proxy protocols. For example, using Trojan-Go to carry Shadowsocks traffic: the remote host runs an SS server listening on `127.0.0.1:12345`, and the remote server has a normal Trojan-Go server running on port 443. You can specify the configuration as follows:

```json
{
    "run_type": "forward",
    "local_addr": "0.0.0.0",
    "local_port": 54321,
    "remote_addr": "your_awesome_server",
    "remote_port": 443,
    "target_addr": "www.google.com",
    "target_port": 12345,
    "password": [
        "your_awesome_password"
    ]
}
```

After this, any TCP/UDP connection to local port 54321 is equivalent to connecting to remote port 12345. You can use the Shadowsocks client to connect to local port 54321, and the SS traffic will be transmitted through Trojan's tunnel connection to the SS server on remote port 12345.
