---
title: "Correctly Configuring Trojan-Go"
draft: false
weight: 22
---

The following describes how to correctly configure Trojan-Go to fully hide your proxy node's characteristics.

Before starting, you need:

- A server that is not blocked by the GFW

- A domain name (free domain services such as .tk can be used)

- Trojan-Go, which can be downloaded from the release page

- A certificate and key, which can be freely obtained from authorities such as Let's Encrypt

### Server Configuration

Our goal is to make your server behave identically to a normal HTTPS website.

First you need an HTTP server. You can use nginx, Apache, Caddy, etc. to configure a local HTTP server, or use someone else's HTTP server. The purpose of the HTTP server is to display a completely normal web page to the GFW when it performs active probing.

**You need to specify the address of this HTTP server in `remote_addr` and `remote_port`. `remote_addr` can be an IP or domain name. Trojan-Go will test whether this HTTP server is working properly; if it is not, Trojan-Go will refuse to start.**

Below is a reasonably secure server configuration `server.json` that requires you to configure an HTTP service on local port 80 (required; you can also use another website's HTTP server, such as `"remote_addr": "example.com"`), and optionally an HTTPS service on port 1234 or a static HTTP page showing "400 Bad Request" (optional; the `fallback_port` field can be removed to skip this step):

```json
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "your_awesome_password"
    ],
    "ssl": {
        "cert": "server.crt",
        "key": "server.key",
        "fallback_port": 1234
    }
}
```

This configuration file makes Trojan-Go listen on port 443 on all IP addresses (0.0.0.0) of the server, using `server.crt` and `server.key` as the certificate and key for TLS handshake. You should use the most complex password possible, while ensuring that the `password` is consistent between client and server. Note that **Trojan-Go will check whether your HTTP server `http://remote_addr:remote_port` is working properly. If your HTTP server is not working, Trojan-Go will refuse to start.**

When a client attempts to connect to the Trojan-Go listening port, the following happens:

- If the TLS handshake succeeds and the TLS content is detected as non-Trojan protocol (possibly an HTTP request or active probing from the GFW), Trojan-Go proxies the TLS connection to the HTTP service on local 127.0.0.1:80. From a remote perspective, the Trojan-Go service appears as an HTTPS website.

- If the TLS handshake succeeds, the Trojan protocol header is confirmed, and the password is correct, the server will parse the request from the client and proxy it; otherwise it is handled the same as the previous step.

- If the TLS handshake fails, it means the other party is not using TLS protocol to connect. Trojan-Go will proxy this TCP connection to the HTTPS service (or HTTP service) running on local 127.0.0.1:1234, returning an HTTP page showing 400 Bad Request. `fallback_port` is an optional field; if not filled in, Trojan-Go will directly terminate the connection. Although optional, it is still strongly recommended to fill it in.

You can verify by using a browser to access your domain `https://your-domain-name.com`. If it works properly, your browser will display a normal HTTPS-protected web page with content consistent with the page on port 80 of the server. You can also use `http://your-domain-name.com:443` to verify that `fallback_port` is working properly.

In fact, you can even use Trojan-Go as your HTTPS server to provide HTTPS service for your website. Visitors can normally browse your website through Trojan-Go without affecting proxy traffic. However, note that you should not set up services with high real-time requirements on `remote_port` and `fallback_port`, as Trojan-Go will intentionally add a small delay when detecting non-Trojan protocol traffic to resist GFW's time-based detection.

After configuration, you can start the server with:

```shell
./trojan-go -config ./server.json
```

### Client Configuration

The corresponding client configuration `client.json`:

```json
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "your_awesome_server",
    "remote_port": 443,
    "password": [
        "your_awesome_password"
    ],
    "ssl": {
        "sni": "your-domain-name.com"
    }
}
```

This client configuration makes Trojan-Go open a Socks5/HTTP proxy (automatically detected) listening on local port 1080. The remote server is `your_awesome_server:443`, where `your_awesome_server` can be an IP or domain name.

If you fill in a domain name in `remote_addr`, `sni` can be omitted. If you fill in an IP address in `remote_addr`, the `sni` field should contain the domain name corresponding to the certificate you applied for, or the Common Name of the self-signed certificate, and they must be consistent. Note that the `sni` field is currently transmitted in **plaintext** in the TLS protocol (to allow the server to provide the appropriate certificate). The GFW has been proven to have SNI detection and blocking capabilities, so do not fill in domain names that are already blocked (such as `google.com`), as this may very likely cause your server to be blocked as well.

After configuration, you can start the client with:

```shell
./trojan-go -config ./client.json
```

More information about configuration files can be found in the corresponding sections in the left navigation bar.
