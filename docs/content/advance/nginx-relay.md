---
title: "A Multi-Path Traffic Splitting Relay Scheme Based on SNI Proxy"
draft: false
weight: 6
---

## Introduction

Trojan is a tool that encrypts data transmission by encapsulating it in TLS. Taking advantage of its TLS characteristics, we can use an SNI proxy to achieve traffic splitting and relay on the same host port for different paths.

## Required Tools and Other Preparations

- Relay machine: nginx 1.11.5 or above
- Endpoint machine: trojan server (no version requirement)

## Configuration Method

For ease of explanation, two relay hosts and two endpoint hosts are used here.
The domain names bound to the four hosts are (a/b/c/d).example.com respectively, as shown in the diagram.
There are 4 interconnection paths in total: a-c, a-d, b-c, and b-d.

```text
                        +-----------------+           +--------------------+
                        |                 +---------->+                    |
                        |   VPS RELAY A   |           |   VPS ENDPOINT C   |
                  +---->+                 |   +------>+                    |
                  |     |  a.example.com  |   |       |   c.example.com    |
                  |     |                 +------+    |                    |
  +----------+    |     +-----------------+   |  |    +--------------------+
  |          |    |                           |  |
  |  client  +----+                           |  |
  |          |    |                           |  |
  +----------+    |     +-----------------+   |  |    +--------------------+
                  |     |                 |   |  |    |                    |
                  |     |   VPS RELAY B   |   |  +--->+   VPS ENDPOINT D   |
                  +---->+                 +---+       |                    |
                        |  b.example.com  |           |   d.example.com    |
                        |                 +---------->+                    |
                        +-----------------+           +--------------------+
```

### Configure Path Domain Names and Corresponding Certificates

First, we need to assign a domain name to each path, and resolve them to the respective entry hosts.

```text
a-c.example.com CNAME a.example.com  
a-d.example.com CNAME a.example.com  
b-c.example.com CNAME b.example.com  
b-d.example.com CNAME b.example.com
```

Then we need to deploy certificates for all target path domain names on the endpoint hosts.
Since the DNS records and host IPs do not match, HTTP validation will not pass. It is recommended to use DNS validation to issue certificates.
The specific DNS validation plugin depends on your domain DNS hosting provider. Here we use AWS Route 53.

```shell
certbot certonly --dns-route53 -d a-c.example.com -d b-c.example.com // On host C
certbot certonly --dns-route53 -d a-d.example.com -d b-d.example.com // On host D
```

### Configure the SNI Proxy

Here we use nginx's `ssl_preread` module to implement the SNI proxy.
Please install nginx and then modify your `nginx.conf` file as follows.
Note that this is not an HTTP service so do not put it inside a virtual host configuration.

Here is the corresponding configuration for host A. Host B follows the same pattern.

```nginx
stream {
  map $ssl_preread_server_name $name {
    a-c.example.com   c.example.com;  # Forward a-c path traffic to host C
    a-d.example.com   d.example.com;  # Forward a-d path traffic to host D

    # If other services occupying port 443 are also needed on this host (e.g., web service and Trojan service),
    # make those services listen on another local port (4000 is used here).
    # All TLS requests not matching the above SNIs will be forwarded to this port. Can be removed if not needed.
    default           localhost:4000;
  }

  server {
    listen      443; # Listen on port 443
    proxy_pass  $name;
    ssl_preread on;
  }
}
```

### Configure the Endpoint Trojan Service

In the previous configuration we used one certificate to issue all target path domain names, so here we can use a single Trojan server instance to handle all target path requests.
The Trojan configuration is the same as usual. Here is an example with irrelevant configuration omitted.

```json
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "ssl": {
        "cert": "/path/to/certificate.crt",
        "key": "/path/to/private.key",
    }
    ...
}
```

Tip: If you need separate independent Trojan server instances for different paths on the endpoint host (e.g., for separate billing services), you can configure another SNI proxy on the endpoint host and forward traffic to different local Trojan server listening ports respectively. Since the configuration is essentially the same as the process described above, it will not be repeated here.

## Preserving the Real Client IP (PROXY Protocol)

When trojan-go runs behind an nginx SNI proxy, all incoming connections appear to originate from `127.0.0.1` (or whichever address nginx connects from). This makes server-side features such as `ip_limit` ineffective, because every client is seen as the same IP.

To solve this, enable the **PROXY protocol**. nginx will prepend a PROXY protocol header containing the real client IP to each proxied connection, and trojan-go will read it.

### nginx configuration

Add `proxy_protocol on;` to the `server` block:

```nginx
stream {
  map $ssl_preread_server_name $name {
    a-c.example.com   c.example.com;
    a-d.example.com   d.example.com;
    default           localhost:4000;
  }

  server {
    listen      443;
    proxy_pass  $name;
    proxy_protocol on;
    ssl_preread on;
  }
}
```

### trojan-go configuration

Add `proxy_protocol` to the `tcp` section in the server config:

```json
{
  "run_type": "server",
  "local_addr": "127.0.0.1",
  "local_port": 8443,
  ...
  "tcp": {
    "proxy_protocol": true
  }
}
```

> **Warning:** Only enable `proxy_protocol` when all connections to trojan-go come from a trusted proxy that sends PROXY protocol headers. If trojan-go is also exposed directly to the internet, untrusted clients could forge PROXY protocol headers to spoof their IP address.

## Summary

Through the configuration method described above, we can achieve multi-entry multi-exit multi-stage Trojan traffic forwarding on a single port.
For multi-stage relaying, simply configure the SNI proxy on the intermediate nodes following the same approach.
