---
title: "Domestic Direct Connection and Ad Blocking"
draft: false
weight: 3
---

### Note: Trojan does not support this feature

Trojan-Go's built-in routing module can help you achieve domestic direct connection, meaning the client connects directly to domestic websites without going through the proxy.

The routing module can be configured with three strategies on the client side (`bypass`, `proxy`, `block`), while only the `block` strategy can be used on the server side.

Here is an example

```json
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "your_server",
    "remote_port": 443,
    "password": [
        "your_password"
    ],
    "ssl": {
        "sni": "your-domain-name.com"
    },
    "mux" :{
        "enabled": true
    },
    "router":{
        "enabled": true,
        "bypass": [
            "geoip:cn",
            "geoip:private",
            "geosite:cn",
            "geosite:geolocation-cn"
        ],
        "block": [
            "geosite:category-ads"
        ],
        "proxy": [
            "geosite:geolocation-!cn"
        ]
    }
}
```

This configuration enables the router module in whitelist mode: when a mainland China or LAN IP/domain is matched, a direct connection is made. If the domain belongs to an ad network, the connection is dropped.

The required databases `geoip.dat` and `geosite.dat` are already included in the release archive and can be used directly. They come from V2Ray's [domain-list-community](https://github.com/v2fly/domain-list-community) and [geoip](https://github.com/v2fly/geoip).

You can use forms like `geosite:cn`, `geosite:geolocation-!cn`, `geosite:category-ads-all`, `geosite:bilibili` to specify a category of domains. All available tags can be found in the [`data`](https://github.com/v2fly/domain-list-community/tree/master/data) directory of the [domain-list-community](https://github.com/v2fly/domain-list-community) repository. For more detailed usage of `geosite.dat`, refer to [V2Ray/Routing#Predefined Domain List](https://www.v2fly.org/config/routing.html#predefined-domain-list).

You can use forms like `geoip:cn`, `geoip:hk`, `geoip:us`, `geoip:private` to specify a category of IP addresses. `geoip:private` is a special entry that covers intranet IPs and reserved IPs; the other categories cover IP ranges for various countries/regions. For country/region codes, refer to [Wikipedia](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2).

You can also configure custom routing rules. For example, to block all example.com domains and their subdomains, as well as 192.168.1.0/24, add the following rule.

```json
"block": [
    "domain:example.com",
    "cidr:192.168.1.0/24"
]
```

Supported formats:

- `"domain:"` — subdomain matching

- `"full:"` — exact domain matching

- `"regexp:"` — regular expression matching

- `"cidr:"` — CIDR matching

For more detailed instructions, refer to the "Full Configuration File" section.
