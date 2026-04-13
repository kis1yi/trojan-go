---
title: "Using Shadowsocks Plugins / Pluggable Transport Layer"
draft: false
weight: 7
---

### Note: Trojan does not support this feature

Trojan-Go supports a pluggable transport layer. In principle, Trojan-Go can use any software with TCP tunnel capability as the transport layer, such as v2ray, shadowsocks, kcp, etc. Trojan-Go is also compatible with the Shadowsocks SIP003 plugin standard, such as GoQuiet, v2ray-plugin, etc. You can also use Tor's transport plugins, such as obfs4, meek, etc.

You can use these plugins to replace Trojan-Go's TLS transport layer.

Once a pluggable transport layer plugin is enabled, the Trojan-Go client will pass **plaintext traffic** directly to the local plugin for processing. The client plugin is responsible for encryption and obfuscation, and transmits the traffic to the server's plugin. The server's plugin receives the traffic, decrypts and parses it, and passes the **plaintext traffic** to the local Trojan-Go server.

You can use any plugin to encrypt and obfuscate traffic. Simply add a `"transport_plugin"` option, specify the path to the plugin executable, and configure it appropriately.

We recommend more strongly that you **design your own protocol and develop the corresponding plugin**, because all currently available plugins cannot interface with Trojan-Go's active probing resistance feature, and some plugins do not even have encryption capability. If you are interested in developing plugins, please check the plugin design guide in the "Implementation Details and Developer Guide" section.

For example, you can use v2ray-plugin which conforms to the SIP003 standard. Here is an example:

**This configuration uses WebSocket plaintext to transport unencrypted Trojan protocol. It presents security risks. This configuration is for demonstration purposes only.**

**Do not use this configuration to penetrate the GFW under any circumstances.**

Server configuration:

```json
...（omitted）
"transport_plugin": {
    "enabled": true,
    "type": "shadowsocks",
    "command": "./v2ray-plugin",
    "arg": ["-server", "-host", "www.baidu.com"]
}
```

Client configuration:

```json
...（omitted）
"transport_plugin": {
    "enabled": true,
    "type": "shadowsocks",
    "command": "./v2ray-plugin",
    "arg": ["-host", "www.baidu.com"]
}
```

Note that the v2ray-plugin requires the `-server` parameter to distinguish client from server. For more details about this plugin, refer to the v2ray-plugin documentation.

After starting Trojan-Go, you can see the v2ray-plugin startup output. The plugin will disguise traffic as WebSocket traffic for transmission.

Non-SIP003 standard plugins may require different configuration. You can set `type` to `"other"` and manually specify the plugin address, startup arguments, and environment variables.
