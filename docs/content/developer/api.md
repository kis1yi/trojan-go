---
title: "API Development"
draft: false
weight: 100
---

Trojan-Go implements an API based on gRPC, using protobuf for data exchange. The client can retrieve traffic and speed information; the server can retrieve per-user traffic, speed, and online status, and can dynamically add/remove users and limit speeds. The API module can be activated by adding the `api` option in the configuration file. Below is an example; the meaning of each field is described in the "Full Configuration File" section.

```json
...
"api": {
    "enabled": true,
    "api_addr": "0.0.0.0",
    "api_port": 10000,
    "ssl": {
      "enabled": true,
      "cert": "api_cert.crt",
      "key": "api_key.key",
      "verify_client": true,
      "client_cert": [
          "api_client_cert1.crt",
          "api_client_cert2.crt"
      ]
    },
}
```

If you need to implement an API client for integration, please refer to the api/service/api.proto file.
