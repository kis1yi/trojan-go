---
title: "Dynamic User Management via API"
draft: false
weight: 10
---

### Note: Trojan does not support this feature

Trojan-Go provides a set of APIs via gRPC. The API supports the following features:

- Add, delete, modify, and query user information

- Traffic statistics

- Speed statistics

- IP connection count statistics

Trojan-Go itself has integrated API control functionality, meaning you can use one Trojan-Go instance to manage another Trojan-Go server.

You need to add API settings to the server configuration you want to control, for example:

```json
{
    ...
    "api": {
        "enabled": true,
        "api_addr": "127.0.0.1",
        "api_port": 10000,
        "allow_payload_capture": false
    }
}
```

`allow_payload_capture` defaults to `false` and should be left at `false` for production deployments. It is only honoured by binaries built with the `apidebug` build tag; default release builds silently downgrade `GetRecords` to metadata-only streaming regardless of the request's `IncludePayload` flag, so production scripts cannot accidentally leak connection bytes. With the `apidebug` tag and the flag set to `false`, `GetRecords` returns `PermissionDenied` so the misconfiguration is loud rather than silent.

When `api_addr` is bound to a non-loopback interface, trojan-go logs a `WARN` at startup if TLS is not enabled, and a separate `WARN` if TLS is enabled but `verify_client` is off. The server is not refused so existing private-network deployments keep working, but the operator should treat such a setup as world-readable and mTLS-protect any internet-reachable API endpoint.

Then start the Trojan-Go server:

```shell
./trojan-go -config ./server.json
```

Then you can use another Trojan-Go to connect to the server for management. The basic command format is:

```shell
./trojan-go -api-addr SERVER_API_ADDRESS -api COMMAND
```

Where `SERVER_API_ADDRESS` is the API address and port, such as 127.0.0.1:10000.

`COMMAND` is the API command. Valid commands are:

- list — list all users

- get — get information for a specific user

- set — set user information (add / delete / modify)

Below are some examples:

1. List all user information

    ```shell
    ./trojan-go -api-addr 127.0.0.1:10000 -api list
    ```

    All user information will be exported in JSON format, including the number of online IPs, real-time speed, total upload and download traffic, etc. Below is an example of a returned result:

    ```json
    [{"user":{"hash":"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"},"status":{"traffic_total":{"upload_traffic":36393,"download_traffic":186478},"speed_current":{"upload_speed":25210,"download_speed":72384},"speed_limit":{"upload_speed":5242880,"download_speed":5242880},"ip_limit":50,"quota":10737418240}}]
    ```

    Traffic units are all bytes. `quota` is the traffic quota in bytes (negative = unlimited, 0 = disabled, positive = byte limit).

2. Get a user's information

    You can use `-target-password` to specify a password, or `-target-hash` to specify the SHA224 hash of the target user's password. The format is the same as the list command:

    ```shell
    ./trojan-go -api-addr 127.0.0.1:10000 -api get -target-password password
    ```

    Or:

    ```shell
    ./trojan-go -api-addr 127.0.0.1:10000 -api get -target-hash d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01
    ```

    The above two commands are equivalent. The following examples uniformly use the plaintext password method; using a hash to specify a user follows the same logic.

    The user's information will be exported in JSON format, similar to the list command. Below is an example of a returned result:

    ```json
    {"user":{"hash":"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"},"status":{"traffic_total":{"upload_traffic":36393,"download_traffic":186478},"speed_current":{"upload_speed":25210,"download_speed":72384},"speed_limit":{"upload_speed":5242880,"download_speed":5242880},"ip_limit":50,"quota":10737418240}}
    ```

3. Add a user

    ```shell
    ./trojan-go -api-addr 127.0.0.1:10000 -api set -add-profile -target-password password
    ```

4. Delete a user

    ```shell
    ./trojan-go -api-addr 127.0.0.1:10000 -api set -delete-profile -target-password password
    ```

5. Modify a user's information

    ```shell
    ./trojan-go -api-addr 127.0.0.1:10000 -api set -modify-profile -target-password password \
        -ip-limit 3 \
        -upload-speed-limit 5242880 \
        -download-speed-limit 5242880 \
        -quota 10737418240
    ```

    This command limits the upload and download speed of the user with password "password" to 5 MiB/s, limits the number of simultaneously connected IPs to 3, and sets the traffic quota to 10 GiB (10737418240 bytes). Note that speed values are in bytes per second. If 0 or a negative number is entered for speed or IP limit, it means no limit.

    The CLI distinguishes between "flag omitted" and "flag explicitly set to its zero value". Only flags that you actually pass on the command line are sent in the request — fields you do not mention are left untouched on the server side. In particular, `trojan-go -api set -modify-profile -target-password password -ip-limit 3` does **not** zero out the user's existing quota; the `quota` field is simply not included in the request.

6. Manage a user's quota

    Quota can be read from the `quota` field in the `get` or `list` response. To set or modify a user's quota via the CLI:

    ```shell
    ./trojan-go -api-addr 127.0.0.1:10000 -api set -modify-profile -target-password password -quota 10737418240
    ```

    This sets the quota for the user with password "password" to 10 GiB (10737418240 bytes).

    Quota semantics:

    - **Negative** value (typically `-1`) — unlimited. Newly created users start at `-1` so a static `password` list in the YAML/JSON config keeps authenticating.
    - **`0`** — user is disabled. Authentication is rejected and any active tunnel is closed via the per-user cutoff signal.
    - **Positive** value — byte limit. Once `download + upload >= quota` the user's active tunnel is closed in-flight (within ~1 second of crossing the threshold) rather than at the next polling tick.

    On the wire, the proto3 `quota` field is `optional int64`, so callers can distinguish "field absent" (leave existing value as is) from "field present with value 0" (explicitly disable the user). Add with omitted quota leaves the user at the default `-1`; Add with explicit `quota=0` disables the user; Modify with omitted quota preserves the previous value; Modify with explicit `quota=0` disables the user. The CLI uses `flag.Visit` to enforce the same convention — `-quota` is only sent when you pass it on the command line. Downstream Go gRPC consumers should regenerate their stubs: `UserStatus.Quota` is now `*int64` with the standard `GetQuota()` accessor.
