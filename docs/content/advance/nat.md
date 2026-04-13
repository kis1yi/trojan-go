---
title: "Transparent Proxy"
draft: false
weight: 11
---

### Note: Trojan does not fully support this feature (UDP)

Trojan-Go supports transparent TCP/UDP proxy based on tproxy.

To enable transparent proxy mode, take a correct client configuration (see the basic configuration section) and change `run_type` to `nat`, then adjust the local listening port as needed.

Next you need to add iptables rules. Assuming your gateway has two network interfaces, the following configuration forwards inbound packets from one interface (LAN) to Trojan-Go, which then sends them to the remote Trojan-Go server through the tunnel via the other interface (internet). Replace `$SERVER_IP`, `$TROJAN_GO_PORT`, and `$INTERFACE` with your own values:

```shell
# Create TROJAN_GO chain
iptables -t mangle -N TROJAN_GO

# Bypass Trojan-Go server address
iptables -t mangle -A TROJAN_GO -d $SERVER_IP -j RETURN

# Bypass private addresses
iptables -t mangle -A TROJAN_GO -d 0.0.0.0/8 -j RETURN
iptables -t mangle -A TROJAN_GO -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A TROJAN_GO -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A TROJAN_GO -d 169.254.0.0/16 -j RETURN
iptables -t mangle -A TROJAN_GO -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A TROJAN_GO -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A TROJAN_GO -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A TROJAN_GO -d 240.0.0.0/4 -j RETURN

# Mark packets that did not match the above rules
iptables -t mangle -A TROJAN_GO -j TPROXY -p tcp --on-port $TROJAN_GO_PORT --tproxy-mark 0x01/0x01
iptables -t mangle -A TROJAN_GO -j TPROXY -p udp --on-port $TROJAN_GO_PORT --tproxy-mark 0x01/0x01

# All TCP/UDP packets coming in from $INTERFACE jump to the TROJAN_GO chain
iptables -t mangle -A PREROUTING -p tcp -i $INTERFACE -j TROJAN_GO
iptables -t mangle -A PREROUTING -p udp -i $INTERFACE -j TROJAN_GO

# Add route: marked packets re-enter the local loopback
ip route add local default dev lo table 100
ip rule add fwmark 1 lookup 100
```

After configuration, **start Trojan-Go client with root privileges**:

```shell
sudo trojan-go
```
