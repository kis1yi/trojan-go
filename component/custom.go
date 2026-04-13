//go:build custom || full
// +build custom full

package build

import (
	_ "github.com/kis1yi/trojan-go/proxy/custom"
	_ "github.com/kis1yi/trojan-go/tunnel/adapter"
	_ "github.com/kis1yi/trojan-go/tunnel/dokodemo"
	_ "github.com/kis1yi/trojan-go/tunnel/freedom"
	_ "github.com/kis1yi/trojan-go/tunnel/http"
	_ "github.com/kis1yi/trojan-go/tunnel/mux"
	_ "github.com/kis1yi/trojan-go/tunnel/router"
	_ "github.com/kis1yi/trojan-go/tunnel/shadowsocks"
	_ "github.com/kis1yi/trojan-go/tunnel/simplesocks"
	_ "github.com/kis1yi/trojan-go/tunnel/socks"
	_ "github.com/kis1yi/trojan-go/tunnel/tls"
	_ "github.com/kis1yi/trojan-go/tunnel/tproxy"
	_ "github.com/kis1yi/trojan-go/tunnel/transport"
	_ "github.com/kis1yi/trojan-go/tunnel/trojan"
	_ "github.com/kis1yi/trojan-go/tunnel/websocket"
)
