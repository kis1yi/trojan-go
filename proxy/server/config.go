package server

import (
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/proxy/client"
)

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return new(client.Config)
	})
}
