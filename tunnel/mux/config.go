package mux

import "github.com/kis1yi/trojan-go/config"

type MuxConfig struct {
	Enabled       bool `json:"enabled" yaml:"enabled"`
	IdleTimeout   int  `json:"idle_timeout" yaml:"idle-timeout"`
	Concurrency   int  `json:"concurrency" yaml:"concurrency"`
	StreamBuffer  int  `json:"stream_buffer" yaml:"stream-buffer"`
	ReceiveBuffer int  `json:"receive_buffer" yaml:"receive-buffer"`
	Protocol      int  `json:"protocol" yaml:"protocol"`
}

type Config struct {
	Mux MuxConfig `json:"mux" yaml:"mux"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{
			Mux: MuxConfig{
				Enabled:       false,
				IdleTimeout:   30,
				Concurrency:   8,
				StreamBuffer:  4194304,
				ReceiveBuffer: 4194304,
				Protocol:      2,
			},
		}
	})
}
