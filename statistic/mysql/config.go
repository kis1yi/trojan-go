package mysql

import (
	"time"

	"github.com/kis1yi/trojan-go/config"
)

type MySQLConfig struct {
	Enabled      bool   `json:"enabled" yaml:"enabled"`
	ServerHost   string `json:"server_addr" yaml:"server-addr"`
	ServerPort   int    `json:"server_port" yaml:"server-port"`
	Database     string `json:"database" yaml:"database"`
	Username     string `json:"username" yaml:"username"`
	Password     string `json:"password" yaml:"password"`
	CheckRate    int    `json:"check_rate" yaml:"check-rate"`
	QueryTimeout int    `json:"query_timeout" yaml:"query-timeout"` // seconds; <=0 means default
}

type Config struct {
	MySQL MySQLConfig `json:"mysql" yaml:"mysql"`
}

// DefaultQueryTimeout is the per-Query/Exec deadline applied to every MySQL
// call when MySQLConfig.QueryTimeout is left at zero. P1-3 of the 2026
// hardening plan: every DB call must be bounded so a stuck server cannot
// freeze the updater goroutine.
const DefaultQueryTimeout = 5 * time.Second

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{
			MySQL: MySQLConfig{
				ServerPort:   3306,
				CheckRate:    30,
				QueryTimeout: 5,
			},
		}
	})
}
