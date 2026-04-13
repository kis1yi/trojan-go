//go:build mysql || full || mini
// +build mysql full mini

package build

import (
	_ "github.com/kis1yi/trojan-go/statistic/mysql"
)
