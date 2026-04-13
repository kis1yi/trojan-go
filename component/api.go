//go:build api || full
// +build api full

package build

import (
	_ "github.com/kis1yi/trojan-go/api/control"
	_ "github.com/kis1yi/trojan-go/api/service"
)
