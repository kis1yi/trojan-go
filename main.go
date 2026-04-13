package main

import (
	"flag"

	_ "github.com/kis1yi/trojan-go/component"
	"github.com/kis1yi/trojan-go/log"
	"github.com/kis1yi/trojan-go/option"
)

func main() {
	flag.Parse()
	for {
		h, err := option.PopOptionHandler()
		if err != nil {
			log.Fatal("invalid options")
		}
		err = h.Handle()
		if err == nil {
			break
		}
	}
}
