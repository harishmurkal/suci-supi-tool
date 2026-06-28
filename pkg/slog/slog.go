package slog

import (
	"fmt"
	"os"
	"strings"
)

// Enabled controls debug output. Default false, can be enabled via env or SetEnabled.
var Enabled bool

func init() {
	v := os.Getenv("SUCI_DEBUG")
	if v == "" {
		v = os.Getenv("DEBUG")
	}
	if v != "" {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "1" || v == "true" || v == "yes" || v == "on" {
			Enabled = true
		}
	}
}

// SetEnabled allows enabling/disabling debug output at runtime
func SetEnabled(b bool) { Enabled = b }

// Debugf prints formatted debug output when Enabled is true
func Debugf(format string, a ...interface{}) {
	if !Enabled {
		return
	}
	fmt.Printf(format, a...)
}
