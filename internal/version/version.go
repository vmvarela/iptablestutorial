// Package version exposes build-time version information injected via -ldflags.
package version

import "runtime"

// Variables set at build time via:
//
//	go build -ldflags "-X github.com/vmvarela/iptablestutorial/internal/version.Version=1.0.0 ..."
var (
	Version   = "dev"
	GitCommit = "none"
	BuildTime = "unknown"
)

// String returns a human-readable version string.
func String() string {
	return Version + " (commit=" + GitCommit + " built=" + BuildTime + " " + runtime.Version() + ")"
}
