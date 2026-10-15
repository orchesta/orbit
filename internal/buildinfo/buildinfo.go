// Package buildinfo carries values stamped into the binary at build time.
package buildinfo

// Version is the release version. Release builds set it with
//
//	go build -ldflags "-X github.com/orchesta/orbit/internal/buildinfo.Version=v1.2.3"
//
// and other builds report "dev".
var Version = "dev"
