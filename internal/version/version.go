package version

// Version is the current application version.
// Override at build time with:
//
//	go build -ldflags "-X github.com/brightcolor/sender-report/internal/version.Version=v1.2.3" ./...
var Version = "v0.9.49"
