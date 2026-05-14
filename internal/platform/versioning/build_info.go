package versioning

// BuildInfo carries ldflags-injected version metadata from main
// BuildInfo holds metadata about the build, including the version,
// commit hash, and build date.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}
