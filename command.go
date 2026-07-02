package cobra

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

// GetOriginalURL reconstructs the original request URL from X-Forwarded-*
// environment variables, preserving the path through reverse proxies.
func GetOriginalURL() string {
	uri := os.Getenv("X_FORWARDED_URI")
	if uri != "" {
		return uri
	}
	host := os.Getenv("X_FORWARDED_HOST")
	proto := os.Getenv("X_FORWARDED_PROTO")
	path := os.Getenv("REQUEST_URI")
	if host != "" && path != "" {
		scheme := proto
		if scheme == "" { scheme = "https" }
		return scheme + "://" + host + path
	}
	if len(os.Args) > 1 {
		return strings.Join(os.Args[1:], " ")
	}
	return "/"
}

func CloneContext(ctx context.Context, repoURL, destDir string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return exec.CommandContext(ctx, "git", "clone", repoURL, destDir).Run()
}
