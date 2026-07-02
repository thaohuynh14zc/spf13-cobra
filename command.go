package cobra

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

// GetOriginalURL reads X-Forwarded-* environment variables and reconstructs
// the original request URL, preserving the path through reverse proxies.
// Falls back to os.Args if no proxy headers are present.
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
		if scheme == "" {
			scheme = "https"
		}
		return scheme + "://" + host + path
	}

	if len(os.Args) > 1 {
		return strings.Join(os.Args[1:], " ")
	}
	return "/"
}

// CloneContext clones a git repository with context cancellation support.
// If the context is canceled or times out, the operation is aborted.
func CloneContext(ctx context.Context, repoURL string, destDir string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	cmd := exec.CommandContext(ctx, "git", "clone", repoURL, destDir)
	err := cmd.Run()
	if err != nil {
		_ = os.RemoveAll(destDir)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
}
