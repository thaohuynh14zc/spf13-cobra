package cobra

import (
	"context"
	"os"
	"os/exec"
)

// CloneContext clones a git repository with context cancellation support.
// If the context is canceled or times out, the operation is aborted, and the destination directory is cleaned up.
func CloneContext(ctx context.Context, repoURL string, destDir string) error {
	// Check if context is already canceled
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Use exec.CommandContext to ensure the git process is killed if the context is canceled
	cmd := exec.CommandContext(ctx, "git", "clone", repoURL, destDir)

	err := cmd.Run()
	if err != nil {
		// Clean up the destination directory on failure or cancellation
		_ = os.RemoveAll(destDir)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}

	return nil
}
