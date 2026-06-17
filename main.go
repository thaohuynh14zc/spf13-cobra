package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/thaohuynh14zc/spf13-cobra/pkg/middleware"
)

var (
	reverseProxy   bool
	trustedIPs     []string
	allowedDomains []string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "oauth2-proxy",
		Short: "OAuth2 Proxy with session refresh fix",
		Long:  `A proxy that handles OAuth2 authentication and preserves deep-links during session refresh cycle in reverse proxy mode.`,
		Run: func(cmd *cobra.Command, args []string) {
			handler := &middleware.SessionHandler{
				ReverseProxy:   reverseProxy,
				AllowedDomains: allowedDomains,
			}
			fmt.Printf("Starting oauth2-proxy (Reverse Proxy: %v)\n", handler.ReverseProxy)
			// In a real application, the server would start here using handler.RefreshMiddleware
		},
	}

	// Acceptance Criteria: CLI configuration flags must support enabling/disabling this behavior
	rootCmd.Flags().BoolVar(&reverseProxy, "reverse-proxy", false, "enable reverse proxy mode to use X-Forwarded-Uri or X-Auth-Request-Redirect for redirects")
	rootCmd.Flags().StringSliceVar(&trustedIPs, "trusted-ips", []string{}, "list of trusted proxy IPs")
	rootCmd.Flags().StringSliceVar(&allowedDomains, "allowed-domains", []string{}, "list of allowed domains for redirection (open-redirect protection)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
