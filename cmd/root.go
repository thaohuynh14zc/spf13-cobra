package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
)

var (
	// CLI flags
	reverseProxyEnabled bool
	trustedIPs          []string
	defaultRedirectURL  string
	allowedRedirectDomains []string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "oauth2-proxy",
	Short: "A reverse proxy that provides authentication with Google, Github, or other providers",
	Long: `OAuth2 Proxy is a reverse proxy that provides authentication with various OAuth2 providers.
It can be used to protect any web application behind a reverse proxy.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Build middleware options from CLI flags
		middlewareOpts := options.MiddlewareOptions{
			SessionRefreshEnabled:  reverseProxyEnabled,
			DefaultRedirectURL:     defaultRedirectURL,
			AllowedRedirectDomains: allowedRedirectDomains,
		}

		// Validate configuration
		if middlewareOpts.SessionRefreshEnabled {
			if middlewareOpts.DefaultRedirectURL == "" {
				middlewareOpts.DefaultRedirectURL = "/"
			}
			// Validate allowed domains if any
			for _, domain := range middlewareOpts.AllowedRedirectDomains {
				if err := validation.ValidateRedirectURI("https://"+domain, middlewareOpts.AllowedRedirectDomains); err != nil {
					fmt.Fprintf(os.Stderr, "Invalid allowed domain %q: %v\n", domain, err)
					os.Exit(1)
				}
			}
		}

		// Create the session refresh middleware
		sessionRefreshMiddleware := middleware.NewSessionRefreshMiddleware(
			middlewareOpts.DefaultRedirectURL,
			middlewareOpts.AllowedRedirectDomains,
			middlewareOpts.SessionRefreshEnabled,
		)

		// Apply middleware to the HTTP handler chain
		// This is a simplified example; actual integration depends on the server setup
		fmt.Println("Session refresh middleware configured:")
		fmt.Printf("  Enabled: %v\n", middlewareOpts.SessionRefreshEnabled)
		fmt.Printf("  Default Redirect URL: %s\n", middlewareOpts.DefaultRedirectURL)
		fmt.Printf("  Allowed Redirect Domains: %v\n", middlewareOpts.AllowedRedirectDomains)

		// In a real application, you would pass the middleware to the HTTP server
		_ = sessionRefreshMiddleware
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Define CLI flags
	rootCmd.Flags().BoolVar(&reverseProxyEnabled, "reverse-proxy", false, "Enable reverse proxy mode (preserve original request path via X-Forwarded-Uri)")
	rootCmd.Flags().StringSliceVar(&trustedIPs, "trusted-ips", []string{}, "List of trusted IPs for reverse proxy mode")
	rootCmd.Flags().StringVar(&defaultRedirectURL, "default-redirect-url", "/", "Default redirect URL when no original URI is found")
	rootCmd.Flags().StringSliceVar(&allowedRedirectDomains, "allowed-redirect-domains", []string{}, "List of allowed domains for redirects (prevents open redirect)")
}
