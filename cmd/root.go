package cmd

import (
	"fmt"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions"
	"github.com/spf13/cobra"
)

var (
	sessionOpts *options.SessionOptions
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "oauth2-proxy",
	Short: "A reverse proxy that provides authentication with OAuth2",
	Long:  `OAuth2 Proxy is a reverse proxy that provides authentication with various OAuth2 providers.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize session store with options
		store := sessions.NewSessionStore(nil, sessionOpts)
		_ = store
		fmt.Println("OAuth2 Proxy started with session refresh redirect support")
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
	sessionOpts = options.NewSessionOptions()

	// Add reverse proxy flags
	rootCmd.Flags().BoolVar(&sessionOpts.ReverseProxy, "reverse-proxy", false, "Enable reverse proxy mode (trust X-Forwarded-* headers)")
	rootCmd.Flags().StringSliceVar(&sessionOpts.TrustedIPs, "trusted-ips", []string{}, "List of trusted IPs for reverse proxy headers")
	rootCmd.Flags().StringVar(&sessionOpts.DefaultRedirectURL, "default-redirect-url", "/", "Default redirect URL when no redirect header is present")
}
