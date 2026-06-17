package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/sniegul-szam/spf13-cobra/pkg/server"
)

var (
	listenAddr        string
	upstream          string
	redirectURL       string
	providerURL       string
	clientID          string
	clientSecret      string
	cookieSecret      string
	cookieRefresh     time.Duration
	reverseProxy      bool
	trustedIPs        []string
	defaultRedirect   string
	shutdownTimeout   time.Duration
	showVersion       bool
)

const version = "0.1.0"

func main() {
	rootCmd := &cobra.Command{
		Use:   "oauth2-proxy",
		Short: "A lightweight OAuth2 reverse proxy with session refresh support",
		Long: `oauth2-proxy is a reverse proxy that provides authentication
with OAuth2 providers (Google, GitHub, Keycloak, etc.). It preserves the
X-Forwarded-Uri header during session refresh cycles, ensuring users are
redirected back to their original destination after re-authentication.

This proxy uses spf13/cobra for CLI configuration parsing.`,
		RunE: runProxy,
		Version: version,
	}

	// Define CLI flags
	rootCmd.Flags().StringVarP(&listenAddr, "listen", "l", ":4180", "Address to listen on")
	rootCmd.Flags().StringVarP(&upstream, "upstream", "u", "", "Upstream URL to proxy requests to")
	rootCmd.Flags().StringVar(&redirectURL, "redirect-url", "", "OAuth2 callback URL")
	rootCmd.Flags().StringVar(&providerURL, "provider-url", "", "OAuth2 provider base URL")
	rootCmd.Flags().StringVarP(&clientID, "client-id", "i", "", "OAuth2 client ID")
	rootCmd.Flags().StringVarP(&clientSecret, "client-secret", "s", "", "OAuth2 client secret")
	rootCmd.Flags().StringVar(&cookieSecret, "cookie-secret", "", "Secret used to encrypt session cookies")
	rootCmd.Flags().DurationVar(&cookieRefresh, "cookie-refresh", 1*time.Hour, "Session refresh interval")
	rootCmd.Flags().BoolVar(&reverseProxy, "reverse-proxy", false, "Trust X-Forwarded-* headers from reverse proxy")
	rootCmd.Flags().StringSliceVar(&trustedIPs, "trusted-ips", nil, "CIDR ranges trusted for proxy headers")
	rootCmd.Flags().StringVar(&defaultRedirect, "default-redirect", "/", "Default redirect URL after auth")
	rootCmd.Flags().DurationVar(&shutdownTimeout, "shutdown-timeout", 30*time.Second, "Graceful shutdown timeout")
	rootCmd.Flags().BoolVar(&showVersion, "version", false, "Show version")

	_ = rootCmd.MarkFlagRequired("upstream")
	_ = rootCmd.MarkFlagRequired("client-id")
	_ = rootCmd.MarkFlagRequired("client-secret")
	_ = rootCmd.MarkFlagRequired("cookie-secret")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runProxy(cmd *cobra.Command, args []string) error {
	// Build configuration
	cfg := &server.Config{
		ListenAddr:      listenAddr,
		Upstream:        upstream,
		RedirectURL:     redirectURL,
		OAuthProviderURL: providerURL,
		ClientID:        clientID,
		ClientSecret:    clientSecret,
		CookieSecret:    cookieSecret,
		CookieRefresh:   cookieRefresh,
		ReverseProxy:    reverseProxy,
		TrustedCIDRs:    trustedIPs,
		DefaultRedirect: defaultRedirect,
	}

	// If no explicit redirect URL, build one from listen address
	if cfg.RedirectURL == "" {
		scheme := "http"
		if !strings.HasPrefix(listenAddr, ":") {
			scheme = "https"
		}
		host := listenAddr
		if strings.HasPrefix(host, ":") {
			host = "localhost" + host
		}
		cfg.RedirectURL = fmt.Sprintf("%s://%s/oauth2/callback", scheme, host)
	}

	// If no provider URL set, derive from redirect URL (common convention)
	if cfg.OAuthProviderURL == "" {
		cfg.OAuthProviderURL = strings.TrimSuffix(cfg.RedirectURL, "/oauth2/callback")
	}

	// Create and start the server
	srv, err := server.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	httpServer := srv.Start()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	log.Printf("[server] received signal %v, shutting down (timeout: %v)...", sig, shutdownTimeout)
	return srv.Shutdown(httpServer, shutdownTimeout)
}
