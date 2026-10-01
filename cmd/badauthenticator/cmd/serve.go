package cmd

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tantosec/badAuthenticator/internal/config"
	"github.com/tantosec/badAuthenticator/internal/handlers"
	"github.com/tantosec/badAuthenticator/pkg/contextkeys"
	"github.com/tantosec/badAuthenticator/pkg/logging"
	"github.com/tantosec/badAuthenticator/pkg/middleware"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the HTTP API.",
	Long:  `Serve the attestation, assertion and credential-listing APIs. Use --public-dir to also serve static files.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := logging.GetLogger()
		port, _ := cmd.Flags().GetInt("port")
		bindAddress, _ := cmd.Flags().GetString("bind-address")
		publicDir, _ := cmd.Flags().GetString("public-dir")
		readTimeout, _ := cmd.Flags().GetDuration("read-timeout")
		readHeaderTimeout, _ := cmd.Flags().GetDuration("read-header-timeout")
		writeTimeout, _ := cmd.Flags().GetDuration("write-timeout")
		idleTimeout, _ := cmd.Flags().GetDuration("idle-timeout")
		shutdownTimeout, _ := cmd.Flags().GetDuration("shutdown-timeout")
		allowGETAttestation, _ := cmd.Flags().GetBool("allow-get-attestation")
		allowUnauthenticatedAttestation, _ := cmd.Flags().GetBool("allow-unauthenticated-attestation")

		db, ok := cmd.Context().Value(contextkeys.DBKey{}).(*sql.DB)
		if !ok || db == nil {
			return fmt.Errorf("database connection not found in command context")
		}

		serverConfig := serverConfig{
			Port:                            port,
			BindAddress:                     bindAddress,
			PublicDir:                       publicDir,
			ReadTimeout:                     readTimeout,
			ReadHeaderTimeout:               readHeaderTimeout,
			WriteTimeout:                    writeTimeout,
			IdleTimeout:                     idleTimeout,
			ShutdownTimeout:                 shutdownTimeout,
			AllowUnauthenticatedAttestation: allowUnauthenticatedAttestation,
			AllowGETAttestation:             allowGETAttestation,
		}

		logger.Info("Starting server", "address", net.JoinHostPort(bindAddress, strconv.Itoa(port)))
		return startServer(db, serverConfig)
	},
}

type serverConfig struct {
	Port                            int
	BindAddress                     string
	PublicDir                       string
	ReadTimeout                     time.Duration
	ReadHeaderTimeout               time.Duration
	WriteTimeout                    time.Duration
	IdleTimeout                     time.Duration
	ShutdownTimeout                 time.Duration
	AllowGETAttestation             bool
	AllowUnauthenticatedAttestation bool
}

func startServer(db *sql.DB, cfg serverConfig) error {
	mux := http.NewServeMux()
	logger := logging.GetLogger()

	if strings.TrimSpace(cfg.BindAddress) == "" {
		cfg.BindAddress = config.DefaultHTTPBindAddress
	}

	if cfg.PublicDir != "" {
		info, err := os.Stat(cfg.PublicDir)
		if err != nil {
			return fmt.Errorf("cannot open public directory %q: %w", cfg.PublicDir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("public path %q is not a directory", cfg.PublicDir)
		}
		mux.Handle("/", http.FileServer(http.Dir(cfg.PublicDir)))
	}

	attestationHandler := handlers.AttestationAPIHandler(db, cfg.AllowGETAttestation)
	assertionHandler := handlers.AssertionAPIHandler(db)
	listCredentialsHandler := handlers.ListCredsAPIHandler(db)

	validTokens, err := config.LoadBearerTokens()
	if err != nil {
		return err
	}
	authenticatedAssertionHandler := middleware.BearerTokenAuthMiddleware(assertionHandler, validTokens)
	authenticatedListCredentialsHandler := middleware.BearerTokenAuthMiddleware(listCredentialsHandler, validTokens)
	var registeredAttestationHandler http.Handler = middleware.BearerTokenAuthMiddleware(attestationHandler, validTokens)
	if cfg.AllowUnauthenticatedAttestation {
		registeredAttestationHandler = attestationHandler
		logger.Warn("Bearer authentication is disabled for /api/v1/attest")
	}

	mux.Handle("/api/v1/attest", registeredAttestationHandler)
	mux.Handle("/api/v1/assert", authenticatedAssertionHandler)
	mux.Handle("/api/v1/listCredentials", authenticatedListCredentialsHandler)

	corsHandler := middleware.CORSMiddleware(mux)
	loggingHandler := middleware.RequestLogger(corsHandler)

	server := &http.Server{
		Addr:              net.JoinHostPort(cfg.BindAddress, strconv.Itoa(cfg.Port)),
		Handler:           loggingHandler,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}
	return nil
}

func init() {
	serveCmd.Flags().IntP("port", "p", config.DefaultHTTPPort, "Port to listen on for the web server")
	serveCmd.Flags().String("bind-address", config.DefaultHTTPBindAddress, "IP address to listen on (0.0.0.0 listens on all interfaces)")
	serveCmd.Flags().String("public-dir", "", "Serve static files from an existing directory")
	serveCmd.Flags().Duration("read-timeout", config.DefaultHTTPReadTimeout, "Maximum duration for reading the entire request")
	serveCmd.Flags().Duration("read-header-timeout", config.DefaultHTTPReadHeaderTimeout, "Maximum duration for reading request headers")
	serveCmd.Flags().Duration("write-timeout", config.DefaultHTTPWriteTimeout, "Maximum duration before timing out response writes")
	serveCmd.Flags().Duration("idle-timeout", config.DefaultHTTPIdleTimeout, "Maximum time to wait for the next request on keep-alive connections")
	serveCmd.Flags().Duration("shutdown-timeout", config.DefaultHTTPShutdownTimeout, "Maximum duration for graceful shutdown")
	serveCmd.Flags().Bool("allow-get-attestation", false, "Enable idempotent GET requests on /api/v1/attest")
	serveCmd.Flags().Bool("allow-unauthenticated-attestation", false, "Skip bearer authentication for /api/v1/attest")
	rootCmd.AddCommand(serveCmd)
}
