package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/vaultify/vaultify/internal/api"
	"github.com/vaultify/vaultify/internal/audit"
	"github.com/vaultify/vaultify/internal/config"
	"github.com/vaultify/vaultify/internal/crypto"
	"github.com/vaultify/vaultify/internal/storage"
	// "github.com/vaultify/vaultify/pkg/types"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize services
	cryptoSvc := crypto.NewCryptoService()
	
	// Initialize Redis storage
	storageSvc, err := storage.NewRedisStorage(cfg.Redis)
	if err != nil {
		log.Fatalf("Failed to initialize Redis storage: %v", err)
	}
	defer storageSvc.Close()

	// Initialize audit logger
	auditSvc, err := audit.NewLogger(cfg.Audit.LogFile, []byte(cfg.Audit.SecretKey))
	if err != nil {
		log.Fatalf("Failed to initialize audit logger: %v", err)
	}

	// Initialize gRPC server
	vaultifyServer := api.NewVaultifyServer(storageSvc, cryptoSvc, auditSvc, cfg)

	// Start gRPC server
	grpcServer := grpc.NewServer()
	
	// Register reflection service for debugging
	reflection.Register(grpcServer)

	// Start HTTP server for health checks and web UI
	httpRouter := mux.NewRouter()
	setupHTTPRoutes(httpRouter, vaultifyServer)

	// Start servers
	go startHTTPServer(cfg.Server.HTTPPort, httpRouter)
	go startGRPCServer(cfg.Server.GRPCPort, grpcServer)

	// Start cleanup routine
	go startCleanupRoutine(storageSvc)

	// Wait for interrupt signal
	waitForShutdown(grpcServer)
}

func startGRPCServer(port int, server *grpc.Server) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", port, err)
	}

	// Register the Vaultify server
	log.Printf("Starting gRPC server on port %d", port)
	if err := server.Serve(listener); err != nil {
		log.Fatalf("Failed to serve gRPC: %v", err)
	}
}

func startHTTPServer(port int, handler http.Handler) {
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: handler,
	}

	// Start the HTTP server
	log.Printf("Starting HTTP server on port %d", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to serve HTTP: %v", err)
	}
}

func setupHTTPRoutes(router *mux.Router, vaultifyServer *api.VaultifyServer) {
	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Call the health check method
		health, err := vaultifyServer.HealthCheck(ctx)
		if err != nil {
			http.Error(w, "Health check failed", http.StatusInternalServerError)
			return
		}

		// Set response headers
		w.Header().Set("Content-Type", "application/json")
		if health.Status != "healthy" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		// Simple JSON response
		fmt.Fprintf(w, `{"status":"%s","version":"%s","timestamp":"%s"}`,
			health.Status, health.Version, health.Timestamp.Format(time.RFC3339))
	}).Methods("GET")

	// Secret sharing page (placeholder for web UI)
	router.HandleFunc("/s/{token}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		token := vars["token"]

		// Simple HTML page for secret retrieval
		html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Vaultify - Retrieve Secret</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .container { background: #f5f5f5; padding: 30px; border-radius: 10px; }
        input, button { padding: 10px; margin: 10px 0; width: 100%%; box-sizing: border-box; }
        button { background: #007cba; color: white; border: none; cursor: pointer; }
        button:hover { background: #005a87; }
        .error { color: red; margin: 10px 0; }
        .success { color: green; margin: 10px 0; background: #e8f5e8; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Vaultify</h1>
        <h2>Retrieve Secret</h2>
        <p>Enter the password to decrypt and retrieve your secret.</p>
        <div id="error" class="error" style="display: none;"></div>
        <div id="success" class="success" style="display: none;"></div>
        <input type="password" id="password" placeholder="Enter password" />
        <button onclick="retrieveSecret()">Retrieve Secret</button>
        <p><small>This secret will be deleted after retrieval.</small></p>
    </div>
    <script>
        const token = '%s';
        async function retrieveSecret() {
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error');
            const successDiv = document.getElementById('success');
            
            errorDiv.style.display = 'none';
            successDiv.style.display = 'none';
            
            if (!password) {
                errorDiv.textContent = 'Password is required';
                errorDiv.style.display = 'block';
                return;
            }
            
            try {
                // This would connect to the actual API in a real implementation
                successDiv.innerHTML = '<strong>Secret retrieved!</strong><br>In a real implementation, this would show the decrypted secret.';
                successDiv.style.display = 'block';
                document.getElementById('password').value = '';
            } catch (error) {
                errorDiv.textContent = 'Failed to retrieve secret: ' + error.message;
                errorDiv.style.display = 'block';
            }
        }
        
        document.getElementById('password').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                retrieveSecret();
            }
        });
    </script>
</body>
</html>`, token)

		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	}).Methods("GET")

	// Static files for web UI (placeholder)
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./web/dist/"))).Methods("GET")
}

func startCleanupRoutine(storage *storage.RedisStorage) {
	ticker := time.NewTicker(1 * time.Hour) // Run cleanup every hour
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			if err := storage.Cleanup(ctx); err != nil {
				log.Printf("Cleanup error: %v", err)
			}
			cancel()
		}
	}
}

func waitForShutdown(grpcServer *grpc.Server) {
	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("Received signal %v, shutting down...", sig)

	// Graceful shutdown
	grpcServer.GracefulStop()
}