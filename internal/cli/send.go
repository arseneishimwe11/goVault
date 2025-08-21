package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	// "syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/vaultify/vaultify/internal/crypto"
	"github.com/vaultify/vaultify/pkg/types"
)

// NewSendCmd creates the send command
func NewSendCmd() *cobra.Command {
	var (
		ttl      string
		maxReads int32
		password string
		file     string
	)

	cmd := &cobra.Command{
		Use:   "send [secret]",
		Short: "Send a secret securely",
		Long: `Send a secret securely with end-to-end encryption.
The secret will be encrypted before sending to the server.

Examples:
  vaultify send "my secret"
  vaultify send "my secret" --ttl=1h --max-reads=1
  vaultify send --file=secret.txt
  echo "my secret" | vaultify send`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSend(cmd, args, ttl, maxReads, password, file)
		},
	}

	cmd.Flags().StringVar(&ttl, "ttl", "24h", "Time to live (e.g., 1h, 30m, 7d)")
	cmd.Flags().Int32Var(&maxReads, "max-reads", 1, "Maximum number of reads (0 = unlimited)")
	cmd.Flags().StringVar(&password, "password", "", "Password for encryption (will prompt if not provided)")
	cmd.Flags().StringVar(&file, "file", "", "Read secret from file instead of argument")

	return cmd
}

func runSend(cmd *cobra.Command, args []string, ttlStr string, maxReads int32, password, file string) error {
	// Get global flags
	serverAddr, _ := cmd.Flags().GetString("server")
	jsonOutput, _ := cmd.Flags().GetBool("json")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Parse TTL
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return fmt.Errorf("invalid TTL format: %w", err)
	}

	// Get the secret content
	var secret string
	if file != "" {
		// Read from file
		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
		secret = string(content)
	} else if len(args) > 0 {
		// From command line argument
		secret = args[0]
	} else {
		// Check if there's input from stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			// Reading from pipe
			scanner := bufio.NewScanner(os.Stdin)
			var lines []string
			for scanner.Scan() {
				lines = append(lines, scanner.Text())
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("failed to read from stdin: %w", err)
			}
			secret = strings.Join(lines, "\n")
		} else {
			// Interactive mode - prompt for secret
			fmt.Print("Enter secret: ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				secret = scanner.Text()
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("failed to read secret: %w", err)
			}
		}
	}

	if secret == "" {
		return fmt.Errorf("secret cannot be empty")
	}

	// Get password if not provided
	if password == "" {
		fmt.Print("Enter password for encryption: ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			password = scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}

	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	// Encrypt the secret locally
	cryptoSvc := crypto.NewCryptoService()
	encryptedData, err := cryptoSvc.Encrypt(secret, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Create request (currently unused, placeholder for future implementation)
	_ = &types.StoreSecretRequest{
		Secret:   encryptedData,
		Password: password,
		TTL:      ttl,
		MaxReads: maxReads,
		Metadata: map[string]string{
			"client":    "vaultify-cli",
			"encrypted": "true",
		},
	}

	if verbose {
		fmt.Printf("Sending secret to %s...\n", serverAddr)
		fmt.Printf("TTL: %v\n", ttl)
		fmt.Printf("Max reads: %d\n", maxReads)
	}

	// Send to server (placeholder - would use gRPC client)
	response := &types.StoreSecretResponse{
		Token:     generateMockToken(),
		ShareURL:  fmt.Sprintf("http://localhost:8081/s/%s", generateMockToken()),
		ExpiresAt: time.Now().Add(ttl),
	}

	// Output result
	if jsonOutput {
		output, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal response: %w", err)
		}
		fmt.Println(string(output))
	} else {
		fmt.Printf("✅ Secret stored successfully!\n\n")
		fmt.Printf("Token: %s\n", response.Token)
		fmt.Printf("Share URL: %s\n", response.ShareURL)
		fmt.Printf("Expires: %s\n", response.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("\nTo retrieve: vaultify get %s\n", response.Token)
	}

	return nil
}

// Mock token generation for demonstration
func generateMockToken() string {
	return "demo_token_" + fmt.Sprintf("%d", time.Now().Unix())
}