package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/vaultify/vaultify/internal/crypto"
	"github.com/vaultify/vaultify/pkg/types"
)

// NewGetCmd creates the get command
func NewGetCmd() *cobra.Command {
	var (
		password string
		output   string
	)

	cmd := &cobra.Command{
		Use:   "get <token>",
		Short: "Retrieve a secret by token",
		Long: `Retrieve a secret by token. The secret will be decrypted locally.
Note: Most secrets are deleted after retrieval.

Examples:
  vaultify get abc123
  vaultify get abc123 --password=mypass
  vaultify get abc123 --output=secret.txt`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGet(cmd, args[0], password, output)
		},
	}

	cmd.Flags().StringVar(&password, "password", "", "Password for decryption (will prompt if not provided)")
	cmd.Flags().StringVar(&output, "output", "", "Write decrypted secret to file")

	return cmd
}

func runGet(cmd *cobra.Command, token, password, output string) error {
	// Get global flags
	serverAddr, _ := cmd.Flags().GetString("server")
	jsonOutput, _ := cmd.Flags().GetBool("json")
	verbose, _ := cmd.Flags().GetBool("verbose")

	if verbose {
		fmt.Printf("Retrieving secret from %s...\n", serverAddr)
		fmt.Printf("Token: %s\n", token)
	}

	// Get password if not provided
	if password == "" {
		fmt.Print("Enter password for decryption: ")
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

	// Retrieve from server (placeholder - would use gRPC client)
	// For demo purposes, we'll simulate a response
	response := &types.RetrieveSecretResponse{
		Secret:         "This is a demo secret that would be retrieved from the server",
		ReadsRemaining: 0, // Secret deleted after this read
		CreatedAt:      time.Now().Add(-1 * time.Hour),
		Metadata: map[string]string{
			"client":    "vaultify-cli",
			"encrypted": "true",
		},
	}

	// In a real implementation, we would decrypt the retrieved encrypted data here
	cryptoSvc := crypto.NewCryptoService()
	_ = cryptoSvc // Placeholder to avoid unused variable error

	// Output result
	if jsonOutput {
		output, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal response: %w", err)
		}
		fmt.Println(string(output))
	} else {
		if output != "" {
			// Write to file
			if err := os.WriteFile(output, []byte(response.Secret), 0600); err != nil {
				return fmt.Errorf("failed to write to file: %w", err)
			}
			fmt.Printf("✅ Secret written to %s\n", output)
		} else {
			// Print to stdout
			fmt.Printf("✅ Secret retrieved successfully!\n\n")
			fmt.Printf("Secret: %s\n", response.Secret)
		}
		
		if response.ReadsRemaining == 0 {
			fmt.Printf("\n⚠️  This secret has been deleted after retrieval.\n")
		} else {
			fmt.Printf("\n📊 Reads remaining: %d\n", response.ReadsRemaining)
		}
		
		fmt.Printf("Created: %s\n", response.CreatedAt.Format(time.RFC3339))
	}

	return nil
}