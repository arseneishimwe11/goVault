package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/vaultify/vaultify/pkg/types"
)

// NewMetadataCmd creates the metadata command
func NewMetadataCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "metadata <token>",
		Short: "Get metadata about a secret without retrieving it",
		Long: `Get metadata about a secret without retrieving or decrypting it.
This does not count against the read limit and does not delete the secret.

Examples:
  vaultify metadata abc123`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMetadata(cmd, args[0])
		},
	}

	return cmd
}

func runMetadata(cmd *cobra.Command, token string) error {
	// Get global flags
	serverAddr, _ := cmd.Flags().GetString("server")
	jsonOutput, _ := cmd.Flags().GetBool("json")
	verbose, _ := cmd.Flags().GetBool("verbose")

	if verbose {
		fmt.Printf("Getting metadata from %s...\n", serverAddr)
		fmt.Printf("Token: %s\n", token)
	}

	// Get metadata from server (placeholder - would use gRPC client)
	// For demo purposes, we'll simulate a response
	metadata := &types.SecretMetadata{
		Token:          token,
		Exists:         true,
		MaxReads:       1,
		ReadsRemaining: 1,
		CreatedAt:      time.Now().Add(-30 * time.Minute),
		ExpiresAt:      time.Now().Add(23*time.Hour + 30*time.Minute),
		Metadata: map[string]string{
			"client":    "vaultify-cli",
			"encrypted": "true",
		},
	}

	// Output result
	if jsonOutput {
		output, err := json.MarshalIndent(metadata, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
		fmt.Println(string(output))
	} else {
		fmt.Printf("📊 Secret Metadata\n\n")
		fmt.Printf("Token: %s\n", metadata.Token)
		fmt.Printf("Exists: %t\n", metadata.Exists)
		
		if metadata.Exists {
			fmt.Printf("Max reads: %d\n", metadata.MaxReads)
			if metadata.MaxReads > 0 {
				fmt.Printf("Reads remaining: %d\n", metadata.ReadsRemaining)
			} else {
				fmt.Printf("Reads remaining: unlimited\n")
			}
			fmt.Printf("Created: %s\n", metadata.CreatedAt.Format(time.RFC3339))
			fmt.Printf("Expires: %s\n", metadata.ExpiresAt.Format(time.RFC3339))
			
			// Calculate time until expiration
			timeUntilExpiry := time.Until(metadata.ExpiresAt)
			if timeUntilExpiry > 0 {
				fmt.Printf("Time until expiry: %s\n", formatDuration(timeUntilExpiry))
			} else {
				fmt.Printf("⚠️  Secret has expired\n")
			}
			
			if len(metadata.Metadata) > 0 {
				fmt.Printf("\nMetadata:\n")
				for key, value := range metadata.Metadata {
					fmt.Printf("  %s: %s\n", key, value)
				}
			}
		}
	}

	return nil
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0f seconds", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0f minutes", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1f hours", d.Hours())
	}
	return fmt.Sprintf("%.1f days", d.Hours()/24)
}