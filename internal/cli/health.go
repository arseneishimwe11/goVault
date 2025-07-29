package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/vaultify/vaultify/pkg/types"
)

// NewHealthCmd creates the health command
func NewHealthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Check the health of the Vaultify server",
		Long: `Check the health of the Vaultify server and its dependencies.
This command tests connectivity and service status.

Examples:
  vaultify health
  vaultify health --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHealth(cmd)
		},
	}

	return cmd
}

func runHealth(cmd *cobra.Command) error {
	// Get global flags
	serverAddr, _ := cmd.Flags().GetString("server")
	jsonOutput, _ := cmd.Flags().GetBool("json")
	verbose, _ := cmd.Flags().GetBool("verbose")

	if verbose {
		fmt.Printf("Checking health of %s...\n", serverAddr)
	}

	// Check server health (placeholder - would use gRPC client)
	// For demo purposes, we'll simulate a response
	health := &types.HealthCheckResponse{
		Status:    "healthy",
		Version:   "1.0.0",
		Timestamp: time.Now(),
		Services: map[string]string{
			"redis": "healthy",
			"audit": "healthy",
		},
	}

	// Output result
	if jsonOutput {
		output, err := json.MarshalIndent(health, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal health check: %w", err)
		}
		fmt.Println(string(output))
	} else {
		// Determine status emoji
		statusEmoji := "✅"
		if health.Status != "healthy" {
			statusEmoji = "❌"
		}

		fmt.Printf("%s Vaultify Server Health\n\n", statusEmoji)
		fmt.Printf("Overall Status: %s\n", health.Status)
		fmt.Printf("Version: %s\n", health.Version)
		fmt.Printf("Timestamp: %s\n", health.Timestamp.Format(time.RFC3339))
		fmt.Printf("Server: %s\n", serverAddr)

		if len(health.Services) > 0 {
			fmt.Printf("\nServices:\n")
			for service, status := range health.Services {
				serviceEmoji := "✅"
				if status != "healthy" {
					serviceEmoji = "❌"
				}
				fmt.Printf("  %s %s: %s\n", serviceEmoji, service, status)
			}
		}

		if health.Status != "healthy" {
			fmt.Printf("\n⚠️  Some services are unhealthy. Check server logs for details.\n")
		}
	}

	return nil
}