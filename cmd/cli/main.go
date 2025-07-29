package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vaultify/vaultify/internal/cli"
)

var version = "1.0.0"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vaultify",
		Short: "Secure, encrypted secret-sharing CLI",
		Long: `Vaultify is a secure, encrypted secret-sharing tool that allows you to 
share secrets safely and ephemerally with end-to-end encryption, audit logging, 
and tamper-proof guarantees.`,
		Version: version,
	}

	// Global flags
	cmd.PersistentFlags().String("server", "localhost:8080", "Vaultify server address")
	cmd.PersistentFlags().Bool("insecure", false, "Use insecure connection (for development)")
	cmd.PersistentFlags().Bool("json", false, "Output in JSON format")
	cmd.PersistentFlags().Bool("verbose", false, "Verbose output")

	// Add subcommands
	cmd.AddCommand(cli.NewSendCmd())
	cmd.AddCommand(cli.NewGetCmd())
	cmd.AddCommand(cli.NewMetadataCmd())
	cmd.AddCommand(cli.NewHealthCmd())
	cmd.AddCommand(cli.NewVersionCmd(version))

	return cmd
}