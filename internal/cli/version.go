package cli

import (
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/spf13/cobra"
)

// VersionInfo contains version information
type VersionInfo struct {
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
	BuildTime string `json:"build_time"`
}

// NewVersionCmd creates the version command
func NewVersionCmd(version string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long: `Show version information for the Vaultify CLI.

Examples:
  vaultify version
  vaultify version --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVersion(cmd, version)
		},
	}

	return cmd
}

func runVersion(cmd *cobra.Command, version string) error {
	// Get global flags
	jsonOutput, _ := cmd.Flags().GetBool("json")

	versionInfo := VersionInfo{
		Version:   version,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		BuildTime: time.Now().Format(time.RFC3339), // In a real build, this would be set at compile time
	}

	if jsonOutput {
		output, err := json.MarshalIndent(versionInfo, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal version info: %w", err)
		}
		fmt.Println(string(output))
	} else {
		fmt.Printf("🔐 Vaultify CLI\n\n")
		fmt.Printf("Version: %s\n", versionInfo.Version)
		fmt.Printf("Go Version: %s\n", versionInfo.GoVersion)
		fmt.Printf("Platform: %s\n", versionInfo.Platform)
		fmt.Printf("Build Time: %s\n", versionInfo.BuildTime)
		fmt.Printf("\nA secure, encrypted secret-sharing tool.\n")
		fmt.Printf("For more information, visit: https://github.com/vaultify/vaultify\n")
	}

	return nil
}