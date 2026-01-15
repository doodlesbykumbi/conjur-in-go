package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"

	"conjur-in-go/pkg/config"
)

// configurationApplyCmd represents the configuration apply command
var configurationApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Restart the Conjur server to apply new configuration",
	Long: `Validate the current state of the configuration file and then restart the
Conjur server to pick up any changes.

Note that this will NOT incorporate changes to environment variables because
Linux process environments are static once a process has started.

Use --test to validate configuration without restarting.

Example:
  conjurctl configuration apply
  conjurctl configuration apply --test`,
	Run: func(cmd *cobra.Command, args []string) {
		testMode, _ := cmd.Flags().GetBool("test")

		if err := applyConfiguration(testMode); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to apply configuration: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	configurationCmd.AddCommand(configurationApplyCmd)
	configurationApplyCmd.Flags().Bool("test", false, "Validate configuration without restarting")
}

func applyConfiguration(testMode bool) error {
	// Load and validate configuration
	fmt.Println("Validating configuration...")

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	fmt.Printf("Config file: %s\n", cfg.ConfigFilePath())

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Check required environment variables
	if os.Getenv("DATABASE_URL") == "" {
		return fmt.Errorf("DATABASE_URL is not set")
	}
	if os.Getenv("CONJUR_DATA_KEY") == "" {
		return fmt.Errorf("CONJUR_DATA_KEY is not set")
	}

	fmt.Println("Configuration is valid.")

	if testMode {
		fmt.Println("Test mode: not restarting server.")
		return nil
	}

	// Find the conjurctl server process and send SIGHUP to reload
	fmt.Println("Sending reload signal to server...")

	// Try to find and signal the server process
	pgrep := exec.Command("pgrep", "-f", "conjurctl server")
	output, err := pgrep.Output()
	if err != nil {
		return fmt.Errorf("no running conjurctl server found")
	}

	var pid int
	if _, err := fmt.Sscanf(string(output), "%d", &pid); err != nil {
		return fmt.Errorf("failed to parse PID: %w", err)
	}

	// Send SIGHUP to trigger reload
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	if err := process.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("failed to send signal: %w", err)
	}

	fmt.Printf("Sent reload signal to process %d\n", pid)
	fmt.Println("Server will reload configuration.")

	return nil
}
