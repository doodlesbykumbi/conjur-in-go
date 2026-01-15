package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"conjur-in-go/pkg/config"
)

// configurationShowCmd represents the configuration show command
var configurationShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show Conjur configuration attributes and their sources",
	Long: `Show Conjur configuration attributes and their sources.

The values displayed by this command reflect the current state of the
configuration sources. For example, the environment variables and config
file. These may not reflect the current values used by the running Conjur
server.

Config file location: /etc/conjur/config/conjur.yml (or CONJUR_CONFIG_PATH)

Example:
  conjurctl configuration show
  conjurctl configuration show --output json`,
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		if err := showConfiguration(output); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to show configuration: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	configurationCmd.AddCommand(configurationShowCmd)
	configurationShowCmd.Flags().StringP("output", "o", "text", "Output format (text or json)")
}

func showConfiguration(output string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	if output == "json" {
		jsonOutput, err := cfg.FormatJSON()
		if err != nil {
			return err
		}
		fmt.Println(jsonOutput)
		return nil
	}

	fmt.Print(cfg.FormatText())
	return nil
}
