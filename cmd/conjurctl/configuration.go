package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// configurationCmd represents the configuration command
var configurationCmd = &cobra.Command{
	Use:   "configuration",
	Short: "Manage Conjur configuration",
	Long:  `Manage Conjur configuration settings.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("error: Command 'configuration' requires a subcommand (show, apply)")
		fmt.Println()
		_ = cmd.Help()
		os.Exit(1)
	},
}

func init() {
	rootCmd.AddCommand(configurationCmd)
}
