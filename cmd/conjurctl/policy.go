package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// policyCmd represents the policy command
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage policies",
	Long:  `Manage Conjur policies.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("error: Command 'policy' requires a subcommand (load)")
		fmt.Println()
		_ = cmd.Help()
		os.Exit(1)
	},
}

func init() {
	rootCmd.AddCommand(policyCmd)
}
