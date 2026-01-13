package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// accountCmd represents the account command
var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Manage accounts",
	Long:  `Manage organization accounts.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("error: Command 'account' requires a subcommand (create, delete)")
		fmt.Println()
		_ = cmd.Help()
		os.Exit(1)
	},
}

func init() {
	rootCmd.AddCommand(accountCmd)
}
