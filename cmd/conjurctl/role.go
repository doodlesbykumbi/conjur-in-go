package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// roleCmd represents the role command
var roleCmd = &cobra.Command{
	Use:   "role",
	Short: "Manage roles",
	Long:  `Manage roles and their credentials.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("error: Command 'role' requires a subcommand (retrieve-key)")
		fmt.Println()
		_ = cmd.Help()
		os.Exit(1)
	},
}

func init() {
	rootCmd.AddCommand(roleCmd)
}
