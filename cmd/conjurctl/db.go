package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// dbCmd represents the db command
var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Manage the database",
	Long:  `Manage the database schema and migrations.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("error: Command 'db' requires a subcommand (migrate)")
		fmt.Println()
		_ = cmd.Help()
		os.Exit(1)
	},
}

func init() {
	rootCmd.AddCommand(dbCmd)
}
