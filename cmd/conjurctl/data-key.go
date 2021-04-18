package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// dataKeyCmd represents the data-key command
var dataKeyCmd = &cobra.Command{
	Use:   "data-key",
	Short: "Manage the data encryption key",
	Long: `Manage the data encryption key`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("error: Command 'data-key' requires a subcommand generate")
		fmt.Println()
		cmd.Help()
		os.Exit(1)
	},
}

func init() {
	rootCmd.AddCommand(dataKeyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// dataKeyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// dataKeyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
