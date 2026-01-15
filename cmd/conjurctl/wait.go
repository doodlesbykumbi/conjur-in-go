package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// waitCmd represents the wait command
var waitCmd = &cobra.Command{
	Use:   "wait",
	Short: "Wait for the Conjur server to be ready",
	Long: `Wait for the Conjur server to be ready by polling the status endpoint.

This command will repeatedly check the server status until it responds
successfully or the maximum number of retries is reached.

Example:
  conjurctl wait
  conjurctl wait --port 3000 --retries 60`,
	Run: func(cmd *cobra.Command, args []string) {
		port, _ := cmd.Flags().GetInt("port")
		retries, _ := cmd.Flags().GetInt("retries")

		if err := waitForServer(port, retries); err != nil {
			fmt.Fprintf(os.Stderr, "Server did not become ready: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Conjur server is ready")
	},
}

func init() {
	rootCmd.AddCommand(waitCmd)
	waitCmd.Flags().IntP("port", "p", defaultPortInt(), "Server port to check")
	waitCmd.Flags().IntP("retries", "r", 90, "Number of retries")
}

func waitForServer(port, retries int) error {
	url := fmt.Sprintf("http://localhost:%d/", port)
	client := &http.Client{Timeout: 2 * time.Second}

	fmt.Println("Waiting for Conjur to be ready...")

	for i := 0; i < retries; i++ {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 300 {
				fmt.Println()
				fmt.Println("Conjur is ready!")
				return nil
			}
		}

		fmt.Print(".")
		time.Sleep(1 * time.Second)
	}

	fmt.Println()
	return fmt.Errorf("Conjur is not ready after %d seconds", retries)
}
