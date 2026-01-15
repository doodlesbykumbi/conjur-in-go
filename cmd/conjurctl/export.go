package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

// exportCmd represents the export command
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export the Conjur data for migration",
	Long: `Export the Conjur data necessary to migrate to another Conjur instance.

This command exports:
- Database dump (pg_dump)
- Data encryption key
- Account list

The export is encrypted with a generated key file.

Example:
  conjurctl export
  conjurctl export --out-dir /backup --label mybackup`,
	Run: func(cmd *cobra.Command, args []string) {
		outDir, _ := cmd.Flags().GetString("out-dir")
		label, _ := cmd.Flags().GetString("label")

		if label == "" {
			label = time.Now().Format("2006-01-02T15-04-05Z")
		}

		if err := runExport(outDir, label); err != nil {
			fmt.Fprintf(os.Stderr, "Export failed: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringP("out-dir", "o", ".", "Output directory")
	exportCmd.Flags().StringP("label", "l", "", "Label for archive filename (default: timestamp)")
}

func runExport(outDir, label string) error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL environment variable is required")
	}

	dataKey := os.Getenv("CONJUR_DATA_KEY")
	if dataKey == "" {
		return fmt.Errorf("CONJUR_DATA_KEY environment variable is required")
	}

	fmt.Printf("Exporting to '%s'...\n", outDir)

	// Create output directory
	if err := os.MkdirAll(outDir, 0770); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Ensure export key exists
	keyFile := filepath.Join(outDir, "key")
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		fmt.Printf("Generating key file %s\n", keyFile)
		keyBytes := make([]byte, 64)
		if _, err := rand.Read(keyBytes); err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}
		if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(keyBytes)), 0600); err != nil {
			return fmt.Errorf("failed to write key file: %w", err)
		}
	} else {
		fmt.Printf("Using key from %s\n", keyFile)
	}

	// Create backup directory
	backupDir := filepath.Join(outDir, "backup")
	if err := os.MkdirAll(backupDir, 0770); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create etc directory
	etcDir := filepath.Join(outDir, "etc")
	if err := os.MkdirAll(etcDir, 0770); err != nil {
		return fmt.Errorf("failed to create etc directory: %w", err)
	}

	// Export database
	dbDump := filepath.Join(backupDir, "conjur.db")
	fmt.Println("Exporting database...")
	pgDump := exec.Command("pg_dump", "-Fc", "-f", dbDump, dbURL)
	pgDump.Stderr = os.Stderr
	if err := pgDump.Run(); err != nil {
		return fmt.Errorf("pg_dump failed: %w", err)
	}

	// Export data key
	dataKeyFile := filepath.Join(etcDir, "possum.key")
	if err := os.WriteFile(dataKeyFile, []byte("CONJUR_DATA_KEY="+dataKey+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write data key file: %w", err)
	}

	// Export accounts (list from slosilo_keystore)
	accountsFile := filepath.Join(backupDir, "accounts")
	fmt.Println("Exporting accounts...")
	psql := exec.Command("psql", dbURL, "-t", "-c",
		"SELECT REPLACE(id, 'authn:', '') FROM slosilo_keystore WHERE id LIKE 'authn:%' AND id != 'authn:!'")
	accountsOutput, err := psql.Output()
	if err != nil {
		return fmt.Errorf("failed to get accounts: %w", err)
	}
	if err := os.WriteFile(accountsFile, accountsOutput, 0600); err != nil {
		return fmt.Errorf("failed to write accounts file: %w", err)
	}

	// Create archive
	archiveFile := filepath.Join(outDir, label+".tar.xz")
	fmt.Println("Creating archive...")
	tar := exec.Command("tar", "Jcf", archiveFile, "-C", outDir,
		"--transform=s|^|/opt/conjur/|",
		"backup", "etc")
	tar.Stderr = os.Stderr
	if err := tar.Run(); err != nil {
		return fmt.Errorf("tar failed: %w", err)
	}

	// Encrypt archive with GPG
	fmt.Println("Encrypting archive...")
	gpg := exec.Command("gpg", "-c", "--cipher-algo", "AES256", "--batch",
		"--passphrase-file", keyFile, "--no-use-agent", archiveFile)
	gpg.Stderr = os.Stderr
	if err := gpg.Run(); err != nil {
		return fmt.Errorf("gpg encryption failed: %w", err)
	}

	// Cleanup temporary files
	_ = os.RemoveAll(backupDir)
	_ = os.RemoveAll(etcDir)
	_ = os.Remove(archiveFile)

	fmt.Println()
	fmt.Printf("Export placed in %s.gpg\n", archiveFile)
	fmt.Printf("It's encrypted with key in %s.\n", keyFile)
	fmt.Println("If you're going to store the export, make")
	fmt.Println("sure to store the key file separately.")

	return nil
}
