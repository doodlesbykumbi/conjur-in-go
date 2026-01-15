package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"conjur-in-go/pkg/authenticator"
	"conjur-in-go/pkg/authenticator/authn"
	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/server/endpoints"
	"conjur-in-go/pkg/slosilo"
	"conjur-in-go/pkg/slosilo/store"
)

// NOTES
// tokenSigningPrivateKey is stored in slosilo keystore

func defaultBindAddress() string {
	if addr := os.Getenv("BIND_ADDRESS"); addr != "" {
		return addr
	}
	return "0.0.0.0"
}

func defaultPort() string {
	if port := os.Getenv("PORT"); port != "" {
		return port
	}
	return "8000"
}

func defaultPortInt() int {
	if port := os.Getenv("PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			return p
		}
	}
	return 8000
}

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the Conjur application server",
	Long: `Run the Conjur application server 

To run the server requires the environment variables CONJUR_DATA_KEY and DATABASE_URL.

By default, database migrations are run on startup. Use --no-migrate to skip.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Validate required environment variables first (fail fast)
		dataKeyB64, ok := os.LookupEnv("CONJUR_DATA_KEY")
		if !ok {
			fmt.Fprintln(os.Stderr, "CONJUR_DATA_KEY environment variable is required")
			os.Exit(1)
		}

		if os.Getenv("DATABASE_URL") == "" {
			fmt.Fprintln(os.Stderr, "DATABASE_URL environment variable is required")
			os.Exit(1)
		}

		// Run migrations unless --no-migrate is set
		noMigrate, _ := cmd.Flags().GetBool("no-migrate")
		if !noMigrate {
			log.Println("Running database migrations...")
			if err := runMigrations(); err != nil {
				fmt.Fprintf(os.Stderr, "Migration failed: %v\n", err)
				os.Exit(1)
			}
		}

		dataKey, err := base64.StdEncoding.DecodeString(dataKeyB64)
		if err != nil {
			fmt.Println("Bad CONJUR_DATA_KEY:", err)
			os.Exit(1)
		}

		cipher, err := slosilo.NewSymmetric(dataKey)
		if err != nil {
			fmt.Println("Unable to initiate cipher:", err)
			os.Exit(1)
		}

		db, err := gorm.Open(
			postgres.New(
				postgres.Config{
					DSN:                  os.Getenv("DATABASE_URL"),
					PreferSimpleProtocol: true, // disables implicit prepared statement usage
				},
			),
			&gorm.Config{},
		)
		if err != nil {
			fmt.Println("Unable to connect to DB:", err)
			os.Exit(1)
		}
		ctx := context.WithValue(context.Background(), "cipher", cipher)
		db = db.WithContext(ctx)

		keystore := store.NewKeyStore(db)

		// Register basic authenticator
		authnAuth := authn.New(db, cipher)
		authenticator.DefaultRegistry.Register(authnAuth)
		_ = authenticator.DefaultRegistry.Enable("authn")

		// Note: JWT authenticators are created on-demand during request handling
		// based on CONJUR_AUTHENTICATORS config. No pre-registration needed.

		host, _ := cmd.Flags().GetString("bind-address")
		port, _ := cmd.Flags().GetString("port")
		s := server.NewServer(keystore, cipher, db, host, port)

		endpoints.RegisterAll(s)

		log.Printf("Running server at http://%s:%s...\n", host, port)
		log.Fatal(s.Start())
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serverCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	serverCmd.Flags().StringP("port", "p", defaultPort(), "server listen port")
	serverCmd.Flags().StringP("bind-address", "b", defaultBindAddress(), "server bind address")
	serverCmd.Flags().Bool("no-migrate", false, "skip running database migrations on start")
}
