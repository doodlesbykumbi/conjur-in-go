package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/server/endpoints"
	"conjur-in-go/pkg/slosilo"
	"conjur-in-go/pkg/slosilo/store"
)

// NOTES
// tokenSigningPrivateKey is stored in slosilo keystore

const defaultBindAddress = "127.0.0.1"
const defaultPort = "8000"

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the Conjur application server",
	Long: `Run the Conjur application server 

To run the server requires the environment variables CONJUR_DATA_KEY and DATABASE_URL.`,
	Run: func(cmd *cobra.Command, args []string) {
		dataKeyB64, ok := os.LookupEnv("CONJUR_DATA_KEY")
		if !ok {
			fmt.Println("No CONJUR_DATA_KEY")
			os.Exit(1)
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

		host, _ := cmd.Flags().GetString("bind-address")
		port, _ := cmd.Flags().GetString("port")
		s := server.NewServer(keystore, db, host, port)

		endpoints.RegisterSecretsEndpoints(s)
		endpoints.RegisterAuthenticateEndpoint(s)

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
	serverCmd.Flags().StringP("port", "p", defaultPort, "server listen port")
	serverCmd.Flags().StringP("bind-address", "b", defaultBindAddress, "server bind address")
}
