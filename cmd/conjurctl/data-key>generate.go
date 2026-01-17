package main

import (
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
)

// dataKeyGenerateCmd represents the data-key > generate command
var dataKeyGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a data encryption key",
	Long: `
Generate a data encryption key

Use this command to generate a new Base64-encoded 256 bit data encryption key. Once generated, this key should be placed into the environment of
the Conjur server. It will be used to encrypt all sensitive data which is stored in the database, including the token-signing private key.

Example:

$ export CONJUR_DATA_KEY="$(conjurctl data-key generate)" 
`,
	Run: func(cmd *cobra.Command, args []string) {
		bytes, _ := slosilo.RandomBytes(32)
		fmt.Printf("%s", base64.StdEncoding.Strict().EncodeToString(bytes))
	},
}

func init() {
	dataKeyCmd.AddCommand(dataKeyGenerateCmd)
}
