package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"conjur-in-go/pkg/slosilo"
	"conjur-in-go/pkg/utils"
)

func TestName(t *testing.T) {
	testDataKey, _ := base64.StdEncoding.DecodeString("2AP/N4ajPY3rsjpaIagjjA+JHjDbIw+hI+uI32jnrP4=")

	t.Run("Symmetric", func(t *testing.T) {
		t.Skip()

		add := []byte("myConjurAccount:variable:BotApp/secretVar")
		version, _ := hex.DecodeString("47")
		tag, _ := hex.DecodeString("545e57ad5dd125c7f5206e2b7dbd12bc")
		nonce, _ := hex.DecodeString("10e17cf62fca1e336a306961")
		cipherText, _ := hex.DecodeString("ab2678a47e0f4ae87b4ffae9babb91fdef8e15a34391b663")

		expectedSecretValue := []byte("5f7bd49c1e68a0fe0f9ab216")
		var expectedEncSecretValue []byte
		for _, part := range [][]byte{version, tag, nonce, cipherText} {
			expectedEncSecretValue = append(expectedEncSecretValue, part...)
		}

		cipher, _ := slosilo.NewSymmetric(testDataKey)
		secretValue, _ := cipher.Decrypt(add, expectedEncSecretValue)

		if string(expectedSecretValue) != string(secretValue) {
			t.Fatal("PublicDecrypt failed")
		}

		encSecretValue, _ := cipher.Encrypt(add, expectedSecretValue, nonce)

		if string(encSecretValue) != string(expectedEncSecretValue) {
			t.Fatal("Encrypt failed")
		}
	})

	t.Run("Key", func(t *testing.T) {
		t.Skip()
		encPkey, _ := hex.DecodeString("47af2d19c59c0f532c34384f3aad2af1f3e05fba68b5cc4818c93a960d67c0cd6c5aad3b9613b325a9c4b936489650c839d9b6812936b6ae395463f75f3d2f1fa657998d57bae9841f5950fb907219d845d0111370cc6b16930f936c71c4e1833f5eb7fd18e6697d15059b34bfdd10a3edee3f296a5cd781da87ca753c5974f661a10c5db980d0e29a7272c214686183d6d82fcadb5a68a4856d6d8988d03b270a30ce625448cc1e9321dd332e1b984ffa50cdf9e4d2e04e682235536e1a58edfb477a1f17a223b8c55223f1adcb9b1de6403de259cfd181d646bd6cd6dc2e6f6cf25ccb8940b30f6455cf0e77dd67d0eb11b1ac5f4c89c01bf10bde5b50654e00e8f62b86577d36ffd957b6462c53d00c6763f1e548e9de065bb0a5ff39e1e73c8ec91f46c342a73aa7aeec2ded51809e50cec4a63a32fc1743faac7aa7e4b3ae292bce61ad6409b1b55276b7a7af4319d663a27659ebcaff575e8fa9e8373a88ee04dc5cd41a997c78a5a29fe59b77bf076c444b5dfa83416d0c35d9651428f03d5f593674529d67323ab9e841960782b687ac5e48845ef0847ee680b48ba8411f28c8619f4b930381b4a233a2cfb101dda17a371b051c7488c982f1a383eb9219fa95a847fa6dc391a4a83f65dd97469fa30a44224a1bf7bceb64ffc6d91dba476e98de139694805d1c618f42d02ebd0e1e7f923462e0ac65ab3f4e6a0527e8133c7fa644de5cfd17ae6f6d27675487fa1cd4357c87a816c020353161aa681e25bd05807dd5bc1f40c6d44775325c7e69c556915db364d841eaf52f32595d576befeaa4735c05e15561c41eb6852bd4022a5d745af89024a650d49e72e486347a202dc88ab597df73e08347c651f534f8fc14859f5d14dc9cf7ed1b74cbb256d2d78035256061a472bbad5d4306c4a4ba98a19d2c0374b6bbbd9a70ca922eee5db98954dd8eef21492daf0658ac10bc67194707cd9cec5236a25ca7293ae6d07317c35329511321d020d58934717a28c72f62f4ba990e7ae38074f05ffc3e236d0f0eac158381739d051c35a71144b7811eb67da281944403e08b2fe1ec732392269e674a224c02c22b40e697813f69569e1dfe62da440b3fb3858d55433ce67fe7583c5d27d8afafdfde597a09888a176e79805d70c88496ce2d11f1decd51863f398aee771680180b1dae48ab0099bba881a0ee9e53e93a9ce5b908e0f0de2fbc52928c21fe85aa89b973b0ad8028b79dbe0c267e80b51fdf5e539513f50b92d0fdb7d82b6d7dab344a9343c63ceaef1cae8a4897f1cd1222c8f7a7c4006065449bdfdf716df34c320436e34b6f4bd79dd57d4444fb5e8657925cc9a8dea521978dfda096308d7af54548ffdc1a30a5958ababe3ea8b30ca594654605daedc64c0ac6ebd32d86751d92153e7a007fedec579869957eec034127f152d32346b31025ffa473a92f6665f5d5478c84307047f99fcae2bfc373025dbc50df4e75a5912f417a706991b1b23b1e9c6eddcaa41984343a982f97f019db197145ee4fc948d8a9dabab2e8539ffded5ee19a699eb8c4be8690278e56293a5a41b5cf497679b6d08d901f1971ac15db74d69012e50df12e567afeb439f906d50a92365d497d8ee4c01fa0d3c63e9ec03c571c1caf9caace087a53c77dbcfdb956c0416ef2ed553a69478996f1ee52ed1770ca85773ef38186cb71d5e85396d11911446369dbd7")
		cipher, _ := slosilo.NewSymmetric(testDataKey)
		accountPkey, _ := cipher.Decrypt([]byte("authn:myConjurAccount"), encPkey)

		key, _ := slosilo.NewKey(accountPkey)

		header := "eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiIxMGQxODQ5NzJiYTUyOWE1YWJkZGRmY2I4ZjdiM2ZhYWZmMGI4NGMxYTg0NjdhZmJlMzcyY2FkY2I1YjhkOGEyIn0="
		claims := "eyJzdWIiOiJEYXZlQEJvdEFwcCIsImlhdCI6MTYxODU4NzMwNX0="
		sig, _ := base64.URLEncoding.DecodeString("ptt9nTv6q1bTkhAv4Wgv2lxE2D4_WljYaD6UAYMpUVNJhL8N41sDK__EVG-ZHUT9bXWRrObNKad6f_pRKqi8qf9j5BzNwCq5Te32O5QOMKbuegPf6dSyKSCmmEqhZluFZbIrRel3qjNtnUbYIddVJDGJmtCLylGNu410iw6MEFGVbDNhKqEcQphsTGUiur11m0SFeaPiudlUNUVaJ9nnafyf2PCQWcxd3dALiWBF8DZqSjA9v5xW3cExXiqafomE9e4z-gl3yiOyyY5iGOv5f7wOVbnQYff1VVNWGSBN1dco4k5ZcZT2NYgsSIMWUz78damgQ-braMyTWHqMZw7kSxFF09k4PaFCx_7LmenI5mOHGKaBagGZE3t2uifNunC6")
		stringtosign := strings.Join([]string{header, claims}, ".")
		fmt.Println(
			key.Verify(
				[]byte(
					stringtosign,
				),
				sig,
			),
		)
		return
		//res, _ := key.PrivateEncrypt([]byte("hello"))
		//fmt.Println(hex.EncodeToString(res))
		//return;
		fingerprint := key.Fingerprint()
		//
		//sig, _ := base64.URLEncoding.DecodeString("UTLLE_ENMv4SQvLn1iJMUMojmCvgD00xovn2syPc6iekrbW6SaKsKby4_qePYVd6Iq78REyEorKxFfdT5lFzpF4FoZ_qqz_PAwdGQo0DsZH7Urlt2keH4cFNVVPqq5bZIQahAtB9SLKM4LYiVdyByMQOrPymZf8Yf5AIaBTLXBtVTSsMqFSrn8yKXqa9i50v0md8fi2O4HvcDImOFKmrQWRQEOdeywusa0nVyaIEZ8znMXRId0XeiMglUAXEHnIGLck6MpPnNHf_LAPH2t0ctyP84Snse6YhC63xEnAhcFaqHWEelGoiOhSEJPyqDX7ihILuEbs8jEbwr0FTbxsPssNlo0KDs_VbHpHGP9JLvUbw4VKA8qO7UGO8-Aji9fnp")
		////salt, _ := slosilo.RandomBytes(32)
		//
		//// protected
		//header := "eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiIxMGQxODQ5NzJiYTUyOWE1YWJkZGRmY2I4ZjdiM2ZhYWZmMGI4NGMxYTg0NjdhZmJlMzcyY2FkY2I1YjhkOGEyIn0="
		////// payload
		//claims := "eyJzdWIiOiJEYXZlQEJvdEFwcCIsImlhdCI6MTYxODYwNDczMX0="
		////
		//
		//salt := sig[len(sig)-32:]
		////fmt.Println(string(salt))
		////return
		//stringtosign := strings.Join([]string{header, claims}, ".")
		////_, _ = key.Sign([]byte(stringtosign), salt)
		//signature, _ := key.Sign([]byte(stringtosign), salt)
		////fmt.Println(len(signature))
		//
		//fmt.Println(base64.URLEncoding.EncodeToString(signature))
		//return
		newclaimsMap := map[string]interface{}{
			"iat": time.Now().Unix(),
			"sub": "Dave@BotApp",
		}
		newheaderMap := map[string]interface{}{
			"alg": "conjur.org/slosilo/v2",
			"kid": fingerprint,
		}
		newheader := utils.ToJson(newheaderMap)
		newclaims := utils.ToJson(newclaimsMap)

		newsalt, _ := slosilo.RandomBytes(32)
		//newsalt := salt
		stringToSign := strings.Join(
			[]string{
				base64.URLEncoding.EncodeToString([]byte(newheader)),
				base64.URLEncoding.EncodeToString([]byte(newclaims)),
			},
			".",
		)

		newsignature, _ := key.Sign(
			[]byte(
				stringToSign,
			),
			newsalt,
		)
		fmt.Println(
			key.Verify(
				[]byte(
					stringToSign,
				),
				newsignature,
			),
		)

		return
		newjwt := map[string]string{
			"protected": base64.URLEncoding.EncodeToString([]byte(newheader)),
			"payload":   base64.URLEncoding.EncodeToString([]byte(newclaims)),
			"signature": base64.URLEncoding.EncodeToString(newsignature),
		}

		fmt.Println(utils.ToJson(newjwt))
	})

	t.Run("Token", func(t *testing.T) {
		t.Skip()
		tokenStr := `{
  "protected": "eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiIxMGQxODQ5NzJiYTUyOWE1YWJkZGRmY2I4ZjdiM2ZhYWZmMGI4NGMxYTg0NjdhZmJlMzcyY2FkY2I1YjhkOGEyIn0=",
  "payload": "eyJzdWIiOiJEYXZlQEJvdEFwcCIsImlhdCI6MTYxODU4NzMwNX0=",
  "signature": "pst9nTv6q1bTkhAv4Wgv2lxE2D4_WljYaD6UAYMpUVNJhL8N41sDK__EVG-ZHUT9bXWRrObNKad6f_pRKqi8qf9j5BzNwCq5Te32O5QOMKbuegPf6dSyKSCmmEqhZluFZbIrRel3qjNtnUbYIddVJDGJmtCLylGNu410iw6MEFGVbDNhKqEcQphsTGUiur11m0SFeaPiudlUNUVaJ9nnafyf2PCQWcxd3dALiWBF8DZqSjA9v5xW3cExXiqafomE9e4z-gl3yiOyyY5iGOv5f7wOVbnQYff1VVNWGSBN1dco4k5ZcZT2NYgsSIMWUz78damgQ-braMyTWHqMZw7kSxFF09k4PaFCx_7LmenI5mOHGKaBagGZE3t2uifNunC6"
}
`
		token, err := slosilo.NewParsedToken([]byte(tokenStr))
		fmt.Println(token, err)
	})

	t.Run("Gen", func(t *testing.T) {
		encPkey, _ := hex.DecodeString("47af2d19c59c0f532c34384f3aad2af1f3e05fba68b5cc4818c93a960d67c0cd6c5aad3b9613b325a9c4b936489650c839d9b6812936b6ae395463f75f3d2f1fa657998d57bae9841f5950fb907219d845d0111370cc6b16930f936c71c4e1833f5eb7fd18e6697d15059b34bfdd10a3edee3f296a5cd781da87ca753c5974f661a10c5db980d0e29a7272c214686183d6d82fcadb5a68a4856d6d8988d03b270a30ce625448cc1e9321dd332e1b984ffa50cdf9e4d2e04e682235536e1a58edfb477a1f17a223b8c55223f1adcb9b1de6403de259cfd181d646bd6cd6dc2e6f6cf25ccb8940b30f6455cf0e77dd67d0eb11b1ac5f4c89c01bf10bde5b50654e00e8f62b86577d36ffd957b6462c53d00c6763f1e548e9de065bb0a5ff39e1e73c8ec91f46c342a73aa7aeec2ded51809e50cec4a63a32fc1743faac7aa7e4b3ae292bce61ad6409b1b55276b7a7af4319d663a27659ebcaff575e8fa9e8373a88ee04dc5cd41a997c78a5a29fe59b77bf076c444b5dfa83416d0c35d9651428f03d5f593674529d67323ab9e841960782b687ac5e48845ef0847ee680b48ba8411f28c8619f4b930381b4a233a2cfb101dda17a371b051c7488c982f1a383eb9219fa95a847fa6dc391a4a83f65dd97469fa30a44224a1bf7bceb64ffc6d91dba476e98de139694805d1c618f42d02ebd0e1e7f923462e0ac65ab3f4e6a0527e8133c7fa644de5cfd17ae6f6d27675487fa1cd4357c87a816c020353161aa681e25bd05807dd5bc1f40c6d44775325c7e69c556915db364d841eaf52f32595d576befeaa4735c05e15561c41eb6852bd4022a5d745af89024a650d49e72e486347a202dc88ab597df73e08347c651f534f8fc14859f5d14dc9cf7ed1b74cbb256d2d78035256061a472bbad5d4306c4a4ba98a19d2c0374b6bbbd9a70ca922eee5db98954dd8eef21492daf0658ac10bc67194707cd9cec5236a25ca7293ae6d07317c35329511321d020d58934717a28c72f62f4ba990e7ae38074f05ffc3e236d0f0eac158381739d051c35a71144b7811eb67da281944403e08b2fe1ec732392269e674a224c02c22b40e697813f69569e1dfe62da440b3fb3858d55433ce67fe7583c5d27d8afafdfde597a09888a176e79805d70c88496ce2d11f1decd51863f398aee771680180b1dae48ab0099bba881a0ee9e53e93a9ce5b908e0f0de2fbc52928c21fe85aa89b973b0ad8028b79dbe0c267e80b51fdf5e539513f50b92d0fdb7d82b6d7dab344a9343c63ceaef1cae8a4897f1cd1222c8f7a7c4006065449bdfdf716df34c320436e34b6f4bd79dd57d4444fb5e8657925cc9a8dea521978dfda096308d7af54548ffdc1a30a5958ababe3ea8b30ca594654605daedc64c0ac6ebd32d86751d92153e7a007fedec579869957eec034127f152d32346b31025ffa473a92f6665f5d5478c84307047f99fcae2bfc373025dbc50df4e75a5912f417a706991b1b23b1e9c6eddcaa41984343a982f97f019db197145ee4fc948d8a9dabab2e8539ffded5ee19a699eb8c4be8690278e56293a5a41b5cf497679b6d08d901f1971ac15db74d69012e50df12e567afeb439f906d50a92365d497d8ee4c01fa0d3c63e9ec03c571c1caf9caace087a53c77dbcfdb956c0416ef2ed553a69478996f1ee52ed1770ca85773ef38186cb71d5e85396d11911446369dbd7")
		cipher, _ := slosilo.NewSymmetric(testDataKey)
		accountPkey, _ := cipher.Decrypt([]byte("authn:myConjurAccount"), encPkey)

		key, _ := slosilo.NewKey(accountPkey)
		newclaimsMap := map[string]interface{}{
			"iat": time.Now().Unix(),
			"sub": "host/Dave@BotApp",
		}
		fingerprint := key.Fingerprint()
		newheaderMap := map[string]interface{}{
			"alg": "conjur.org/slosilo/v2",
			"kid": fingerprint,
		}
		newheader := utils.ToJson(newheaderMap)
		newclaims := utils.ToJson(newclaimsMap)

		newsalt, _ := slosilo.RandomBytes(32)
		//newsalt := salt
		stringToSign := strings.Join(
			[]string{
				base64.URLEncoding.EncodeToString([]byte(newheader)),
				base64.URLEncoding.EncodeToString([]byte(newclaims)),
			},
			".",
		)

		newsignature, _ := key.Sign(
			[]byte(
				stringToSign,
			),
			newsalt,
		)
		newjwt := map[string]string{
			"protected": base64.URLEncoding.EncodeToString([]byte(newheader)),
			"payload":   base64.URLEncoding.EncodeToString([]byte(newclaims)),
			"signature": base64.URLEncoding.EncodeToString(newsignature),
		}

		fmt.Println(utils.ToJson(newjwt))
	})
}
