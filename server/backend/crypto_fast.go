package backend

import "github.com/ProtonMail/gopenpgp/v3/crypto"

var preCompKey *crypto.Key

func init() {
	// Use the default profile (curve25519) for speed: this key is reused
	// across tests via FastGenerateKey, so the actual algorithm does not
	// matter as long as key generation is fast.
	pgp := crypto.PGP()
	key, err := pgp.KeyGeneration().AddUserId("name", "email").New().GenerateKey()
	if err != nil {
		panic(err)
	}

	preCompKey = key
}

// FastGenerateKey is a fast version of GenerateKey that uses a pre-computed key.
// This is useful for testing but is incredibly insecure.
func FastGenerateKey(_, _ string, passphrase []byte, _ string, _ int) (string, error) {
	pgp := crypto.PGP()
	encKey, err := pgp.LockKey(preCompKey, passphrase)
	if err != nil {
		return "", err
	}

	return encKey.Armor()
}
