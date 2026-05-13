package backend

import (
	"github.com/ProtonMail/go-srp"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// GenerateKey is the v3 equivalent of the v2 helper.GenerateKey: it generates
// a new pgp key, encrypts it with the given passphrase, and returns the armored
// string. keyType controls the algorithm ("rsa" -> 4096-bit RSA, anything else
// uses the profile default, which is curve25519). bits is ignored in v3.
var GenerateKey = func(name, email string, passphrase []byte, keyType string, bits int) (string, error) {
	pgp := crypto.PGP()

	builder := pgp.KeyGeneration().AddUserId(name, email)
	if keyType == "rsa" {
		builder = builder.OverrideProfileAlgorithm(crypto.KeyGenerationRSA4096)
	}

	key, err := builder.New().GenerateKey()
	if err != nil {
		return "", err
	}
	defer key.ClearPrivateParams()

	locked, err := pgp.LockKey(key, passphrase)
	if err != nil {
		return "", err
	}

	return locked.Armor()
}

func hashPassword(password, salt []byte) ([]byte, error) {
	passphrase, err := srp.MailboxPassword(password, salt)
	if err != nil {
		return nil, err
	}

	return passphrase[len(passphrase)-31:], nil
}

func encryptWithSignature(kr *crypto.KeyRing, b []byte) (string, string, error) {
	pgp := crypto.PGP()

	encHandle, err := pgp.Encryption().Recipients(kr).New()
	if err != nil {
		return "", "", err
	}

	enc, err := encHandle.Encrypt(b)
	if err != nil {
		return "", "", err
	}

	encArm, err := enc.Armor()
	if err != nil {
		return "", "", err
	}

	signHandle, err := pgp.Sign().SigningKeys(kr).Detached().New()
	if err != nil {
		return "", "", err
	}

	sigArm, err := signHandle.Sign(b, crypto.Armor)
	if err != nil {
		return "", "", err
	}

	return encArm, string(sigArm), nil
}
