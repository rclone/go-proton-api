package backend

import (
	_ "embed"

	"github.com/ProtonMail/gopenpgp/v3/armor"
)

var modulus string

func init() {
	// v3 has no NewClearTextMessage helper; rebuild the v2 armored output
	// shape: a SIGNED MESSAGE header, the body, then an armored signature.
	armSig, err := armor.ArmorPGPSignature(sig)
	if err != nil {
		panic(err)
	}

	modulus = "-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA512\r\n\r\n" +
		string(asc) +
		"\r\n" +
		armSig
}

//go:embed modulus.asc
var asc []byte

//go:embed modulus.sig
var sig []byte
