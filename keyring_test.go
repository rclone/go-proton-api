package proton

import (
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/stretchr/testify/require"
)

func TestKeyring_Unlock(t *testing.T) {
	r := require.New(t)

	pgp := crypto.PGP()
	newKey := func(id, passphrase string) Key {
		key, err := pgp.KeyGeneration().AddUserId(id, id+"@email.com").New().GenerateKey()
		r.NoError(err)
		defer key.ClearPrivateParams()

		locked, err := pgp.LockKey(key, []byte(passphrase))
		r.NoError(err)

		serial, err := locked.Serialize()
		r.NoError(err)

		return Key{
			ID:         id,
			PrivateKey: serial,
			Active:     true,
		}
	}

	keys := Keys{
		newKey("1", "good_phrase"),
		newKey("2", "good_phrase"),
		newKey("3", "bad_phrase"),
	}

	_, err := keys.Unlock([]byte("ugly_phrase"), nil)
	r.Error(err)

	kr, err := keys.Unlock([]byte("bad_phrase"), nil)
	r.NoError(err)
	r.Equal(1, kr.CountEntities())

	kr, err = keys.Unlock([]byte("good_phrase"), nil)
	r.NoError(err)
	r.Equal(2, kr.CountEntities())
}
