package proton_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	proton "github.com/rclone/go-proton-api"
)

// newTestKeyRing generates a keyring holding one fresh key. v6 selects a
// crypto-refresh (RFC 9580) key with AEAD preferences, like the v6 file node
// keys Proton Drive uses.
func newTestKeyRing(t *testing.T, v6 bool) *crypto.KeyRing {
	t.Helper()
	pgp := crypto.PGP()
	if v6 {
		p := profile.RFC9580()
		p.AeadEncryption = &packet.AEADConfig{DefaultMode: packet.AEADModeGCM}
		pgp = crypto.PGPWithProfile(p)
	}
	key, err := pgp.KeyGeneration().AddUserId("test", "test@example.com").New().GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kr, err := crypto.NewKeyRing(key)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	return kr
}

// checkNonAeadFormat asserts msg is a v3 PKESK followed by a v1 SEIPD packet.
func checkNonAeadFormat(t *testing.T, label string, msg []byte) {
	t.Helper()
	r := packet.NewReader(bytes.NewReader(msg))
	p, err := r.Next()
	if err != nil {
		t.Fatalf("%s: read first packet: %v", label, err)
	}
	ek, ok := p.(*packet.EncryptedKey)
	if !ok {
		t.Fatalf("%s: first packet: got %T, want PKESK", label, p)
	}
	if ek.Version != 3 {
		t.Fatalf("%s: PKESK version: got %d, want 3", label, ek.Version)
	}
	p, err = r.Next()
	if err != nil {
		t.Fatalf("%s: read second packet: %v", label, err)
	}
	se, ok := p.(*packet.SymmetricallyEncrypted)
	if !ok {
		t.Fatalf("%s: second packet: got %T, want SEIPD", label, p)
	}
	if se.Version != 1 {
		t.Fatalf("%s: SEIPD version: got %d, want 1", label, se.Version)
	}
}

// TestEncryptMessageNonAead checks that the old (pre-crypto-refresh) wire
// format is produced even when the recipient is a v6 key advertising AEAD
// support, and that the message still decrypts and verifies.
func TestEncryptMessageNonAead(t *testing.T) {
	addrKR := newTestKeyRing(t, false)
	plaintext := []byte("some auxiliary data")

	for _, v6 := range []bool{false, true} {
		nodeKR := newTestKeyRing(t, v6)

		enc, err := proton.EncryptMessageNonAead(nodeKR, plaintext, addrKR)
		if err != nil {
			t.Fatalf("v6=%v: encrypt: %v", v6, err)
		}
		checkNonAeadFormat(t, "message", enc.Bytes())

		dec, err := crypto.PGP().Decryption().DecryptionKeys(nodeKR).VerificationKeys(addrKR).New()
		if err != nil {
			t.Fatalf("v6=%v: decryption handle: %v", v6, err)
		}
		res, err := dec.Decrypt(enc.Bytes(), crypto.Bytes)
		if err != nil {
			t.Fatalf("v6=%v: decrypt: %v", v6, err)
		}
		if sigErr := res.SignatureError(); sigErr != nil {
			t.Fatalf("v6=%v: signature: %v", v6, sigErr)
		}
		if !bytes.Equal(res.Bytes(), plaintext) {
			t.Fatalf("v6=%v: plaintext mismatch", v6)
		}
	}
}

// TestSetEncXAttrStringNonAead checks that the xattr blob is written in the
// old wire format when the node key is a v6 file node key. The official
// Proton clients cannot decrypt an AEAD-encrypted xattr.
func TestSetEncXAttrStringNonAead(t *testing.T) {
	addrKR := newTestKeyRing(t, false)
	nodeKR := newTestKeyRing(t, true)

	xattr := &proton.RevisionXAttrCommon{
		ModificationTime: "2026-08-01T00:00:00+0000",
		Size:             1234,
	}
	var req proton.CommitRevisionReq
	if err := req.SetEncXAttrString(addrKR, nodeKR, xattr); err != nil {
		t.Fatalf("SetEncXAttrString: %v", err)
	}

	msg, err := crypto.NewPGPMessageFromArmored(req.XAttr)
	if err != nil {
		t.Fatalf("unarmor xattr: %v", err)
	}
	checkNonAeadFormat(t, "xattr", msg.Bytes())

	dec, err := crypto.PGP().Decryption().DecryptionKeys(nodeKR).VerificationKeys(addrKR).New()
	if err != nil {
		t.Fatalf("decryption handle: %v", err)
	}
	res, err := dec.Decrypt(msg.Bytes(), crypto.Bytes)
	if err != nil {
		t.Fatalf("decrypt xattr: %v", err)
	}
	if sigErr := res.SignatureError(); sigErr != nil {
		t.Fatalf("signature: %v", sigErr)
	}
	var got proton.RevisionXAttr
	if err := json.Unmarshal(res.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal xattr: %v", err)
	}
	if got.Common.Size != xattr.Size || got.Common.ModificationTime != xattr.ModificationTime {
		t.Fatalf("xattr round-trip mismatch: %+v", got)
	}
}

// TestSetNameNonAead checks that the encrypted name is written in the old
// wire format even if the recipient node key is v6.
func TestSetNameNonAead(t *testing.T) {
	addrKR := newTestKeyRing(t, false)
	nodeKR := newTestKeyRing(t, true)

	var req proton.CreateFileReq
	if err := req.SetName("file.txt", addrKR, nodeKR); err != nil {
		t.Fatalf("SetName: %v", err)
	}
	msg, err := crypto.NewPGPMessageFromArmored(req.Name)
	if err != nil {
		t.Fatalf("unarmor name: %v", err)
	}
	checkNonAeadFormat(t, "name", msg.Bytes())
}
