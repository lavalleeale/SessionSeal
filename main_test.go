package sessionseal_test

import (
	"crypto/aes"
	"log"
	"testing"

	b64 "encoding/base64"
	"encoding/json"

	sessionseal "github.com/lavalleeale/SessionSeal"
)

type TestData struct {
	Name  string
	Extra bool
}

func TestInvalid(t *testing.T) {
	original := "test"
	data := []byte(original)
	sealed, _ := b64.URLEncoding.DecodeString(sessionseal.Seal("test", data))
	sealed[50+aes.BlockSize] = 0x01
	_, err := sessionseal.Unseal("test", b64.URLEncoding.EncodeToString(sealed))
	if err == nil || err.Error() != "invalid sig" {
		t.Errorf(err.Error())
	}
}

func TestSeal(t *testing.T) {
	original := TestData{Name: "test", Extra: false}
	data, _ := json.Marshal(original)
	sealed := sessionseal.Seal("test", data)
	log.Println(len(data))
	unsealed, err := sessionseal.Unseal("test", sealed)
	if err != nil {
		t.Errorf(err.Error())
	}
	var new TestData
	json.Unmarshal(unsealed, &new)
	if new != original {
		t.Errorf("Unsealed %s, want %s", new.Name, original.Name)
	}
}
