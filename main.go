package sessionseal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"log"

	b64 "encoding/base64"

	"golang.org/x/crypto/pbkdf2"
)

func Unseal(password string, sealed string) ([]byte, error) {
	data, err := b64.URLEncoding.DecodeString(sealed)
	if err != nil {
		log.Fatalf("error while parsing b64: %s", err)
	}
	encSalt := data[0:8]
	signSalt := data[8:16]
	iv := data[16 : 16+aes.BlockSize]
	expectedMAC := data[16+aes.BlockSize : 48+aes.BlockSize]
	encrypted := data[48+aes.BlockSize:]
	key := GenerateAESKey(password, encSalt)
	hmacKey := GenerateKey(password, signSalt)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encrypted)
	if hmac.Equal(mac.Sum(nil), expectedMAC) {
		decrypted := Decrypt(key, iv, encrypted)
		return bytes.Trim(decrypted, "\x00"), nil
	} else {
		return nil, fmt.Errorf("invalid sig")
	}
}

func Seal(password string, data []byte) string {
	return b64.URLEncoding.EncodeToString(SealBytes(password, data))
}

func SealBytes(password string, data []byte) []byte {
	encSalt := RandomBytes(8)
	signSalt := RandomBytes(8)
	iv := RandomBytes(aes.BlockSize)
	key := GenerateAESKey(password, encSalt)
	hmacKey := GenerateKey(password, signSalt)
	encrypted := Encrypt(key, iv, data)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encrypted)
	expectedMAC := mac.Sum(nil)

	return append(
		append(
			append(
				append(
					encSalt,
					signSalt...),
				iv...),
			expectedMAC...),
		encrypted...)
}

func Encrypt(key cipher.Block, iv []byte, data []byte) []byte {
	buf := make([]byte, len(data)+aes.BlockSize-len(data)%aes.BlockSize)
	copy(buf, data)
	enc := cipher.NewCBCDecrypter(key, iv)
	enc.CryptBlocks(buf, buf)
	return buf
}

func Decrypt(key cipher.Block, iv []byte, data []byte) []byte {
	buf := make([]byte, len(data)+len(data)%aes.BlockSize)
	copy(buf, data)
	enc := cipher.NewCBCEncrypter(key, iv)
	enc.CryptBlocks(buf, buf)
	return buf
}

func RandomBytes(len int) []byte {
	buf := make([]byte, len)
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatalf("error while generating random string: %s", err)
	}
	return buf
}

func GenerateKey(password string, salt []byte) []byte {
	dk := pbkdf2.Key([]byte(password), salt, 4096, 32, sha1.New)
	return dk
}

func GenerateAESKey(password string, salt []byte) cipher.Block {
	dk := pbkdf2.Key([]byte(password), salt, 4096, 32, sha1.New)
	key, err := aes.NewCipher(dk)
	if err != nil {
		log.Fatalf("error while generating key: %s", err)
	}
	return key
}
