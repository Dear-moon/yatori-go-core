package zhihuishu

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

// The AI course frontend publishes this key material. The server seals the
// session keys with the matching private key, so a public operation opens them.
const (
	sessionKeyAIModule     = 6
	sessionKeyCourseModule = 13
	sessionKeyPublicKey    = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgfZmpLpPEpEFRKBe+ZjWJUjPe+7qg7pGqcfN3j2egJ8H2mrKwaEqZEnPnpi2O3hN8HRyaFozDOp8gwZiYfiIZjWy0Jr/FNAiiKYh5bq0GsEn+ieMmRyJg/+i1rqizhvCXvFdrdGhFTw5EBwTpsGdwe1utdlrvIJUAFWj9Yh4qbQIDAQAB"
	sessionIVHex           = "31673371716468346a7662736b623978"
	sessionKeyEndpoint     = "https://appcomm-user.zhihuishu.com/app-commserv-user/c/has"
)

// fetchSessionKeys derives the study keys from the installed cookies.
func (c *Client) fetchSessionKeys(ctx context.Context) error {
	pub, err := sessionPublicKey()
	if err != nil {
		return &RequestError{Operation: "session key", Kind: ErrUnexpectedResponse}
	}
	keys := make(map[int][]byte, 2)
	for _, module := range []int{sessionKeyAIModule, sessionKeyCourseModule} {
		key, err := c.requestModuleKey(ctx, pub, module)
		if err != nil {
			return err
		}
		keys[module] = key
	}
	iv, err := hex.DecodeString(sessionIVHex)
	if err != nil || len(iv) != aes.BlockSize {
		return &RequestError{Operation: "session iv", Kind: ErrUnexpectedResponse}
	}
	c.aiKey = keys[sessionKeyAIModule]
	c.courseKey = keys[sessionKeyCourseModule]
	c.iv = iv
	return nil
}

func (c *Client) requestModuleKey(ctx context.Context, pub *rsa.PublicKey, module int) ([]byte, error) {
	payload, err := json.Marshal(map[string]int{"module": module})
	if err != nil {
		return nil, &RequestError{Operation: "session key", Kind: ErrUnexpectedResponse}
	}
	sealed, err := rsa.EncryptPKCS1v15(rand.Reader, pub, payload)
	if err != nil {
		return nil, &RequestError{Operation: "session key", Kind: ErrRequestFailed, cause: err}
	}
	target := sessionKeyEndpoint + "?uid=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sealed))
	var response struct {
		Status string `json:"status"`
		RT     struct {
			SL string `json:"sl"`
		} `json:"rt"`
	}
	if err := c.request(ctx, "session key", http.MethodGet, target, nil, nil, &response); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(response.RT.SL))
	if err != nil || len(raw) == 0 {
		return nil, &RequestError{Operation: "session key seal", Kind: ErrUnexpectedResponse}
	}
	plain, err := decryptWithPublicKey(pub, raw)
	if err != nil {
		return nil, &RequestError{Operation: "session key decrypt", Kind: ErrUnexpectedResponse, cause: err}
	}
	var material struct {
		CKey string `json:"cKey"`
	}
	if json.Unmarshal(plain, &material) != nil || !validAESKey([]byte(material.CKey)) {
		return nil, &RequestError{Operation: "session key material", Kind: ErrUnexpectedResponse}
	}
	return []byte(material.CKey), nil
}

func sessionPublicKey() (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(sessionKeyPublicKey)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, ErrUnexpectedResponse
	}
	return pub, nil
}

// decryptWithPublicKey applies the raw RSA public operation, then strips the
// PKCS#1 v1.5 type 1 block that carried the session key.
func decryptWithPublicKey(pub *rsa.PublicKey, ciphertext []byte) ([]byte, error) {
	size := pub.Size()
	if len(ciphertext) != size {
		return nil, ErrUnexpectedResponse
	}
	message := new(big.Int).Exp(new(big.Int).SetBytes(ciphertext), big.NewInt(int64(pub.E)), pub.N)
	block := make([]byte, size)
	raw := message.Bytes()
	if len(raw) > size {
		return nil, ErrUnexpectedResponse
	}
	copy(block[size-len(raw):], raw)
	if block[0] != 0x00 || block[1] != 0x01 {
		return nil, ErrUnexpectedResponse
	}
	i := 2
	for ; i < len(block) && block[i] == 0xFF; i++ {
	}
	if i < 10 || i >= len(block) || block[i] != 0x00 {
		return nil, ErrUnexpectedResponse
	}
	return block[i+1:], nil
}
