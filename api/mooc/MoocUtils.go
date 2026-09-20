package mooc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"time"

	"github.com/tjfoc/gmsm/sm4"
	"github.com/tjfoc/gmsm/x509"
)

var publicKey = "BC60B8B9E4FFEFFA219E5AD77F11F9E2"

var rsaPublic = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5gsH+AA4XWONB5TDcUd+xCz7e\njOFHZKlcZDx+pF1i7Gsvi1vjyJoQhRtRSn950x498VUkx7rUxg1/ScBVfrRxQOZ8\nxFBye3pjAzfb22+RCuYApSVpJ3OO3KsEuKExftz9oFBv3ejxPlYc5yq7YiBO8XlT\nnQN0Sa4R4qhPO3I2MQIDAQAB\n-----END PUBLIC KEY-----"

func BuildRtId() (string, error) {
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	result := make([]byte, 32)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", &RequestError{Operation: "request identifier", Kind: ErrRequestFailed, cause: err}
		}
		result[i] = charset[n.Int64()]
	}
	return string(result), nil
}

func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA public key")
	}
	return pub, nil
}

func BuildPowGetPParams(pd, pkid, un, pvSid string, channel int, topURL, rtid string) string {
	return marshalParams(map[string]any{"pd": pd, "pkid": pkid, "un": un, "pvSid": pvSid, "channel": strconv.Itoa(channel), "topURL": topURL, "rtid": rtid})
}

func BuildZCInitParams(pd, pkid, pkht string, channel int, topURL, rtid string) string {
	return BuildDLInitParams(pd, pkid, pkht, channel, topURL, rtid)
}

func BuildDLInitParams(pd, pkid, pkht string, channel int, topURL, rtid string) string {
	return marshalParams(map[string]any{"pd": pd, "pkid": pkid, "pkht": pkht, "channel": channel, "topURL": topURL, "rtid": rtid})
}

func BuildGTParams(un string, channel int, pd, pkid string, topURL, rtid string) string {
	return marshalParams(map[string]any{"un": un, "pd": pd, "pkid": pkid, "channel": channel, "topURL": topURL, "rtid": rtid})
}

func BuildLParams(l, d int, un, pw, pd, pkid, tk, domains, puzzle string, spendTime, runTimes int, sid, x string, t, sign, channel int, topURL, rtid string) string {
	args := marshalParams(map[string]any{"x": x, "t": t, "sign": sign})
	return marshalParams(map[string]any{"l": l, "d": d, "un": un, "pw": pw, "pd": pd, "pkid": pkid, "tk": tk, "domains": domains,
		"pVParam": map[string]any{"puzzle": puzzle, "spendTime": spendTime, "runTimes": runTimes, "sid": sid, "args": args},
		"channel": channel, "topURL": topURL, "rtid": rtid})
}

// All callers supply only strings, integers, and maps containing those types.
func marshalParams(params map[string]any) string {
	encoded, _ := json.Marshal(params)
	return string(encoded)
}

func PowGetPTurnLData(puzzle, mod, x string, t int, minTime, maxTime int64) (int, int64, int, string, error) {
	count, elapsed, iterations, result, _, err := VdfAsync(Data{Args: Args{Puzzle: puzzle, Mod: mod, X: x, T: t}, MinTime: minTime, MaxTime: maxTime})
	return count, elapsed, iterations, result, err
}

func MOOCEncMS4(content string) (string, error) {
	key, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", &RequestError{Operation: "encrypt", Kind: ErrRequestFailed, cause: err}
	}
	out, err := sm4.Sm4Ecb(key, []byte(content), true)
	if err != nil {
		return "", &RequestError{Operation: "encrypt", Kind: ErrRequestFailed, cause: err}
	}
	return hex.EncodeToString(out), nil
}

func MOOCRSA(content string) (string, error) {
	pub, err := parseRSAPublicKey(rsaPublic)
	if err != nil {
		return "", &RequestError{Operation: "password encryption", Kind: ErrRequestFailed, cause: err}
	}
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(content))
	if err != nil {
		return "", &RequestError{Operation: "password encryption", Kind: ErrRequestFailed, cause: err}
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func PowSign(key string, seed int) uint32 {
	data := []byte(key)
	var h1 = uint32(seed)
	var c1 uint32 = 0xcc9e2d51
	var c2 uint32 = 0x1b873593

	// body
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k1 := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2

		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}

	// tail
	var k1 uint32
	tail := data[nblocks*4:]
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}

	// finalization
	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return h1
}

type Args struct {
	Mod    string
	T      int
	Puzzle string
	X      string
}

type Data struct {
	NeedCheck bool
	Sid       string
	HashFunc  string
	MaxTime   int64
	MinTime   int64
	Args      Args
}

func VdfAsync(data Data) (int, int64, int, string, uint32, error) {
	return VdfAsyncContext(context.Background(), data)
}

// Bounds prevent malformed remote challenges from exhausting CPU or memory.
func validateProof(data Data) (*big.Int, *big.Int, error) {
	invalid := &RequestError{Operation: "proof parameters", Kind: ErrUnexpectedResponse}
	if data.MinTime < 0 || data.MaxTime <= 0 || data.MinTime > data.MaxTime || data.MaxTime > 60000 ||
		data.Args.T < 0 || data.Args.T > 10000000 || len(data.Args.X) > 1024 || len(data.Args.Mod) > 1024 {
		return nil, nil, invalid
	}
	x, ok := new(big.Int).SetString(data.Args.X, 16)
	if !ok || x.Sign() < 0 {
		return nil, nil, invalid
	}
	mod, ok := new(big.Int).SetString(data.Args.Mod, 16)
	if !ok || mod.Cmp(big.NewInt(1)) <= 0 {
		return nil, nil, invalid
	}
	return x, mod, nil
}

func VdfAsyncContext(ctx context.Context, data Data) (int, int64, int, string, uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, 0, "", 0, err
	}
	bigx, bigmod, err := validateProof(data)
	if err != nil {
		return 0, 0, 0, "", 0, err
	}
	startTime := time.Now()
	count := 0
	tmp, sq := new(big.Int), new(big.Int)
	for i := 0; i < data.Args.T || time.Since(startTime).Milliseconds() < data.MinTime; i++ {
		if i%256 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, 0, 0, "", 0, err
			}
		}
		sq.Mul(bigx, bigx)
		tmp.Mod(sq, bigmod)
		bigx.Set(tmp)
		count++
		if time.Since(startTime).Milliseconds() > data.MaxTime {
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, 0, "", 0, err
	}
	elapsed := time.Since(startTime).Milliseconds()
	joined := "runTimes=" + strconv.Itoa(count) + "&spendTime=" + strconv.FormatInt(elapsed, 10) + "&t=" + strconv.Itoa(count) + "&x=" + url.QueryEscape(bigx.Text(16))
	return count, elapsed, count, bigx.Text(16), PowSign(joined, count), nil
}
