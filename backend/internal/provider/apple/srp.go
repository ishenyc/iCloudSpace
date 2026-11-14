package apple

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

// RFC 5054 Appendix A, 2048-bit group. Apple uses SHA-256 and RFC padding for
// k/u; passwordMaterial below implements the s2k and s2k_fo preprocessing.
const group2048 = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

type srpAttempt struct{ secret, public *big.Int }

func srpGroup() (*big.Int, *big.Int) {
	n, _ := new(big.Int).SetString(group2048, 16)
	return n, big.NewInt(2)
}

func beginSRP() (*srpAttempt, error) {
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, invalid("srp_entropy")
	}
	// RFC 5054 section 3.1 recommends at least 256 bits of random ephemeral.
	entropy[0] |= 0x80
	a := new(big.Int).SetBytes(entropy[:])
	n, g := srpGroup()
	return &srpAttempt{secret: a, public: new(big.Int).Exp(g, a, n)}, nil
}

type srpChallenge struct {
	Protocol     string `json:"protocol"`
	Salt         string `json:"salt"`
	Iterations   int    `json:"iteration"`
	ServerPublic string `json:"b"`
	Continuation string `json:"c"`
}

func hash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}
func padded(n *big.Int) []byte { return n.FillBytes(make([]byte, 256)) }

func passwordMaterial(password string, salt []byte, iterations int, protocol string) ([]byte, error) {
	if iterations < 1 || iterations > 1_000_000 || len(salt) < 8 || len(salt) > 1024 {
		return nil, invalid("srp_challenge")
	}
	digest := sha256.Sum256([]byte(password))
	var input []byte
	switch protocol {
	case "s2k":
		input = digest[:]
	case "s2k_fo":
		input = []byte(hex.EncodeToString(digest[:]))
	default:
		return nil, invalid("srp_protocol")
	}
	return pbkdf2.Key(input, salt, iterations, 32, sha256.New), nil
}

// proof applies the SRP-6a equations. math/big modular exponentiation is not a
// constant-time primitive; this TLS-only network adapter makes no local side-
// channel resistance claim. No alternate/custom group is accepted.
func (a *srpAttempt) proof(ctx context.Context, identity, password string, challenge srpChallenge) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", networkError("srp_challenge", err, false, false)
	}
	if len(challenge.Salt) > 2048 || len(challenge.ServerPublic) > 344 || !field(challenge.Continuation, 32768, true) {
		return "", "", invalid("srp_challenge")
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(challenge.Salt)
	if err != nil {
		return "", "", invalid("srp_challenge")
	}
	encodedB, err := base64.StdEncoding.Strict().DecodeString(challenge.ServerPublic)
	if err != nil || len(encodedB) == 0 || len(encodedB) > 256 {
		return "", "", invalid("srp_challenge")
	}
	n, g := srpGroup()
	b := new(big.Int).SetBytes(encodedB)
	if b.Sign() == 0 || b.Cmp(n) >= 0 {
		return "", "", invalid("srp_challenge")
	}
	material, err := passwordMaterial(password, salt, challenge.Iterations, challenge.Protocol)
	if err != nil {
		return "", "", err
	}
	if err := ctx.Err(); err != nil {
		return "", "", networkError("srp_challenge", err, false, false)
	}
	x := new(big.Int).SetBytes(hash(salt, hash([]byte(":"), material)))
	u := new(big.Int).SetBytes(hash(padded(a.public), padded(b)))
	if u.Sign() == 0 {
		return "", "", invalid("srp_challenge")
	}
	k := new(big.Int).SetBytes(hash(n.Bytes(), padded(g)))
	verifier := new(big.Int).Exp(g, x, n)
	base := new(big.Int).Sub(b, new(big.Int).Mul(k, verifier))
	base.Mod(base, n)
	if base.Sign() == 0 {
		return "", "", invalid("srp_challenge")
	}
	exponent := new(big.Int).Add(a.secret, new(big.Int).Mul(u, x))
	shared := new(big.Int).Exp(base, exponent, n)
	key := hash(shared.Bytes())
	nHash, gHash := hash(n.Bytes()), hash(padded(g))
	for i := range nHash {
		nHash[i] ^= gHash[i]
	}
	clientProof := hash(nHash, hash([]byte(identity)), salt, a.public.Bytes(), b.Bytes(), key)
	serverProof := hash(a.public.Bytes(), clientProof, key)
	return base64.StdEncoding.EncodeToString(clientProof), base64.StdEncoding.EncodeToString(serverProof), nil
}
