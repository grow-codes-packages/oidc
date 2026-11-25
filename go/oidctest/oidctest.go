// Package oidctest is a local fake OpenID provider for tests: it serves
// /.well-known/openid-configuration and /jwks over httptest, mints signed tokens and rotates keys.
// Never use it outside tests.
package oidctest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// Key is one signing key of the fake IdP.
type Key struct {
	Kid  string
	Alg  string // RS256/384/512, PS256/384/512, ES256/384/512 or EdDSA
	priv crypto.Signer
	jwk  map[string]any
}

// IdP is a fake OpenID provider. Create it with New and Close it when done.
type IdP struct {
	// Server is the underlying test server; Issuer is its URL.
	Server *httptest.Server
	// Issuer is the iss of minted tokens (the server URL).
	Issuer string
	// Audience is the aud of minted tokens.
	Audience string

	mu       sync.Mutex
	keys     []*Key
	current  string
	counter  int
	hits     map[string]int
	failWith int
}

// New starts a fake IdP with one key of alg (RS256/384/512, PS256/384/512, ES256/384/512 or EdDSA;
// anything else means RS256) and the given audience.
func New(audience, alg string) *IdP {
	idp := &IdP{Audience: audience, hits: map[string]int{}}
	idp.Server = httptest.NewServer(http.HandlerFunc(idp.serve))
	idp.Issuer = idp.Server.URL
	idp.Rotate(alg)
	return idp
}

// Close stops the server.
func (i *IdP) Close() { i.Server.Close() }

// Hits returns how often path was requested.
func (i *IdP) Hits(path string) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.hits[path]
}

// Fail makes every response use status (0 = serve normally).
func (i *IdP) Fail(status int) {
	i.mu.Lock()
	i.failWith = status
	i.mu.Unlock()
}

func (i *IdP) serve(w http.ResponseWriter, r *http.Request) {
	i.mu.Lock()
	i.hits[r.URL.Path]++
	fail := i.failWith
	keys := make([]map[string]any, 0, len(i.keys))
	for _, k := range i.keys {
		keys = append(keys, k.jwk)
	}
	i.mu.Unlock()
	if fail != 0 {
		w.WriteHeader(fail)
		return
	}
	var body any
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		body = map[string]any{"issuer": i.Issuer, "jwks_uri": i.Issuer + "/jwks"}
	case "/jwks":
		body = map[string]any{"keys": keys}
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ecCurves maps an ES algorithm to its curve and JWK crv.
var ecCurves = map[string]struct {
	curve elliptic.Curve
	crv   string
}{
	"ES256": {elliptic.P256(), "P-256"},
	"ES384": {elliptic.P384(), "P-384"},
	"ES512": {elliptic.P521(), "P-521"},
}

// Rotate adds a new current key of alg (RS256/384/512, PS256/384/512, ES256/384/512 or EdDSA;
// anything else means RS256); older keys stay published until RemoveKey.
func (i *IdP) Rotate(alg string) *Key {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.counter++
	k := &Key{Kid: fmt.Sprintf("key-%d", i.counter), Alg: alg}
	switch alg {
	case "ES256", "ES384", "ES512":
		c := ecCurves[alg]
		priv, _ := ecdsa.GenerateKey(c.curve, rand.Reader)
		raw, _ := priv.PublicKey.Bytes() // 0x04 || X || Y
		size := (len(raw) - 1) / 2
		k.priv = priv
		k.jwk = map[string]any{"kty": "EC", "crv": c.crv, "x": b64(raw[1 : 1+size]), "y": b64(raw[1+size:])}
	case "EdDSA":
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		k.priv = priv
		k.jwk = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(pub)}
	default:
		switch alg {
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		default:
			k.Alg = "RS256"
		}
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		k.priv = priv
		k.jwk = map[string]any{"kty": "RSA", "n": b64(priv.N.Bytes()), "e": b64(big.NewInt(int64(priv.E)).Bytes())}
	}
	k.jwk["kid"], k.jwk["alg"], k.jwk["use"] = k.Kid, k.Alg, "sig"
	i.keys = append(i.keys, k)
	i.current = k.Kid
	return k
}

// RemoveKey stops publishing kid.
func (i *IdP) RemoveKey(kid string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for n, k := range i.keys {
		if k.Kid == kid {
			i.keys = append(i.keys[:n], i.keys[n+1:]...)
			return
		}
	}
}

// MintOptions tune a minted token.
type MintOptions struct {
	// Kid selects the signing key (default: current). "-" omits the kid header.
	Kid string
	// Header overrides header fields.
	Header map[string]any
	// TTL is the lifetime (default 5 min).
	TTL time.Duration
}

// Mint signs claims (merged over iss, aud, sub "user-1", iat, exp; a nil value removes a claim).
func (i *IdP) Mint(claims map[string]any, opts MintOptions) string {
	i.mu.Lock()
	kid := opts.Kid
	if kid == "" || kid == "-" {
		kid = i.current
	}
	var key *Key
	for _, k := range i.keys {
		if k.Kid == kid {
			key = k
		}
	}
	i.mu.Unlock()
	if key == nil {
		panic("oidctest: unknown kid " + kid)
	}
	ttl := opts.TTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now()
	all := map[string]any{"iss": i.Issuer, "aud": i.Audience, "sub": "user-1", "iat": now.Unix(), "exp": now.Add(ttl).Unix()}
	for name, value := range claims {
		if value == nil {
			delete(all, name)
		} else {
			all[name] = value
		}
	}
	header := map[string]any{"alg": key.Alg, "typ": "JWT", "kid": key.Kid}
	if opts.Kid == "-" {
		delete(header, "kid")
	}
	for name, value := range opts.Header {
		header[name] = value
	}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(all)
	signed := b64(h) + "." + b64(p)
	return signed + "." + b64(Sign(key, []byte(signed)))
}

// Sign signs data with key in JWS form for key.Alg (RS* PKCS#1 v1.5, PS* PSS with a salt as long
// as the hash, ES* fixed-size r||s, EdDSA raw).
func Sign(key *Key, data []byte) []byte {
	h := crypto.SHA256
	if strings.HasSuffix(key.Alg, "384") {
		h = crypto.SHA384
	} else if strings.HasSuffix(key.Alg, "512") {
		h = crypto.SHA512
	}
	var digest []byte
	switch h {
	case crypto.SHA384:
		d := sha512.Sum384(data)
		digest = d[:]
	case crypto.SHA512:
		d := sha512.Sum512(data)
		digest = d[:]
	default:
		d := sha256.Sum256(data)
		digest = d[:]
	}
	switch priv := key.priv.(type) {
	case *ecdsa.PrivateKey:
		r, s, _ := ecdsa.Sign(rand.Reader, priv, digest)
		size := (priv.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out
	case ed25519.PrivateKey:
		return ed25519.Sign(priv, data)
	case *rsa.PrivateKey:
		if strings.HasPrefix(key.Alg, "PS") {
			sig, _ := rsa.SignPSS(rand.Reader, priv, h, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			return sig
		}
		sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, h, digest)
		return sig
	}
	return nil
}
