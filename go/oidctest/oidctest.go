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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// Key is one signing key of the fake IdP.
type Key struct {
	Kid  string
	Alg  string // RS256, ES256 or EdDSA
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

// New starts a fake IdP with one key of alg (RS256, ES256 or EdDSA) and the given audience.
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

// Rotate adds a new current key of alg; older keys stay published until RemoveKey.
func (i *IdP) Rotate(alg string) *Key {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.counter++
	k := &Key{Kid: fmt.Sprintf("key-%d", i.counter), Alg: alg}
	switch alg {
	case "ES256":
		priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		raw, _ := priv.PublicKey.Bytes() // 0x04 || X || Y
		k.priv = priv
		k.jwk = map[string]any{"kty": "EC", "crv": "P-256", "x": b64(raw[1:33]), "y": b64(raw[33:])}
	case "EdDSA":
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		k.priv = priv
		k.jwk = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(pub)}
	default:
		k.Alg = "RS256"
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

// Sign signs data with key in JWS form (RS256 PKCS#1 v1.5, ES256 r||s, EdDSA raw).
func Sign(key *Key, data []byte) []byte {
	digest := sha256.Sum256(data)
	switch priv := key.priv.(type) {
	case *ecdsa.PrivateKey:
		r, s, _ := ecdsa.Sign(rand.Reader, priv, digest[:])
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	case ed25519.PrivateKey:
		return ed25519.Sign(priv, data)
	case *rsa.PrivateKey:
		sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
		return sig
	}
	return nil
}
