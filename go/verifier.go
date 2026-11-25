package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Defaults of a Verifier.
const (
	// DefaultClockSkew is the tolerance applied to exp and nbf.
	DefaultClockSkew = 60 * time.Second
	// DefaultJWKSCacheTTL is how long a fetched JWKS is used before it is refetched.
	DefaultJWKSCacheTTL = 10 * time.Minute
	// DefaultJWKSRefreshCooldown is the minimum interval between two refetches caused by an unknown kid.
	DefaultJWKSRefreshCooldown = 30 * time.Second
	// DefaultHTTPTimeout bounds discovery and JWKS requests.
	DefaultHTTPTimeout = 10 * time.Second
	// DefaultRolesClaim is the claim that holds the roles.
	DefaultRolesClaim = "roles"
)

// Supported signing algorithms (asymmetric only; "none" and HMAC are never accepted).
const (
	RS256 = "RS256" // RSASSA-PKCS1-v1_5 with SHA-256
	RS384 = "RS384" // RSASSA-PKCS1-v1_5 with SHA-384
	RS512 = "RS512" // RSASSA-PKCS1-v1_5 with SHA-512
	PS256 = "PS256" // RSASSA-PSS with SHA-256
	PS384 = "PS384" // RSASSA-PSS with SHA-384
	PS512 = "PS512" // RSASSA-PSS with SHA-512
	ES256 = "ES256" // ECDSA P-256 with SHA-256
	ES384 = "ES384" // ECDSA P-384 with SHA-384
	ES512 = "ES512" // ECDSA P-521 with SHA-512
	EdDSA = "EdDSA" // Ed25519
)

// DefaultAlgorithms is the default algorithm allow-list: every supported algorithm.
var DefaultAlgorithms = []string{RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA}

// User is the authenticated user of a verified access token.
type User struct {
	// Sub is the "sub" claim.
	Sub string `json:"sub"`
	// Email is the "email" claim ("" when absent).
	Email string `json:"email,omitempty"`
	// Name is the "name" claim, else "preferred_username" ("" when absent).
	Name string `json:"name,omitempty"`
	// Roles are the role names from the roles claim.
	Roles []string `json:"roles"`
	// Claims holds every claim of the token (numbers as json.Number).
	Claims map[string]any `json:"claims"`
}

// HasRole reports whether the user has at least one of roles (case-insensitive).
func (u *User) HasRole(roles ...string) bool {
	return u != nil && HasAnyRole(u.Roles, roles)
}

// Options configures a Verifier. Zero values select the defaults.
type Options struct {
	// Issuer is the expected "iss" (exact match); discovery uses <Issuer>/.well-known/openid-configuration.
	Issuer string
	// Audience is the expected "aud" (the token's aud must contain it).
	Audience string
	// JWKSURL skips discovery when set.
	JWKSURL string
	// RolesClaim is the claim (or dotted path such as realm_access.roles) with the roles. Default "roles".
	RolesClaim string
	// Algorithms is the allow-list, a subset of RS256/384/512, PS256/384/512, ES256/384/512, EdDSA.
	// Default all of them.
	Algorithms []string
	// ClockSkew is the exp/nbf tolerance. Default 60 s; a negative value means no tolerance.
	ClockSkew time.Duration
	// JWKSCacheTTL is the JWKS cache lifetime. Default 10 min.
	JWKSCacheTTL time.Duration
	// JWKSRefreshCooldown is the minimum interval between unknown-kid refetches. Default 30 s; negative = none.
	JWKSRefreshCooldown time.Duration
	// HTTPClient fetches discovery and the JWKS. Default: a client with DefaultHTTPTimeout.
	HTTPClient *http.Client
	// Now is the clock (tests). Default time.Now.
	Now func() time.Time
}

// Verifier verifies OIDC access tokens (JWT) against the issuer's JWKS. It is safe for concurrent use.
//
// It checks the signature (RS256/384/512, PS256/384/512, ES256/384/512, EdDSA allow-list; the key
// must match the algorithm: RSA for RS and PS, the EC curve P-256/P-384/P-521 for ES256/384/512,
// Ed25519 for EdDSA), iss (exact), aud (contains), exp
// (required), nbf and sub with a clock skew (default 60 s). Keys come from JWKSURL or OIDC
// discovery, are cached (default 10 min) and refetched when a token names an unknown kid (key
// rotation, at most once per cooldown).
//
// Errors are *Error: ErrAuthentication for every invalid token (the message names the failed
// check, never the token), ErrUnavailable when discovery or the JWKS cannot be fetched, ErrConfig
// for invalid options.
type Verifier struct {
	issuer, audience, rolesClaim, jwksURL string
	algorithms                            []string
	skew, ttl, cooldown                   time.Duration
	httpClient                            *http.Client
	now                                   func() time.Time

	mu        sync.Mutex // guards the fields below
	fetchMu   sync.Mutex // serializes fetches
	resolved  string
	keys      []jwk
	fetchedAt time.Time
}

// New validates opts and returns a Verifier. No network call is made.
func New(opts Options) (*Verifier, error) {
	v := &Verifier{
		issuer:     strings.TrimSpace(opts.Issuer),
		audience:   strings.TrimSpace(opts.Audience),
		rolesClaim: strings.TrimSpace(opts.RolesClaim),
		jwksURL:    strings.TrimSpace(opts.JWKSURL),
		algorithms: opts.Algorithms,
		skew:       durationOr(opts.ClockSkew, DefaultClockSkew),
		ttl:        durationOr(opts.JWKSCacheTTL, DefaultJWKSCacheTTL),
		cooldown:   durationOr(opts.JWKSRefreshCooldown, DefaultJWKSRefreshCooldown),
		httpClient: opts.HTTPClient,
		now:        opts.Now,
	}
	if v.issuer == "" {
		return nil, ConfigError("oidc: issuer is required")
	}
	if v.audience == "" {
		return nil, ConfigError("oidc: audience is required")
	}
	if err := checkURL("issuer", v.issuer); err != nil {
		return nil, err
	}
	if v.jwksURL != "" {
		if err := checkURL("JWKSURL", v.jwksURL); err != nil {
			return nil, err
		}
	}
	if v.rolesClaim == "" {
		v.rolesClaim = DefaultRolesClaim
	}
	if len(v.algorithms) == 0 {
		v.algorithms = DefaultAlgorithms
	}
	for _, alg := range v.algorithms {
		if !slices.Contains(DefaultAlgorithms, alg) {
			return nil, ConfigError("oidc: algorithms must be a subset of RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA")
		}
	}
	v.algorithms = slices.Clone(v.algorithms)
	if v.httpClient == nil {
		v.httpClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	if v.now == nil {
		v.now = time.Now
	}
	return v, nil
}

func durationOr(value, def time.Duration) time.Duration {
	switch {
	case value < 0:
		return 0
	case value == 0:
		return def
	default:
		return value
	}
}

func checkURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ConfigError("oidc: " + name + " is not a URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ConfigError("oidc: " + name + " must use http or https")
	}
	return nil
}

// FromEnv builds a Verifier from GROW_AUTH_ISSUER (required), GROW_AUTH_AUDIENCE (default
// GROW_AUTH_CLIENT_ID), GROW_AUTH_JWKS_URL, GROW_AUTH_ROLES_CLAIM (default "roles") and
// GROW_AUTH_CLOCK_SKEW (duration, default 60s). ctx is reserved for future discovery at startup.
func FromEnv(ctx context.Context) (*Verifier, error) {
	return FromEnvWith(ctx, Options{}, os.Getenv)
}

// FromEnvWith is FromEnv with explicit option overrides (non-zero fields win) and a lookup
// function (os.Getenv, or a map lookup in tests).
func FromEnvWith(_ context.Context, overrides Options, getenv func(string) string) (*Verifier, error) {
	get := func(name string) string { return strings.TrimSpace(getenv(name)) }
	opts := overrides
	if opts.Issuer == "" {
		opts.Issuer = get("GROW_AUTH_ISSUER")
	}
	if opts.Issuer == "" {
		return nil, ConfigError("oidc: GROW_AUTH_ISSUER is required")
	}
	if opts.Audience == "" {
		opts.Audience = get("GROW_AUTH_AUDIENCE")
	}
	if opts.Audience == "" {
		opts.Audience = get("GROW_AUTH_CLIENT_ID")
	}
	if opts.Audience == "" {
		return nil, ConfigError("oidc: GROW_AUTH_AUDIENCE (or GROW_AUTH_CLIENT_ID) is required")
	}
	if opts.JWKSURL == "" {
		opts.JWKSURL = get("GROW_AUTH_JWKS_URL")
	}
	if opts.RolesClaim == "" {
		opts.RolesClaim = get("GROW_AUTH_ROLES_CLAIM")
	}
	if raw := get("GROW_AUTH_CLOCK_SKEW"); opts.ClockSkew == 0 && raw != "" {
		skew, err := ParseDuration(raw)
		if err != nil {
			return nil, ConfigError("oidc: GROW_AUTH_CLOCK_SKEW is not a duration")
		}
		opts.ClockSkew = skew
		if skew == 0 {
			opts.ClockSkew = -1
		}
	}
	return New(opts)
}

// Issuer returns the expected issuer.
func (v *Verifier) Issuer() string { return v.issuer }

// Audience returns the expected audience.
func (v *Verifier) Audience() string { return v.audience }

// RolesClaim returns the roles claim path.
func (v *Verifier) RolesClaim() string { return v.rolesClaim }

// ClockSkew returns the exp/nbf tolerance.
func (v *Verifier) ClockSkew() time.Duration { return v.skew }

// ClearCache drops the cached JWKS so the next verification refetches it.
func (v *Verifier) ClearCache() {
	v.mu.Lock()
	v.keys, v.fetchedAt = nil, time.Time{}
	v.mu.Unlock()
}

func authErr(reason string) *Error {
	return &Error{Code: ErrorCodeAuthentication, Message: "verify: " + reason}
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// Verify verifies a raw JWT access token and returns its user.
func (v *Verifier) Verify(ctx context.Context, token string) (*User, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, authErr("malformed token")
	}
	var header jwtHeader
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, authErr("malformed token header")
	}
	if !slices.Contains(v.algorithms, header.Alg) {
		return nil, authErr("algorithm " + quoteAlg(header.Alg) + " is not allowed")
	}
	claims := map[string]any{}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, authErr("malformed token payload")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, authErr("malformed token signature")
	}
	signed := []byte(parts[0] + "." + parts[1])

	keys, fetchedAt, err := v.keySet(ctx, false)
	if err != nil {
		return nil, err
	}
	candidates := matchKeys(keys, header)
	if len(candidates) == 0 && header.Kid != "" && v.now().Sub(fetchedAt) >= v.cooldown {
		if keys, _, err = v.keySet(ctx, true); err != nil {
			return nil, err
		}
		candidates = matchKeys(keys, header)
	}
	if len(candidates) == 0 {
		kid := header.Kid
		if kid == "" {
			kid = "(none)"
		}
		return nil, authErr("no key matches kid " + kid)
	}
	if !slices.ContainsFunc(candidates, func(k jwk) bool { return k.verify(header.Alg, signed, sig) }) {
		return nil, authErr("signature is invalid")
	}
	if err := v.checkClaims(claims); err != nil {
		return nil, err
	}
	return v.toUser(claims), nil
}

func quoteAlg(alg string) string {
	if alg == "" {
		return "(none)"
	}
	if len(alg) > 16 {
		alg = alg[:16]
	}
	return alg
}

func decodeSegment(seg string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	return dec.Decode(out)
}

func numericClaim(claims map[string]any, name string) (float64, bool, error) {
	raw, ok := claims[name]
	if !ok {
		return 0, false, nil
	}
	n, isNum := raw.(json.Number)
	if !isNum {
		return 0, true, authErr("claim " + name + " is invalid (not a number)")
	}
	f, err := n.Float64()
	if err != nil {
		return 0, true, authErr("claim " + name + " is invalid (not a number)")
	}
	return f, true, nil
}

func (v *Verifier) checkClaims(claims map[string]any) error {
	if iss, _ := claims["iss"].(string); iss != v.issuer {
		return authErr("claim iss is invalid (unexpected value)")
	}
	if !audienceContains(claims["aud"], v.audience) {
		return authErr("claim aud is invalid (unexpected value)")
	}
	now := float64(v.now().UnixNano()) / 1e9
	skew := v.skew.Seconds()
	exp, ok, err := numericClaim(claims, "exp")
	if err != nil {
		return err
	}
	if !ok {
		return authErr("claim exp is invalid (missing)")
	}
	if now > exp+skew {
		return authErr("token expired")
	}
	nbf, ok, err := numericClaim(claims, "nbf")
	if err != nil {
		return err
	}
	if ok && now+skew < nbf {
		return authErr("claim nbf is invalid (not yet valid)")
	}
	if sub, _ := claims["sub"].(string); sub == "" {
		return authErr("claim sub is invalid (missing)")
	}
	return nil
}

func audienceContains(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		return slices.ContainsFunc(a, func(item any) bool { s, _ := item.(string); return s == want })
	}
	return false
}

func (v *Verifier) toUser(claims map[string]any) *User {
	u := &User{Roles: ExtractRoles(claims, v.rolesClaim), Claims: claims}
	u.Sub, _ = claims["sub"].(string)
	u.Email, _ = claims["email"].(string)
	if name, ok := claims["name"].(string); ok {
		u.Name = name
	} else {
		u.Name, _ = claims["preferred_username"].(string)
	}
	return u
}

// keySet returns the cached keys, fetching them when absent, expired or force is set.
func (v *Verifier) keySet(ctx context.Context, force bool) ([]jwk, time.Time, error) {
	v.mu.Lock()
	keys, at := v.keys, v.fetchedAt
	v.mu.Unlock()
	if !force && keys != nil && v.now().Sub(at) < v.ttl {
		return keys, at, nil
	}
	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()
	v.mu.Lock()
	if v.fetchedAt.After(at) && v.keys != nil { // another goroutine fetched meanwhile
		keys, at = v.keys, v.fetchedAt
		v.mu.Unlock()
		return keys, at, nil
	}
	v.mu.Unlock()
	uri, err := v.jwksURI(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := v.getJSON(ctx, "jwks", uri, &doc); err != nil {
		return nil, time.Time{}, err
	}
	if doc.Keys == nil {
		return nil, time.Time{}, NewError(ErrorCodeUnavailable, "jwks: response has no keys array", nil)
	}
	parsed := make([]jwk, 0, len(doc.Keys))
	for _, raw := range doc.Keys {
		if k, ok := parseJWK(raw); ok {
			parsed = append(parsed, k)
		}
	}
	now := v.now()
	v.mu.Lock()
	v.keys, v.fetchedAt = parsed, now
	v.mu.Unlock()
	return parsed, now, nil
}

func (v *Verifier) jwksURI(ctx context.Context) (string, error) {
	if v.jwksURL != "" {
		return v.jwksURL, nil
	}
	v.mu.Lock()
	resolved := v.resolved
	v.mu.Unlock()
	if resolved != "" {
		return resolved, nil
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := v.getJSON(ctx, "discovery", strings.TrimRight(v.issuer, "/")+"/.well-known/openid-configuration", &doc); err != nil {
		return "", err
	}
	if doc.JWKSURI == "" {
		return "", NewError(ErrorCodeUnavailable, "discovery: document has no jwks_uri", nil)
	}
	v.mu.Lock()
	v.resolved = doc.JWKSURI
	v.mu.Unlock()
	return doc.JWKSURI, nil
}

func (v *Verifier) getJSON(ctx context.Context, operation, uri string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return NewError(ErrorCodeUnavailable, operation+": invalid request", err)
	}
	req.Header.Set("Accept", "application/json")
	res, err := v.httpClient.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ContextError(operation, ctxErr)
		}
		return NewError(ErrorCodeUnavailable, operation+": request failed", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		e := NewError(ErrorCodeUnavailable, operation+": unexpected response (HTTP "+strconv.Itoa(res.StatusCode)+")", nil)
		e.HTTPStatus = res.StatusCode
		return e
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, res.Body, 1<<20)).Decode(out); err != nil {
		return NewError(ErrorCodeUnavailable, operation+": response is not JSON", err)
	}
	return nil
}

// jwk is one parsed public key.
type jwk struct {
	kid, alg, use string
	key           crypto.PublicKey
}

type rawJWK struct {
	Kty, Kid, Alg, Use, Crv, N, E, X, Y string
}

func parseJWK(raw json.RawMessage) (jwk, bool) {
	var r rawJWK
	if err := json.Unmarshal(raw, &r); err != nil {
		return jwk{}, false
	}
	k := jwk{kid: r.Kid, alg: r.Alg, use: r.Use}
	b := func(s string) []byte {
		out, _ := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
		return out
	}
	switch {
	case r.Kty == "RSA":
		n, e := b(r.N), b(r.E)
		if len(n) < 256 || len(e) == 0 || len(e) > 4 { // at least 2048-bit keys
			return jwk{}, false
		}
		k.key = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	case r.Kty == "EC" && ecCurves[r.Crv].curve != nil:
		c := ecCurves[r.Crv]
		x, y := b(r.X), b(r.Y)
		if len(x) != c.size || len(y) != c.size {
			return jwk{}, false
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(c.curve, append(append([]byte{4}, x...), y...))
		if err != nil {
			return jwk{}, false
		}
		k.key = pub
	case r.Kty == "OKP" && r.Crv == "Ed25519":
		x := b(r.X)
		if len(x) != ed25519.PublicKeySize {
			return jwk{}, false
		}
		k.key = ed25519.PublicKey(x)
	default:
		return jwk{}, false
	}
	return k, true
}

// ecCurve is a JWK curve with its coordinate size in bytes.
type ecCurve struct {
	curve elliptic.Curve
	size  int
}

// ecCurves maps a JWK crv to its curve.
var ecCurves = map[string]ecCurve{
	"P-256": {elliptic.P256(), 32},
	"P-384": {elliptic.P384(), 48},
	"P-521": {elliptic.P521(), 66},
}

// ecCurveFor is the curve an ES algorithm requires.
var ecCurveFor = map[string]string{ES256: "P-256", ES384: "P-384", ES512: "P-521"}

// compatible reports whether the key can verify alg: the key type (and EC curve) must match the
// algorithm, and a declared JWK alg must equal it.
func (k jwk) compatible(alg string) bool {
	if k.use == "enc" || (k.alg != "" && k.alg != alg) {
		return false
	}
	switch pub := k.key.(type) {
	case *rsa.PublicKey:
		switch alg {
		case RS256, RS384, RS512, PS256, PS384, PS512:
			return true
		}
	case *ecdsa.PublicKey:
		crv, ok := ecCurveFor[alg]
		return ok && pub.Curve == ecCurves[crv].curve
	case ed25519.PublicKey:
		return alg == EdDSA
	}
	return false
}

func matchKeys(keys []jwk, h jwtHeader) []jwk {
	var out []jwk
	for _, k := range keys {
		if (h.Kid == "" || k.kid == h.Kid) && k.compatible(h.Alg) {
			out = append(out, k)
		}
	}
	return out
}

// hashFor is the digest of an RS, PS or ES algorithm (by its 3-digit suffix).
func hashFor(alg string) crypto.Hash {
	switch alg[len(alg)-3:] {
	case "384":
		return crypto.SHA384
	case "512":
		return crypto.SHA512
	}
	return crypto.SHA256
}

func digest(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA384:
		d := sha512.Sum384(data)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(data)
		return d[:]
	}
	d := sha256.Sum256(data)
	return d[:]
}

// verify checks sig over signed with alg; compatible(alg) must hold.
func (k jwk) verify(alg string, signed, sig []byte) bool {
	switch pub := k.key.(type) {
	case *rsa.PublicKey:
		h := hashFor(alg)
		if strings.HasPrefix(alg, "PS") {
			return rsa.VerifyPSS(pub, h, digest(h, signed), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: h}) == nil
		}
		return rsa.VerifyPKCS1v15(pub, h, digest(h, signed), sig) == nil
	case *ecdsa.PublicKey:
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return false
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(pub, digest(hashFor(alg), signed), r, s)
	case ed25519.PublicKey:
		return ed25519.Verify(pub, signed, sig)
	}
	return false
}
