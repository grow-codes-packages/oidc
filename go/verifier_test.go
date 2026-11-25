package oidc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	oidc "github.com/grow-codes-packages/oidc/go"
	"github.com/grow-codes-packages/oidc/go/oidctest"
)

func newVerifier(t *testing.T, idp *oidctest.IdP, mod func(*oidc.Options)) *oidc.Verifier {
	t.Helper()
	opts := oidc.Options{Issuer: idp.Issuer, Audience: "app-client"}
	if mod != nil {
		mod(&opts)
	}
	v, err := oidc.New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func wantAuth(t *testing.T, err error, contains string) {
	t.Helper()
	if !errors.Is(err, oidc.ErrAuthentication) {
		t.Fatalf("want AUTHENTICATION, got %v", err)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("error %q does not contain %q", err, contains)
	}
}

func TestOIDC01VerifiesRS256ViaDiscovery(t *testing.T) {
	idp := oidctest.New("app-client", "RS256")
	defer idp.Close()
	token := idp.Mint(map[string]any{"email": "a@b.test", "name": "Ann",
		"roles": []any{map[string]any{"name": "admin", "owner": "org"}, map[string]any{"name": "user"}}}, oidctest.MintOptions{})
	user, err := newVerifier(t, idp, nil).Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if user.Sub != "user-1" || user.Email != "a@b.test" || user.Name != "Ann" || strings.Join(user.Roles, ",") != "admin,user" {
		t.Fatalf("user = %+v", user)
	}
	if !user.HasRole("ADMIN") || user.HasRole("x") || idp.Hits("/.well-known/openid-configuration") != 1 {
		t.Fatal("roles or discovery hits wrong")
	}
}

func TestOIDC02And03OtherAlgorithms(t *testing.T) {
	for _, alg := range []string{"ES256", "EdDSA", "ES384", "ES512", "RS384", "RS512", "PS256", "PS384", "PS512"} {
		idp := oidctest.New("app-client", alg)
		user, err := newVerifier(t, idp, nil).Verify(context.Background(), idp.Mint(map[string]any{"preferred_username": "bob"}, oidctest.MintOptions{}))
		idp.Close()
		if err != nil || user.Name != "bob" {
			t.Fatalf("%s: %v %+v", alg, err, user)
		}
	}
}

func TestOIDC04To08Claims(t *testing.T) {
	idp := oidctest.New("app-client", "RS256")
	defer idp.Close()
	v := newVerifier(t, idp, nil)
	ctx := context.Background()
	now := time.Now().Unix()
	mint := func(c map[string]any) string { return idp.Mint(c, oidctest.MintOptions{}) }
	_, err := v.Verify(ctx, mint(map[string]any{"iss": "http://evil.test"}))
	wantAuth(t, err, "iss")
	_, err = v.Verify(ctx, mint(map[string]any{"aud": "other"}))
	wantAuth(t, err, "aud")
	if _, err = v.Verify(ctx, mint(map[string]any{"aud": []any{"other", "app-client"}})); err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(ctx, mint(map[string]any{"exp": now - 120}))
	wantAuth(t, err, "expired")
	if _, err = v.Verify(ctx, mint(map[string]any{"exp": now - 30})); err != nil {
		t.Fatal("within skew:", err)
	}
	strict := newVerifier(t, idp, func(o *oidc.Options) { o.ClockSkew = -1 })
	_, err = strict.Verify(ctx, mint(map[string]any{"exp": now - 30}))
	wantAuth(t, err, "expired")
	_, err = v.Verify(ctx, mint(map[string]any{"nbf": now + 120}))
	wantAuth(t, err, "nbf")
	if _, err = v.Verify(ctx, mint(map[string]any{"nbf": now + 30})); err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(ctx, mint(map[string]any{"exp": nil}))
	wantAuth(t, err, "exp")
	_, err = v.Verify(ctx, mint(map[string]any{"exp": "soon"}))
	wantAuth(t, err, "exp")
	_, err = v.Verify(ctx, mint(map[string]any{"nbf": "soon"}))
	wantAuth(t, err, "nbf")
	_, err = v.Verify(ctx, mint(map[string]any{"sub": nil}))
	wantAuth(t, err, "sub")
}

func TestOIDC09RejectsAlgorithms(t *testing.T) {
	idp := oidctest.New("app-client", "RS256")
	defer idp.Close()
	v := newVerifier(t, idp, nil)
	ctx := context.Background()
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	_, err := v.Verify(ctx, enc(map[string]any{"alg": "none"})+"."+enc(map[string]any{"sub": "x"})+".")
	wantAuth(t, err, "not allowed")
	for _, alg := range []string{"HS256", "HS384", "HS512", "None", "NONE"} {
		_, err = v.Verify(ctx, enc(map[string]any{"alg": alg})+"."+enc(map[string]any{"sub": "x"})+".c2ln")
		wantAuth(t, err, alg+" is not allowed")
	}
	_, err = v.Verify(ctx, enc(map[string]any{"alg": strings.Repeat("A", 40)})+".e30.c2ln")
	wantAuth(t, err, "not allowed")
	_, err = v.Verify(ctx, enc(map[string]any{})+".e30.c2ln")
	wantAuth(t, err, "(none) is not allowed")
	idp.Rotate("ES256")
	rsOnly := newVerifier(t, idp, func(o *oidc.Options) { o.Algorithms = []string{oidc.RS256} })
	_, err = rsOnly.Verify(ctx, idp.Mint(nil, oidctest.MintOptions{}))
	wantAuth(t, err, "not allowed")
	for token, msg := range map[string]string{
		"nope":        "malformed token",
		"!!.e30.c2ln": "malformed token header",
		enc(map[string]any{"alg": "RS256"}) + ".!!.c2ln": "malformed token payload",
		enc(map[string]any{"alg": "RS256"}) + ".e30.!!":  "malformed token signature",
	} {
		_, err = v.Verify(ctx, token)
		wantAuth(t, err, msg)
	}
}

func TestOIDC10BadSignature(t *testing.T) {
	idp := oidctest.New("app-client", "ES256")
	defer idp.Close()
	other := oidctest.New("app-client", "ES256")
	defer other.Close()
	token := idp.Mint(nil, oidctest.MintOptions{})
	forged := other.Mint(map[string]any{"iss": idp.Issuer}, oidctest.MintOptions{})
	parts := strings.Split(token, ".")
	fparts := strings.Split(forged, ".")
	_, err := newVerifier(t, idp, nil).Verify(context.Background(), parts[0]+"."+parts[1]+"."+fparts[2])
	wantAuth(t, err, "signature")
	_, err = newVerifier(t, idp, nil).Verify(context.Background(), parts[0]+"."+parts[1]+".AAAA")
	wantAuth(t, err, "signature")
}

func TestOIDC11And12Rotation(t *testing.T) {
	idp := oidctest.New("app-client", "RS256")
	defer idp.Close()
	now := time.Now()
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	v := newVerifier(t, idp, func(o *oidc.Options) { o.Now = clock })
	ctx := context.Background()
	if _, err := v.Verify(ctx, idp.Mint(nil, oidctest.MintOptions{})); err != nil {
		t.Fatal(err)
	}
	idp.Rotate("EdDSA")
	_, err := v.Verify(ctx, idp.Mint(nil, oidctest.MintOptions{}))
	wantAuth(t, err, "no key matches kid key-2")
	if idp.Hits("/jwks") != 1 {
		t.Fatalf("refetched within cooldown: %d", idp.Hits("/jwks"))
	}
	mu.Lock()
	now = now.Add(31 * time.Second)
	mu.Unlock()
	if _, err := v.Verify(ctx, idp.Mint(nil, oidctest.MintOptions{})); err != nil {
		t.Fatal(err)
	}
	if idp.Hits("/jwks") != 2 {
		t.Fatalf("jwks hits = %d", idp.Hits("/jwks"))
	}
}

func TestOIDC13CachingAndNoKid(t *testing.T) {
	idp := oidctest.New("app-client", "RS256")
	defer idp.Close()
	now := time.Now()
	var mu sync.Mutex
	v := newVerifier(t, idp, func(o *oidc.Options) {
		o.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	})
	ctx := context.Background()
	token := idp.Mint(nil, oidctest.MintOptions{TTL: time.Hour})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if _, err := v.Verify(ctx, token); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if idp.Hits("/jwks") != 1 {
		t.Fatalf("jwks hits = %d", idp.Hits("/jwks"))
	}
	mu.Lock()
	now = now.Add(11 * time.Minute)
	mu.Unlock()
	_, _ = v.Verify(ctx, token)
	v.ClearCache()
	_, _ = v.Verify(ctx, token)
	if idp.Hits("/jwks") != 3 {
		t.Fatalf("jwks hits = %d", idp.Hits("/jwks"))
	}
	if _, err := v.Verify(ctx, idp.Mint(nil, oidctest.MintOptions{Kid: "-", TTL: time.Hour})); err != nil {
		t.Fatal("no kid:", err)
	}
	_, err := newVerifier(t, idp, nil).Verify(ctx, idp.Mint(nil, oidctest.MintOptions{Kid: "-", Header: map[string]any{"alg": "ES256"}}))
	wantAuth(t, err, "no key matches kid (none)")
}

func TestOIDC14JWKSURLSkipsDiscovery(t *testing.T) {
	idp := oidctest.New("app-client", "RS256")
	defer idp.Close()
	v := newVerifier(t, idp, func(o *oidc.Options) { o.JWKSURL = idp.Issuer + "/jwks" })
	if _, err := v.Verify(context.Background(), idp.Mint(nil, oidctest.MintOptions{})); err != nil {
		t.Fatal(err)
	}
	if idp.Hits("/.well-known/openid-configuration") != 0 {
		t.Fatal("discovery was called")
	}
}

func TestOIDC15Unavailable(t *testing.T) {
	idp := oidctest.New("app-client", "RS256")
	defer idp.Close()
	token := idp.Mint(nil, oidctest.MintOptions{})
	idp.Fail(500)
	ctx := context.Background()
	_, err := newVerifier(t, idp, nil).Verify(ctx, token)
	if !errors.Is(err, oidc.ErrUnavailable) || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("got %v", err)
	}
	serve := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
	}
	for body, msg := range map[string]string{"nope": "not JSON", `{"issuer":"x"}`: "no jwks_uri", `{"jwks_uri":"http://127.0.0.1:1/j"}`: "request failed"} {
		s := serve(body)
		v, _ := oidc.New(oidc.Options{Issuer: s.URL, Audience: "a"})
		_, err := v.Verify(ctx, token)
		s.Close()
		if !errors.Is(err, oidc.ErrUnavailable) || !strings.Contains(err.Error(), msg) {
			t.Fatalf("%s: got %v", body, err)
		}
	}
	s := serve(`{}`)
	defer s.Close()
	v, _ := oidc.New(oidc.Options{Issuer: idp.Issuer, Audience: "a", JWKSURL: s.URL})
	if _, err := v.Verify(ctx, token); !strings.Contains(err.Error(), "no keys array") {
		t.Fatalf("got %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := v.Verify(cancelled, token); !errors.Is(err, oidc.ErrCancelled) {
		t.Fatalf("got %v", err)
	}
}

func TestOIDC16RolesClaim(t *testing.T) {
	idp := oidctest.New("app-client", "RS256")
	defer idp.Close()
	token := idp.Mint(map[string]any{"realm_access": map[string]any{"roles": []any{"editor"}}, "scope": "a b"}, oidctest.MintOptions{})
	for claim, want := range map[string]string{"realm_access.roles": "editor", "scope": "a,b", "": ""} {
		u, err := newVerifier(t, idp, func(o *oidc.Options) { o.RolesClaim = claim }).Verify(context.Background(), token)
		if err != nil || strings.Join(u.Roles, ",") != want {
			t.Fatalf("%q: %v %v", claim, err, u)
		}
	}
	roles := oidc.ExtractRoles(map[string]any{"roles": []any{map[string]any{"code": "b"}, map[string]any{"role": "c"},
		map[string]any{"value": "d"}, map[string]any{"x": 1}, 3, " ", "b"}}, "")
	if strings.Join(roles, ",") != "b,c,d" {
		t.Fatal(roles)
	}
	if r := oidc.ExtractRoles(map[string]any{"https://x/roles": []any{"r"}}, "https://x/roles"); len(r) != 1 {
		t.Fatal(r)
	}
	if _, ok := oidc.ClaimAt(map[string]any{"a": []any{}}, "a.b"); ok {
		t.Fatal("non-object path")
	}
	if _, ok := oidc.ClaimAt(map[string]any{"a": map[string]any{}}, "a.b"); ok {
		t.Fatal("missing")
	}
	if !oidc.HasAnyRole(nil, nil) || oidc.HasAnyRole([]string{"x"}, []string{"y"}) {
		t.Fatal("HasAnyRole")
	}
}

func TestOIDC17FromEnv(t *testing.T) {
	ctx := context.Background()
	env := map[string]string{"GROW_AUTH_ISSUER": "http://idp:8000", "GROW_AUTH_CLIENT_ID": "app", "GROW_AUTH_ROLES_CLAIM": "groups"}
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	v, err := oidc.FromEnvWith(ctx, oidc.Options{}, get(env))
	if err != nil || v.Audience() != "app" || v.RolesClaim() != "groups" || v.ClockSkew() != time.Minute || v.Issuer() != "http://idp:8000" {
		t.Fatalf("%v %+v", err, v)
	}
	env["GROW_AUTH_AUDIENCE"], env["GROW_AUTH_JWKS_URL"], env["GROW_AUTH_CLOCK_SKEW"] = "api", "http://idp:8000/jwks", "5s"
	if v, err = oidc.FromEnvWith(ctx, oidc.Options{}, get(env)); err != nil || v.Audience() != "api" || v.ClockSkew() != 5*time.Second {
		t.Fatalf("%v", err)
	}
	env["GROW_AUTH_CLOCK_SKEW"] = "0"
	if v, err = oidc.FromEnvWith(ctx, oidc.Options{}, get(env)); err != nil || v.ClockSkew() != 0 {
		t.Fatalf("%v", err)
	}
	env["GROW_AUTH_CLOCK_SKEW"] = "soon"
	if _, err = oidc.FromEnvWith(ctx, oidc.Options{}, get(env)); !errors.Is(err, oidc.ErrConfig) {
		t.Fatal(err)
	}
	if _, err = oidc.FromEnvWith(ctx, oidc.Options{}, get(map[string]string{})); !errors.Is(err, oidc.ErrConfig) {
		t.Fatal(err)
	}
	if _, err = oidc.FromEnvWith(ctx, oidc.Options{}, get(map[string]string{"GROW_AUTH_ISSUER": "http://x"})); !strings.Contains(err.Error(), "GROW_AUTH_AUDIENCE") {
		t.Fatal(err)
	}
	t.Setenv("GROW_AUTH_ISSUER", "http://idp")
	t.Setenv("GROW_AUTH_AUDIENCE", "x")
	if _, err = oidc.FromEnv(ctx); err != nil {
		t.Fatal(err)
	}
	for _, o := range []oidc.Options{
		{Audience: "a"}, {Issuer: "http://x"}, {Issuer: "nope", Audience: "a"}, {Issuer: "ftp://x", Audience: "a"},
		{Issuer: "http://x", Audience: "a", JWKSURL: "bad"}, {Issuer: "http://x", Audience: "a", Algorithms: []string{"HS256"}},
	} {
		if _, err := oidc.New(o); !errors.Is(err, oidc.ErrConfig) {
			t.Fatalf("%+v: %v", o, err)
		}
	}
}

func TestJWKSIgnoresUnusableKeys(t *testing.T) {
	idp := oidctest.New("app-client", "RS256")
	defer idp.Close()
	ec := idp.Rotate("ES256")
	token := idp.Mint(nil, oidctest.MintOptions{Kid: "-"})
	idp.RemoveKey(ec.Kid)
	idp.RemoveKey("missing")
	// Fetch the real keys, then serve them together with junk entries.
	res, err := http.Get(idp.Issuer + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Keys []map[string]any }
	_ = json.NewDecoder(res.Body).Decode(&doc)
	_ = res.Body.Close()
	junk := []any{
		"not-an-object",
		map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB"},
		map[string]any{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"},
		map[string]any{"kty": "EC", "crv": "P-256", "x": strings.Repeat("A", 43), "y": strings.Repeat("A", 43)},
		map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AA"},
		map[string]any{"kty": "oct", "k": "AA"},
	}
	for _, k := range doc.Keys {
		enc := map[string]any{}
		wrongAlg := map[string]any{}
		for name, value := range k {
			enc[name], wrongAlg[name] = value, value
		}
		enc["use"] = "enc"
		wrongAlg["alg"] = "RS512"
		junk = append(junk, enc, wrongAlg)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": junk})
	}))
	defer srv.Close()
	v, _ := oidc.New(oidc.Options{Issuer: idp.Issuer, Audience: "app-client", JWKSURL: srv.URL})
	_, err = v.Verify(context.Background(), token)
	wantAuth(t, err, "no key matches kid (none)")
	if oidc.ExtractRoles(map[string]any{}, "roles") == nil {
		t.Fatal("nil roles")
	}
	u := idp.Mint(map[string]any{"aud": []any{1, "x"}}, oidctest.MintOptions{Kid: "key-1"})
	_, err = newVerifier(t, idp, nil).Verify(context.Background(), u)
	wantAuth(t, err, "aud")
	_, err = newVerifier(t, idp, nil).Verify(context.Background(), idp.Mint(map[string]any{"aud": 5}, oidctest.MintOptions{Kid: "key-1"}))
	wantAuth(t, err, "aud")
	_, err = newVerifier(t, idp, nil).Verify(context.Background(), idp.Mint(map[string]any{"exp": json.RawMessage("1e400")}, oidctest.MintOptions{Kid: "key-1"}))
	wantAuth(t, err, "exp")
}

// servedJWKS serves the given keys as a JWKS and returns its URL.
func servedJWKS(t *testing.T, keys ...map[string]any) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// publicJWK fetches the published JWK of kid from idp, without its "alg" when dropAlg is set.
func publicJWK(t *testing.T, idp *oidctest.IdP, kid string, dropAlg bool) map[string]any {
	t.Helper()
	res, err := http.Get(idp.Issuer + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var doc struct{ Keys []map[string]any }
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range doc.Keys {
		if k["kid"] == kid {
			if dropAlg {
				delete(k, "alg")
			}
			return k
		}
	}
	t.Fatalf("kid %s not published", kid)
	return nil
}

// resign replaces the header alg of a token minted by key and signs it again with key's own
// algorithm, so the header names an algorithm the key was not made for.
func resign(key *oidctest.Key, token, alg string) string {
	parts := strings.Split(token, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	header := map[string]any{}
	_ = json.Unmarshal(raw, &header)
	header["alg"] = alg
	h, _ := json.Marshal(header)
	signed := base64.RawURLEncoding.EncodeToString(h) + "." + parts[1]
	return signed + "." + base64.RawURLEncoding.EncodeToString(oidctest.Sign(key, []byte(signed)))
}

func TestOIDC19AlgKeyMismatchRejected(t *testing.T) {
	ctx := context.Background()
	verify := func(idp *oidctest.IdP, jwks, token string) error {
		v, err := oidc.New(oidc.Options{Issuer: idp.Issuer, Audience: "app-client", JWKSURL: jwks})
		if err != nil {
			t.Fatal(err)
		}
		_, err = v.Verify(ctx, token)
		return err
	}
	cases := []struct {
		name, keyAlg, headerAlg string
		dropAlg                 bool
		want                    string
	}{
		{"P-256 key, header ES384", "ES256", "ES384", true, "no key matches"},
		{"P-384 key, header ES256", "ES384", "ES256", true, "no key matches"},
		{"P-521 key, header ES384", "ES512", "ES384", true, "no key matches"},
		{"P-384 key, header RS384", "ES384", "RS384", true, "no key matches"},
		{"RSA key with alg RS256, header PS256", "RS256", "PS256", false, "no key matches"},
		{"RSA key without alg, PKCS1 signature, header PS256", "RS256", "PS256", true, "signature is invalid"},
		{"RSA key without alg, header ES256", "RS256", "ES256", true, "no key matches"},
		{"Ed25519 key, header ES256", "EdDSA", "ES256", true, "no key matches"},
		{"P-256 key with alg ES256, header ES384", "ES256", "ES384", false, "no key matches"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idp := oidctest.New("app-client", c.keyAlg)
			defer idp.Close()
			key := idp.Rotate(c.keyAlg)
			jwks := servedJWKS(t, publicJWK(t, idp, key.Kid, c.dropAlg))
			good := idp.Mint(nil, oidctest.MintOptions{})
			if err := verify(idp, jwks, good); err != nil {
				t.Fatalf("matching alg rejected: %v", err)
			}
			wantAuth(t, verify(idp, jwks, resign(key, good, c.headerAlg)), c.want)
		})
	}
	// A matching key type but the wrong hash: a PS256 key signature presented as PS384.
	idp := oidctest.New("app-client", "PS256")
	defer idp.Close()
	key := idp.Rotate("PS256")
	jwks := servedJWKS(t, publicJWK(t, idp, key.Kid, true))
	wantAuth(t, verify(idp, jwks, resign(key, idp.Mint(nil, oidctest.MintOptions{}), "PS384")), "signature is invalid")
	// ES signatures of the wrong length never verify.
	es := oidctest.New("app-client", "ES384")
	defer es.Close()
	parts := strings.Split(es.Mint(nil, oidctest.MintOptions{}), ".")
	_, err := newVerifier(t, es, nil).Verify(ctx, parts[0]+"."+parts[1]+"."+base64.RawURLEncoding.EncodeToString(make([]byte, 64)))
	wantAuth(t, err, "signature is invalid")
}
