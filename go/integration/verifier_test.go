package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	oidc "github.com/grow-codes-packages/oidc/go"
)

// TestVerifierRealToken verifies a real Casdoor access token (minted by docker/bootstrap)
// through discovery + JWKS, and runs it through the net/http middleware.
func TestVerifierRealToken(t *testing.T) {
	bootstrap := os.Getenv("GROW_BOOTSTRAP_ENV")
	if bootstrap == "" {
		bootstrap = "/bootstrap/env"
	}
	loadBootstrapEnv(t, bootstrap)
	token := os.Getenv("GROW_OIDC_TOKEN")
	if token == "" || os.Getenv("GROW_AUTH_ISSUER") == "" {
		t.Skip("GROW_OIDC_TOKEN / GROW_AUTH_ISSUER not set; run through docker/compose.yml")
	}
	ctx := context.Background()
	v, err := oidc.FromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user, err := v.Verify(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	role := os.Getenv("GROW_OIDC_IT_ROLE")
	if user.Sub != os.Getenv("GROW_OIDC_IT_SUB") || user.Email != os.Getenv("GROW_OIDC_IT_EMAIL") || !slices.Contains(user.Roles, role) {
		t.Fatalf("user = %+v", user)
	}

	sig := token[strings.LastIndex(token, ".")+1:]
	flipped := "A"
	if strings.HasPrefix(sig, "A") {
		flipped = "B"
	}
	if _, err := v.Verify(ctx, token[:strings.LastIndex(token, ".")+1]+flipped+sig[1:]); !errors.Is(err, oidc.ErrAuthentication) {
		t.Fatalf("tampered token: %v", err)
	}
	other, err := oidc.FromEnvWith(ctx, oidc.Options{Audience: "someone-else"}, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Verify(ctx, token); !errors.Is(err, oidc.ErrAuthentication) {
		t.Fatalf("wrong audience: %v", err)
	}

	h := v.Middleware(oidc.RequireRoles(role)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := oidc.UserFrom(r.Context())
		_, _ = w.Write([]byte(u.Sub))
	})))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != user.Sub {
		t.Fatalf("middleware: %d %q", rec.Code, rec.Body.String())
	}
}

// TestClientRealProvider checks the client against the provider: health via discovery, ping via
// userinfo with the minted token, AUTHENTICATION for a wrong token, UNSUPPORTED serverVersion.
func TestClientRealProvider(t *testing.T) {
	bootstrap := os.Getenv("GROW_BOOTSTRAP_ENV")
	if bootstrap == "" {
		bootstrap = "/bootstrap/env"
	}
	loadBootstrapEnv(t, bootstrap)
	if os.Getenv("GROW_OIDC_URL") == "" || os.Getenv("GROW_OIDC_TOKEN") == "" {
		t.Skip("run through docker/compose.yml")
	}
	ctx := context.Background()
	c, err := oidc.NewClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if hs, err := c.Health(ctx); err != nil || !hs.Healthy {
		t.Fatalf("health %+v %v", hs, err)
	}
	if _, err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ServerVersion(ctx); !errors.Is(err, oidc.ErrUnsupported) {
		t.Fatalf("version: %v", err)
	}
	cfg := c.Config()
	cfg.Token = oidc.NewSecret("wrong-token-for-integration")
	bad, err := oidc.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bad.Close() }()
	if _, err := bad.Ping(ctx); !errors.Is(err, oidc.ErrAuthentication) || strings.Contains(err.Error(), "wrong-token") {
		t.Fatalf("bad token: %v", err)
	}
}
