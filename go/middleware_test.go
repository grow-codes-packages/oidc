package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	oidc "github.com/grow-codes-packages/oidc/go"
	"github.com/grow-codes-packages/oidc/go/oidctest"
)

func TestOIDC18Middleware(t *testing.T) {
	idp := oidctest.New("api", "RS256")
	defer idp.Close()
	v, _ := oidc.New(oidc.Options{Issuer: idp.Issuer, Audience: "api"})
	me := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := oidc.UserFrom(r.Context())
		sub := ""
		if ok {
			sub = u.Sub
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": sub})
	})
	mux := http.NewServeMux()
	mux.Handle("/me", v.Middleware(me))
	mux.Handle("/admin", v.Middleware(oidc.RequireRoles("admin")(me)))
	mux.Handle("/maybe", v.OptionalMiddleware(me))
	mux.Handle("/any", oidc.RequireRoles()(me))
	call := func(path, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	user := idp.Mint(map[string]any{"roles": []any{"user"}}, oidctest.MintOptions{})
	admin := idp.Mint(map[string]any{"roles": []any{map[string]any{"name": "Admin"}}}, oidctest.MintOptions{})
	cases := []struct {
		path, auth string
		want       int
	}{
		{"/me", "", 401}, {"/me", "Bearer x.y.z", 401}, {"/me", "Basic abc", 401}, {"/me", "Bearer a b", 401},
		{"/me", "bearer " + user, 200}, {"/admin", "Bearer " + user, 403}, {"/admin", "Bearer " + admin, 200},
		{"/maybe", "", 200}, {"/maybe", "Bearer x.y.z", 401}, {"/any", "", 401},
	}
	for _, c := range cases {
		if got := call(c.path, c.auth); got.Code != c.want {
			t.Fatalf("%s %q: %d, want %d", c.path, c.auth, got.Code, c.want)
		}
	}
	if w := call("/me", ""); w.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate")
	}
	idp.Fail(503)
	down, _ := oidc.New(oidc.Options{Issuer: idp.Issuer, Audience: "api"})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+user)
	w := httptest.NewRecorder()
	down.Middleware(me).ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("down: %d", w.Code)
	}
	if u, ok := oidc.UserFrom(oidc.WithUser(context.Background(), &oidc.User{Sub: "s"})); !ok || u.Sub != "s" {
		t.Fatal("WithUser")
	}
	if _, ok := oidc.UserFrom(context.Background()); ok {
		t.Fatal("UserFrom empty")
	}
}
