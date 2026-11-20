package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// newTestClient builds a client for url with fast retries; mutate adjusts the config.
func newTestClient(t *testing.T, url string, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{CommonConfig: CommonConfig{URL: url, Retry: fastRetry(3)}, Token: NewSecret(testToken)}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestClientConfig(t *testing.T) {
	t.Run("core.config.env-precedence", func(t *testing.T) {
		saved, savedTok := vendorEnv, vendorTokenEnv
		t.Cleanup(func() { vendorEnv, vendorTokenEnv = saved, savedTok })
		vendorEnv = VendorEnv{URL: []string{"VENDOR_ADDR"}}
		vendorTokenEnv = []string{"VENDOR_TOKEN"}

		env := map[string]string{EnvPrefix + "URL": "http://grow:1", "VENDOR_ADDR": "http://vendor:2", "VENDOR_TOKEN": "vendor-token"}
		cfg, err := ConfigFromEnvWith(Config{}, env)
		if err != nil || cfg.URL != "http://grow:1" || cfg.Token.Reveal() != "vendor-token" {
			t.Fatalf("env: %v %s", err, cfg)
		}
		env[EnvPrefix+"TOKEN"] = "grow-token"
		cfg, _ = ConfigFromEnvWith(Config{}, env)
		if cfg.Token.Reveal() != "grow-token" {
			t.Fatal("GROW_* token must beat the vendor variable")
		}
		cfg, _ = ConfigFromEnvWith(Config{CommonConfig: CommonConfig{URL: "https://explicit"}, Token: NewSecret("explicit")}, env)
		if cfg.URL != "https://explicit" || cfg.Token.Reveal() != "explicit" {
			t.Fatal("explicit must win")
		}
		cfg, _ = ConfigFromEnvWith(Config{}, map[string]string{})
		if cfg.URL != DefaultURL || cfg.RequestTimeout != DefaultRequestTimeout {
			t.Fatalf("defaults: %s", cfg)
		}
		_, err = ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "TOTAL_TIMEOUT": "forever-xyz"})
		if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), EnvPrefix+"TOTAL_TIMEOUT") || strings.Contains(err.Error(), "forever-xyz") {
			t.Fatalf("invalid value: %v", err)
		}
		if _, err := ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "URL": "ftp://nope"}); !errors.Is(err, ErrConfig) {
			t.Fatalf("invalid url: %v", err)
		}
		t.Setenv(EnvPrefix+"URL", "http://process-env:9")
		if cfg, err := ConfigFromEnv(); err != nil || cfg.URL != "http://process-env:9" {
			t.Fatalf("process env: %v %s", err, cfg.URL)
		}
	})

	t.Run("core.redaction.config", func(t *testing.T) {
		cfg := Config{
			CommonConfig: CommonConfig{URL: "https://h", Headers: map[string]string{"X-Api-Key": "hdr-xyz"}},
			Token:        NewSecret("tok-xyz"),
		}
		forms := fmt.Sprintf("%v|%+v|%#v|%s", cfg, cfg, cfg, cfg.String())
		if strings.Contains(forms, "tok-xyz") || strings.Contains(forms, "hdr-xyz") || !strings.Contains(forms, "Token:"+Redacted) {
			t.Fatalf("forms: %s", forms)
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		if _, err := NewClient(Config{CommonConfig: CommonConfig{URL: "mailto:x"}}); !errors.Is(err, ErrConfig) {
			t.Fatalf("NewClient: %v", err)
		}
		if _, err := NewClient(Config{CommonConfig: CommonConfig{TLS: TLSConfig{CACertPEM: "bad"}}}); !errors.Is(err, ErrConfig) {
			t.Fatalf("bad TLS: %v", err)
		}
	})
}

func TestClient(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = w.Write([]byte(`{"issuer":"http://idp.test","userinfo_endpoint":"http://` + r.Host + `/api/userinfo?schema=openid","jwks_uri":"x"}`))
		case "/api/userinfo":
			if r.Header.Get("Authorization") != "Bearer "+testToken || r.URL.Query().Get("schema") != "openid" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	t.Run("health ping version", func(t *testing.T) {
		c := newTestClient(t, ts.URL, nil)
		if hs, err := c.Health(t.Context()); err != nil || !hs.Healthy || hs.Status != "ok" || hs.Details["issuer"] != "http://idp.test" || len(hs.Details) != 2 {
			t.Fatalf("health %+v %v", hs, err)
		}
		if d, err := c.Ping(t.Context()); err != nil || d <= 0 {
			t.Fatalf("ping %s %v", d, err)
		}
		if _, err := c.ServerVersion(t.Context()); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("version %v", err)
		}
		if c.Config().URL != ts.URL {
			t.Fatal("Config()")
		}
	})

	t.Run("authentication errors", func(t *testing.T) {
		bad := newTestClient(t, ts.URL, func(cfg *Config) { cfg.Token = NewSecret("wrong-token") })
		if _, err := bad.Ping(t.Context()); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("bad token: %v", err)
		}
		none := newTestClient(t, ts.URL, func(cfg *Config) { cfg.Token = Secret{} })
		if _, err := none.Ping(t.Context()); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("no token: %v", err)
		}
	})

	t.Run("ping and version errors", func(t *testing.T) {
		noUserinfo := newTestServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) { _, _ = w.Write([]byte(`{"issuer":"x"}`)) })
		if _, err := newTestClient(t, noUserinfo.URL, nil).Ping(t.Context()); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("no userinfo: %v", err)
		}
		ts500 := newTestServer(t, statusHandler(http.StatusInternalServerError))
		c := newTestClient(t, ts500.URL, func(cfg *Config) { cfg.Retry = fastRetry(0) })
		if _, err := c.Ping(t.Context()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("discovery 500: %v", err)
		}
		if hs, err := c.Health(t.Context()); err != nil || hs.Healthy {
			t.Fatalf("health 500: %+v %v", hs, err)
		}
		tsBad := newTestServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) { _, _ = w.Write([]byte("nope")) })
		if _, err := newTestClient(t, tsBad.URL, nil).Ping(t.Context()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("discovery decode: %v", err)
		}
		cancelled, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := c.ServerVersion(cancelled); !errors.Is(err, ErrCancelled) {
			t.Fatalf("version cancelled: %v", err)
		}
		_ = c.Close()
		if _, err := c.ServerVersion(t.Context()); !errors.Is(err, ErrCancelled) {
			t.Fatalf("version closed: %v", err)
		}
	})

	t.Run("relative endpoint", func(t *testing.T) {
		for _, tc := range [][3]string{
			{"http://kc/realms/x/", "http://kc/realms/x/protocol/userinfo", "/protocol/userinfo"},
			{"http://a", "http://b/api/userinfo?x=1", "/api/userinfo?x=1"},
			{"http://a", "http://b/api/userinfo", "/api/userinfo"},
			{"http://a", "::bad", "::bad"},
		} {
			if got := RelativeEndpoint(tc[0], tc[1]); got != tc[2] {
				t.Fatalf("%v: %q", tc, got)
			}
		}
	})

	t.Run("core.close.idempotent", func(t *testing.T) {
		c := newTestClient(t, ts.URL, nil)
		first, second := c.Close(), c.Close()
		if first != nil || second != nil {
			t.Fatal("close")
		}
		if _, err := c.Ping(t.Context()); !errors.Is(err, ErrCancelled) {
			t.Fatalf("after close: %v", err)
		}
	})

	t.Run("core.health.unreachable", func(t *testing.T) {
		c := newTestClient(t, "http://"+closedAddr(t), func(cfg *Config) { cfg.ConnectTimeout = time.Second })
		if hs, err := c.Health(t.Context()); err != nil || hs.Healthy || hs.Status != "unreachable" {
			t.Fatalf("hs=%+v err=%v", hs, err)
		}
	})

	t.Run("from env", func(t *testing.T) {
		t.Setenv(EnvPrefix+"URL", ts.URL)
		t.Setenv(EnvPrefix+"TOKEN", testToken)
		c, err := NewClientFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Ping(t.Context()); err != nil {
			t.Fatal(err)
		}
		t.Setenv(EnvPrefix+"URL", "mailto:x")
		if _, err := NewClientFromEnv(); !errors.Is(err, ErrConfig) {
			t.Fatalf("bad env: %v", err)
		}
	})
}
