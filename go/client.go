package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client is the OIDC client. It is safe for concurrent use.
type Client struct {
	cfg       Config
	transport *httpTransport
	closeOnce sync.Once
}

// NewClient validates cfg and returns a client.
func NewClient(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.CommonConfig = cfg.withDefaults(DefaultURL)
	t, err := newHTTPTransport(cfg.CommonConfig)
	if err != nil {
		return nil, err
	}
	t.addSecret(cfg.Token.Reveal())
	return &Client{cfg: cfg, transport: t}, nil
}

// NewClientFromEnv builds a client from the environment (see ConfigFromEnv).
func NewClientFromEnv() (*Client, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return NewClient(cfg)
}

// Config returns the effective configuration.
func (c *Client) Config() Config { return c.cfg }

func (c *Client) authHeader() http.Header {
	h := http.Header{}
	if !c.cfg.Token.IsZero() {
		h.Set("Authorization", "Bearer "+c.cfg.Token.Reveal())
	}
	return h
}

// DiscoveryPath is the discovery document path, relative to the provider URL (realm prefixes
// such as Keycloak's are kept).
const DiscoveryPath = ".well-known/openid-configuration"

// Health checks liveness without credentials: GET <url>/.well-known/openid-configuration. It
// reports an unreachable or unhealthy provider in the result; it fails only for CANCELLED and CONFIG.
func (c *Client) Health(ctx context.Context) (HealthStatus, error) {
	hs, err := c.transport.checkHealth(ctx, "health", &request{Method: http.MethodGet, Path: DiscoveryPath})
	if err == nil && hs.Details != nil {
		keep := map[string]string{"httpStatus": hs.Details["httpStatus"]}
		if issuer, ok := hs.Details["issuer"]; ok {
			keep["issuer"] = issuer
		}
		hs.Details = keep
	}
	return hs, err
}

// Ping makes an authenticated round trip with the configured access token (Token): GET the
// provider's userinfo_endpoint from discovery. It returns the latency (AUTHENTICATION error on a
// rejected token, UNSUPPORTED when the provider has no userinfo endpoint).
func (c *Client) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	res, err := c.transport.do(ctx, &request{Method: http.MethodGet, Path: DiscoveryPath, Operation: "ping"})
	if err != nil {
		return 0, err
	}
	var doc struct {
		UserinfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := res.decodeJSON("ping", &doc); err != nil {
		return 0, err
	}
	if doc.UserinfoEndpoint == "" {
		return 0, UnsupportedError("ping", "the provider has no userinfo endpoint")
	}
	path, rawQuery, _ := strings.Cut(RelativeEndpoint(c.cfg.URL, doc.UserinfoEndpoint), "?")
	query, _ := url.ParseQuery(rawQuery)
	req := &request{Method: http.MethodGet, Path: path, Header: c.authHeader(), Operation: "ping"}
	if len(query) > 0 {
		req.Query = query
	}
	if _, err := c.transport.do(ctx, req); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// ServerVersion is UNSUPPORTED: OpenID Connect providers expose no version (CANCELLED once closed).
func (c *Client) ServerVersion(ctx context.Context) (string, error) {
	if c.transport.closed.Load() {
		return "", &Error{Code: ErrorCodeCancelled, Message: "serverVersion: client is closed"}
	}
	if err := ctx.Err(); err != nil {
		return "", ContextError("serverVersion", err)
	}
	return "", UnsupportedError("serverVersion", "OpenID Connect providers expose no version")
}

// RelativeEndpoint returns an endpoint's path relative to the provider URL: the part after the
// provider URL when the endpoint starts with it (keeps realm prefixes out), else its path and query.
func RelativeEndpoint(base, endpoint string) string {
	root := strings.TrimRight(base, "/")
	if strings.HasPrefix(endpoint, root+"/") {
		return endpoint[len(root):]
	}
	if u, err := url.Parse(endpoint); err == nil && u.Path != "" {
		if u.RawQuery != "" {
			return u.Path + "?" + u.RawQuery
		}
		return u.Path
	}
	return endpoint
}

// Close releases resources. It is idempotent.
func (c *Client) Close() error {
	c.closeOnce.Do(c.transport.close)
	return nil
}
