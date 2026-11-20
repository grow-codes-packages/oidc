// Package oidc is the Grow Codes SDK for OIDC.
//
// Create a client from the environment (GROW_OIDC_URL,
// GROW_OIDC_TOKEN, ...) or from a Config literal:
//
//	client, err := oidc.NewClientFromEnv()
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	status, err := client.Health(ctx)
//
// Every error is an *Error; compare codes with errors.Is against the Err*
// sentinels (errors.Is(err, oidc.ErrNotFound)). Credentials are wrapped in
// Secret and never appear in errors, hooks or logs.
//
// OIDC is a trademark of its owner (OpenID Foundation (specification); any OpenID Connect provider); this package is not
// affiliated with or endorsed by it.
package oidc
