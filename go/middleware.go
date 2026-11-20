package oidc

import (
	"context"
	"net/http"
	"strings"
)

type userKey struct{}

// WithUser returns a copy of ctx carrying user (used by Middleware; handy in tests).
func WithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, userKey{}, user)
}

// UserFrom returns the user stored by Middleware.
func UserFrom(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userKey{}).(*User)
	return u, ok && u != nil
}

// BearerToken returns the bearer token of the Authorization header ("" when there is none).
// The scheme is matched case-insensitively.
func BearerToken(r *http.Request) string {
	scheme, token, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if !ok || !strings.EqualFold(scheme, "bearer") {
		return ""
	}
	token = strings.TrimSpace(token)
	if strings.ContainsAny(token, " \t") {
		return ""
	}
	return token
}

func deny(w http.ResponseWriter, status int, code string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
}

// Middleware verifies the bearer token of every request and stores the user in the request
// context (UserFrom). Missing or invalid token → 401, JWKS/discovery unreachable → 503. The
// response never says why a token was rejected.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return v.middleware(next, false)
}

// OptionalMiddleware is Middleware that lets requests without a token through anonymously
// (an invalid token is still 401).
func (v *Verifier) OptionalMiddleware(next http.Handler) http.Handler {
	return v.middleware(next, true)
}

func (v *Verifier) middleware(next http.Handler, optional bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := BearerToken(r)
		if token == "" {
			if optional {
				next.ServeHTTP(w, r)
				return
			}
			deny(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		user, err := v.Verify(r.Context(), token)
		if err == nil {
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), user)))
			return
		}
		switch CodeOf(err) {
		case ErrorCodeUnavailable, ErrorCodeTimeout, ErrorCodeCancelled:
			deny(w, http.StatusServiceUnavailable, "auth_unavailable")
		default:
			deny(w, http.StatusUnauthorized, "unauthorized")
		}
	})
}

// RequireRoles returns middleware (placed after Middleware) that answers 401 without a user and
// 403 unless the user has at least one of roles (case-insensitive). No roles = any user.
func RequireRoles(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := UserFrom(r.Context())
			switch {
			case !ok:
				deny(w, http.StatusUnauthorized, "unauthorized")
			case !HasAnyRole(user.Roles, roles):
				deny(w, http.StatusForbidden, "forbidden")
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
}
