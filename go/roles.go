package oidc

import (
	"slices"
	"strings"
)

// ClaimAt returns the value at a claim path: a claim name ("roles") or a dotted path into nested
// objects ("realm_access.roles"). An exact top-level match wins, so claim names containing dots
// ("https://example.com/roles") keep working.
func ClaimAt(claims map[string]any, path string) (any, bool) {
	if v, ok := claims[path]; ok {
		return v, true
	}
	var current any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		if current, ok = m[part]; !ok {
			return nil, false
		}
	}
	return current, true
}

// roleObjectKeys are tried in order when a roles claim holds objects (Casdoor roles: [{name: …}]).
var roleObjectKeys = []string{"name", "code", "role", "value"}

func roleName(entry any) string {
	switch e := entry.(type) {
	case string:
		return strings.TrimSpace(e)
	case map[string]any:
		for _, key := range roleObjectKeys {
			if s, ok := e[key].(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

// ExtractRoles returns the role names of the claim at rolesClaim (default "roles"):
// a string is split on commas and whitespace; an array yields each string, or each object's
// name (Casdoor), code, role or value; anything else yields no roles. Duplicates are removed.
func ExtractRoles(claims map[string]any, rolesClaim string) []string {
	if rolesClaim == "" {
		rolesClaim = DefaultRolesClaim
	}
	raw, _ := ClaimAt(claims, rolesClaim)
	var names []string
	switch r := raw.(type) {
	case string:
		names = strings.FieldsFunc(r, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' || c == '\n' })
	case []any:
		for _, entry := range r {
			names = append(names, roleName(entry))
		}
	}
	out := []string{}
	for _, name := range names {
		if name != "" && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// HasAnyRole reports whether have contains at least one of required (case-insensitive).
// An empty required list means any authenticated user.
func HasAnyRole(have, required []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, want := range required {
		if slices.ContainsFunc(have, func(h string) bool { return strings.EqualFold(h, want) }) {
			return true
		}
	}
	return false
}
