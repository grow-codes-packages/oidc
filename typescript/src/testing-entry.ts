// Service-owned entry point of `@grow-codes/oidc/testing`: sdk-kit generates it once. It
// re-exports the generated test helpers; add service test helpers below (for example
// `export * from "./bootstrap.js";`). tsup (`testing/index`) and typedoc build from this file.

/**
 * Test helpers for `@grow-codes/oidc`: in-memory fakes and the conformance runner.
 * Import from `@grow-codes/oidc/testing`.
 *
 * @module testing
 */

export * from "./testing/index.js";
export * from "./oidc/fake-idp.js";
