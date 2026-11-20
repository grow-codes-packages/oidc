#!/bin/sh
# One-shot bootstrap for the Docker integration suites (sdk-kit SPEC §8).
#
# OWNED BY THIS REPOSITORY: sdk-kit writes this skeleton once and never overwrites it.
# Runs in the `bootstrap` service of docker/compose.service.yml after `service` is healthy.
# Prepare Casdoor (the OpenID provider under test) for the tests (init/unseal, users, tokens, streams, buckets ...) and write
# the credentials the tests need to /bootstrap/env with bootstrap_set. Exit non-zero on failure:
# the test containers then never start and compose-run.sh prints this job's log.
# Never print secret values.
set -eu
# shellcheck source=lib.sh
. /scripts/lib.sh

: "${SERVICE_URL:?SERVICE_URL is not set}"

bootstrap_begin

# --- Casdoor: organization, application, role, user and a real access token ---------------------
bootstrap_wait_http -t 120 "$SERVICE_URL/api/health"
minted=$(mktemp)
python3 /scripts/mint.py "$minted" || bootstrap_fail "minting a Casdoor token failed"
while IFS='=' read -r key value; do
  [ -n "$key" ] && bootstrap_set "$key" "$value"
done <"$minted"
rm -f "$minted"
# -------------------------------------------------------------------------------------------------

bootstrap_commit
