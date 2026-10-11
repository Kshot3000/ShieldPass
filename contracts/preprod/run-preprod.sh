#!/usr/bin/env bash
# ShieldPass on Midnight Preprod: deploy + live drill (see shieldpass-preprod.mjs).
#   contracts/preprod/run-preprod.sh [--dry-run]
# Holds the shared Preprod wallet lock (the same wallet PlutusShield's relay uses),
# reads the Blockfrost Midnight Preprod project id from the secrets env (never printed).
set -euo pipefail
SP=$(cd "$(dirname "$0")/../.." && pwd)
H=${MIDNIGHT_AGENT_HOME:-/workspace/Midnight-GrokBot-Agent}
LOCK=${MIDNIGHT_WALLET_LOCK:-$H/.plutusshield-run/.wallet.lock}
R=${SHIELDPASS_RUN_DIR:-$H/.shieldpass-run}
mkdir -p "$R"
exec 9>"$LOCK"
flock -w 3600 9 || { echo "wallet lock wait timed out; nothing submitted" >&2; exit 1; }
[ -n "${BLOCKFROST_MIDNIGHT_PREPROD_ID:-}" ] || export $(grep -v '^#' "${BLOCKFROST_MIDNIGHT_ENV:-/workspace/PlutusShield-secrets/blockfrost-midnight-preprod.env}" | grep '^BLOCKFROST_MIDNIGHT_PREPROD_ID=' | xargs)
# Run from a workspace with midnight-js + wallet-sdk installed; copy the compiled contract
# next to it so one compact-runtime instance serves both.
rm -rf "$R/shieldpass" && cp -r "$SP/contracts/src/managed/shieldpass" "$R/shieldpass"
cp "$SP/contracts/preprod/shieldpass-preprod.mjs" "$R/shieldpass-preprod.mjs"
cd "$R"
export SHIELDPASS_OUT=$R/shieldpass
export SHIELDPASS_SECRETS=${SHIELDPASS_SECRETS:-/workspace/ShieldPass-secrets}
export SHIELDPASS_VERIFY_SDK=$SP/packages/verify/src/index.ts
export SHIELDPASS_PUBLIC_RECORD=${SHIELDPASS_PUBLIC_RECORD:-$SP/deployments/preprod.json}
export MIDNIGHT_WALLET_FACADE=$H/packages/preprod-hello-stub/src/wallet-facade.mjs
export MIDNIGHT_LOAD_ENV=$H/packages/preprod-hello-stub/src/load-env.mjs
# Redact Blockfrost project ids from anything a library logs (e.g. polkadot RPC-CORE reconnect lines).
REDACT_PID='s/(project_id=)[^&[:space:]"]+/\1…/g; s/nightpreprod[A-Za-z0-9]+/nightpreprod…/g'
exec node --max-old-space-size=6144 --no-warnings shieldpass-preprod.mjs "$@" > >(sed -u -E "$REDACT_PID") 2> >(sed -u -E "$REDACT_PID" >&2)
