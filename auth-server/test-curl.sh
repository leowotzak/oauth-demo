#!/usr/bin/env bash
# curl tests for the auth server's POST /token endpoint.
#
# Usage:
#   go run .            # in another terminal
#   ./test-curl.sh
#
# To try one by hand, copy the curl part and replace $T and $S1-$S3 with the
# URL and secrets from .env.

set -u
cd "$(dirname "$0")"
set -a; source .env; set +a

T="${TOKEN_URL:-http://localhost:8080/token}"
S1="$SECRET1"; S2="$SECRET2"; S3="$SECRET3"
pass=0; fail=0

if ! curl -s -o /dev/null "$T"; then
  echo "Server not reachable at $T. Start it with: go run ." >&2
  exit 1
fi

# check NAME WANT_STATUS WANT_TEXT CURL_ARGS...
# WANT_TEXT must appear in the response body (an error code or a scope).
check() {
  local name=$1 want_status=$2 want_text=$3; shift 3
  local out status body
  out=$(curl -s -w '\n%{http_code}' "$@")
  status=${out##*$'\n'}; body=${out%$'\n'*}; body=${body%$'\n'}
  if [ "$status" = "$want_status" ] && [[ "$body" == *"$want_text"* ]]; then
    pass=$((pass + 1)); printf 'PASS  %-40s %s\n' "$name" "$body"
  else
    fail=$((fail + 1)); printf 'FAIL  %-40s got %s %s, want %s %s\n' "$name" "$status" "$body" "$want_status" "$want_text"
  fi
}

echo "== Success"
check "basic auth, default scope"  200 '"scope":"notes:read"' -u "client2:$S2" -d grant_type=client_credentials "$T"
check "credentials in body"         200 '"scope":"notes:read"' -d grant_type=client_credentials -d client_id=client2 -d "client_secret=$S2" "$T"
check "several scopes"              200 '"scope":"notes:read metrics:read"' -u "client3:$S3" -d grant_type=client_credentials --data-urlencode "scope=notes:read metrics:read" "$T"

echo "== Errors"
check "GET"                         405 ''                       "$T"
check "no credentials"              401 invalid_client          -d grant_type=client_credentials "$T"
check "wrong secret"                401 invalid_client          -u client2:wrong -d grant_type=client_credentials "$T"
check "unknown client"              401 invalid_client          -u "client4:$S2" -d grant_type=client_credentials "$T"
check "missing grant_type"          400 invalid_request         -u "client2:$S2" -d scope=notes:read "$T"
check "password grant"              400 unsupported_grant_type  -u "client2:$S2" -d grant_type=password "$T"
check "client1 not allowed"         400 unauthorized_client     -u "client1:$S1" -d grant_type=client_credentials "$T"
check "scope not allowed"           400 invalid_scope           -u "client2:$S2" -d grant_type=client_credentials -d scope=notes:write "$T"
check "one bad scope fails the lot" 400 invalid_scope           -u "client3:$S3" -d grant_type=client_credentials --data-urlencode "scope=notes:read notes:delete" "$T"

echo
echo "$pass passed, $fail failed"
[ $fail = 0 ]
