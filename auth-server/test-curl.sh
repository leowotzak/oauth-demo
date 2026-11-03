#!/usr/bin/env bash
# curl test suite for the auth server's POST /token endpoint.
#
# Usage:
#   go run .            # in another terminal (after: set -a; source .env; set +a)
#   ./test-curl.sh      # runs every case and prints PASS/FAIL
#
# Each case is one curl command. To try one by hand, copy the curl part and
# replace $T, $S1, $S2, $S3 with the URL and secrets from .env.

set -u
cd "$(dirname "$0")"
set -a; source .env; set +a

T="${TOKEN_URL:-http://localhost:8080/token}"
S1="$SECRET1"; S2="$SECRET2"; S3="$SECRET3"
FORM="Content-Type: application/x-www-form-urlencoded"

pass=0; fail=0
body=$(mktemp); trap 'rm -f "$body"' EXIT

if ! curl -s -o /dev/null "$T"; then
  echo "Server not reachable at $T. Start it with: go run ." >&2
  exit 1
fi

# check NAME STATUS ERROR [SCOPE] -- CURL_ARGS...
# ERROR is the expected OAuth error code, or "-" for a success/non-OAuth response.
# SCOPE (optional) is the expected granted scope on success.
check() {
  local name=$1 want_status=$2 want_error=$3 want_scope=""
  shift 3
  if [ "$1" != "--" ]; then want_scope=$1; shift; fi
  shift # the --

  local status
  status=$(curl -s -o "$body" -w '%{http_code}' "$@")
  local got_error got_scope
  got_error=$(grep -o '"error":"[^"]*"' "$body" | cut -d'"' -f4)
  got_scope=$(grep -o '"scope":"[^"]*"' "$body" | cut -d'"' -f4)

  local ok=1
  [ "$status" = "$want_status" ] || ok=0
  if [ "$want_error" != "-" ]; then [ "$got_error" = "$want_error" ] || ok=0; fi
  if [ -n "$want_scope" ]; then [ "$got_scope" = "$want_scope" ] || ok=0; fi
  if [ "$want_status" = 200 ]; then grep -q '"access_token"' "$body" || ok=0; fi

  if [ $ok = 1 ]; then
    pass=$((pass + 1)); printf 'PASS  %-48s %s %s\n' "$name" "$status" "${got_error:-$got_scope}"
  else
    fail=$((fail + 1)); printf 'FAIL  %-48s got %s %s, want %s %s\n        body: %s\n' \
      "$name" "$status" "${got_error:-$got_scope}" "$want_status" "${want_error/-/}${want_scope}" "$(cat "$body")"
  fi
}

echo "== Success"
check "basic auth, scope omitted → defaults" 200 - "notes:read" -- \
  -u "client2:$S2" -d grant_type=client_credentials "$T"
check "basic auth, explicit scope" 200 - "notes:read" -- \
  -u "client2:$S2" -d grant_type=client_credentials -d scope=notes:read "$T"
check "credentials in body" 200 - "notes:read" -- \
  -d grant_type=client_credentials -d client_id=client2 --data-urlencode "client_secret=$S2" "$T"
check "several scopes" 200 - "notes:read notes:write metrics:read" -- \
  -u "client3:$S3" -d grant_type=client_credentials --data-urlencode "scope=notes:read notes:write metrics:read" "$T"
check "duplicate scope dropped" 200 - "notes:read" -- \
  -u "client3:$S3" -d grant_type=client_credentials --data-urlencode "scope=notes:read notes:read" "$T"
check "client3 default narrower than allowed" 200 - "notes:read" -- \
  -u "client3:$S3" -d grant_type=client_credentials "$T"
check "content type with charset" 200 - "notes:read" -- \
  -u "client2:$S2" -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -d grant_type=client_credentials "$T"
check "hand-built Basic header (§2.3.1)" 200 - "notes:read" -- \
  -H "Authorization: Basic $(printf '%s:%s' client2 "$S2" | base64)" -d grant_type=client_credentials "$T"

echo "== Request format"
check "GET" 405 - -- \
  "$T"
check "JSON body" 400 invalid_request -- \
  -u "client2:$S2" -H "Content-Type: application/json" -d '{"grant_type":"client_credentials"}' "$T"
check "params in query string are ignored" 400 invalid_request -- \
  -u "client2:$S2" -X POST -H "$FORM" "$T?grant_type=client_credentials"
check "repeated parameter" 400 invalid_request -- \
  -u "client2:$S2" -d grant_type=client_credentials -d grant_type=client_credentials "$T"

echo "== Client authentication"
check "no credentials" 401 invalid_client -- \
  -d grant_type=client_credentials "$T"
check "wrong secret" 401 invalid_client -- \
  -u client2:wrong -d grant_type=client_credentials "$T"
check "unknown client" 401 invalid_client -- \
  -u "client4:$S2" -d grant_type=client_credentials "$T"
check "another client's secret" 401 invalid_client -- \
  -u "client2:$S1" -d grant_type=client_credentials "$T"
check "secret hash instead of secret" 401 invalid_client -- \
  -u "client2:$SECRET2_HASH" -d grant_type=client_credentials "$T"
check "wrong secret in body" 401 invalid_client -- \
  -d grant_type=client_credentials -d client_id=client2 -d client_secret=wrong "$T"
check "basic and body credentials together" 400 invalid_request -- \
  -u "client2:$S2" -d grant_type=client_credentials -d client_id=client2 --data-urlencode "client_secret=$S2" "$T"

echo "== Grant type"
check "missing grant_type" 400 invalid_request -- \
  -u "client2:$S2" -d scope=notes:read "$T"
check "password grant" 400 unsupported_grant_type -- \
  -u "client2:$S2" -d grant_type=password "$T"
check "made-up grant" 400 unsupported_grant_type -- \
  -u "client2:$S2" -d grant_type=magic "$T"
check "grant_type wrong case" 400 unsupported_grant_type -- \
  -u "client2:$S2" -d grant_type=Client_Credentials "$T"
check "client1 not allowed client_credentials" 400 unauthorized_client -- \
  -u "client1:$S1" -d grant_type=client_credentials "$T"
check "client2 not allowed authorization_code" 400 unauthorized_client -- \
  -u "client2:$S2" -d grant_type=authorization_code "$T"
check "allowed but not implemented yet" 400 unsupported_grant_type -- \
  -u "client1:$S1" -d grant_type=authorization_code "$T"

echo "== Scope"
check "scope not allowed" 400 invalid_scope -- \
  -u "client2:$S2" -d grant_type=client_credentials -d scope=notes:write "$T"
check "scope wrong case" 400 invalid_scope -- \
  -u "client2:$S2" -d grant_type=client_credentials -d scope=NOTES:READ "$T"
check "one bad scope fails the lot" 400 invalid_scope -- \
  -u "client3:$S3" -d grant_type=client_credentials --data-urlencode "scope=notes:read notes:delete" "$T"
check "wrong resource" 400 invalid_scope -- \
  -u "client2:$S2" -d grant_type=client_credentials -d scope=metrics:read "$T"
check "empty scope" 400 invalid_scope -- \
  -u "client2:$S2" -d grant_type=client_credentials -d scope= "$T"
check "double space in scope" 400 invalid_scope -- \
  -u "client3:$S3" -d grant_type=client_credentials --data-urlencode "scope=notes:read  notes:write" "$T"
check "trailing space in scope" 400 invalid_scope -- \
  -u "client2:$S2" -d grant_type=client_credentials --data-urlencode "scope=notes:read " "$T"

echo
echo "$pass passed, $fail failed"
[ $fail = 0 ]
