#!/usr/bin/env bash
# End-to-end curl tests: get tokens from auth-server, use them on the notes API.
#
# Usage (three terminals):
#   cd auth-server && go run .        # :8080
#   cd resource-server && go run .    # :8081
#   ./resource-server/test-curl.sh

set -u
cd "$(dirname "$0")"
set -a; source ../auth-server/.env; set +a   # client secrets, for getting tokens

AUTH="${AUTH_URL:-http://localhost:8080}"
API="${API_URL:-http://localhost:8081}"
pass=0; fail=0

for url in "$AUTH/token" "$API/notes"; do
  if ! curl -s -o /dev/null "$url"; then
    echo "Not reachable: $url. Start both servers first (see the top of this file)." >&2
    exit 1
  fi
done

# token CLIENT SECRET [SCOPE] → prints an access token
token() {
  curl -s -u "$1:$2" -d grant_type=client_credentials ${3:+--data-urlencode "scope=$3"} "$AUTH/token" \
    | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

# check NAME WANT_STATUS WANT_TEXT CURL_ARGS...
check() {
  local name=$1 want_status=$2 want_text=$3; shift 3
  local out status body
  out=$(curl -s -D - -w '\n%{http_code}' "$@")
  status=${out##*$'\n'}; body=${out%$'\n'*}
  if [ "$status" = "$want_status" ] && [[ "$body" == *"$want_text"* ]]; then
    pass=$((pass + 1)); printf 'PASS  %-34s %s\n' "$name" "$status"
  else
    fail=$((fail + 1)); printf 'FAIL  %-34s got %s, want %s containing %s\n%s\n' "$name" "$status" "$want_status" "$want_text" "$body"
  fi
}

READ=$(token client2 "$SECRET2")                                # notes:read
WRITE=$(token client3 "$SECRET3" "notes:read notes:write")      # notes:read notes:write
echo "client2 token: ${READ:0:10}…   client3 token: ${WRITE:0:10}…"

echo "== Introspection (what the notes API asks the auth server)"
check "active token"            200 '"active":true'  -u "notes-api:$NOTES_API_SECRET" -d "token=$READ" "$AUTH/introspect"
check "unknown token"           200 '"active":false' -u "notes-api:$NOTES_API_SECRET" -d "token=made-up" "$AUTH/introspect"
check "caller not authenticated" 401 invalid_client   -d "token=$READ" "$AUTH/introspect"

echo "== Notes API"
check "no token"                401 'Bearer realm="notes"'                  "$API/notes"
check "made-up token"           401 'error="invalid_token"'                 -H "Authorization: Bearer made-up" "$API/notes"
check "read token: GET"         200 'Buy milk'                              -H "Authorization: Bearer $READ" "$API/notes"
check "read token: POST"        403 'error="insufficient_scope"'            -H "Authorization: Bearer $READ" -d '{"text":"hi"}' "$API/notes"
check "write token: POST"       201 'from curl'                             -H "Authorization: Bearer $WRITE" -d '{"text":"from curl"}' "$API/notes"

echo
echo "$pass passed, $fail failed"
[ $fail = 0 ]
