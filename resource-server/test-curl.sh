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

# user_token USER PASSWORD → logs the user in as client1 (authorization code
# flow with PKCE) and prints the access token. This is what client-app will do
# in a browser.
VERIFIER=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk               # RFC 7636 example
CHALLENGE=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
CALLBACK=http://localhost:9000/callback
user_token() {
  local location code
  location=$(curl -s -o /dev/null -w '%{redirect_url}' \
    -d response_type=code -d client_id=client1 --data-urlencode "redirect_uri=$CALLBACK" \
    --data-urlencode "scope=notes:read notes:write" -d state=s -d "code_challenge=$CHALLENGE" -d code_challenge_method=S256 \
    -d "username=$1" --data-urlencode "password=$2" -d decision=allow "$AUTH/authorize")
  code=$(echo "$location" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
  curl -s -u "client1:$SECRET1" -d grant_type=authorization_code -d "code=$code" \
    --data-urlencode "redirect_uri=$CALLBACK" -d "code_verifier=$VERIFIER" "$AUTH/token" \
    | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

READ=$(token client2 "$SECRET2")                                # notes:read
WRITE=$(token client3 "$SECRET3" "notes:read notes:write")      # notes:read notes:write
ALICE=$(user_token alice "$ALICE_PASSWORD")                     # client1 acting for alice
BOB=$(user_token bob "$BOB_PASSWORD")                           # client1 acting for bob
echo "tokens: client2 ${READ:0:8}…  client3 ${WRITE:0:8}…  alice ${ALICE:0:8}…  bob ${BOB:0:8}…"

echo "== Introspection (what the notes API asks the auth server)"
check "active token"            200 '"active":true'  -u "notes-api:$NOTES_API_SECRET" -d "token=$READ" "$AUTH/introspect"
check "user token has sub"      200 '"sub":"user-1"' -u "notes-api:$NOTES_API_SECRET" -d "token=$ALICE" "$AUTH/introspect"
check "unknown token"           200 '"active":false' -u "notes-api:$NOTES_API_SECRET" -d "token=made-up" "$AUTH/introspect"
check "caller not authenticated" 401 invalid_client   -d "token=$READ" "$AUTH/introspect"

echo "== Notes API"
check "no token"                401 'Bearer realm="notes"'                  "$API/notes"
check "made-up token"           401 'error="invalid_token"'                 -H "Authorization: Bearer made-up" "$API/notes"
check "read token: GET"         200 '"owner":"client:client2"'              -H "Authorization: Bearer $READ" "$API/notes"
check "read token: POST"        403 'error="insufficient_scope"'            -H "Authorization: Bearer $READ" -d '{"text":"hi"}' "$API/notes"
check "write token: POST"       201 'from curl'                             -H "Authorization: Bearer $WRITE" -d '{"text":"from curl"}' "$API/notes"

echo "== Users (authorization code tokens, both from client1)"
check "alice sees her notes"    200 '"owner":"user-1","notes":["Buy milk"]' -H "Authorization: Bearer $ALICE" "$API/notes"
check "bob adds a note"         201 "bob's note"                            -H "Authorization: Bearer $BOB" -d "{\"text\":\"bob's note\"}" "$API/notes"
check "alice can't see it"      200 '"notes":["Buy milk"]'                  -H "Authorization: Bearer $ALICE" "$API/notes"

echo
echo "$pass passed, $fail failed"
[ $fail = 0 ]
