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
# user_login USER PASSWORD → the full token response (access and refresh tokens)
user_login() {
  local location code
  location=$(curl -s -o /dev/null -w '%{redirect_url}' \
    -d response_type=code -d client_id=client1 --data-urlencode "redirect_uri=$CALLBACK" \
    --data-urlencode "scope=notes:read notes:write" -d state=s -d "code_challenge=$CHALLENGE" -d code_challenge_method=S256 \
    -d "username=$1" --data-urlencode "password=$2" -d decision=allow "$AUTH/authorize")
  code=$(echo "$location" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
  curl -s -u "client1:$SECRET1" -d grant_type=authorization_code -d "code=$code" \
    --data-urlencode "redirect_uri=$CALLBACK" -d "code_verifier=$VERIFIER" "$AUTH/token"
}
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }   # field NAME < json
user_token() { user_login "$1" "$2" | field access_token; }

READ=$(token client2 "$SECRET2")                                # notes:read
WRITE=$(token client3 "$SECRET3" "notes:read notes:write")      # notes:read notes:write
ALICE=$(user_token alice "$ALICE_PASSWORD")                     # client1 acting for alice
BOB=$(user_token bob "$BOB_PASSWORD")                           # client1 acting for bob
echo "tokens: client2 ${READ:0:8}…  client3 ${WRITE:0:8}…  alice ${ALICE:0:8}…  bob ${BOB:0:8}…"

# claims TOKEN → the JWT's payload, decoded (anyone can read it; only the signature makes it trustworthy)
claims() {
  local p=${1#*.}; p=${p%%.*}; p=$(printf '%s' "$p" | tr '_-' '/+')
  while [ $(( ${#p} % 4 )) -ne 0 ]; do p="$p="; done
  printf '%s' "$p" | base64 -d 2>/dev/null
}

echo "== JWT access tokens (checked by the notes API with the auth server's public key)"
check "public key is published" 200 '"crv":"Ed25519"' "$AUTH/.well-known/jwks.json"
[[ "$(claims "$ALICE")" == *'"sub":"user-1"'* && "$(claims "$ALICE")" == *'"aud":"notes-api"'* ]] \
  && { pass=$((pass + 1)); echo "PASS  alice's token names her and the API"; } \
  || { fail=$((fail + 1)); echo "FAIL  alice's claims: $(claims "$ALICE")"; }
[[ "$(claims "$READ")" != *'"sub"'* ]] \
  && { pass=$((pass + 1)); echo "PASS  client token has no user"; } \
  || { fail=$((fail + 1)); echo "FAIL  client2's claims: $(claims "$READ")"; }
# Widen client2's scope in the payload, keeping the original signature.
P=$(claims "$READ" | sed 's/"scope":"notes:read"/"scope":"notes:read notes:write"/' | base64 | tr '+/' '-_' | tr -d '=\n')
TAMPERED="${READ%%.*}.$P.${READ##*.}"
check "tampered token rejected" 401 'bad signature' -H "Authorization: Bearer $TAMPERED" -d '{"text":"x"}' "$API/notes"

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

echo "== Revocation (the auth server's deny list in Redis)"
REVOKE_ME=$(token client2 "$SECRET2")
check "works before revoking"   200 '"owner":"client:client2"'              -H "Authorization: Bearer $REVOKE_ME" "$API/notes"
check "client revokes it"       200 ''                                      -u "client2:$SECRET2" -d "token=$REVOKE_ME" "$AUTH/revoke"
check "rejected after revoking" 401 'revoked'                               -H "Authorization: Bearer $REVOKE_ME" "$API/notes"


echo "== Refresh tokens (rotation, and reuse revokes the whole login)"
LOGIN=$(user_login alice "$ALICE_PASSWORD")
OLD_REFRESH=$(echo "$LOGIN" | field refresh_token)
REFRESHED=$(curl -s -u "client1:$SECRET1" -d grant_type=refresh_token -d "refresh_token=$OLD_REFRESH" "$AUTH/token")
NEW_ACCESS=$(echo "$REFRESHED" | field access_token); NEW_REFRESH=$(echo "$REFRESHED" | field refresh_token)
[[ -n "$NEW_REFRESH" && "$NEW_REFRESH" != "$OLD_REFRESH" ]] \
  && { pass=$((pass + 1)); echo "PASS  refresh rotates the refresh token"; } \
  || { fail=$((fail + 1)); echo "FAIL  refresh response: $REFRESHED"; }
check "new access token works"  200 '"owner":"user-1"'                      -H "Authorization: Bearer $NEW_ACCESS" "$API/notes"
check "old refresh token reused" 400 'this login has been revoked'          -u "client1:$SECRET1" -d grant_type=refresh_token -d "refresh_token=$OLD_REFRESH" "$AUTH/token"
check "so the newest one is dead" 400 invalid_grant                         -u "client1:$SECRET1" -d grant_type=refresh_token -d "refresh_token=$NEW_REFRESH" "$AUTH/token"
check "and its access token too" 401 'revoked'                              -H "Authorization: Bearer $NEW_ACCESS" "$API/notes"

echo
echo "$pass passed, $fail failed"
[ $fail = 0 ]
