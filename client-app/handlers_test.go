package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const testSecret = "client1-secret"

// fakes stands in for auth-server's /token and /revoke and the notes API. It
// records the code_challenge the app sent at /login, checks the exchange the
// same way the real auth server does, and rotates refresh tokens like it.
type fakes struct {
	t           *testing.T
	auth, notes *httptest.Server
	challenge   string // from the /authorize URL the app built
	exchanges   int    // how many code exchanges /token handled
	refreshes   int    // how many refreshes /token handled
	refresh     string // the one refresh token that currently works
	expiresIn   int    // lifetime given to access tokens, in seconds
	valid       map[string]bool
	revoked     []string
	noteList    []string
}

func newFakes(t *testing.T) *fakes {
	f := &fakes{t: t, noteList: []string{"Buy milk"}, expiresIn: 3600, valid: map[string]bool{}}

	// issue answers /token with a new access token and refresh token.
	issue := func(w http.ResponseWriter, access, refresh string) {
		f.valid[access] = true
		f.refresh = refresh
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":%d,"refresh_token":%q}`, access, f.expiresIn, refresh)
	}

	f.auth = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		id, secret, _ := r.BasicAuth()
		if r.URL.Path == "/revoke" {
			if id == "client1" && secret == testSecret {
				f.revoked = append(f.revoked, r.PostForm.Get("token"))
			}
			return // 200 OK, like the real /revoke
		}
		if id != "client1" || secret != testSecret {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		if r.PostForm.Get("grant_type") == "refresh_token" {
			if r.PostForm.Get("refresh_token") != f.refresh {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			f.refreshes++ // rotate: a new pair, and the old refresh token stops working
			issue(w, fmt.Sprintf("tok-alice-%d", f.refreshes), fmt.Sprintf("ref-%d", f.refreshes+1))
			return
		}
		f.exchanges++
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		switch {
		case r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("code") != "good-code":
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		case r.PostForm.Get("redirect_uri") != "http://localhost:9000/callback":
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		case base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge:
			http.Error(w, `{"error":"invalid_grant","error_description":"PKCE"}`, http.StatusBadRequest)
		default:
			issue(w, "tok-alice", "ref-1")
		}
	}))
	t.Cleanup(f.auth.Close)

	f.notes = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); !f.valid[token] {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			var body struct{ Text string }
			json.NewDecoder(r.Body).Decode(&body)
			f.noteList = append(f.noteList, body.Text)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(notesResponse{"user-1", f.noteList}) // like the real API
			return
		}
		json.NewEncoder(w).Encode(notesResponse{"user-1", f.noteList})
	}))
	t.Cleanup(f.notes.Close)
	return f
}

// browser is a test HTTP client that keeps cookies and doesn't follow
// redirects, so tests can look at each step. Its app stores sessions in its
// own fake Redis (redis).
type browser struct {
	t      *testing.T
	client *http.Client
	base   string
	redis  *miniredis.Miniredis
}

func newBrowser(t *testing.T, f *fakes) *browser {
	mr := miniredis.RunT(t)
	return newBrowserWith(t, f, redis.NewClient(&redis.Options{Addr: mr.Addr()}), mr)
}

func newBrowserWith(t *testing.T, f *fakes, rdb *redis.Client, mr *miniredis.Miniredis) *browser {
	a := newApp("client1", testSecret, "http://localhost:9000/callback", f.auth.URL, f.notes.URL, rdb)
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &browser{t, &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, srv.URL, mr}
}

func (b *browser) get(path string) (*http.Response, string) {
	b.t.Helper()
	resp, err := b.client.Get(b.base + path)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func (b *browser) post(path string, form url.Values) *http.Response {
	b.t.Helper()
	resp, err := b.client.PostForm(b.base+path, form)
	if err != nil {
		b.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// startLogin follows GET /login and returns the /authorize parameters.
func (b *browser) startLogin(f *fakes) url.Values {
	b.t.Helper()
	resp, _ := b.get("/login")
	if resp.StatusCode != http.StatusFound {
		b.t.Fatalf("/login: status %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	f.challenge = loc.Query().Get("code_challenge")
	return loc.Query()
}

func TestLoginRedirectsToAuthorize(t *testing.T) {
	f := newFakes(t)
	b := newBrowser(t, f)
	resp, _ := b.get("/login")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	q := loc.Query()

	if !strings.HasPrefix(loc.String(), f.auth.URL+"/authorize?") {
		t.Errorf("redirected to %q, want the auth server's /authorize", loc)
	}
	want := map[string]string{
		"response_type":         "code",
		"client_id":             "client1",
		"redirect_uri":          "http://localhost:9000/callback",
		"scope":                 "notes:read notes:write",
		"code_challenge_method": "S256",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if len(q.Get("state")) < 20 || len(q.Get("code_challenge")) != 43 {
		t.Errorf("state %q / code_challenge %q look wrong", q.Get("state"), q.Get("code_challenge"))
	}
	if q.Has("code_verifier") || q.Has("client_secret") {
		t.Error("the verifier or secret went through the browser")
	}
}

func TestFullLogin(t *testing.T) {
	f := newFakes(t)
	b := newBrowser(t, f)
	state := b.startLogin(f).Get("state")

	resp, body := b.get("/callback?code=good-code&state=" + url.QueryEscape(state))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback: status %d, Location %q, body %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}

	_, home := b.get("/")
	if !strings.Contains(home, "Buy milk") || !strings.Contains(home, "user-1") {
		t.Errorf("home page doesn't show alice's notes:\n%s", home)
	}
	if strings.Contains(home, "tok-alice") {
		t.Error("the access token reached the browser")
	}
	for _, c := range b.client.Jar.Cookies(mustParse(b.base)) {
		if strings.Contains(c.Value, "tok-alice") {
			t.Error("the access token is in a cookie")
		}
	}

	b.post("/notes", url.Values{"text": {"from the browser"}})
	if _, home = b.get("/"); !strings.Contains(home, "from the browser") {
		t.Error("added note not shown")
	}

	b.post("/logout", nil)
	if _, home = b.get("/"); !strings.Contains(home, "Log in with auth-server") {
		t.Error("still logged in after logout")
	}
}

func TestCallbackRejectsWrongState(t *testing.T) {
	f := newFakes(t)
	b := newBrowser(t, f)
	b.startLogin(f)

	resp, _ := b.get("/callback?code=good-code&state=attacker-state")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	if f.exchanges != 0 {
		t.Error("exchanged a code from a callback with the wrong state")
	}
}

func TestCallbackWithoutLogin(t *testing.T) {
	// A callback the browser never started (the CSRF case): no state saved.
	f := newFakes(t)
	b := newBrowser(t, f)
	if resp, _ := b.get("/callback?code=good-code&state=anything"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	if f.exchanges != 0 {
		t.Error("exchanged a code without a login in progress")
	}
}

func TestStateIsSingleUse(t *testing.T) {
	f := newFakes(t)
	b := newBrowser(t, f)
	cb := "/callback?code=good-code&state=" + url.QueryEscape(b.startLogin(f).Get("state"))

	b.get(cb)
	if resp, _ := b.get(cb); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("replayed callback: status %d, want 400", resp.StatusCode)
	}
}

func TestCallbackDenied(t *testing.T) {
	f := newFakes(t)
	b := newBrowser(t, f)
	state := b.startLogin(f).Get("state")

	_, body := b.get("/callback?error=access_denied&state=" + url.QueryEscape(state))
	if !strings.Contains(body, "access_denied") || !strings.Contains(body, "Log in with auth-server") {
		t.Errorf("denied login page:\n%s", body)
	}
	if f.exchanges != 0 {
		t.Error("tried to exchange after access_denied")
	}
}

func TestFailedExchange(t *testing.T) {
	f := newFakes(t)
	b := newBrowser(t, f)
	state := b.startLogin(f).Get("state")

	resp, body := b.get("/callback?code=stolen-code&state=" + url.QueryEscape(state))
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "authorization code") {
		t.Errorf("status %d, body %s", resp.StatusCode, body)
	}
	if _, home := b.get("/"); !strings.Contains(home, "Log in with auth-server") {
		t.Error("logged in despite a failed exchange")
	}
}

func mustParse(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}

// Logging out revokes the token at the auth server, not just here.
func TestLogoutRevokesToken(t *testing.T) {
	f := newFakes(t)
	b := newBrowser(t, f)
	b.get("/callback?code=good-code&state=" + url.QueryEscape(b.startLogin(f).Get("state")))

	b.post("/logout", nil)
	// It revokes the refresh token, which ends the whole login at the auth server.
	if len(f.revoked) != 1 || f.revoked[0] != "ref-1" {
		t.Errorf("revoked %v, want [ref-1] (sent as client1)", f.revoked)
	}
	if _, home := b.get("/"); !strings.Contains(home, "Log in with auth-server") {
		t.Error("still logged in after logout")
	}
}

// Redis holds only hashed session IDs, so a dump of it can't be used to take
// over anyone's session.
func TestSessionIDsAreHashedInRedis(t *testing.T) {
	f := newFakes(t)
	b := newBrowser(t, f)
	b.get("/callback?code=good-code&state=" + url.QueryEscape(b.startLogin(f).Get("state")))

	var id string
	for _, c := range b.client.Jar.Cookies(mustParse(b.base)) {
		if c.Name == "session" {
			id = c.Value
		}
	}
	keys := b.redis.Keys()
	if id == "" || len(keys) == 0 {
		t.Fatalf("session cookie %q, keys %v", id, keys)
	}
	for _, k := range keys {
		if strings.Contains(k, id) {
			t.Errorf("Redis key %q contains the raw session ID", k)
		}
	}
}

// Sessions live in Redis, so a restarted app (same Redis) keeps users logged in.
func TestSessionSurvivesRestart(t *testing.T) {
	f := newFakes(t)
	b := newBrowser(t, f)
	b.get("/callback?code=good-code&state=" + url.QueryEscape(b.startLogin(f).Get("state")))

	restarted := newBrowserWith(t, f, redis.NewClient(&redis.Options{Addr: b.redis.Addr()}), b.redis)
	restarted.client.Jar = b.client.Jar // same browser, same cookie
	if _, home := restarted.get("/"); !strings.Contains(home, "Buy milk") {
		t.Errorf("logged out after a restart:\n%s", home)
	}
}

// Without Redis there's nowhere to keep state and the verifier: stop at /login.
func TestRedisDown(t *testing.T) {
	f := newFakes(t)
	b := newBrowserWith(t, f, redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1}), nil)
	if resp, _ := b.get("/login"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", resp.StatusCode)
	}
}

// An expired access token is refreshed automatically, and the rotated pair is
// saved: the next refresh must use the new refresh token, not the old one.
func TestExpiredTokenIsRefreshed(t *testing.T) {
	f := newFakes(t)
	f.expiresIn = 1 // x/oauth2 treats this as already expired (10s early)
	b := newBrowser(t, f)
	b.get("/callback?code=good-code&state=" + url.QueryEscape(b.startLogin(f).Get("state")))

	if _, home := b.get("/"); !strings.Contains(home, "Buy milk") {
		t.Fatalf("not refreshed into a working token:\n%s", home)
	}
	if f.refreshes != 1 {
		t.Fatalf("refreshes = %d, want 1", f.refreshes)
	}
	// The second refresh succeeds only if the app saved ref-2 from the first.
	if _, home := b.get("/"); !strings.Contains(home, "Buy milk") || f.refreshes != 2 {
		t.Errorf("second refresh failed (refreshes = %d); the rotated refresh token wasn't saved", f.refreshes)
	}
}

// If the refresh is refused (revoked, reused, or past the login's lifetime),
// the user is logged out and asked to log in again.
func TestFailedRefreshLogsOut(t *testing.T) {
	f := newFakes(t)
	f.expiresIn = 1
	b := newBrowser(t, f)
	b.get("/callback?code=good-code&state=" + url.QueryEscape(b.startLogin(f).Get("state")))

	f.refresh = "something-else" // the auth server no longer accepts ours
	_, home := b.get("/")
	if !strings.Contains(home, "Log in again") || !strings.Contains(home, "Log in with auth-server") {
		t.Errorf("not logged out after a refused refresh:\n%s", home)
	}
}
