package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"tinyauth/internal/auth"
	"tinyauth/internal/hooks"
	"tinyauth/internal/linkdb"
	"tinyauth/internal/oauth"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"
)

func newTestHandlers(t *testing.T) (*Handlers, *auth.Auth) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	a := auth.NewAuth(types.AuthConfig{
		HMACSecret:        "12345678901234567890123456789012",
		EncryptionSecret:  "abcdefabcdefabcdefabcdefabcdefab",
		SessionCookieName: "session",
		SessionExpiry:     3600,
		CookieSecure:      false,
		Domain:            "example.com",
	})

	prov := &providers.Providers{Github: oauth.NewOAuth(oauth2.Config{}, false)}
	hk := hooks.NewHooks(types.HooksConfig{}, a, prov)
	db := linkdb.New(t.TempDir())

	h := NewHandlers(types.HandlersConfig{}, a, hk, prov, nil, db, []string{"admin@example.com"})
	return h, a
}

func createCookie(t *testing.T, a *auth.Auth, username, email string) *http.Cookie {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "http://example.com/", nil)
	err := a.CreateSessionCookie(c, &types.SessionCookie{
		Username:    username,
		Name:        username,
		Email:       email,
		Provider:    "github",
		OAuthGroups: "",
	})
	if err != nil {
		t.Fatalf("failed to create session cookie: %v", err)
	}
	res := w.Result()
	cookies := res.Cookies()
	if len(cookies) == 0 {
		t.Fatalf("no cookies set")
	}
	return cookies[0]
}

func TestLinkingFlow(t *testing.T) {
	h, a := newTestHandlers(t)

	// user1 gets a short code
	user1 := createCookie(t, a, "user1", "user1@example.com")
	req := httptest.NewRequest("POST", "/api/link/getshortlink", nil)
	req.AddCookie(user1)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	h.GetShortLinkHandler(c)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var codeResp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &codeResp); err != nil || codeResp.Code == "" {
		t.Fatalf("failed to get code: %v", err)
	}

	// user2 redeems the code
	user2 := createCookie(t, a, "user2", "user2@example.com")
	body := strings.NewReader("{\"code\":\"" + codeResp.Code + "\"}")
	req2 := httptest.NewRequest("POST", "/api/link/useshortlink", body)
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(user2)
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = req2
	h.UseShortLinkHandler(c2)
	if w2.Code != 200 {
		t.Fatalf("expected 200, got %d", w2.Code)
	}

	// user1 lists linked accounts
	req3 := httptest.NewRequest("GET", "/api/link/getlinkedaccounts", nil)
	req3.AddCookie(user1)
	w3 := httptest.NewRecorder()
	c3, _ := gin.CreateTestContext(w3)
	c3.Request = req3
	h.GetLinkedAccountsHandler(c3)
	if w3.Code != 200 {
		t.Fatalf("expected 200, got %d", w3.Code)
	}
	var listResp struct {
		Accounts []string `json:"accounts"`
	}
	if err := json.Unmarshal(w3.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to parse accounts: %v", err)
	}
	if len(listResp.Accounts) != 1 || listResp.Accounts[0] != "user2" {
		t.Fatalf("unexpected accounts: %v", listResp.Accounts)
	}

	// admin views links
	admin := createCookie(t, a, "admin", "admin@example.com")
	req4 := httptest.NewRequest("GET", "/api/link/adminshowlinkedaccounts?account=user1", nil)
	req4.AddCookie(admin)
	w4 := httptest.NewRecorder()
	c4, _ := gin.CreateTestContext(w4)
	c4.Request = req4
	h.AdminShowLinkedAccountsHandler(c4)
	if w4.Code != 200 {
		t.Fatalf("expected 200, got %d", w4.Code)
	}
	var adminResp struct {
		Accounts []string `json:"accounts"`
	}
	if err := json.Unmarshal(w4.Body.Bytes(), &adminResp); err != nil {
		t.Fatalf("failed to parse admin accounts: %v", err)
	}
	if len(adminResp.Accounts) != 1 || adminResp.Accounts[0] != "user2" {
		t.Fatalf("unexpected admin accounts: %v", adminResp.Accounts)
	}

	// admin unlinks
	unlinkBody := strings.NewReader("{\"a\":\"user1\",\"b\":\"user2\"}")
	req5 := httptest.NewRequest("DELETE", "/api/link/adminunlinkaccounts", unlinkBody)
	req5.Header.Set("Content-Type", "application/json")
	req5.AddCookie(admin)
	w5 := httptest.NewRecorder()
	c5, _ := gin.CreateTestContext(w5)
	c5.Request = req5
	h.AdminUnlinkAccountsHandler(c5)
	if w5.Code != 200 {
		t.Fatalf("expected 200, got %d", w5.Code)
	}

	// user1 now has no links
	req6 := httptest.NewRequest("GET", "/api/link/getlinkedaccounts", nil)
	req6.AddCookie(user1)
	w6 := httptest.NewRecorder()
	c6, _ := gin.CreateTestContext(w6)
	c6.Request = req6
	h.GetLinkedAccountsHandler(c6)
	var afterResp struct {
		Accounts []string `json:"accounts"`
	}
	json.Unmarshal(w6.Body.Bytes(), &afterResp)
	if len(afterResp.Accounts) != 0 {
		t.Fatalf("expected no accounts, got %v", afterResp.Accounts)
	}
}

func TestExpiredCode(t *testing.T) {
	h, a := newTestHandlers(t)

	user1 := createCookie(t, a, "user1", "user1@example.com")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("POST", "/api/link/getshortlink", nil)
	req.AddCookie(user1)
	c.Request = req
	h.GetShortLinkHandler(c)
	var resp struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)

	// expire the code
	h.codeMu.Lock()
	entry := h.codes[resp.Code]
	entry.Expires = time.Now().Add(-time.Hour)
	h.codes[resp.Code] = entry
	h.codeMu.Unlock()

	// attempt to redeem
	user2 := createCookie(t, a, "user2", "user2@example.com")
	body := strings.NewReader("{\"code\":\"" + resp.Code + "\"}")
	req2 := httptest.NewRequest("POST", "/api/link/useshortlink", body)
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(user2)
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = req2
	h.UseShortLinkHandler(c2)
	if w2.Code != 400 {
		t.Fatalf("expected 400 for expired code, got %d", w2.Code)
	}
}
