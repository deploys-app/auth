package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/acoshift/pgsql/pgctx"
)

type RedirectHandler struct {
	OAuth2ClientID string
	BaseURL        string
}

func (h RedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	if clientID == "" {
		http.Error(w, "Missing client_id parameter", http.StatusBadRequest)
		return
	}

	callbackState := r.FormValue("state")
	if callbackState == "" {
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	callbackURL := r.FormValue("redirect_uri")
	if callbackURL == "" {
		http.Error(w, "Missing redirect_uri parameter", http.StatusBadRequest)
		return
	}
	if !isURL(callbackURL) {
		http.Error(w, "Invalid redirect_uri parameter", http.StatusBadRequest)
		return
	}

	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	if codeChallenge != "" && codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}
	resource := r.FormValue("resource")

	ctx := r.Context()

	oauth2Client, err := getOAuth2Client(ctx, clientID)
	if errors.Is(err, ErrOAuth2ClientNotFound) {
		slog.WarnContext(ctx, "redirect: invalid client_id", "client_id", clientID)
		http.Error(w, "Invalid client_id parameter", http.StatusBadRequest)
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "redirect: get oauth2 client", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Public clients (CLI / MCP) must use PKCE.
	if oauth2Client.IsPublic() {
		if codeChallenge == "" {
			http.Error(w, "Missing code_challenge parameter", http.StatusBadRequest)
			return
		}
		if codeChallengeMethod != "S256" {
			http.Error(w, "Unsupported code_challenge_method parameter", http.StatusBadRequest)
			return
		}
	}

	// The redirect URI must match one of the client's registered redirect_uris —
	// an exact URI, or an operator-provisioned "regexp:" pattern. Applies to every
	// client type now that the legacy single-pattern redirect_uri column is gone.
	if !redirectURIAllowed(oauth2Client.RedirectURIs, callbackURL) {
		slog.WarnContext(ctx, "redirect: invalid redirect_uri", "client_id", clientID, "redirect_uri", callbackURL)
		http.Error(w, "Invalid redirect_uri parameter", http.StatusBadRequest)
		return
	}

	state := generateState()
	sessionID := generateSessionID()

	err = saveSession(ctx, sessionID, &Session{
		ClientID:            oauth2Client.ID,
		State:               state,
		CallbackState:       callbackState,
		CallbackURL:         callbackURL,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Resource:            resource,
	})
	if err != nil {
		slog.ErrorContext(ctx, "redirect: save session", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "s",
		Value:    sessionID,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", h.OAuth2ClientID)
	params.Set("redirect_uri", h.BaseURL+"/callback")
	params.Set("scope", "https://www.googleapis.com/auth/userinfo.email")
	params.Set("access_type", "online")
	// select_account shows Google's account chooser but skips the consent screen
	// for users who already granted access — one screen on returning logins
	// instead of two. We only read the email scope with access_type=online, so we
	// never needed the forced re-consent that prompt=consent implies.
	params.Set("prompt", "select_account")
	params.Set("state", state)

	target := "https://accounts.google.com/o/oauth2/auth?" + params.Encode()
	http.Redirect(w, r, target, http.StatusFound)
}

func isURL(s string) bool {
	p, err := url.Parse(s)
	if err != nil {
		return false
	}
	return (p.Scheme == "http" || p.Scheme == "https") && p.Host != ""
}

// googleTokenURL is Google's OAuth2 token endpoint. It is a variable so tests
// can point the callback exchange at a stub server.
var googleTokenURL = "https://oauth2.googleapis.com/token"

type CallbackHandler struct {
	OAuth2ClientID     string
	OAuth2ClientSecret string
	BaseURL            string
}

func (h CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state == "" {
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Missing code parameter", http.StatusBadRequest)
		return
	}

	var sessionID string
	{
		c, _ := r.Cookie("s")
		if c != nil {
			sessionID = c.Value
		}
	}
	if sessionID == "" {
		http.Error(w, "Missing session cookie", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	session, err := getSession(ctx, sessionID)
	if errors.Is(err, ErrOAuth2SessionNotFound) {
		http.Error(w, "Invalid session cookie", http.StatusBadRequest)
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "callback: get session", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if session.State != state {
		slog.WarnContext(ctx, "callback: mismatch state", "state", state, "session_state", session.State)
		http.Error(w, "Mismatch state", http.StatusBadRequest)
		return
	}

	// exchange token
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code", code)
	params.Set("redirect_uri", h.BaseURL+"/callback")
	params.Set("client_id", h.OAuth2ClientID)
	params.Set("client_secret", h.OAuth2ClientSecret)

	resp, err := http.Post(googleTokenURL, "application/x-www-form-urlencoded", strings.NewReader(params.Encode()))
	if err != nil {
		slog.WarnContext(ctx, "callback: exchange token", "error", err)
		failResponse(w, r)
		return
	}
	defer resp.Body.Close()
	defer io.Copy(io.Discard, resp.Body)

	var idToken string
	{
		var respBody struct {
			IDToken string `json:"id_token"`
		}
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		if err != nil {
			slog.ErrorContext(ctx, "callback: decode google response", "error", err)
			failResponse(w, r)
			return
		}
		idToken = respBody.IDToken
	}
	email, err := extractEmailFromIDToken(idToken)
	if err != nil {
		slog.ErrorContext(ctx, "callback: extract id token", "error", err)
		failResponse(w, r)
		return
	}

	returnCode := generateCode()
	err = insertOAuth2Code(ctx, session.ClientID, returnCode, &OAuth2Code{
		Email:               email,
		CodeChallenge:       session.CodeChallenge,
		CodeChallengeMethod: session.CodeChallengeMethod,
		RedirectURI:         session.CallbackURL,
		Resource:            session.Resource,
	})
	if err != nil {
		slog.ErrorContext(ctx, "callback: insert oauth2 code", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	callback, err := url.Parse(session.CallbackURL)
	if err != nil {
		slog.ErrorContext(ctx, "callback: parse callback url", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	{
		q := callback.Query()
		q.Set("state", session.CallbackState)
		q.Set("code", returnCode)
		callback.RawQuery = q.Encode()
	}
	http.Redirect(w, r, callback.String(), http.StatusFound)
}

func failResponse(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://www.deploys.app", http.StatusFound)
}

func extractEmailFromIDToken(idToken string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		slog.Error("invalid id_token", "id_token", idToken)
		return "", errors.New("invalid id_token")
	}
	payload, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	var tokenInfo struct {
		Email string `json:"email"`
	}
	err = json.Unmarshal(payload, &tokenInfo)
	if err != nil {
		return "", err
	}
	return tokenInfo.Email, nil
}

type RevokeHandler struct{}

func (RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	callback := r.FormValue("callback")
	if callback == "" {
		callback = "https://www.deploys.app/"
	}
	if token == "" {
		http.Redirect(w, r, callback, http.StatusFound)
		return
	}

	ctx := r.Context()
	hashedToken := hashToken(token)
	_, err := pgctx.Exec(ctx, `delete from user_tokens where token = $1`, hashedToken)
	if err != nil {
		slog.ErrorContext(ctx, "revoke: delete token", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, callback, http.StatusFound)
}

type RevokePostHandler struct{}

func (RevokePostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var reqBody struct {
		Token string `json:"token"`
	}
	err := json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		apiErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	token := reqBody.Token
	if token == "" {
		apiOKResponse(w, nil)
		return
	}

	ctx := r.Context()
	hashedToken := hashToken(token)
	_, err = pgctx.Exec(ctx, `delete from user_tokens where token = $1`, hashedToken)
	if err != nil {
		slog.ErrorContext(ctx, "revoke: delete token", "error", err)
		apiErrorResponse(w, http.StatusInternalServerError, "internal server error")
		return
	}
	apiOKResponse(w, nil)
}

type TokenHandler struct{}

func (TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	grantType := r.PostFormValue("grant_type")
	if grantType != "" && grantType != "authorization_code" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	clientID := r.PostFormValue("client_id")
	if clientID == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing client_id")
		return
	}
	code := r.PostFormValue("code")
	if code == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing code")
		return
	}

	ctx := r.Context()
	oauth2Client, err := getOAuth2Client(ctx, clientID)
	if errors.Is(err, ErrOAuth2ClientNotFound) {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client_id")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "token: get oauth2 client", "error", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	// Authenticate the client. Public clients (CLI / MCP) rely on PKCE instead
	// of a secret; confidential clients must present client_secret.
	if oauth2Client.IsPublic() {
		if r.PostFormValue("code_verifier") == "" {
			oauthError(w, http.StatusBadRequest, "invalid_request", "missing code_verifier")
			return
		}
	} else {
		clientSecret := r.PostFormValue("client_secret")
		if clientSecret == "" {
			oauthError(w, http.StatusBadRequest, "invalid_request", "missing client_secret")
			return
		}
		if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(oauth2Client.Secret)) != 1 {
			oauthError(w, http.StatusUnauthorized, "invalid_client", "invalid client_secret")
			return
		}
	}

	oauth2Code, err := getOAuth2Code(ctx, clientID, code)
	if errors.Is(err, ErrOAuth2CodeNotFound) {
		slog.WarnContext(ctx, "token: invalid code", "client_id", clientID)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired code")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "token: get oauth2 code", "error", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	// PKCE: verify whenever the code was issued with a challenge.
	if oauth2Code.CodeChallenge != "" {
		verifier := r.PostFormValue("code_verifier")
		if !verifyPKCE(verifier, oauth2Code.CodeChallenge, oauth2Code.CodeChallengeMethod) {
			slog.WarnContext(ctx, "token: pkce verification failed", "client_id", clientID)
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	}

	// For public clients the redirect_uri presented here must match the one the
	// code was bound to at the authorize step (RFC 6749 §4.1.3).
	if oauth2Client.IsPublic() && oauth2Code.RedirectURI != "" {
		if r.PostFormValue("redirect_uri") != oauth2Code.RedirectURI {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
			return
		}
	}

	token := generateToken()
	hashedToken := hashToken(token)
	err = insertToken(ctx, hashedToken, oauth2Code.Email)
	if err != nil {
		slog.ErrorContext(ctx, "token: insert token", "error", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	var resp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
	resp.AccessToken = token
	resp.TokenType = "Bearer"
	resp.ExpiresIn = tokenTTLSeconds
	resp.RefreshToken = token // retained for backward compatibility with the existing web client

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	json.NewEncoder(w).Encode(body)
}

type apiResult struct {
	OK     bool      `json:"ok"`
	Result any       `json:"result,omitempty"`
	Error  *apiError `json:"error,omitempty"`
}

type apiError struct {
	Message string `json:"message"`
}

func apiOKResponse(w http.ResponseWriter, result any) {
	if result == nil {
		result = struct{}{}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(apiResult{
		OK:     true,
		Result: result,
	})
}

func apiErrorResponse(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(apiResult{
		OK: false,
		Error: &apiError{
			Message: message,
		},
	})
}
