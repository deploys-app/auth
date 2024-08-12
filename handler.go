package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/acoshift/pgsql/pgctx"
)

type RedirectHandler struct {
	OAuth2ClientID string
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

	ctx := r.Context()

	oauth2Client, err := getOAuth2Client(ctx, clientID)
	if errors.Is(err, ErrOAuth2ClientNotFound) {
		http.Error(w, "Invalid client_id parameter", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	pattern := oauth2Client.RedirectURI
	pattern = strings.ReplaceAll(pattern, ".", `\.`)
	pattern = strings.ReplaceAll(pattern, "/", `\/`)
	pattern = strings.ReplaceAll(pattern, "*", `.*`)
	re := regexp.MustCompile(`^` + pattern + `$`)
	if !re.MatchString(callbackURL) {
		http.Error(w, "Invalid redirect_uri parameter", http.StatusBadRequest)
		return
	}

	state := generateState()
	sessionID := generateSessionID()

	err = saveSession(ctx, sessionID, &Session{
		ClientID:      oauth2Client.ID,
		State:         state,
		CallbackState: callbackState,
		CallbackURL:   callbackURL,
	})
	if err != nil {
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
	params.Set("redirect_uri", "https://auth.deploys.app/callback")
	params.Set("scope", "https://www.googleapis.com/auth/userinfo.email")
	params.Set("access_type", "online")
	params.Set("prompt", "consent")
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

type CallbackHandler struct {
	OAuth2ClientID     string
	OAuth2ClientSecret string
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
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if session.State != state {
		http.Error(w, "Mismatch state", http.StatusBadRequest)
		return
	}

	// exchange token
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code", code)
	params.Set("redirect_uri", "https://auth.deploys.app/callback")
	params.Set("client_id", h.OAuth2ClientID)
	params.Set("client_secret", h.OAuth2ClientSecret)

	resp, err := http.Post("https://oauth2.googleapis.com/token", "application/x-www-form-urlencoded", strings.NewReader(params.Encode()))
	if err != nil {
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
			failResponse(w, r)
			return
		}
		idToken = respBody.IDToken
	}
	email, err := extractEmailFromIDToken(idToken)
	if err != nil {
		failResponse(w, r)
		return
	}

	returnCode := generateCode()
	err = insertOAuth2Code(ctx, session.ClientID, code, email)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	callback, err := url.Parse(session.CallbackURL)
	if err != nil {
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
		apiErrorResponse(w, http.StatusInternalServerError, "internal server error")
		return
	}
	apiOKResponse(w, nil)
}

type TokenHandler struct{}

func (TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientID := r.PostFormValue("client_id")
	if clientID == "" {
		http.Error(w, "Missing client_id parameter", http.StatusBadRequest)
		return
	}
	clientSecret := r.PostFormValue("client_secret")
	if clientSecret == "" {
		http.Error(w, "Missing client_secret parameter", http.StatusBadRequest)
		return
	}
	code := r.PostFormValue("code")
	if code == "" {
		http.Error(w, "Missing code parameter", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	oauth2Client, err := getOAuth2Client(ctx, clientID)
	if errors.Is(err, ErrOAuth2ClientNotFound) {
		http.Error(w, "Invalid client_id parameter", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if oauth2Client.Secret != clientSecret {
		http.Error(w, "Invalid client_secret parameter", http.StatusBadRequest)
		return
	}

	email, err := getOAuth2EmailFromCode(ctx, clientID, code)
	if errors.Is(err, ErrOAuth2CodeNotFound) {
		http.Error(w, "Invalid code parameter", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	token := generateToken()
	hashedToken := hashToken(token)
	err = insertToken(ctx, hashedToken, email)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var resp struct {
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	resp.TokenType = "bearer"
	resp.RefreshToken = token

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(resp)
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
