package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

// --- Types ---

type Server struct {
	router *gin.Engine
	db     *sql.DB
}

type User struct {
	email  string
	login  string
	token  string
	admin  bool
}

type CodeVerifier struct {
	mutex  sync.RWMutex
	store  map[string]string
}

type Users struct {
	mutex  sync.RWMutex
	store  map[string]User
}

// --- Static Global Variables ---

var (
	clientID     = os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURL  = os.Getenv("REDIRECT_URL")
	bindAddress  = os.Getenv("BIND_ADDRESS")
	jwtSecret    = []byte(os.Getenv("JWT_SECRET"))
)

// --- Dynamic Global Variables ---

var (
	codeVerifier = CodeVerifier {
		mutex: sync.RWMutex{},
		store: map[string]string{},
	}
	users        = Users {
		mutex: sync.RWMutex{},
		store: map[string]User{},
	}
)

// --- Helpers ---

func (s *Server) getUser(email string) (User, error) {
	users.mutex.RLock()
	user, ok := users.store[email]
	users.mutex.RUnlock()
	if !ok {
		user = User {
			email: "",
			token: "",
			login: "",
			admin: false,
		}

		// Query single row
		row := s.db.QueryRow("SELECT token, login, admin FROM users WHERE email = ?", email)
		err := row.Scan(&user.token, &user.login, &user.admin)
		if err == nil {
			user.email = email
		} else if err == sql.ErrNoRows {
			// add email record to db
			_, err := s.db.Exec(`INSERT OR REPLACE INTO users (email, token, login, admin) VALUES (?, ?, ?, ?)`, email, user.token, user.login, user.admin)
			if err == nil {
				user.email = email
			} else {
				log.Println("[WARN] failed to create record for user with ID:", email, ", error:", err.Error())
			}
		}

		if user.email != "" {
			users.mutex.Lock()
			users.store[email] = user
			users.mutex.Unlock()
		}
	}

	return user, nil
}

func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func codeChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func generateJWT(email string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(time.Minute * 30).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func splitToken(token string) []string {
	return strings.Split(token, ".")
}

func extendedLogFormatter() gin.LogFormatter {
	return func(param gin.LogFormatterParams) string {
		logged := ""
		if m, ok := param.Keys["logged"]; ok {
			fields := m.(map[string]any)
			for k, v := range fields {
				logged += fmt.Sprintf(" | %s=%v", k, v)
			}
		}

		return fmt.Sprintf(
			"[GIN] %s | %3d | %13.3fms | %15s | %-7s | \"%s\"%s\n",
			param.TimeStamp.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
			param.StatusCode,
			float64(param.Latency)/1e6,
			param.ClientIP,
			param.Method,
			param.Path,
			logged)
	}
}

func logUTC(v ...any) {
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	log.Println("[GIN]", ts, fmt.Sprint(v...))
}

func (s *Server) ensureUserMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// get email from claims
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		token, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if !token.Valid {
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}
		email := token.Claims.(jwt.MapClaims)["email"].(string)
		addLoggedKeyValue(c, "identity", email) // reported as identity instead of email

		// get records from cache
		user, err := s.getUser(email)
		if err != nil || user.login == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}

		c.Set("email", email)
		c.Set("login", user.login)
		c.Set("token", user.token)
		c.Set("admin", user.admin)

		addLoggedKeyValue(c, "identity", email)

		c.Next()
	}
}

func (s *Server) ensureAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		adminAny, ok := c.Get("admin")
		if !ok {
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}

		if admin, ok := adminAny.(bool); !ok || !admin {
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}

		c.Next()
	}
}

func addLoggedKeyValue(c *gin.Context, key string, value string) {
	m, exists := c.Get("logged")
	if !exists {
		m = map[string]any{}    // create a new one
		c.Set("logged", m)  // store it
	}

	// Add new field
	m.(map[string]any)[key] = value
}

func getString(c *gin.Context, key string) (string, error) {
	valueAny, ok := c.Get(key)
	if !ok {
		return "", errors.New("key not found: " + key)
	}

	if value, ok := valueAny.(string); ok {
		return value, nil
	}

	return "", errors.New("value cast failed: " + key)
}

func getBool(c *gin.Context, key string) (bool, error) {
	valueAny, ok := c.Get(key)
	if !ok {
		return false, errors.New("key not found: " + key)
	}

	if value, ok := valueAny.(bool); ok {
		return value, nil
	}

	return false, errors.New("value cast failed: " + key)
}

func getUser(c *gin.Context) (User, error) {
	user := User {
		email: "",
		token: "",
		login: "",
		admin: false,
	}

	email, err := getString(c, "email");
	if err != nil {
		return user, err
	}

	login, err := getString(c, "login");
	if err != nil {
		return user, err
	}

	admin, err := getBool(c, "admin");
	if err != nil {
		return user, err
	}

	user.email = email
	user.login = login
	user.admin = admin
	return user, nil
}

// --- Routes /open ---

func (s *Server) openStatusHandler(c *gin.Context) {
	c.JSON(200, gin.H{ "status": "ok"})
}

func (s *Server) openOidcLoginHandler(c *gin.Context) {
	forceConsent := c.Query("force_consent")
	verifier, _ := generateCodeVerifier()
	challenge := codeChallengeS256(verifier)
	state := fmt.Sprintf("%d", time.Now().UnixNano())

	codeVerifier.mutex.Lock()
	codeVerifier.store[state] = verifier
	codeVerifier.mutex.Unlock()

	authURL, _ := url.Parse("https://accounts.google.com/o/oauth2/v2/auth")
	params := url.Values{}
	params.Add("client_id", clientID)
	params.Add("response_type", "code")
	params.Add("scope", "openid email")
	params.Add("redirect_uri", redirectURL)
	params.Add("state", state)
	params.Add("code_challenge", challenge)
	params.Add("code_challenge_method", "S256")
	params.Add("access_type", "offline")
	if forceConsent == "1" {
		params.Add("prompt", "consent")
	}
	authURL.RawQuery = params.Encode()

	c.Redirect(302, authURL.String())
}

func (s *Server) openOidcCallbackHandler(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	codeVerifier.mutex.RLock()
	verifier, ok := codeVerifier.store[state]
	codeVerifier.mutex.RUnlock()
	if !ok {
		c.JSON(400, gin.H{"error": "invalid state"})
		return
	}
	codeVerifier.mutex.Lock()
	delete(codeVerifier.store, state)
	codeVerifier.mutex.Unlock()

	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code":          {code},
		"code_verifier": {verifier},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURL},
	})
	if err != nil {
		c.JSON(500, gin.H{"error": "token exchange failed"})
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	var tokenResp struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		c.JSON(500, gin.H{"error": "failed to parse token response"})
		return
	}

	// Decode email claim from OIDC token
	parts := splitToken(tokenResp.IDToken)
	if len(parts) < 2 {
		c.JSON(500, gin.H{"error": "invalid ID token"})
		return
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to decode ID token"})
		return
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		c.JSON(500, gin.H{"error": "failed to parse ID token payload"})
		return
	}

	// get the user record
	user, err := s.getUser(claims.Email)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to get identity"})
		return
	}

	// store the refresh token if one was returned
	if tokenResp.RefreshToken != "" {
		_, err = s.db.Exec(`INSERT OR REPLACE INTO users (email, token, login, admin) VALUES (?, ?, ?, ?)`, user.email, tokenResp.RefreshToken, user.login, user.admin)
		if err == nil {
			user.token = tokenResp.RefreshToken
		}
	}

	if user.token == "" {
		// No refresh token available -> signal to client by not giving the JWT
		c.JSON(200, gin.H{ "status": "need_consent", "token": ""})
		return
	}

	jwtToken, _ := generateJWT(user.email)
	c.JSON(200, gin.H { "status": "ok", "token": jwtToken, })
}

// --- Routes /user ---

func (s *Server) userOidcRefreshHandler(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(401, gin.H{"error": "missing Authorization header"})
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if !token.Valid {
		c.JSON(401, gin.H{"error": "invalid token"})
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	email := claims["email"].(string)
	user, err := s.getUser(email)
	if err != nil {
		c.JSON(401, gin.H{"error": "failed to get identity"})
		return
	}

	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"refresh_token": {user.token},
		"grant_type":    {"refresh_token"},
	})
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to refresh token"})
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	var refreshResp struct{ IDToken string `json:"id_token"` }
	json.Unmarshal(body, &refreshResp)

	newJWT, _ := generateJWT(user.email)
	c.JSON(200, gin.H{"token": newJWT})
}

func (s *Server) userInfoHandler(c *gin.Context) {
	user, err := getUser(c);
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H {
		"message": "user data",
		"email": user.email,
		"login": user.login,
		"admin": user.admin,
	})
}

// --- Startup ---

func (s *Server) prepareRouter() {
	s.router.Use(gin.LoggerWithFormatter(extendedLogFormatter()))
	s.router.Use(gin.Recovery())

	open := s.router.Group("/open")
	open.GET("/status", s.openStatusHandler)
	open.GET("/oidc/login", s.openOidcLoginHandler)
	open.GET("/oidc/callback", s.openOidcCallbackHandler)

	user := s.router.Group("/user")
	user.Use(s.ensureUserMiddleware())
	user.GET("/info", s.userInfoHandler)
	user.GET("/oidc/refresh", s.userOidcRefreshHandler)

	admin := s.router.Group("/admin")
	admin.Use(s.ensureUserMiddleware())
	admin.Use(s.ensureAdminMiddleware())
	admin.GET("/info", s.userInfoHandler)

	s.router.SetTrustedProxies([]string{"127.0.0.1", "::1"})
}

func main() {
	if clientID == "" || len(jwtSecret) == 0 {
		log.Fatal("GOOGLE_CLIENT_ID and JWT_SECRET must be set")
	}

	db, err := sql.Open("sqlite3", "./data/backuptool.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Ensure the directory exists
	if err := os.MkdirAll("./data", os.ModePerm); err != nil {
		log.Fatalf("failed to create data directory: %v", err)
	}

	// Create tables
	_, err = db.Exec(
		`
		CREATE TABLE IF NOT EXISTS users (
			email TEXT PRIMARY KEY,
			token TEXT,
			login TEXT,
			admin BOOLEAN NOT NULL DEFAULT 0
		);
		`)
	if err != nil {
		log.Fatal(err)
	}

	s := &Server{router: gin.New(), db: db}
	s.prepareRouter()
	log.SetFlags(0)
	logUTC("| Starting BIND_ADDRESS=", bindAddress)
	s.router.Run(bindAddress)
}

