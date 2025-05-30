package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

type User struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

func main() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Warning: .env file not found, relying on system environment variables")
	}

	var err error
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		panic(fmt.Sprintf("[ERROR] Unable to establish connection with a db: %v", err))
	}
	fmt.Println("[LOG] Database connection established")
	defer db.Close()

	createUsersTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL UNIQUE,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(createUsersTableSQL)
	if err != nil {
		panic(fmt.Sprintf("[ERROR] Unable to create users table: %v", err))
	}

	tmdbAPIBearer := os.Getenv("TMDB_API_BEARER")
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		panic("[ERROR] JWT_SECRET environment variable not set")
	}
	if tmdbAPIBearer == "" {
		panic("[ERROR] TMDB_API_BEARER environment variable not set")
	}

	http.HandleFunc("/register", withCORS(registerHandler))
	http.HandleFunc("/login", withCORS(loginHandler))
	http.HandleFunc("/me", withCORS(meHandler))

	http.HandleFunc("/series/", withCORS(authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/series/")
		parts := strings.Split(path, "/")

		switch {
		case len(parts) == 2 && parts[1] == "videos":
			seriesVideosHandler(tmdbAPIBearer)(w, r)

		case len(parts) == 1 && parts[0] != "":
			seriesDetailsHandler(tmdbAPIBearer)(w, r)

		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	})))
	http.HandleFunc("/series/top_rated", withCORS(authMiddleware(topRatedHandler(tmdbAPIBearer))))

	println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}

func proxyToTMDB(w http.ResponseWriter, r *http.Request, tmdbURL, bearerToken string) {
	// Build new request
	req, err := http.NewRequest("GET", tmdbURL, nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to fetch TMDB data", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy status and body
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func seriesDetailsHandler(apiBearer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/series/")
		if id == "" {
			http.Error(w, "Series ID missing", http.StatusBadRequest)
			return
		}

		tmdbURL := fmt.Sprintf(
			"https://api.themoviedb.org/3/tv/%s?language=en-US",
			id,
		)
		proxyToTMDB(w, r, tmdbURL, apiBearer)
	}
}

func seriesVideosHandler(apiBearer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/series/"), "/")
		if len(parts) != 2 || parts[1] != "videos" {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		id := parts[0]
		tmdbURL := fmt.Sprintf(
			"https://api.themoviedb.org/3/tv/%s/videos?language=en-US",
			id,
		)
		proxyToTMDB(w, r, tmdbURL, apiBearer)
	}
}

func topRatedHandler(apiBearer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if page == "" {
			page = "1"
		}

		tmdbURL := fmt.Sprintf(
			"https://api.themoviedb.org/3/tv/top_rated?language=en-US&page=%s",
			page,
		)

		proxyToTMDB(w, r, tmdbURL, apiBearer)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var existingID int
	err = db.QueryRow("SELECT id FROM users WHERE email = ?", req.Email).Scan(&existingID)
	if err == nil {
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	}
	err = db.QueryRow("SELECT id FROM users WHERE username = ?", req.Username).Scan(&existingID)
	if err == nil {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		fmt.Printf("Error hashing password: %v\n", err)
		return
	}

	_, err = db.Exec("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", req.Email, req.Username, string(hashedPassword))
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		fmt.Printf("Error inserting user into database: %v\n", err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var user User
	var storedPassword string
	err = db.QueryRow("SELECT id, email, username, password, created_at FROM users WHERE email = ?", req.Identifier).
		Scan(&user.ID, &user.Email, &user.Username, &storedPassword, &user.CreatedAt)
	if err != nil {
		err = db.QueryRow("SELECT id, email, username, password, created_at FROM users WHERE username = ?", req.Identifier).Scan(&user.ID, &user.Email, &user.Username, &storedPassword, &user.CreatedAt)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(req.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": user.ID,
		"exp":    time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":  user,
		"token": tokenString,
	})
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := authHeader[len("Bearer "):]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	userID := int(claims["userID"].(float64))

	var user User
	err = db.QueryRow("SELECT id, email, created_at FROM users WHERE id = ?", userID).
		Scan(&user.ID, &user.Email, &user.CreatedAt)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(user)
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin) // don't use "*" with credentials
		}
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true") // needed if you send cookies/auth headers

		// Preflight response
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}
