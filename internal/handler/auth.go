package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/BaGreal2/zveri-server/internal/model"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func RegisterHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req model.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		var existingID int
		if err := db.QueryRow("SELECT id FROM users WHERE email = ?", req.Email).Scan(&existingID); err == nil {
			http.Error(w, "Email already exists", http.StatusConflict)
			return
		}
		if err := db.QueryRow("SELECT id FROM users WHERE username = ?", req.Username).Scan(&existingID); err == nil {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		_, err := db.Exec("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", req.Email, req.Username, string(hashedPassword))
		if err != nil {
			http.Error(w, "Error creating user", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
	}
}

func LoginHandler(db *sql.DB, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req model.LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		var user model.User
		var hashed string
		query := "SELECT id, email, username, password, created_at FROM users WHERE email = ? OR username = ?"
		err := db.QueryRow(query, req.Identifier, req.Identifier).Scan(&user.ID, &user.Email, &user.Username, &hashed, &user.CreatedAt)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(hashed), []byte(req.Password)) != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"userID": user.ID,
			"exp":    time.Now().Add(24 * time.Hour).Unix(),
		})

		tokenString, _ := token.SignedString([]byte(jwtSecret))

		json.NewEncoder(w).Encode(map[string]interface{}{
			"user":  user,
			"token": tokenString,
		})
	}
}

func MeHandler(db *sql.DB, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(authHeader[len("Bearer "):], func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		userID := int(claims["userID"].(float64))

		var user model.User
		if err := db.QueryRow("SELECT id, email, created_at FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Email, &user.CreatedAt); err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(user)
	}
}
