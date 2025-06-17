package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/BaGreal2/zveri-server/internal/middleware"
	"github.com/BaGreal2/zveri-server/internal/model"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func RegisterHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req model.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		var existingID int
		if err := db.QueryRow("SELECT id FROM users WHERE email = $1", req.Email).Scan(&existingID); err == nil {
			http.Error(w, "Email already exists", http.StatusConflict)
			return
		}
		if err := db.QueryRow("SELECT id FROM users WHERE username = $1", req.Username).Scan(&existingID); err == nil {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		_, err := db.Exec("INSERT INTO users (email, username, password) VALUES ($1, $2, $3)", req.Email, req.Username, string(hashedPassword))
		if err != nil {
			http.Error(w, fmt.Sprintf("Error creating user: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
	}
}

func LoginHandler(db *sql.DB, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
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
		query := "SELECT id, email, username, password, created_at FROM users WHERE email = $1 OR username = $2"
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

func MeHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value(middleware.UserIDKey).(int)

		var user model.User
		err := db.QueryRow(`
			SELECT id, email, username, bio, avatar_url, created_at
			FROM users WHERE id = $1`, userID).
			Scan(&user.ID, &user.Email, &user.Username, &user.Bio, &user.AvatarURL, &user.CreatedAt)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(user)
	}
}

func UpdateProfileHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		userID := r.Context().Value(middleware.UserIDKey).(int)

		var req struct {
			Email     string  `json:"email"`
			Username  string  `json:"username"`
			Bio       *string `json:"bio"`
			AvatarURL *string `json:"avatar_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		_, err := db.Exec(`
			UPDATE users SET email = $1, username = $2, bio = $3, avatar_url = $4
			WHERE id = $5`,
			req.Email, req.Username, req.Bio, req.AvatarURL, userID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Could not update profile: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Profile updated"})
	}
}

func DeleteProfileHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		userID := r.Context().Value(middleware.UserIDKey).(int)

		_, err := db.Exec("DELETE FROM users WHERE id = $1", userID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Could not delete user: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "User deleted"})
	}
}
