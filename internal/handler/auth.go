package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/BaGreal2/zveri-server/internal/middleware"
	"github.com/BaGreal2/zveri-server/internal/model"

	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v4"
	"time"
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

func MeHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value(middleware.UserIDKey).(int)

		var user model.User
		err := db.QueryRow(`
			SELECT id, email, username, bio, avatar_url, created_at
			FROM users WHERE id = ?`, userID).
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
			UPDATE users SET email = ?, username = ?, bio = ?, avatar_url = ?
			WHERE id = ?`,
			req.Email, req.Username, req.Bio, req.AvatarURL, userID)
		if err != nil {
			http.Error(w, "Could not update profile", http.StatusInternalServerError)
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

		_, err := db.Exec("DELETE FROM users WHERE id = ?", userID)
		if err != nil {
			http.Error(w, "Could not delete user", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "User deleted"})
	}
}
