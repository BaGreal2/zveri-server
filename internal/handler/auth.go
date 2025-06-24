package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/BaGreal2/zveri-server/internal/config"
	"github.com/BaGreal2/zveri-server/internal/middleware"
	"github.com/BaGreal2/zveri-server/internal/model"
	"github.com/BaGreal2/zveri-server/internal/tmdb"
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

func topGenres(count map[string]int, n int) []string {
	type kv struct {
		Key string
		Val int
	}
	arr := make([]kv, 0, len(count))
	for k, v := range count {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].Val > arr[j].Val })
	limit := n
	if len(arr) < n {
		limit = len(arr)
	}
	out := make([]string, limit)
	for i := 0; i < limit; i++ {
		out[i] = arr[i].Key
	}
	return out
}

func MeHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value(middleware.UserIDKey).(int)

		var user model.User
		err := db.QueryRow(`
            SELECT id, email, username, bio, avatar_url, background_url, created_at
            FROM users WHERE id = $1`, userID).
			Scan(&user.ID, &user.Email, &user.Username, &user.Bio,
				&user.AvatarURL, &user.BackgroundURL, &user.CreatedAt)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		rows, _ := db.Query(`SELECT series_id FROM user_favorites WHERE user_id=$1`, userID)
		defer rows.Close()
		genreCount := map[string]int{}
		for rows.Next() {
			var sid string
			if rows.Scan(&sid) == nil {
				if gs, e := tmdb.FetchGenres(config.GetTMDBToken(), sid); e == nil {
					for _, g := range gs {
						genreCount[g]++
					}
				}
			}
		}
		user.FavoriteGenres = topGenres(genreCount, 5)

		json.NewEncoder(w).Encode(user)
	}
}

func PatchProfileHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		userID := r.Context().Value(middleware.UserIDKey).(int)

		var req model.UpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		set := []string{}
		args := []interface{}{}
		i := 1

		if req.Email != nil {
			set = append(set, fmt.Sprintf("email=$%d", i))
			args, i = append(args, *req.Email), i+1
		}
		if req.Username != nil {
			set = append(set, fmt.Sprintf("username=$%d", i))
			args, i = append(args, *req.Username), i+1
		}
		if req.Bio != nil {
			set = append(set, fmt.Sprintf("bio=$%d", i))
			args, i = append(args, *req.Bio), i+1
		}
		if req.AvatarURL != nil {
			set = append(set, fmt.Sprintf("avatar_url=$%d", i))
			args, i = append(args, *req.AvatarURL), i+1
		}
		if req.BackgroundURL != nil {
			set = append(set, fmt.Sprintf("background_url=$%d", i))
			args, i = append(args, *req.BackgroundURL), i+1
		}

		if len(set) == 0 { // nothing to update
			w.WriteHeader(http.StatusNoContent)
			return
		}

		args = append(args, userID)
		q := fmt.Sprintf("UPDATE users SET %s WHERE id=$%d", strings.Join(set, ","), i)

		if _, err := db.Exec(q, args...); err != nil {
			http.Error(w, "update failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
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
