package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/BaGreal2/zveri-server/internal/middleware"
)

func AddFavoriteHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		userID := r.Context().Value(middleware.UserIDKey).(int)
		seriesID := strings.TrimPrefix(r.URL.Path, "/favorites/")

		if seriesID == "" {
			http.Error(w, "Series ID missing", http.StatusBadRequest)
			return
		}

		_, err := db.Exec(`
			INSERT INTO user_favorites (user_id, series_id)
			VALUES ($1, $2)
			ON CONFLICT (user_id, series_id) DO NOTHING
		`, userID, seriesID)

		if err != nil {
			http.Error(w, fmt.Sprintf("Could not add favorite: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

func RemoveFavoriteHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		userID := r.Context().Value(middleware.UserIDKey).(int)
		seriesID := strings.TrimPrefix(r.URL.Path, "/favorites/")

		if seriesID == "" {
			http.Error(w, "Series ID missing", http.StatusBadRequest)
			return
		}

		_, err := db.Exec("DELETE FROM user_favorites WHERE user_id = $1 AND series_id = $2", userID, seriesID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Could not remove favorite: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func ListFavoritesHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value(middleware.UserIDKey).(int)

		rows, err := db.Query("SELECT series_id FROM user_favorites WHERE user_id = $1", userID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Could not retrieve favorites: %v", err), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var favorites []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				favorites = append(favorites, id)
			}
		}

		json.NewEncoder(w).Encode(map[string][]string{"favorites": favorites})
	}
}
