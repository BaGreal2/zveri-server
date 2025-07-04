package main

import (
	"fmt"
	"net/http"

	"github.com/BaGreal2/zveri-server/internal/config"
	"github.com/BaGreal2/zveri-server/internal/db"
	"github.com/BaGreal2/zveri-server/internal/handler"
	"github.com/BaGreal2/zveri-server/internal/middleware"
)

func main() {
	config.LoadEnv()

	database := db.Init()
	defer database.Close()

	jwtSecret := config.GetJWTSecret()
	tmdbToken := config.GetTMDBToken()

	http.HandleFunc("/register", handler.WithCORS(handler.RegisterHandler(database)))
	http.HandleFunc("/login", handler.WithCORS(handler.LoginHandler(database, jwtSecret)))

	secured := middleware.AuthMiddleware(jwtSecret)

	http.HandleFunc("/me", handler.WithCORS(secured(handler.MeHandler(database))))
	http.HandleFunc("/me/update", handler.WithCORS(secured(handler.PatchProfileHandler(database))))
	http.HandleFunc("/me/delete", handler.WithCORS(secured(handler.DeleteProfileHandler(database))))

	http.HandleFunc("/favorites", handler.WithCORS(http.RedirectHandler("/favorites/", http.StatusPermanentRedirect).ServeHTTP))
	http.HandleFunc("/favorites/", handler.WithCORS(secured(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			handler.AddFavoriteHandler(database)(w, r)
		case http.MethodGet:
			handler.ListFavoritesHandler(database)(w, r)
		case http.MethodDelete:
			handler.RemoveFavoriteHandler(database)(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})))

	http.HandleFunc("/series/", handler.WithCORS(secured(handler.SeriesRouter(tmdbToken))))
	http.HandleFunc("/series/top_rated", handler.WithCORS(secured(handler.TopRatedHandler(tmdbToken))))

	fmt.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}
