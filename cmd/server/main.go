package main

import (
	"fmt"
	"net/http"

	"github.com/BaGreal2/zveri-server/internal/config"
	"github.com/BaGreal2/zveri-server/internal/db"
	"github.com/BaGreal2/zveri-server/internal/handler"
	"github.com/BaGreal2/zveri-server/internal/middleware"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	config.LoadEnv()

	database := db.Init()
	defer database.Close()

	jwtSecret := config.GetJWTSecret()
	tmdbToken := config.GetTMDBToken()

	http.HandleFunc("/register", handler.WithCORS(handler.RegisterHandler(database)))
	http.HandleFunc("/login", handler.WithCORS(handler.LoginHandler(database, jwtSecret)))
	http.HandleFunc("/me", handler.WithCORS(handler.MeHandler(database, jwtSecret)))

	secured := middleware.AuthMiddleware(jwtSecret)

	http.HandleFunc("/series/", handler.WithCORS(secured(handler.SeriesRouter(tmdbToken))))
	http.HandleFunc("/series/top_rated", handler.WithCORS(secured(handler.TopRatedHandler(tmdbToken))))

	fmt.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}
