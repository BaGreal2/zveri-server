package handler

import (
	"net/http"
	"strings"

	"github.com/BaGreal2/zveri-server/internal/tmdb"
)

func SeriesRouter(apiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/series/")
		parts := strings.Split(path, "/")

		switch {
		case len(parts) == 2 && parts[1] == "videos":
			tmdb.SeriesVideosHandler(apiKey)(w, r)
		case len(parts) == 1 && parts[0] != "":
			tmdb.SeriesDetailsHandler(apiKey)(w, r)
		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}
}

func TopRatedHandler(apiKey string) http.HandlerFunc {
	return tmdb.TopRatedHandler(apiKey)
}
