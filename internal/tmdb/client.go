package tmdb

import (
	"fmt"
	"io"
	"net/http"
)

func SeriesDetailsHandler(apiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/series/"):]
		tmdbURL := fmt.Sprintf("https://api.themoviedb.org/3/tv/%s?language=en-US", id)
		proxyToTMDB(w, r, tmdbURL, apiKey)
	}
}

func SeriesVideosHandler(apiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := r.URL.Path[len("/series/"):]
		id := parts[:len(parts)-len("/videos")]
		tmdbURL := fmt.Sprintf("https://api.themoviedb.org/3/tv/%s/videos?language=en-US", id)
		proxyToTMDB(w, r, tmdbURL, apiKey)
	}
}

func TopRatedHandler(apiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if page == "" {
			page = "1"
		}
		tmdbURL := fmt.Sprintf("https://api.themoviedb.org/3/tv/top_rated?language=en-US&page=%s", page)
		proxyToTMDB(w, r, tmdbURL, apiKey)
	}
}

func proxyToTMDB(w http.ResponseWriter, r *http.Request, url, bearer string) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "TMDB request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
