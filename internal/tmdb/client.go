package tmdb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type tmdbDetails struct {
	Genres []struct {
		Name string `json:"name"`
	} `json:"genres"`
}

func FetchGenres(apiKey, id string) ([]string, error) {
	url := fmt.Sprintf("https://api.themoviedb.org/3/tv/%s?language=en-US", id)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var d tmdbDetails
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	out := make([]string, len(d.Genres))
	for i, g := range d.Genres {
		out[i] = g.Name
	}
	return out, nil
}

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
