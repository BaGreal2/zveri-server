package model

import "time"

type User struct {
	ID             int       `json:"id"`
	Email          string    `json:"email"`
	Username       string    `json:"username"`
	Bio            *string   `json:"bio,omitempty"`
	AvatarURL      *string   `json:"avatar_url,omitempty"`
	BackgroundURL  *string   `json:"background_url,omitempty"`
	FavoriteGenres []string  `json:"favorite_genres,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type UpdateRequest struct {
	Email         *string `json:"email"`
	Username      *string `json:"username"`
	Bio           *string `json:"bio"`
	AvatarURL     *string `json:"avatar_url"`
	BackgroundURL *string `json:"background_url"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}
