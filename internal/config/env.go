package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

func LoadEnv() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Warning: .env file not found")
	}
}

func GetJWTSecret() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		panic("JWT_SECRET not set")
	}
	return secret
}

func GetTMDBToken() string {
	token := os.Getenv("TMDB_API_BEARER")
	if token == "" {
		panic("TMDB_API_BEARER not set")
	}
	return token
}
