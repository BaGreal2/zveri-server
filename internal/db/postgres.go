package db

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

func Init() *sql.DB {
	dsn := os.Getenv("DATABASE_URL")
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to DB: %v", err))
	}

	createUsersTable := `
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        bio TEXT,
        avatar_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`

	createFavoritesTable := `
    CREATE TABLE IF NOT EXISTS user_favorites (
        user_id INTEGER NOT NULL,
        series_id TEXT NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, series_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );`

	if _, err := db.Exec(createUsersTable); err != nil {
		panic(fmt.Sprintf("Failed to create users table: %v", err))
	}

	if _, err := db.Exec(createFavoritesTable); err != nil {
		panic(fmt.Sprintf("Failed to create favorites table: %v", err))
	}

	fmt.Println("PostgreSQL DB initialized")
	return db
}
