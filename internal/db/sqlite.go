package db

import (
	"database/sql"
	"fmt"
)

func Init() *sql.DB {
	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		panic(fmt.Sprintf("DB connection error: %v", err))
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL UNIQUE,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.Exec(createTable); err != nil {
		panic(fmt.Sprintf("Failed to create table: %v", err))
	}

	fmt.Println("Database initialized")
	return db
}
