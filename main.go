package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
//	"io"
	"log"
	"net/http"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
)

func mainPageHandler(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "index.html")
}

type PageData struct {
    ErrorMessage string
}

func main() {
    fmt.Println("twitter clone :)")

    tmpl, err := template.ParseFiles("index.html")
    if err != nil {
        log.Fatal(err)
    }

    db, err := sql.Open("sqlite3", "database.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    dbAccountTable := `
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );`

    dbCreateAccount := `INSERT INTO accounts (name, username, password) VALUES (?, ?, ?)`

    res, err := db.Exec(dbAccountTable)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(res.RowsAffected())

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        tmpl.Execute(w, nil)
    })
    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "POST" {
    
        }

        r.ParseForm()
        username := r.FormValue("username")
        password := r.FormValue("password")

        fmt.Println("Username",username)
        fmt.Println("Password",password)
    })

    http.HandleFunc("/create-account", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
            http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
            return
        }

//      for debug
//      body, _ := io.ReadAll(r.Body)
//      fmt.Println("Raw request body:", string(body))

        err := r.ParseMultipartForm(10 << 20)
        if err != nil {
            fmt.Println(err);
            w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
            http.Error(w, `{"error": "Invalid form data"}`, http.StatusBadRequest)
            return
        }

        name := r.FormValue("name")
        username := r.FormValue("username")
        password := r.FormValue("password")

        fmt.Println("New account:")
        fmt.Println("  Name:", name)
        fmt.Println("  Username:", username)
        fmt.Println("  Password:", password)

        var existingUsername string
        err = db.QueryRow("SELECT username FROM accounts WHERE username = ?", username).Scan(&existingUsername)
        if err == nil {
            w.Header().Set("Content-Type", "application/json")
            log.Println("Username:",existingUsername,"already exists")
            json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Username: %s already exists", existingUsername)})
            return
        } else if err != sql.ErrNoRows {
            fmt.Println("db error: no rows")
            http.Error(w, `{"error": "Database error"}`, http.StatusInternalServerError)
            return
        }

        // Create new account
        res, err = db.Exec(dbCreateAccount, name, username, password)
        if err != nil {
            http.Error(w, `{"error": "Failed to create account"}`, http.StatusInternalServerError)
            return
        }

        // Success response
        log.Println("new account with username:",username)
        w.WriteHeader(http.StatusOK)
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"message": "Account created successfully"})
    })

    const port = 8080
    fmt.Printf("Server listening on http://localhost:%d\n", port)
    http.ListenAndServe(":" + strconv.Itoa(port), nil)
}
