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
    "golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

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

        username := r.FormValue("username")
        password := r.FormValue("password")

        fmt.Println("Username",username)
        fmt.Println("Password",password)

        var storedHashedPassword string
        err = db.QueryRow("SELECT password FROM accounts WHERE username = ?", username).Scan(&storedHashedPassword)

        if err == sql.ErrNoRows {
            // Username not found
//          http.Error(w, "Invalid username or password", http.StatusUnauthorized)
            json.NewEncoder(w).Encode(map[string]string{"error": "Invalid username or password"})
            return
        } else if err != nil {
            // Database error
            http.Error(w, "Database error", http.StatusInternalServerError)

            return
        }

        err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(password))
        if err != nil {
//          http.Error(w, "Invalid username or password", http.StatusUnauthorized)
            json.NewEncoder(w).Encode(map[string]string{"error": "Invalid username or password"})
            return
        }

        log.Println("logged to account with username",username)
        w.WriteHeader(http.StatusOK)
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"message": "Login success"})
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

        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        if err != nil {
            http.Error(w, "Error hashing password", http.StatusInternalServerError)
            fmt.Println("error hasing password")
            return
        }

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
        res, err = db.Exec(dbCreateAccount, name, username, hashedPassword)
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
