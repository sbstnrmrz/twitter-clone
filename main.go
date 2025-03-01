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
    User UserData
}

type UserData struct {
    Id int
    Name string
    Username string
    Followers int
    Following int
}

func main() {
    fmt.Println("twitter clone :)")

    tmpl, err := template.ParseFiles("login.html")
    if err != nil {
        log.Fatal(err)
    }

    db, err := sql.Open("sqlite3", "database.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    dbAccountTable := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        followers INTEGER DEFAULT 0,
        following INTEGER DEFAULT 0
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

        fmt.Println("Login attemp")
        fmt.Println("  Username",username)
        fmt.Println("  Password",password)

        var storedHashedPassword string
        err = db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedHashedPassword)

        if err == sql.ErrNoRows {
            fmt.Println("invalid username or password")
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusUnauthorized) // Set 401 Unauthorized
            json.NewEncoder(w).Encode(map[string]string{"error": "Invalid username or password"})
            return
        } else if err != nil {
            fmt.Println("database error")
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusInternalServerError) // Set 500 Internal Server Error
            json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
            return
        }

        err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(password))
        if err != nil {
            fmt.Println("invalid username or password")
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusUnauthorized) // Set 401 Unauthorized
            json.NewEncoder(w).Encode(map[string]string{"error": "Invalid username or password"})
            return
        }

        log.Println("logged to account with username",username)
        redirectURL := fmt.Sprintf("/profile?username=%s", username)
        log.Println("Attempting redirect to:", redirectURL)
        log.Println("Response headers before redirect:", w.Header())
//      w.Header().Set("Location", redirectURL) // Explicitly set Location header for debugging
        http.Redirect(w, r, redirectURL, http.StatusSeeOther) // Use 303 instead of 302
        fmt.Println(w.Header())
//      w.WriteHeader(http.StatusOK)
//      http.Redirect(w, r, redirectURL, http.StatusSeeOther)
    })

    http.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
        username := r.URL.Query().Get("username")
        if username == "" {
            fmt.Println("username:",username,"profile not found")
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Username not found"})
            return
        }
        fmt.Println("profile")

        var user UserData
        err := db.QueryRow(`
            SELECT id, name, username, followers, following 
            FROM users WHERE username = ?`, username).Scan(
            &user.Id,
            &user.Name,
            &user.Username,
            &user.Followers,
            &user.Following,
        )

        fmt.Println("user data requested: ")
        fmt.Println("  id:",user.Id)
        fmt.Println("  username:",user.Username)
        fmt.Println("  followers:",user.Followers)
        fmt.Println("  following:",user.Following)

        if err == sql.ErrNoRows {
            // User not found, return JSON error
            fmt.Println("no rows -> username:",username,"profile not found")
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("User '%s' not found", username)})
            return
        } else if err != nil {
            // Database or other error, return JSON error
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
            log.Println("Database error fetching user", username, err)
            return
        }

        // Execute the profile template with user data
        profileTmpl, err := template.ParseFiles("profile.html")
        if err != nil {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Template error"})
            log.Println("Template error for user", username, err)
            return
        }
        err = profileTmpl.Execute(w, user)
        if err != nil {
            log.Println(err)
        }

//      username := r.URL.Query().Get("username")
//      if username == "" {
//          http.Error(w, "Username not found", http.StatusBadRequest)
//          return
//      }

//      var user UserData
//      err := db.QueryRow(`
//      SELECT id, name, username, followers, following 
//      FROM accounts WHERE username = ?`, username).Scan(
//          &user.id,
//          &user.name,
//          &user.username,
//          &user.followers,
//          &user.following,
//      )

//      if err == sql.ErrNoRows {
//          http.Error(w, "User not found", http.StatusNotFound)
//          return
//      } else if err != nil {
//          http.Error(w, "Database error", http.StatusInternalServerError)
//          return
//      }

//      // Execute the profile template with user data
//      profileTmpl, err := template.ParseFiles("profile.html")
//      if err != nil {
//          http.Error(w, "Template error", http.StatusInternalServerError)
//          return
//      }
//      profileTmpl.Execute(w, user)
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
        err = db.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&existingUsername)
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
        log.Println("new user:",username,"created")
        w.WriteHeader(http.StatusOK)
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"message": "Account created successfully"})
    })

    const port = 8080
    fmt.Printf("Server listening on http://localhost:%d\n", port)
    http.ListenAndServe(":" + strconv.Itoa(port), nil)
}
