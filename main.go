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

type LoginPageData struct {
    ErrorMessage string
    CreateAccountMessage string
}

type CreateAccountPageData struct {
    ErrorMessage string
}

type PageData struct {
    ErrorMessage string
    User UserData
    Posts []Post
}

type UserData struct {
    Id int
    Name string
    Username string
    Followers int
    Following int
}

type Post struct {
    Name      string
    Username  string
    Content   string
    Timestamp string
    Likes     int
}

func main() {
    fmt.Println("twitter clone :)")

    loginPageTmpl, err := template.ParseFiles("login.html")
    if err != nil {
        log.Fatal(err)
    }

    createAccountPageTmpl, err := template.ParseFiles("create_account.html")
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

    dbCreateAccount := `INSERT INTO users (name, username, password) VALUES (?, ?, ?)`

    res, err := db.Exec(dbAccountTable)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(res.RowsAffected())

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    })

    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "GET" {
            err := loginPageTmpl.Execute(w, LoginPageData{})
            if err != nil {
                log.Println(err)
            }
            return
        }

        err := r.ParseForm()
        if err != nil {
            fmt.Println(err);
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
            w.WriteHeader(http.StatusUnauthorized)
            loginPageTmpl.Execute(w, LoginPageData{ErrorMessage: "Invalid username or password"})
            return
        } else if err != nil {
            fmt.Println("database error")
            w.WriteHeader(http.StatusInternalServerError)
            loginPageTmpl.Execute(w, LoginPageData{ErrorMessage: "Database error"})
            return
        }

        err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(password))
        if err != nil {
            fmt.Println("invalid username or password")
            w.WriteHeader(http.StatusUnauthorized)
            loginPageTmpl.Execute(w, LoginPageData{ErrorMessage: "Invalid username or password"})
            return
        }

        log.Println("logged to account with username",username)
        redirectURL := fmt.Sprintf("/profile?username=%s", username)
        log.Println("Attempting redirect to:", redirectURL)
        http.Redirect(w, r, redirectURL, http.StatusSeeOther)
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
            fmt.Println("no rows -> username:",username,"profile not found")
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("User '%s' not found", username)})

            return
        } else if err != nil {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
            log.Println("Database error fetching user", username, err)
            return
        }

        // Query posts for the user
        var posts []Post
        rows, err := db.Query(`
        SELECT u.name, u.username, p.content, p.timestamp, p.likes 
        FROM users u JOIN posts p ON u.id = p.user_id 
        WHERE u.username = ?`, username)
        if err != nil {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Database error fetching posts"})
            log.Println("Database error fetching posts for user", username, err)
            return
        }
        defer rows.Close()

        for rows.Next() {
            var post Post
            err = rows.Scan(&post.Name, &post.Username, &post.Content, &post.Timestamp, &post.Likes)
            if err != nil {
                log.Println("Error scanning post row:", err)
                continue
            }
            posts = append(posts, post)
        }

        // Execute the profile template with user and posts data
        data := PageData{
            User:  user,
            Posts: posts,
        }

        // Execute the profile template with user data
        profileTmpl, err := template.ParseFiles("profile.html")
        if err != nil {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Template error"})
            log.Println("Template error for user", username, err)
            return
        }
        err = profileTmpl.Execute(w, data)
        if err != nil {
            log.Println(err)
        }
    })

    http.HandleFunc("/create-account", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "GET" {
            err := createAccountPageTmpl.Execute(w, CreateAccountPageData{})
            if err != nil {
                fmt.Println(err)
            }
            return
        }

        //      for debug
        //      body, _ := io.ReadAll(r.Body)
        //      fmt.Println("Raw request body:", string(body))

        err := r.ParseForm()
        if err != nil {
            fmt.Println(err);
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
            log.Println("Username:",existingUsername,"already exists")
            createAccountPageTmpl.Execute(w, CreateAccountPageData{fmt.Sprintf("Username: %s already exists", existingUsername)})
            return
        } else if err != sql.ErrNoRows {
            fmt.Println("db error: no rows")
            http.Error(w, `{"error": "Database error"}`, http.StatusInternalServerError)
            createAccountPageTmpl.Execute(w, CreateAccountPageData{"Database error"})
            return
        }

        res, err = db.Exec(dbCreateAccount, name, username, hashedPassword)
        if err != nil {
            fmt.Println("failed to create account")
            http.Error(w, `{"error": "Failed to create account"}`, http.StatusInternalServerError)
            createAccountPageTmpl.Execute(w, CreateAccountPageData{"Failed to create account"})
            return
        }

        // Success response
        log.Println("new user:",username,"created")
        // maybe redirect
        loginPageTmpl.Execute(w, LoginPageData{CreateAccountMessage: fmt.Sprintf("Username: %s created successfully", username)})
    })

    const port = 8080
    fmt.Printf("Server listening on http://localhost:%d\n", port)
    http.ListenAndServe(":" + strconv.Itoa(port), nil)
}
