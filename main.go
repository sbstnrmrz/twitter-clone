package main

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "html/template"
    "log"
    "net/http"
    "strconv"
    "time"

    "golang.org/x/crypto/bcrypt"
    _ "github.com/mattn/go-sqlite3"
)

type LoginPageData struct {
    ErrorMessage        string
    CreateAccountMessage string
}

type CreateAccountPageData struct {
    ErrorMessage string
}

type PageData struct {
    ErrorMessage string
    User         UserData
    Posts        []Post
}

type UserData struct {
    ID        int
    Name      string
    Username  string
    Followers int
    Following int
}

type Post struct {
    ID        int    // Post ID to identify posts for liking
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

    profilePageTmpl, err := template.ParseFiles("profile.html")
    if err != nil {
        log.Fatal(err)
    }

    postPageTmpl, err := template.ParseFiles("post.html")
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

    dbPostsTable := `
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT NOT NULL,
        timestamp TEXT,
        likes INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );`

    dbLikesTable := `
    CREATE TABLE IF NOT EXISTS likes (
        user_id INTEGER,
        post_id INTEGER,
        PRIMARY KEY (user_id, post_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (post_id) REFERENCES posts(id)
    );`

    dbCreateAccount := `INSERT INTO users (name, username, password) VALUES (?, ?, ?)`
    dbCreatePost := `INSERT INTO posts (user_id, content, timestamp, likes) VALUES (?, ?, ?, ?)`
    dbIncrementLikes := `UPDATE posts SET likes = likes + 1 WHERE id = ?`

    _, err = db.Exec(dbAccountTable)
    if err != nil {
        log.Fatal(err)
    }

    _, err = db.Exec(dbPostsTable)
    if err != nil {
        log.Fatal(err)
    }

    _, err = db.Exec(dbLikesTable)
    if err != nil {
        log.Fatal(err)
    }


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
            fmt.Println(err)
            http.Error(w, `{"error": "Invalid form data"}`, http.StatusBadRequest)
            return
        }

        username := r.FormValue("username")
        password := r.FormValue("password")

        fmt.Println("Login attempt")
        fmt.Println("  Username:", username)
        fmt.Println("  Password:", password)

        var storedHashedPassword string
        err = db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedHashedPassword)

        if err == sql.ErrNoRows {
            fmt.Println("Invalid username or password")
            w.WriteHeader(http.StatusUnauthorized)
            loginPageTmpl.Execute(w, LoginPageData{ErrorMessage: "Invalid username or password"})
            return
        } else if err != nil {
            fmt.Println("Database error")
            w.WriteHeader(http.StatusInternalServerError)
            loginPageTmpl.Execute(w, LoginPageData{ErrorMessage: "Database error"})
            return
        }

        err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(password))
        if err != nil {
            fmt.Println("Invalid username or password")
            w.WriteHeader(http.StatusUnauthorized)
            loginPageTmpl.Execute(w, LoginPageData{ErrorMessage: "Invalid username or password"})
            return
        }

        log.Println("Logged in to account with username", username)
        redirectURL := fmt.Sprintf("/profile?username=%s", username)
        log.Println("Attempting redirect to:", redirectURL)
        http.Redirect(w, r, redirectURL, http.StatusSeeOther)
    })

    http.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
        username := r.URL.Query().Get("username")
        if username == "" {
            fmt.Println("Username:", username, "profile not found")
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Username not found"})
            return
        }
        fmt.Println("Profile")

        var user UserData
        err := db.QueryRow(`
            SELECT id, name, username, followers, following 
            FROM users WHERE username = ?`, username).Scan(
            &user.ID,
            &user.Name,
            &user.Username,
            &user.Followers,
            &user.Following,
        )

        fmt.Println("User data requested:")
        fmt.Println("  ID:", user.ID)
        fmt.Println("  Username:", user.Username)
        fmt.Println("  Followers:", user.Followers)
        fmt.Println("  Following:", user.Following)

        if err == sql.ErrNoRows {
            fmt.Println("No rows -> Username:", username, "profile not found")
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("User '%s' not found", username)})
            return
        } else if err != nil {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
            log.Println("Database error fetching user", username, err)
            return
        }

        // Query posts for the user, ordered by timestamp (newest first)
        var posts []Post
        rows, err := db.Query(`
            SELECT p.id, u.name, u.username, p.content, p.timestamp, p.likes 
            FROM users u JOIN posts p ON u.id = p.user_id 
            WHERE u.username = ? 
            ORDER BY p.timestamp DESC`, username)
        if err != nil {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Database error fetching posts"})
            log.Println("Database error fetching posts for user", username, err)
            return
        }
        defer rows.Close()

        for rows.Next() {
            var post Post
            err = rows.Scan(&post.ID, &post.Name, &post.Username, &post.Content, &post.Timestamp, &post.Likes)
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

        err = profilePageTmpl.Execute(w, data)
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

        err := r.ParseForm()
        if err != nil {
            fmt.Println(err)
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
            createAccountPageTmpl.Execute(w, CreateAccountPageData{ErrorMessage: "Error hashing password"})
            fmt.Println("Error hashing password")
            return
        }

        var existingUsername string
        err = db.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&existingUsername)
        if err == nil {
            createAccountPageTmpl.Execute(w, CreateAccountPageData{ErrorMessage: fmt.Sprintf("Username: %s already exists", existingUsername)})
            return
        } else if err != sql.ErrNoRows {
            fmt.Println("Database error: no rows")
            createAccountPageTmpl.Execute(w, CreateAccountPageData{ErrorMessage: "Database error"})
            return
        }

        _, err = db.Exec(dbCreateAccount, name, username, hashedPassword)
        if err != nil {
            createAccountPageTmpl.Execute(w, CreateAccountPageData{ErrorMessage: "Failed to create account"})
            fmt.Println("Failed to create account")
            return
        }

        log.Println("New user:", username, "created")
        // Redirect to the login page after successful account creation
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    })

    http.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "GET" {
            username := r.URL.Query().Get("username")
            if username == "" {
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(map[string]string{"error": "Username not found"})
                return
            }

            var user UserData
            err := db.QueryRow(`
                SELECT id, name, username, followers, following 
                FROM users WHERE username = ?`, username).Scan(
                &user.ID,
                &user.Name,
                &user.Username,
                &user.Followers,
                &user.Following,
            )

            if err == sql.ErrNoRows {
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("User '%s' not found", username)})
                return
            } else if err != nil {
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
                log.Println("Database error fetching user for post", username, err)
                return
            }

            // Serve the post form with the username
            err = postPageTmpl.Execute(w, struct{ Username string }{Username: username})
            if err != nil {
                log.Println(err)
            }
            return
        }

        if r.Method != "POST" {
            http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
            return
        }

        err := r.ParseForm()
        if err != nil {
            fmt.Println("ParseForm error:", err)
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Invalid form data"})
            return
        }

        username := r.FormValue("username")
        content := r.FormValue("content")

        fmt.Println("New post:")
        fmt.Println("  Username:", username)
        fmt.Println("  Content:", content)

        var user UserData
        err = db.QueryRow(`
            SELECT id 
            FROM users WHERE username = ?`, username).Scan(&user.ID)
        if err == sql.ErrNoRows {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("User '%s' not found", username)})
            return
        } else if err != nil {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
            log.Println("Database error fetching user for post", username, err)
            return
        }

        // Insert the post into the database
        timestamp := time.Now().Format("2006-01-02 15:04:05")
        _, err = db.Exec(dbCreatePost, user.ID, content, timestamp, 0)
        if err != nil {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create post"})
            log.Println("Failed to create post for user", username, err)
            return
        }

        log.Println("New post created for username:", username)
        // Redirect back to the profile page after successful post
        http.Redirect(w, r, fmt.Sprintf("/profile?username=%s", username), http.StatusSeeOther)
    })

    // Endpoint to handle liking a post
    http.HandleFunc("/like", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
            http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
            return
        }

        err := r.ParseForm()
        if err != nil {
            fmt.Println("ParseForm error:", err)
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Invalid form data"})
            return
        }

        postIDStr := r.FormValue("post_id")
        username := r.FormValue("username")

        if postIDStr == "" || username == "" {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Post ID or username missing"})
            return
        }

        postID, err := strconv.Atoi(postIDStr)
        if err != nil {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Invalid post ID"})
            return
        }




        // Verify the user exists (optional, for security)
        var user UserData
        err = db.QueryRow(`
        SELECT id 
        FROM users WHERE username = ?`, username).Scan(&user.ID)
        if err == sql.ErrNoRows {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("User '%s' not found", username)})
            return
        } else if err != nil {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
            log.Println("Database error fetching user for like", username, err)
            return
        }

        //      // Increment the likes count for the post
        //      result, err := db.Exec(dbIncrementLikes, postID)
        //      if err != nil {
        //          w.Header().Set("Content-Type", "application/json")
        //          json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update likes"})
        //          log.Println("Failed to increment likes for post", postID, err)
        //          return
        //      }

        //      rowsAffected, err := result.RowsAffected()
        //      if err != nil || rowsAffected == 0 {
        //          w.Header().Set("Content-Type", "application/json")
        //          json.NewEncoder(w).Encode(map[string]string{"error": "Post not found or already liked"})
        //          return
        //      }

        // Attempt to insert a like record (prevent duplicates)
        result, err := db.Exec(`INSERT OR IGNORE INTO likes (user_id, post_id) VALUES (?, ?)`, user.ID, postID)
        if err != nil {
            log.Println("Failed to insert like for post", postID, "user", user.ID, err)
            return
        }

        rowsAffected, err := result.RowsAffected()
        if err != nil {
            log.Println("error aksdlasd")
            return
        }

        if rowsAffected > 0 {
            // Increment the likes count for the post
            _, err = db.Exec(dbIncrementLikes, postID)
            if err != nil {
                log.Println("Failed to increment likes count for post", postID, err)
                return
            }
            log.Println("Post", postID, "liked by user", username)
        } else {
            log.Println("Post", postID, "already liked by user", username)
        }


        log.Println("Post", postID, "liked by user", username)
        // Redirect back to the profile page after liking
        http.Redirect(w, r, fmt.Sprintf("/profile?username=%s", username), http.StatusSeeOther)
    })

    const port = 8080
    fmt.Printf("Server listening on http://localhost:%d\n", port)
    http.ListenAndServe(":" + strconv.Itoa(port), nil)
}
