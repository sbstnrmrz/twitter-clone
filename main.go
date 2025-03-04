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
    "crypto/rand"
    "encoding/base64"
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
    LoggedInUser UserData
    IsOwnProfile bool
    IsFollowing bool
}

type UserData struct {
    ID        int
    Name      string
    Username  string
    Followers int
    Following int
}

type PostPageData struct {
    Username string
    ErrorMessage string
}

type Post struct {
    ID        int    // Post ID to identify posts for liking
    Name      string
    Username  string
    Content   string
    Timestamp string
    Likes     int
    UserLiked bool
}

func generateSessionToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}

func getLoggedInUser(r *http.Request) (string, bool) {
    cookie, err := r.Cookie("session_token")
    if err != nil {
        return "", false
    }
    
    username, exists := sessions[cookie.Value]
    return username, exists
}

func getUserID(db *sql.DB, username string) int {
    var id int
    err := db.QueryRow(`SELECT id FROM users WHERE username = ?`, username).Scan(&id)
    if err != nil {
        fmt.Println(err)
    }

    return id
}

func getUserFromString(db *sql.DB, userStr string) UserData {
    var user UserData
    err := db.QueryRow(`
    SELECT id, name, username, followers, following
    FROM users WHERE username = ?`, userStr).Scan(
        &user.ID,
        &user.Name,
        &user.Username,
        &user.Followers,
        &user.Following,
    )
    if err != nil && err != sql.ErrNoRows {
        log.Println("Database error fetching logged-in user", userStr, err)

        // Handle logged in database error.
    }

    return user
}


func getUserPosts(db *sql.DB, user UserData) []Post {
    var posts []Post
    rows, err := db.Query(`
    SELECT p.id, u.name, u.username, p.content, p.timestamp, p.likes 
    FROM users u JOIN posts p ON u.id = p.user_id 
    WHERE u.username = ? 
    ORDER BY p.timestamp DESC`, user.Username)

    if err != nil {
        log.Println("Database error fetching posts for user", user.Username, err)
        return posts
    }
    defer rows.Close()

    for rows.Next() {
        var post Post
        err = rows.Scan(&post.ID, &post.Name, &post.Username, &post.Content, &post.Timestamp, &post.Likes)
        if err != nil {
            log.Println("Error scanning post row:", err)
            continue
        }

        var userLiked bool
        err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM likes WHERE user_id = ? AND post_id = ?)", user.ID, post.ID).Scan(&userLiked)
        if err != nil {
            log.Println("Error checking like status:", err)
            continue
        }
        post.UserLiked = userLiked;

        posts = append(posts, post)
    }
    
    return posts
}

func getUserPostsWithLoggedUser(db *sql.DB, user UserData, loggedUser UserData) []Post {
    var posts []Post
    rows, err := db.Query(`
    SELECT p.id, u.name, u.username, p.content, p.timestamp, p.likes 
    FROM users u JOIN posts p ON u.id = p.user_id 
    WHERE u.username = ? 
    ORDER BY p.timestamp DESC`, user.Username)

    if err != nil {
        log.Println("Database error fetching posts for user", user.Username, err)
        return posts
    }
    defer rows.Close()

    for rows.Next() {
        var post Post
        err = rows.Scan(&post.ID, &post.Name, &post.Username, &post.Content, &post.Timestamp, &post.Likes)
        if err != nil {
            log.Println("Error scanning post row:", err)
            continue
        }

        var userLiked bool
        err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM likes WHERE user_id = ? AND post_id = ?)", loggedUser.ID, post.ID).Scan(&userLiked)
        if err != nil {
            log.Println("Error checking like status:", err)
            continue
        }
        post.UserLiked = userLiked;

        posts = append(posts, post)
    }
    
    return posts
}

func getAllPosts(db *sql.DB) []Post {
    var posts []Post
    rows, err := db.Query(`
        SELECT p.id, u.id, u.name, u.username, p.content, p.timestamp, p.likes 
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.timestamp DESC
    `)
    if err != nil {
        fmt.Println(err)
        return posts
    }
    defer rows.Close()

    for rows.Next() {
        var post Post
        var userID int
        err = rows.Scan(&post.ID, &userID, &post.Name, &post.Username, &post.Content, &post.Timestamp, &post.Likes)
        if err != nil {
            fmt.Println(err)
            return posts
        }

        var userLiked bool
        err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM likes WHERE user_id = ? AND post_id = ?)", userID, post.ID).Scan(&userLiked)
        if err != nil {
            log.Println("Error checking like status:", err)
            continue
        }
        post.UserLiked = userLiked;

        posts = append(posts, post)
    }

    return posts
}

func getAllPostsWithLoggedUser(db *sql.DB, loggedUser UserData) []Post {
    var posts []Post
    rows, err := db.Query(`
        SELECT p.id, u.id, u.name, u.username, p.content, p.timestamp, p.likes 
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.timestamp DESC
    `)
    if err != nil {
        fmt.Println(err)
        return posts
    }
    defer rows.Close()

    for rows.Next() {
        var post Post
        var userID int
        err = rows.Scan(&post.ID, &userID, &post.Name, &post.Username, &post.Content, &post.Timestamp, &post.Likes)
        if err != nil {
            fmt.Println(err)
            return posts
        }

        var userLiked bool
        err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM likes WHERE user_id = ? AND post_id = ?)", loggedUser.ID, post.ID).Scan(&userLiked)
        if err != nil {
            log.Println("Error checking like status:", err)
            continue
        }
        post.UserLiked = userLiked;

        posts = append(posts, post)
    }

    return posts
}

func likePost(db *sql.DB, loggedUser UserData, postID int) {

}

var sessions = make(map[string]string)

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

    homePageTmpl, err := template.ParseFiles("home.html")
    if err != nil {
        log.Fatal(err)
    }

    db, err := sql.Open("sqlite3", "database.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    dbUsersTable := `
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

    dbFollowsTable := `
    CREATE TABLE IF NOT EXISTS follows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        follower_id INTEGER NOT NULL,  -- The user who follows
        following_id INTEGER NOT NULL, -- The user being followed
        FOREIGN KEY (follower_id) REFERENCES users(id),
        FOREIGN KEY (following_id) REFERENCES users(id),
        UNIQUE (follower_id, following_id) -- Prevent duplicate follows
    );`

    dbCreateAccount := `INSERT INTO users (name, username, password) VALUES (?, ?, ?)`
    dbCreatePost := `INSERT INTO posts (user_id, content, timestamp, likes) VALUES (?, ?, ?, ?)`
    dbIncrementPostLikes := `UPDATE posts SET likes = likes + 1 WHERE id = ?`
    dbDecrementPostLikes := `UPDATE posts SET likes = likes - 1 WHERE id = ?`

    _, err = db.Exec(dbUsersTable)
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

    _, err = db.Exec(dbFollowsTable)
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

        if r.Method == "POST" {
            username := r.FormValue("username")
            password := r.FormValue("password")

            var storedHashedPassword string
            err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedHashedPassword)

            if err == sql.ErrNoRows || bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(password)) != nil {
                loginPageTmpl.Execute(w, LoginPageData{ErrorMessage: "Invalid username or password"})
                return
            }

            // Generate session token
            sessionToken := generateSessionToken()
            sessions[sessionToken] = username

            // Set the session cookie
            http.SetCookie(w, &http.Cookie{
                Name:     "session_token",
                Value:    sessionToken,
                Expires:  time.Now().Add(24 * time.Hour),
                HttpOnly: true,
            })

            // Redirect to profile
            http.Redirect(w, r, "/home", http.StatusSeeOther)
        }
    })

    http.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
        _, loggedIn := getLoggedInUser(r)
        if !loggedIn {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        username := r.URL.Query().Get("username")
        if username == "" {
            http.Error(w, "Username not provided", http.StatusBadRequest)
            return
        }

        var user UserData
        err := db.QueryRow(`SELECT id, name, username, followers, following
        FROM users WHERE username = ?`, username).Scan(
            &user.ID,
            &user.Name,
            &user.Username,
            &user.Followers,
            &user.Following,
        )

        if err == sql.ErrNoRows {
            http.Error(w, "User not found", http.StatusNotFound)
            return
        } else if err != nil {
            log.Println("Database error fetching user", username, err)
            http.Error(w, "Database error", http.StatusInternalServerError)
            return
        }

        // Check if a user is logged in (optional, for like status)
        loggedInUsername, loggedIn := getLoggedInUser(r)
        var loggedInUser UserData
        if loggedIn {
            err = db.QueryRow(`
            SELECT id, name, username, followers, following
            FROM users WHERE username = ?`, loggedInUsername).Scan(
                &loggedInUser.ID,
                &loggedInUser.Name,
                &loggedInUser.Username,
                &loggedInUser.Followers,
                &loggedInUser.Following,
            )
            if err != nil && err != sql.ErrNoRows {
                log.Println("Database error fetching logged-in user", loggedInUsername, err)
                // Handle logged in database error.
            }
        }

        var isFollowing bool
        db.QueryRow("SELECT EXISTS(SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?)", loggedInUser.ID, user.ID).Scan(&isFollowing)
        
        isOwnProfile := false 
        if username == loggedInUsername {
            isOwnProfile = true
        }

        data := PageData{
            User:  user,
            Posts: getUserPostsWithLoggedUser(db, user, loggedInUser),
            LoggedInUser: loggedInUser,
            IsFollowing: isFollowing,
            IsOwnProfile: isOwnProfile,
        }

        fmt.Println("is own profile:", isOwnProfile)
        fmt.Println("is following:", isFollowing)

        err = profilePageTmpl.Execute(w, data)
        if err != nil {
            log.Println(err)
        }
    })


    http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("session_token")
        if err == nil {
            delete(sessions, cookie.Value)
        }

        http.SetCookie(w, &http.Cookie{
            Name:   "session_token",
            Value:  "",
            Expires: time.Unix(0, 0),
            HttpOnly: true,
        })

        http.Redirect(w, r, "/login", http.StatusSeeOther)
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

        _, err = db.Exec(dbCreateAccount, name, username, hashedPassword)
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

    http.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
        username, loggedIn := getLoggedInUser(r)
        if !loggedIn {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
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
            http.Error(w, "User not found", http.StatusNotFound)
            return
        }

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

        fmt.Println("fetched posts from user:",user.Username)
        data := PageData{
            User:  user,
            Posts: getAllPostsWithLoggedUser(db, getUserFromString(db, username)),
        }

        err = homePageTmpl.Execute(w, data)
        if err != nil {
            log.Println(err)
        }
    })

    http.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "GET" {
            username := r.URL.Query().Get("username")
            if username == "" {
                fmt.Println("username not found")
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
                return
            } else if err != nil {
                log.Println("Database error fetching user for post", username, err)
                return
            }

            err = postPageTmpl.Execute(w, PostPageData{Username: username})
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
            return
        } else if err != nil {
            log.Println("Database error fetching user for post", username, err)
            return
        }

        // Insert the post into the database
        timestamp := time.Now().Format("3:04:05 PM - Jan 2, 2006")
        _, err = db.Exec(dbCreatePost, user.ID, content, timestamp, 0)
        if err != nil {
            log.Println("Failed to create post for user", username, err)
            return
        }

        log.Println("New post created for username:", username)
        // Redirect back to the profile page after successful post
        http.Redirect(w, r, "/home", http.StatusSeeOther)
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
        loggedUser, _ := getLoggedInUser(r) 

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

        // this queries the logged user info and so
        // Verify the user exists (optional, for security)
        var user UserData
        err = db.QueryRow(`
        SELECT id 
        FROM users WHERE username = ?`, loggedUser).Scan(&user.ID)
        if err == sql.ErrNoRows {
            log.Println("user", loggedUser, "not found")
            return
        } else if err != nil {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
            log.Println("Database error fetching user for like", loggedUser, err)
            return
        }

        var likeExists bool
        err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM likes WHERE user_id = ? AND post_id = ?)", user.ID, postID).Scan(&likeExists)
        if err != nil {
            fmt.Println(err)
            return
        }

        if likeExists {
            // Unlike the post
            _, err = db.Exec("DELETE FROM likes WHERE user_id = ? AND post_id = ?", user.ID, postID)
            if err != nil {
                fmt.Println(err)
                return
            }
            _, err = db.Exec(dbDecrementPostLikes, postID)
        } else {
            // Like the post
            _, err = db.Exec("INSERT INTO likes (user_id, post_id) VALUES (?, ?)", user.ID, postID)
            if err != nil {
                fmt.Println(err)
                return
            }
            _, err = db.Exec(dbIncrementPostLikes, postID)
        }

        log.Println("Post", postID, "liked by user", user.ID)

        var likeCount int
        query := "SELECT COUNT(*) FROM likes WHERE post_id = ?"
        err = db.QueryRow(query, postID).Scan(&likeCount)
        if err != nil {
            fmt.Println("Error getting like count:", err)
        }
        log.Println("like count:", likeCount)

        // Redirect back to the profile page after liking
        http.Redirect(w, r, fmt.Sprintf("/profile?username=%s", username), http.StatusSeeOther)
    })

    http.HandleFunc("/follow", func(w http.ResponseWriter, r *http.Request) {
        username := r.URL.Query().Get("username")
        if username == "" {
            fmt.Println("username not found")
            return
        }

        loggedUserStr, _ := getLoggedInUser(r) // Get logged-in user ID
        loggedUserID := strconv.Itoa(getUserID(db, loggedUserStr))
        userID := r.PathValue("id")        // Get the user to follow/unfollow

        if loggedUserID == userID {
            http.Error(w, "You cannot follow yourself", http.StatusBadRequest)
            return
        }

        var exists bool
        err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?)", loggedUserID, userID).Scan(&exists)
        if err != nil {
            http.Error(w, "Database error", http.StatusInternalServerError)
            return
        }

        if exists {
            // Unfollow
            _, err = db.Exec("DELETE FROM follows WHERE follower_id = ? AND following_id = ?", loggedUserID, userID)
        } else {
            // Follow
            _, err = db.Exec("INSERT INTO follows (follower_id, following_id) VALUES (?, ?)", loggedUserID, userID)
        }

        if err != nil {
            http.Error(w, "Database error", http.StatusInternalServerError)
            return
        }

        // Redirect back to the profile page (refreshes the page)
        http.Redirect(w, r, fmt.Sprintf("/profile?username=%s", username), http.StatusSeeOther)
    })

    const port = 8080
    fmt.Printf("Server listening on http://localhost:%d\n", port)
    http.ListenAndServe(":" + strconv.Itoa(port), nil)
}
