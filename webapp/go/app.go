package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	m "github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	"github.com/coocood/freecache"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	"github.com/sugawarayuuta/sonnet"

	// profiler
	_ "net/http/pprof"
)

var (
	db             *sqlx.DB
	store          *gsm.MemcacheStore
	deletedUserIDs []int
	cache          *freecache.Cache
)

const (
	postsPerPage  = 20
	ISO8601Format = "2006-01-02T15:04:05-07:00"
	UploadLimit   = 10 * 1024 * 1024 // 10mb
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []Comment
	User         User `db:"users"`
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User      `db:"users"`
}

func init() {
	memdAddr := os.Getenv("ISUCONP_MEMCACHED_ADDRESS")
	if memdAddr == "" {
		memdAddr = "localhost:11211"
	}
	memcacheClient := m.New(memdAddr)
	store = gsm.NewMemcacheStore(memcacheClient, "iscogram_", []byte("sendagaya"))
	cache = freecache.NewCache(10 * 1024 * 1024)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		// initialize posts.comment_count
		"UPDATE posts SET comment_count = (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id)",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}

	query := "SELECT id FROM users WHERE id % 50 = 0"
	err := db.Select(&deletedUserIDs, query)
	if err != nil {
		log.Print(err)
		return
	}
}

func tryLogin(accountName, password string) *User {
	u := User{}
	query := "SELECT * FROM users WHERE account_name = ? AND id NOT IN (?)"

	query, args, err := sqlx.In(query, accountName, deletedUserIDs)
	if err != nil {
		log.Print(err)
		return nil
	}

	query = db.Rebind(query)
	err = db.Get(&u, query, args...)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`).MatchString(accountName) &&
		regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`).MatchString(password)
}

func digest(src string) string {
	h := sha512.New()
	h.Write([]byte(src))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return User{}
	}

	accountName := session.Values["account_name"]
	authority := session.Values["authority"]

	u := User{
		ID:          uid.(int),
		AccountName: accountName.(string),
		Authority:   authority.(int),
	}

	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

type SimpleComment struct {
	PostID          int    `db:"post_id"`
	Comment         string `db:"comment"`
	UserAccountName string `db:"user_account_name"`
}

func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	var posts []Post

	cachedCommentCountKeysMap := make(map[int][]byte, len(results))
	cachedCommentKeysMap := make(map[int][]byte, len(results))

	for _, p := range results {
		cachedCommentCountKeysMap[p.ID] = []byte(fmt.Sprintf("comment_count_%d", p.ID))
		cachedCommentKeysMap[p.ID] = []byte(fmt.Sprintf("comments_%d_%t", p.ID, !allComments))
	}

	commentCounts := make(map[int]int, len(results))
	var missCachedCommentCountPostIDs []int
	for _, p := range results {
		key, ok := cachedCommentCountKeysMap[p.ID]
		if !ok {
			continue
		}

		value, err := cache.Get(key)
		if err == nil {
			commentCount, _ := strconv.Atoi(string(value))

			commentCounts[p.ID] = commentCount
		} else if err == freecache.ErrNotFound {
			missCachedCommentCountPostIDs = append(missCachedCommentCountPostIDs, p.ID)
		} else {
			return nil, err
		}
	}

	if len(missCachedCommentCountPostIDs) > 0 {
		type Count struct {
			PostID       int `db:"id"`
			CommentCount int `db:"comment_count"`
		}

		query := "SELECT id, comment_count FROM posts WHERE id IN (?)"
		query, args, err := sqlx.In(query, missCachedCommentCountPostIDs)
		if err != nil {
			return nil, err
		}

		query = db.Rebind(query)
		var counts []Count
		err = db.Select(&counts, query, args...)
		if err != nil {
			return nil, err
		}

		for _, count := range counts {
			commentCounts[count.PostID] = count.CommentCount

			err := cache.Set([]byte(cachedCommentCountKeysMap[count.PostID]), []byte(strconv.Itoa(count.CommentCount)), 10)
			if err != nil {
				return nil, err
			}
		}
	}

	comments := make(map[int][]SimpleComment, len(results))
	var missCachedCommentsPostIDs []int
	for _, p := range results {
		key, ok := cachedCommentKeysMap[p.ID]
		if !ok {
			continue
		}

		value, err := cache.Get(key)
		if err == nil {
			var cs []SimpleComment
			err := sonnet.Unmarshal(value, &cs)
			if err != nil {
				return nil, err
			}

			comments[p.ID] = cs
		} else if err == freecache.ErrNotFound {
			missCachedCommentsPostIDs = append(missCachedCommentsPostIDs, p.ID)
		} else {
			return nil, err
		}
	}

	if len(missCachedCommentsPostIDs) > 0 {
		query := `
		SELECT comments.post_id, comments.comment, users.account_name AS "user_account_name"
		FROM comments
		JOIN users ON comments.user_id = users.id
		WHERE post_id IN (?)
		ORDER BY comments.created_at DESC
		`

		query, args, err := sqlx.In(query, missCachedCommentsPostIDs)
		if err != nil {
			return nil, err
		}

		query = db.Rebind(query)
		var cs []SimpleComment
		err = db.Select(&cs, query, args...)
		if err != nil {
			return nil, err
		}

		var unsortedComments = make(map[int][]SimpleComment, len(cs))
		for _, c := range cs {
			commentsForPost := unsortedComments[c.PostID]
			if !allComments && len(commentsForPost) >= 3 {
				continue
			}

			unsortedComments[c.PostID] = append(unsortedComments[c.PostID], c)
		}

		for _, postID := range missCachedCommentsPostIDs {
			c := unsortedComments[postID]

			// reverse comments
			for i, j := 0, len(c)-1; i < j; i, j = i+1, j-1 {
				c[i], c[j] = c[j], c[i]
			}

			comments[postID] = c

			b, err := sonnet.Marshal(c)
			if err != nil {
				return nil, err
			}

			err = cache.Set(cachedCommentKeysMap[postID], b, 10)
			if err != nil {
				return nil, err
			}
		}
	}

	for _, p := range results {
		cs := make([]Comment, 0, len(comments[p.ID]))
		for _, c := range comments[p.ID] {
			cs = append(cs, Comment{
				PostID:  c.PostID,
				Comment: c.Comment,
				User: User{
					AccountName: c.UserAccountName,
				},
			})
		}

		p.CommentCount = commentCounts[p.ID]
		p.Comments = cs
		p.CSRFToken = csrfToken

		posts = append(posts, p)
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["account_name"] = u.AccountName
		session.Values["authority"] = u.Authority
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE account_name = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO users (account_name, passhash) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	session.Values["user_id"] = int(uid)
	session.Values["account_name"] = accountName
	session.Values["authority"] = 0
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	delete(session.Values, "account_name")
	delete(session.Values, "authority")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

var postsKey = []byte("posts")

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	results := []Post{}

	cachedIndexPosts, err := cache.Get(postsKey)
	if err == nil {
		err := sonnet.Unmarshal(cachedIndexPosts, &results)
		if err != nil {
			log.Print(err)
			return
		}
	} else if err == freecache.ErrNotFound {
		query := `
		SELECT posts.id, posts.body, posts.mime, posts.created_at,
		users.account_name AS "users.account_name", users.authority AS "users.authority"
		FROM posts
		JOIN users ON posts.user_id = users.id
		WHERE users.id NOT IN (?)
		ORDER BY posts.created_at DESC
		LIMIT ?
		`

		query, args, err := sqlx.In(query, deletedUserIDs, postsPerPage)
		if err != nil {
			log.Print(err)
			return
		}

		query = db.Rebind(query)
		err = db.Select(&results, query, args...)
		if err != nil {
			log.Print(err)
			return
		}

		b, err := sonnet.Marshal(results)
		if err != nil {
			log.Print(err)
			return
		}

		err = cache.Set(postsKey, b, 5)
		if err != nil {
			log.Print(err)
			return
		}
	} else {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	flash := getFlash(w, r, "notice")
	csrfToken := getCSRFToken(r)

	templateLayout(
		w,
		me,
		func(w io.Writer) {
			templateIndex(w, posts, csrfToken, flash)
		},
	)
}

var templateLayoutByteArray = [...][]byte{
	[]byte(`<!DOCTYPE html> <html> <head> <meta charset="utf-8"> <title>Iscogram</title> <link href="/css/style.css" media="screen" rel="stylesheet" type="text/css"> </head> <body> <div class="container"> <div class="header"> <div class="isu-title"> <h1><a href="/">Iscogram</a></h1> </div> <div class="isu-header-menu">`),
	[]byte(`<div><a href="/login">ログイン</a></div>`),
	[]byte(`<div><a href="/@`),
	[]byte(`"><span class="isu-account-name">`),
	[]byte(`</span>さん</a></div>`),
	[]byte(`<div><a href="/admin/banned">管理者用ページ</a></div>`),
	[]byte(`<div><a href="/logout">ログアウト</a></div>`),
	[]byte(`</div> </div>`),
	[]byte(`</div> <script src="/js/timeago.min.js"></script> <script src="/js/main.js"></script> </body> </html>`),
}

func templateLayout(w io.Writer, me User, content func(w io.Writer)) {
	w.Write(templateLayoutByteArray[0])

	if me.ID == 0 {
		w.Write(templateLayoutByteArray[1])
	} else {
		var accountName = []byte(me.AccountName)
		w.Write(templateLayoutByteArray[2])
		w.Write(accountName)
		w.Write(templateLayoutByteArray[3])
		w.Write(accountName)
		w.Write(templateLayoutByteArray[4])

		if me.Authority == 1 {
			w.Write(templateLayoutByteArray[5])
		}

		w.Write(templateLayoutByteArray[6])
	}

	w.Write(templateLayoutByteArray[7])
	content(w)
	w.Write(templateLayoutByteArray[8])
}

var templateIndexByteArray = [...][]byte{
	[]byte(`<div class="isu-submit"> <form method="post" action="/" enctype="multipart/form-data"> <div class="isu-form"> <input type="file" name="file" value="file"> </div> <div class="isu-form"> <textarea name="body"></textarea> </div> <div class="form-submit"> 
	<input type="hidden" name="csrf_token" value="`),
	[]byte(`"> <input type="submit" name="submit" value="submit"> </div>`),
	[]byte(`<div id="notice-message" class="alert alert-danger">`),
	[]byte(`</div>`),
	[]byte(`</form></div>`),
	[]byte(`<div id="isu-post-more"><button id="isu-post-more-btn">もっと見る</button><img class="isu-loading-icon" src="/img/ajax-loader.gif"></div>`),
}

func templateIndex(w io.Writer, posts []Post, csrfToken string, flash string) {
	w.Write(templateIndexByteArray[0])
	w.Write([]byte(csrfToken))
	w.Write(templateIndexByteArray[1])

	if len(flash) > 0 {
		w.Write(templateIndexByteArray[2])
		w.Write([]byte(flash))
		w.Write(templateIndexByteArray[3])
	}
	w.Write(templateIndexByteArray[4])

	templatePosts(w, posts)
	w.Write(templateIndexByteArray[5])
}

var templatePostsByteArray = [...][]byte{
	[]byte(`<div class="isu-posts">`),
	[]byte(`</div>`),
}

func templatePosts(w io.Writer, posts []Post) {
	w.Write(templatePostsByteArray[0])
	for _, p := range posts {
		templatePost(w, p)
	}
	w.Write(templatePostsByteArray[1])
}

var templatePostByteArray = [...][]byte{
	[]byte(`<div class="isu-post" id="pid_`),
	[]byte(`" data-created-at="`),
	[]byte(`"><div class="isu-post-header"><a href="/@`),
	[]byte(`" class="isu-post-account-name">`),
	[]byte(`</a><a href="/posts/`),
	[]byte(`" class="isu-post-permalink"><time class="timeago" datetime="`),
	[]byte(`"></time></a></div><div class="isu-post-image"><img src="`),
	[]byte(`" class="isu-image"></div><div class="isu-post-text"><a href="/@`),
	[]byte(`" class="isu-post-account-name">`),
	[]byte(`</a>`),
	[]byte(`</div><div class="isu-post-comment"><div class="isu-post-comment-count">comments: <b>`),
	[]byte(`</b></div>`),
	[]byte(`<div class="isu-comment"><a href="/@`),
	[]byte(`" class="isu-comment-account-name">`),
	[]byte(`</a><span class="isu-comment-text">`),
	[]byte(`</span></div>`),
	[]byte(`<div class="isu-comment-form"><form method="post" action="/comment"> <input type="text" name="comment"><input type="hidden" name="post_id" value="`),
	[]byte(`"><input type="hidden" name="csrf_token" value="`),
	[]byte(`"><input type="submit" name="submit" value="submit"> </form> </div> </div> </div>`),
}

func templatePost(w io.Writer, post Post) {
	cacheKey := []byte(fmt.Sprintf("template_post_%d", post.ID))
	buf := bytes.NewBuffer(make([]byte, 0, 850+512))

	cached, err := cache.Get(cacheKey)
	if err == nil {
		w.Write(cached)
		return
	} else if err == freecache.ErrNotFound {
		createdAt := []byte(post.CreatedAt.Format(ISO8601Format))
		postID := []byte(strconv.Itoa(post.ID))
		userAccountName := []byte(post.User.AccountName)

		buf.Write(templatePostByteArray[0])
		buf.Write(postID)
		buf.Write(templatePostByteArray[1])
		buf.Write(createdAt)
		buf.Write(templatePostByteArray[2])
		buf.Write(userAccountName)
		buf.Write(templatePostByteArray[3])
		buf.Write(userAccountName)
		buf.Write(templatePostByteArray[4])
		buf.Write(postID)
		buf.Write(templatePostByteArray[5])
		buf.Write(createdAt)
		buf.Write(templatePostByteArray[6])
		buf.Write([]byte(imageURL(post)))
		buf.Write(templatePostByteArray[7])
		buf.Write(userAccountName)
		buf.Write(templatePostByteArray[8])
		buf.Write(userAccountName)
		buf.Write(templatePostByteArray[9])
		buf.Write([]byte(post.Body))
		buf.Write(templatePostByteArray[10])
		buf.Write([]byte(strconv.Itoa(post.CommentCount)))
		buf.Write(templatePostByteArray[11])

		// w.Write([]byte(
		// 	fmt.Sprintf(`
		// 		<div class="isu-post" id="pid_%d" data-created-at="%s">
		// 			<div class="isu-post-header">
		// 				<a href="/@%s" class="isu-post-account-name">%s</a>
		// 				<a href="/posts/%d" class="isu-post-permalink">
		// 				<time class="timeago" datetime="%s"></time>
		// 				</a>
		// 			</div>
		// 			<div class="isu-post-image">
		// 				<img src="%s" class="isu-image">
		// 			</div>
		// 			<div class="isu-post-text">
		// 				<a href="/@%s" class="isu-post-account-name">%s</a>
		// 				%s
		// 			</div>
		// 			<div class="isu-post-comment">
		// 				<div class="isu-post-comment-count">
		// 				comments: <b>%d</b>
		// 		</div>
		// 		`,
		// 		post.ID,
		// 		createdAt,
		// 		post.User.AccountName,
		// 		post.User.AccountName,
		// 		post.ID,
		// 		createdAt,
		// 		imageURL(post),
		// 		post.User.AccountName,
		// 		post.User.AccountName,
		// 		post.Body,
		// 		post.CommentCount,
		// 	),
		// ))

		for _, c := range post.Comments {
			userAccountName := []byte(c.User.AccountName)

			buf.Write(templatePostByteArray[12])
			buf.Write(userAccountName)
			buf.Write(templatePostByteArray[13])
			buf.Write(userAccountName)
			buf.Write(templatePostByteArray[14])
			buf.Write([]byte(c.Comment))
			buf.Write(templatePostByteArray[15])
			// w.Write([]byte(fmt.Sprintf(`
			// 	<div class="isu-comment">
			// 		<a href="/@%s" class="isu-comment-account-name">%s</a>
			// 		<span class="isu-comment-text">%s</span>
			// 	</div>
			// 	`,
			// 	c.User.AccountName,
			// 	c.User.AccountName,
			// 	c.Comment,
			// )))
		}

		buf.Write(templatePostByteArray[16])
		buf.Write(postID)
		buf.Write(templatePostByteArray[17])
		buf.Write([]byte(post.CSRFToken))
		buf.Write(templatePostByteArray[18])
		// w.Write([]byte(fmt.Sprintf(
		// 	`<div class="isu-comment-form"> <form method="post" action="/comment"> <input type="text" name="comment">
		// 	<input type="hidden" name="post_id" value="%d">
		// 	<input type="hidden" name="csrf_token" value="%s">
		// 	<input type="submit" name="submit" value="submit"> </form> </div> </div> </div>
		// 	`,
		// 	post.ID,
		// 	post.CSRFToken,
		// )))

		bytes := buf.Bytes()
		w.Write(bytes)
		cache.Set(cacheKey, bytes, 10)
		return
	} else {
		log.Print(err)
		return
	}
}

func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := chi.URLParam(r, "accountName")
	user := User{}

	query := "SELECT * FROM users WHERE account_name = ? AND id NOT IN (?)"
	query, args, err := sqlx.In(query, accountName, deletedUserIDs)
	if err != nil {
		log.Print(err)
		return
	}

	query = db.Rebind(query)
	err = db.Get(&user, query, args...)
	if err != nil {
		log.Print(err)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}

	query = `
		SELECT posts.id, posts.user_id, posts.body, posts.mime, posts.created_at,
		 users.id AS "users.id", users.account_name AS "users.account_name", users.authority AS "users.authority", users.created_at AS "users.created_at"
		FROM posts
		JOIN users ON posts.user_id = users.id
		WHERE user_id = ? AND users.id NOT IN (?)
		ORDER BY posts.created_at DESC
		LIMIT ?
		`

	query, args, err = sqlx.In(query, user.ID, deletedUserIDs, postsPerPage)
	if err != nil {
		log.Print(err)
		return
	}

	query = db.Rebind(query)
	err = db.Select(&results, query, args...)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	commentCount := 0
	err = db.Get(&commentCount, "SELECT COUNT(*) AS count FROM comments WHERE user_id = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	postIDs := []int{}
	err = db.Select(&postIDs, "SELECT id FROM posts WHERE user_id = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}
	postCount := len(postIDs)

	commentedCount := 0
	query = `
	SELECT COUNT(*)
	FROM comments
	JOIN posts ON comments.post_id = posts.id
	WHERE posts.user_id = ?
	`
	err = db.Get(&commentedCount, query, user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	me := getSessionUser(r)

	templateLayout(
		w,
		me,
		func(w io.Writer) {
			templateUser(w, posts, user, postCount, commentCount, commentedCount)
		},
	)
}

func templateUser(w io.Writer, posts []Post, user User, postCount, commentCount, commentedCount int) {
	w.Write([]byte(fmt.Sprintf(`
		<div class="isu-user">
		<div><span class="isu-user-account-name">%sさん</span>のページ</div>
		<div>投稿数 <span class="isu-post-count">%d</span></div>
		<div>コメント数 <span class="isu-comment-count">%d</span></div>
		<div>被コメント数 <span class="isu-commented-count">%d</span></div>
		</div>`,
		user.AccountName,
		postCount,
		commentCount,
		commentedCount,
	)))

	templatePosts(w, posts)
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	results := []Post{}
	query := `
		SELECT posts.id, posts.user_id, posts.body, posts.mime, posts.created_at,
		 users.id AS "users.id", users.account_name AS "users.account_name", users.authority AS "users.authority", users.created_at AS "users.created_at"
		FROM posts
		JOIN users ON posts.user_id = users.id
		WHERE posts.created_at <= ? AND users.id NOT IN (?)
		ORDER BY posts.created_at DESC
		LIMIT ?
		`

	query, args, err := sqlx.In(query, t.Format(ISO8601Format), deletedUserIDs, postsPerPage)
	if err != nil {
		log.Print(err)
		return
	}

	query = db.Rebind(query)
	err = db.Select(&results, query, args...)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	templatePosts(w, posts)
}

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	query := `
		SELECT posts.id, posts.user_id, posts.body, posts.mime, posts.created_at,
		 users.id AS "users.id", users.account_name AS "users.account_name", users.authority AS "users.authority", users.created_at AS "users.created_at"
		FROM posts 
		JOIN users ON posts.user_id = users.id
		WHERE posts.id = ? AND users.id NOT IN (?)
		`

	query, args, err := sqlx.In(query, pid, deletedUserIDs)
	if err != nil {
		log.Print(err)
		return
	}

	query = db.Rebind(query)
	err = db.Select(&results, query, args...)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), true)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	templateLayout(
		w,
		me,
		func(w io.Writer) {
			templatePostID(w, p)
		},
	)
}

func templatePostID(w io.Writer, post Post) {
	templatePost(w, post)
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	ext := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
			ext = "jpg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
			ext = "png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
			ext = "gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, err := io.ReadAll(file)
	if err != nil {
		log.Print(err)
		return
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO posts (user_id, mime, imgdata, body) VALUES (?,?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		[]byte(""),
		r.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	// write filedata to image file in /public/img
	f, err := os.Create(fmt.Sprintf("../public/img/%d.%s", pid, ext))
	if err != nil {
		log.Print(err)
		return
	}
	defer f.Close()

	_, err = f.Write(filedata)
	if err != nil {
		log.Print(err)
		return
	}

	cache.Del(postsKey)

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
}

func getImage(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	post := Post{}
	err = db.Get(&post, "SELECT mime FROM posts WHERE id = ?", pid)
	if err != nil {
		log.Print(err)
		return
	}

	ext := chi.URLParam(r, "ext")

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		w.Header().Set("Content-Type", post.Mime)

		err = db.Get(&post, "SELECT imgdata FROM posts WHERE id = ?", pid)
		if err != nil {
			log.Print(err)
			return
		}

		f, err := os.Create(fmt.Sprintf("../public/img/%d.%s", pid, ext))
		if err != nil {
			log.Print(err)
			return
		}
		defer f.Close()

		_, err = f.Write(post.Imgdata)
		if err != nil {
			log.Print(err)
			return
		}

		_, err = w.Write(post.Imgdata)
		if err != nil {
			log.Print(err)
			return
		}

		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}

	query := "INSERT INTO comments (post_id, user_id, comment) VALUES (?,?,?)"
	_, err = db.Exec(query, postID, me.ID, r.FormValue("comment"))
	if err != nil {
		log.Print(err)
		return
	}

	query = "UPDATE posts SET comment_count = comment_count + 1 WHERE id = ?"
	_, err = db.Exec(query, postID)
	if err != nil {
		log.Print(err)
		return
	}

	cache.Del([]byte(fmt.Sprintf("comment_count_%d", postID)))
	cache.Del([]byte(fmt.Sprintf("comments_%d_%t", postID, true)))
	cache.Del([]byte(fmt.Sprintf("comments_%d_%t", postID, false)))
	cache.Del([]byte(fmt.Sprintf("template_post_%d", postID)))

	flag := 0
	err = db.Get(
		&flag,
		`
		WITH recent_posts AS (
		SELECT id FROM posts
		ORDER BY created_at DESC
		LIMIT 20
		)
		SELECT COUNT(*) FROM recent_posts
		WHERE id = ?
		`,
		postID,
	)
	if err != nil {
		log.Print(err)
		return
	}

	if flag == 1 {
		cache.Del(postsKey)
	}

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	query := "SELECT * FROM users WHERE authority = 0 AND id NOT IN (?) ORDER BY created_at DESC"
	query, args, err := sqlx.In(query, deletedUserIDs)
	if err != nil {
		log.Print(err)
		return
	}

	query = db.Rebind(query)
	err = db.Select(&users, query, args...)
	if err != nil {
		log.Print(err)
		return
	}

	csrfToken := getCSRFToken(r)

	if me.ID == 0 {
		w.Write([]byte(`<div><a href="/login">ログイン</a></div>`))
	} else {
		w.Write([]byte(fmt.Sprintf(`<div><a href="/@%s"><span class="isu-account-name">%s</span>さん</a></div>`, me.AccountName, me.AccountName)))

		if me.Authority == 1 {
			w.Write([]byte(`<div><a href="/admin/banned">管理者用ページ</a></div>`))
		}

		w.Write([]byte(`<div><a href="/logout">ログアウト</a></div>`))
	}

	w.Write([]byte(`<!DOCTYPE html> <html> <head> <meta charset="utf-8"> <title>Iscogram</title> <link href="/css/style.css" media="screen" rel="stylesheet" type="text/css"> </head> <body> <div class="container"> <div class="header"> <div class="isu-title"> <h1><a href="/">Iscogram</a></h1> </div> <div class="isu-header-menu">`))
	w.Write([]byte(`</div> </div>`))
	w.Write([]byte(`<div><form method="post" action="/admin/banned">`))

	for _, u := range users {
		w.Write([]byte(fmt.Sprintf(
			`<div><input type="checkbox" name="uid[]" id="uid_%d" value="%d" data-account-name="%s"> <label for="uid_%d">%s</label></div>`,
			u.ID,
			u.ID,
			u.AccountName,
			u.ID,
			u.AccountName,
		)))
	}

	w.Write([]byte(fmt.Sprintf(
		`<div class="form-submit"><input type="hidden" name="csrf_token" value="%s"><input type="submit" name="submit" value="submit"></div></form></div>`,
		csrfToken,
	)))
	w.Write([]byte(`</div> <script src="/js/timeago.min.js"></script> <script src="/js/main.js"></script> </body> </html>`))
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	for _, id := range r.Form["uid[]"] {

		i, err := strconv.Atoi(id)
		if err != nil {
			log.Print(err)
			return
		}

		deletedUserIDs = append(deletedUserIDs, i)
	}

	cache.Del(postsKey)

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	// profiler
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
	go func() {
		log.Fatal(http.ListenAndServe(":6060", nil))
	}()

	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	r := chi.NewRouter()

	r.Get("/initialize", getInitialize)
	r.Get("/login", getLogin)
	r.Post("/login", postLogin)
	r.Get("/register", getRegister)
	r.Post("/register", postRegister)
	r.Get("/logout", getLogout)
	r.Get("/", getIndex)
	r.Get("/posts", getPosts)
	r.Get("/posts/{id}", getPostsID)
	r.Post("/", postIndex)
	r.Get("/image/{id}.{ext}", getImage)
	r.Post("/comment", postComment)
	r.Get("/admin/banned", getAdminBanned)
	r.Post("/admin/banned", postAdminBanned)
	r.Get(`/@{accountName:[a-zA-Z]+}`, getAccountName)
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("../public")).ServeHTTP(w, r)
	})

	log.Fatal(http.ListenAndServe(":8080", r))
}
