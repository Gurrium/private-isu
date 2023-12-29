package main

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
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
	"sync"
	"time"

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
	Rendered     RenderedPost
}

type RenderedPost struct {
	ID              []byte
	CreatedAt       []byte
	UserAccountName []byte
	ImageURL        []byte
	Body            []byte
	CommentCount    []byte
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User      `db:"users"`
	Rendered  RenderedComment
}

type RenderedComment struct {
	UserAccountName []byte
	Comment         []byte
}

func init() {
	cache = freecache.NewCache(50 * 1024 * 1024)
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

// ref: https://github.com/methane/pixiv-private-isucon-2016/tree/master

type Session struct {
	Key         string
	UserID      int
	AccountName string
	Authority   int
	CSRFToken   string
	Flash       string
}

type SessionStore struct {
	sync.Mutex
	store map[string]*Session
}

var sessionStore = SessionStore{
	store: make(map[string]*Session),
}

const sessionName = "isucon_go_session"

func (store *SessionStore) Get(r *http.Request) *Session {
	cookie, _ := r.Cookie(sessionName)
	if cookie == nil {
		return &Session{}
	}

	key := cookie.Value
	store.Lock()
	s := store.store[key]
	store.Unlock()

	if s == nil {
		s = &Session{}
	}

	return s
}

func (store *SessionStore) Set(w http.ResponseWriter, sess *Session) {
	key := sess.Key
	if key == "" {
		b := make([]byte, 8)
		crand.Read(b)
		key = hex.EncodeToString(b)
		sess.Key = key
	}

	cookie := sessions.NewCookie(sessionName, key, &sessions.Options{})
	http.SetCookie(w, cookie)

	store.Lock()
	store.store[key] = sess
	store.Unlock()
}

func getSession(r *http.Request) *Session {
	return sessionStore.Get(r)
}

func getSessionUser(r *http.Request) User {
	sess := getSession(r)
	return User{
		ID:          sess.UserID,
		AccountName: sess.AccountName,
		Authority:   sess.Authority,
	}
}

func getFlash(w http.ResponseWriter, r *http.Request) string {
	sess := getSession(r)
	flash := sess.Flash

	sess.Flash = ""
	sessionStore.Set(w, sess)

	return flash
}

func setFlash(w http.ResponseWriter, r *http.Request, flash string) {
	sess := getSession(r)
	sess.Flash = flash
	sessionStore.Set(w, sess)
}

var (
	commentM     sync.Mutex
	commentStore map[int][]Comment = make(map[int][]Comment)
)

func getCommentsLocked(postID int) []Comment {
	if cs, ok := commentStore[postID]; ok {
		return cs
	}

	var cs []Comment

	query := `
		SELECT comments.post_id, comments.comment, users.account_name AS "users.account_name"
		FROM comments
		JOIN users ON comments.user_id = users.id
		WHERE post_id = ?
		ORDER BY comments.created_at
		`

	err := db.Select(&cs, query, postID)
	if err != nil {
		log.Print(err)
		return cs
	}

	for i := 0; i < len(cs); i++ {
		cs[i].Rendered = RenderedComment{
			UserAccountName: []byte(cs[i].User.AccountName),
			Comment:         []byte(cs[i].Comment),
		}
	}

	commentStore[postID] = cs
	return cs
}

func getComments(postID int) []Comment {
	commentM.Lock()
	defer commentM.Unlock()

	return getCommentsLocked(postID)
}

func appendComment(c Comment) {
	commentM.Lock()

	cs := getCommentsLocked(c.PostID)
	c.Rendered = RenderedComment{
		UserAccountName: []byte(c.User.AccountName),
		Comment:         []byte(c.Comment),
	}
	commentStore[c.PostID] = append(cs, c)

	commentM.Unlock()

	postM.Lock()

	getIndexPostsLocked(true, true)

	postM.Unlock()
}

func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	posts := make([]Post, 0, len(results))

	for _, p := range results {
		comments := getComments(p.ID)
		p.CommentCount = len(comments)

		if !allComments && len(comments) > 3 {
			comments = comments[len(comments)-3:]
		}

		p.Comments = comments
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
	return session.CSRFToken
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

	flash := getFlash(w, r)

	templateLayout(
		w,
		me,
		func(w io.Writer) {
			templateLogin(w, flash)
		},
	)
}

var templateLoginByteArray = [...][]byte{
	[]byte(`<div class="header"> <h1>ログイン</h1> </div>`),
	[]byte(`<div id="notice-message" class="alert alert-danger">`),
	[]byte(`</div>`),
	[]byte(`<div class="submit"> <form method="post" action="/login"> <div class="form-account-name"> <span>アカウント名</span> <input type="text" name="account_name"> </div> <div class="form-password"> <span>パスワード</span> <input type="password" name="password"> </div> <div class="form-submit"> <input type="submit" name="submit" value="submit"> </div> </form> </div> <div class="isu-register"> <a href="/register">ユーザー登録</a> </div>`),
}

func templateLogin(w io.Writer, flash string) {
	w.Write(templateLoginByteArray[0])

	if len(flash) > 0 {
		w.Write(templateLoginByteArray[1])
		w.Write([]byte(flash))
		w.Write(templateLoginByteArray[2])
	}

	w.Write(templateLoginByteArray[3])
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	time.Sleep(time.Millisecond * 200)

	if u != nil {
		session := Session{
			UserID:      u.ID,
			AccountName: u.AccountName,
			Authority:   u.Authority,
			CSRFToken:   secureRandomStr(16),
		}

		sessionStore.Set(w, &session)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		setFlash(w, r, "アカウント名かパスワードが間違っています")

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
	}{User{}, getFlash(w, r)})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		setFlash(w, r, "アカウント名は3文字以上、パスワードは6文字以上である必要があります")

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE account_name = ?", accountName)

	if exists == 1 {
		setFlash(w, r, "アカウント名がすでに使われています")

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO users (account_name, passhash) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}

	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	session := Session{
		UserID:      int(uid),
		AccountName: accountName,
		Authority:   0,
		CSRFToken:   secureRandomStr(16),
	}

	sessionStore.Set(w, &session)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	session.UserID = 0
	session.AccountName = ""
	session.Authority = 0
	session.CSRFToken = ""
	sessionStore.Set(w, session)

	http.Redirect(w, r, "/", http.StatusFound)
}

var (
	postM     sync.Mutex
	postStore []Post = make([]Post, 0, cachedPostsCount+1)
)

const cachedPostsCount = postsPerPage * 100

func getIndexPostsLocked(forceUpdate bool, skipQuery bool) []Post {
	// 初期データの時点でpostsPerPage以上あるのは確定
	if len(postStore) >= cachedPostsCount && !forceUpdate {
		return postStore
	}

	ps := make([]Post, 0, cachedPostsCount)

	if skipQuery {
		ps = postStore
	} else {
		query := `
		SELECT posts.id, posts.body, posts.mime, posts.created_at,
		users.account_name AS "users.account_name", users.authority AS "users.authority"
		FROM posts
		JOIN users ON posts.user_id = users.id
		WHERE users.id NOT IN (?)
		ORDER BY posts.created_at DESC
		LIMIT ?
		`

		query, args, err := sqlx.In(query, deletedUserIDs, cachedPostsCount)
		if err != nil {
			log.Print(err)
			return []Post{}
		}

		query = db.Rebind(query)
		err = db.Select(&ps, query, args...)
		if err != nil {
			log.Print(err)
			return []Post{}
		}
	}

	results, err := makePosts(ps, "", false)
	if err != nil {
		log.Print(err)
		return []Post{}
	}

	for i := 0; i < len(results); i++ {
		results[i].Rendered = RenderedPost{
			ID:              []byte(strconv.Itoa(results[i].ID)),
			CreatedAt:       []byte(results[i].CreatedAt.Format(ISO8601Format)),
			UserAccountName: []byte(results[i].User.AccountName),
			ImageURL:        []byte(imageURL(results[i])),
			Body:            []byte(results[i].Body),
			CommentCount:    []byte(strconv.Itoa(results[i].CommentCount)),
		}
	}

	postStore = results
	return results
}

func getIndexPosts() []Post {
	postM.Lock()
	defer postM.Unlock()

	return getIndexPostsLocked(false, false)
}

func appendPost(p Post) {
	postM.Lock()
	defer postM.Unlock()

	ps := getIndexPostsLocked(false, false)
	p.Rendered = RenderedPost{
		ID:              []byte(strconv.Itoa(p.ID)),
		CreatedAt:       []byte(p.CreatedAt.Format(ISO8601Format)),
		UserAccountName: []byte(p.User.AccountName),
		ImageURL:        []byte(imageURL(p)),
		Body:            []byte(p.Body),
		CommentCount:    []byte(strconv.Itoa(p.CommentCount)),
	}
	postStore = append([]Post{p}, ps...)
	postStore = postStore[:cachedPostsCount]
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	results := getIndexPosts()

	csrfToken := getCSRFToken(r)
	posts := make([]Post, 0, postsPerPage)
	for _, p := range results {
		p.CSRFToken = csrfToken
		posts = append(posts, p)

		if len(posts) >= postsPerPage {
			break
		}
	}

	flash := getFlash(w, r)

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
	rendered := post.Rendered
	if len(rendered.ID) > 0 {
		w.Write(templatePostByteArray[0])
		w.Write(rendered.ID)
		w.Write(templatePostByteArray[1])
		w.Write(rendered.CreatedAt)
		w.Write(templatePostByteArray[2])
		w.Write(rendered.UserAccountName)
		w.Write(templatePostByteArray[3])
		w.Write(rendered.UserAccountName)
		w.Write(templatePostByteArray[4])
		w.Write(rendered.ID)
		w.Write(templatePostByteArray[5])
		w.Write(rendered.CreatedAt)
		w.Write(templatePostByteArray[6])
		w.Write(rendered.ImageURL)
		w.Write(templatePostByteArray[7])
		w.Write(rendered.UserAccountName)
		w.Write(templatePostByteArray[8])
		w.Write(rendered.UserAccountName)
		w.Write(templatePostByteArray[9])
		w.Write(rendered.Body)
		w.Write(templatePostByteArray[10])
		w.Write(rendered.CommentCount)
		w.Write(templatePostByteArray[11])

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

		for _, comment := range post.Comments {
			w.Write(templatePostByteArray[12])
			w.Write(comment.Rendered.UserAccountName)
			w.Write(templatePostByteArray[13])
			w.Write(comment.Rendered.UserAccountName)
			w.Write(templatePostByteArray[14])
			w.Write(comment.Rendered.Comment)
			w.Write(templatePostByteArray[15])
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

		w.Write(templatePostByteArray[16])
		w.Write(rendered.ID)
		w.Write(templatePostByteArray[17])
		w.Write([]byte(post.CSRFToken))
		w.Write(templatePostByteArray[18])
		// w.Write([]byte(fmt.Sprintf(
		// 	`<div class="isu-comment-form"> <form method="post" action="/comment"> <input type="text" name="comment">
		// 	<input type="hidden" name="post_id" value="%d">
		// 	<input type="hidden" name="csrf_token" value="%s">
		// 	<input type="submit" name="submit" value="submit"> </form> </div> </div> </div>
		// 	`,
		// 	post.ID,
		// 	post.CSRFToken,
		// )))
	} else {
		createdAt := []byte(post.CreatedAt.Format(ISO8601Format))
		postID := []byte(strconv.Itoa(post.ID))
		userAccountName := []byte(post.User.AccountName)

		w.Write(templatePostByteArray[0])
		w.Write(postID)
		w.Write(templatePostByteArray[1])
		w.Write(createdAt)
		w.Write(templatePostByteArray[2])
		w.Write(userAccountName)
		w.Write(templatePostByteArray[3])
		w.Write(userAccountName)
		w.Write(templatePostByteArray[4])
		w.Write(postID)
		w.Write(templatePostByteArray[5])
		w.Write(createdAt)
		w.Write(templatePostByteArray[6])
		w.Write([]byte(imageURL(post)))
		w.Write(templatePostByteArray[7])
		w.Write(userAccountName)
		w.Write(templatePostByteArray[8])
		w.Write(userAccountName)
		w.Write(templatePostByteArray[9])
		w.Write([]byte(post.Body))
		w.Write(templatePostByteArray[10])
		w.Write([]byte(strconv.Itoa(post.CommentCount)))
		w.Write(templatePostByteArray[11])

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

			w.Write(templatePostByteArray[12])
			w.Write(userAccountName)
			w.Write(templatePostByteArray[13])
			w.Write(userAccountName)
			w.Write(templatePostByteArray[14])
			w.Write([]byte(c.Comment))
			w.Write(templatePostByteArray[15])
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

		w.Write(templatePostByteArray[16])
		w.Write(postID)
		w.Write(templatePostByteArray[17])
		w.Write([]byte(post.CSRFToken))
		w.Write(templatePostByteArray[18])
		// w.Write([]byte(fmt.Sprintf(
		// 	`<div class="isu-comment-form"> <form method="post" action="/comment"> <input type="text" name="comment">
		// 	<input type="hidden" name="post_id" value="%d">
		// 	<input type="hidden" name="csrf_token" value="%s">
		// 	<input type="submit" name="submit" value="submit"> </form> </div> </div> </div>
		// 	`,
		// 	post.ID,
		// 	post.CSRFToken,
		// )))
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

	time.Sleep(time.Millisecond * 200)

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

	cachedResults := make([]Post, 0, postsPerPage)
	cachedPosts := getIndexPosts()
	for _, p := range cachedPosts {
		if p.CreatedAt.Compare(t) <= 0 {
			cachedResults = append(cachedResults, p)
		}

		if len(cachedResults) >= postsPerPage {
			break
		}
	}

	if len(cachedResults) < postsPerPage {
		query := `
		SELECT posts.id, posts.user_id, posts.body, posts.mime, posts.created_at,
		 users.id AS "users.id", users.account_name AS "users.account_name", users.authority AS "users.authority", users.created_at AS "users.created_at"
		FROM posts
		JOIN users ON posts.user_id = users.id
		WHERE posts.created_at <= ? AND users.id NOT IN (?)
		ORDER BY posts.created_at DESC
		LIMIT ?
		`

		var bound time.Time

		if len(cachedResults) == 0 {
			bound = t
		} else {
			bound = cachedResults[len(cachedResults)-1].CreatedAt
		}

		results := make([]Post, 0, postsPerPage-len(cachedResults))

		query, args, err := sqlx.In(query, bound.Format(ISO8601Format), deletedUserIDs, cap(results))
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

		cachedResults = append(cachedResults, results...)
	}

	posts, err := makePosts(cachedResults, getCSRFToken(r), false)
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

	cacheKey := []byte(fmt.Sprintf("get_posts_id_%d", pid))
	var post Post

	cached, err := cache.Get(cacheKey)
	if err == nil {
		err := sonnet.Unmarshal(cached, &post)
		if err != nil {
			log.Print(err)
			return
		}
	} else if err == freecache.ErrNotFound {
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

		posts, err := makePosts(results, "", true)
		if err != nil {
			log.Print(err)
			return
		}

		if len(posts) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		post = posts[0]

		b, err := sonnet.Marshal(post)
		if err != nil {
			log.Print(err)
			return
		}

		err = cache.Set(cacheKey, b, 10)
		if err != nil {
			log.Print(err)
			return
		}
	} else {
		log.Print(err)
		return
	}

	post.CSRFToken = getCSRFToken(r)

	me := getSessionUser(r)

	templateLayout(
		w,
		me,
		func(w io.Writer) {
			templatePostID(w, post)
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
		setFlash(w, r, "画像が必須です")

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
			setFlash(w, r, "投稿できる画像形式はjpgとpngとgifだけです")

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
		setFlash(w, r, "ファイルサイズが大きすぎます")

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

	var createdAt time.Time
	err = db.Get(&createdAt, "SELECT created_at FROM posts WHERE id = ?", pid)
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

	time.Sleep(time.Millisecond * 200)

	appendPost(
		Post{
			ID:        int(pid),
			User:      me,
			Body:      r.FormValue("body"),
			Mime:      mime,
			CreatedAt: createdAt,
		},
	)

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

	appendComment(
		Comment{
			PostID:  postID,
			User:    me,
			Comment: r.FormValue("comment"),
		},
	)

	cache.Del([]byte(fmt.Sprintf("get_posts_id_%d", postID)))

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

	getIndexPostsLocked(true, false)

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

	maxOpenConns := 10
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxOpenConns)
	db.SetConnMaxLifetime(time.Second * time.Duration(maxOpenConns))
	db.SetConnMaxIdleTime(time.Second * time.Duration(maxOpenConns))

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
