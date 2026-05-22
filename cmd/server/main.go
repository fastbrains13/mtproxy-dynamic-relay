package main

import (
	"context"
	"database/sql"
	_ "modernc.org/sqlite"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	_ "embed"
	"golang.org/x/crypto/bcrypt"
)

//go:embed web/admin.html
var adminHTML string

type Proxy struct {
	ID     int    `json:"id"`
	ListID int    `json:"list_id"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Secret string `json:"secret"`
	RTT    int64  `json:"rtt"`
	Status string `json:"status"`
}

type ProxyList struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Port int    `json:"port"`
}

var (
	db            *sql.DB
	mu            sync.RWMutex
	bestProxies   = make(map[int]Proxy) // listID -> best proxy
	activeListen  = make(map[int]net.Listener)
	listenMu      sync.Mutex
)

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "file:/opt/mtproxy-relay/data/app.db?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil { log.Fatal(err) }
	
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, pass_hash TEXT);
		CREATE TABLE IF NOT EXISTS lists (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, port INTEGER UNIQUE);
		CREATE TABLE IF NOT EXISTS proxies (id INTEGER PRIMARY KEY AUTOINCREMENT, list_id INTEGER, host TEXT, port INTEGER, secret TEXT, rtt INTEGER DEFAULT 0, status TEXT DEFAULT 'pending');
	`)
	if err != nil { log.Fatal(err) }

	var count int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		db.Exec("INSERT INTO users (id, username, pass_hash) VALUES (1, 'admin', ?)", string(hash))
		log.Println("🔑 Создан дефолтный логин: admin / admin")
	}
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sess")
		if err != nil || c.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func startMonitor(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var lists []ProxyList
			rows, _ := db.Query("SELECT id, name, port FROM lists")
			for rows.Next() {
				var l ProxyList
				rows.Scan(&l.ID, &l.Name, &l.Port)
				lists = append(lists, l)
			}
			rows.Close()

			for _, list := range lists {
				var proxies []Proxy
				rows, _ := db.Query("SELECT id, host, port, secret FROM proxies WHERE list_id=?", list.ID)
				for rows.Next() {
					var p Proxy
					rows.Scan(&p.ID, &p.Host, &p.Port, &p.Secret)
					proxies = append(proxies, p)
				}
				rows.Close()

				var best *Proxy
				for i := range proxies {
					start := time.Now()
					conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", proxies[i].Host, proxies[i].Port), 2*time.Second)
					rtt := time.Since(start).Milliseconds()
					status := "fail"
					if err == nil && rtt > 0 {
						conn.Close()
						status = "ok"
						if best == nil || rtt < best.RTT {
							p := proxies[i]
							p.RTT = rtt
							p.Status = status
							best = &p
						}
					}
					db.Exec("UPDATE proxies SET rtt=?, status=? WHERE id=?", rtt, status, proxies[i].ID)
				}
				mu.Lock()
				if best != nil {
					bestProxies[list.ID] = *best
				} else {
					delete(bestProxies, list.ID)
				}
				mu.Unlock()
			}
		}
	}
}

func startListener(port int, name string) error {
	listenMu.Lock()
	defer listenMu.Unlock()
	if _, exists := activeListen[port]; exists {
		return nil
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return fmt.Errorf("bind port %d: %w", port, err)
	}
	activeListen[port] = ln
	log.Printf("[%s] 📡 Слушаю порт %d", name, port)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil { return }
			go handleRelay(conn, port, name)
		}
	}()
	return nil
}

func handleRelay(conn net.Conn, listID int, name string) {
	defer conn.Close()
	mu.RLock()
	bp, ok := bestProxies[listID]
	mu.RUnlock()
	if !ok { conn.Close(); return }

	backend, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", bp.Host, bp.Port), 3*time.Second)
	if err != nil { log.Printf("[%s] Backend fail: %v", name, err); return }
	defer backend.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(backend, conn) }()
	go func() { defer wg.Done(); io.Copy(conn, backend) }()
	wg.Wait()
}

func initListeners(ctx context.Context) {
	var lists []ProxyList
	rows, _ := db.Query("SELECT id, name, port FROM lists")
	for rows.Next() {
		var l ProxyList
		rows.Scan(&l.ID, &l.Name, &l.Port)
		lists = append(lists, l)
	}
	rows.Close()

	for _, l := range lists {
		go startListener(l.Port, l.Name)
	}

	// Watch for new lists
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done(): return
			case <-ticker.C:
				var lists []ProxyList
				rows, _ := db.Query("SELECT id, name, port FROM lists")
				for rows.Next() {
					var l ProxyList
					rows.Scan(&l.ID, &l.Name, &l.Port)
					lists = append(lists, l)
				}
				rows.Close()
				for _, l := range lists {
					startListener(l.Port, l.Name)
				}
			}
		}
	}()
}

func setupRoutes(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			u, p := r.FormValue("username"), r.FormValue("password")
			var hash string
			db.QueryRow("SELECT pass_hash FROM users WHERE username=?", u).Scan(&hash)
			if hash != "" && bcrypt.CompareHashAndPassword([]byte(hash), []byte(p)) == nil {
				http.SetCookie(w, &http.Cookie{Name: "sess", Value: "auth", Path: "/", MaxAge: 86400, HttpOnly: true, SameSite: http.SameSiteStrictMode})
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
		}
		fmt.Fprintf(w, `<html><body style="font-family:sans-serif;padding:40px"><h2>🔐 Вход</h2><form method="post">
		<input name="username" placeholder="Логин" style="padding:8px;margin:5px 0"><br>
		<input type="password" name="password" placeholder="Пароль" style="padding:8px;margin:5px 0"><br>
		<button type="submit" style="padding:8px 16px;cursor:pointer">Войти</button></form></body></html>`)
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sess", MaxAge: -1, Path: "/"})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	mux.HandleFunc("/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, adminHTML)
	}))
	mux.HandleFunc("/api/lists", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			rows, _ := db.Query("SELECT id, name, port FROM lists")
			defer rows.Close()
			var lists []ProxyList
			for rows.Next() { var l ProxyList; rows.Scan(&l.ID, &l.Name, &l.Port); lists = append(lists, l) }
			json.NewEncoder(w).Encode(lists)
		} else if r.Method == "POST" {
			name, portStr := r.FormValue("name"), r.FormValue("port")
			port, _ := strconv.Atoi(portStr)
			db.Exec("INSERT INTO lists (name, port) VALUES (?, ?)", name, port)
			w.Write([]byte(`{"ok":true}`))
		} else if r.Method == "DELETE" {
			id := r.URL.Query().Get("id")
			db.Exec("DELETE FROM lists WHERE id=?", id)
			db.Exec("DELETE FROM proxies WHERE list_id=?", id)
			listenMu.Lock()
			if ln, ok := activeListen[port]; ok { ln.Close(); delete(activeListen, port) }
			listenMu.Unlock()
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	mux.HandleFunc("/api/proxies", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			rows, _ := db.Query("SELECT id, list_id, host, port, secret, rtt, status FROM proxies")
			defer rows.Close()
			var ps []Proxy
			for rows.Next() { var p Proxy; rows.Scan(&p.ID, &p.ListID, &p.Host, &p.Port, &p.Secret, &p.RTT, &p.Status); ps = append(ps, p) }
			json.NewEncoder(w).Encode(ps)
		} else if r.Method == "POST" {
			lid, _ := strconv.Atoi(r.FormValue("list_id"))
			host, portStr, secret := r.FormValue("host"), r.FormValue("port"), r.FormValue("secret")
			port, _ := strconv.Atoi(portStr)
			db.Exec("INSERT INTO proxies (list_id, host, port, secret) VALUES (?, ?, ?, ?)", lid, host, port, secret)
			w.Write([]byte(`{"ok":true}`))
		} else if r.Method == "DELETE" {
			db.Exec("DELETE FROM proxies WHERE id=?", r.URL.Query().Get("id"))
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	mux.HandleFunc("/api/status", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.RLock()
		defer mu.RUnlock()
		json.NewEncoder(w).Encode(bestProxies)
	}))
	go http.ListenAndServe(":8080", mux)
	log.Println("🌐 Админка: http://<IP>:8080 | Логин: admin / Пароль: admin")
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	os.MkdirAll("/opt/mtproxy-relay/data", 0750)
	initDB()
	initListeners(ctx)
	go startMonitor(ctx)
	setupRoutes(ctx)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("🛑 Graceful shutdown...")
	listenMu.Lock()
	for _, ln := range activeListen { ln.Close() }
	listenMu.Unlock()
	cancel()
}