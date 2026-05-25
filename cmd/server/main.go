package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
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
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Port   int    `json:"port"`
	Secret string `json:"secret"`
}

var (
	db           *sql.DB
	mu           sync.RWMutex
	bestProxies  = make(map[int]Proxy)
	activeListen = make(map[int]net.Listener)
	listenMu     sync.Mutex
)

func generateSecret() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func decodeMTProxySecret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(secret)
	if len(secret) == 32 {
		decoded, err := hex.DecodeString(secret)
		if err != nil || len(decoded) != 16 {
			return nil, fmt.Errorf("invalid hex secret")
		}
		return decoded, nil
	}
	if len(secret) > 32 {
		if _, err := hex.DecodeString(secret); err == nil {
			decoded, _ := hex.DecodeString(secret)
			if len(decoded) >= 17 {
				return decoded[1:17], nil
			} else if len(decoded) >= 16 {
				return decoded[len(decoded)-16:], nil
			}
		}
	}
	if len(secret) < 32 && !strings.ContainsAny(secret, "_/-") {
		if _, err := hex.DecodeString(secret); err == nil {
			padded := secret + strings.Repeat("0", 32-len(secret))
			decoded, _ := hex.DecodeString(padded)
			return decoded[:16], nil
		}
	}
	s := strings.ReplaceAll(secret, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	for len(s)%4 != 0 {
		s += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 secret: %w", err)
	}
	if len(decoded) >= 17 {
		return decoded[1:17], nil
	} else if len(decoded) >= 16 {
		return decoded[len(decoded)-16:], nil
	}
	result := make([]byte, 16)
	copy(result, decoded)
	return result, nil
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "file:/opt/mtproxy-relay/data/app.db?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, pass_hash TEXT);
		CREATE TABLE IF NOT EXISTS lists (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, port INTEGER UNIQUE, secret TEXT);
		CREATE TABLE IF NOT EXISTS proxies (id INTEGER PRIMARY KEY AUTOINCREMENT, list_id INTEGER, host TEXT, port INTEGER, secret TEXT, rtt INTEGER DEFAULT 0, status TEXT DEFAULT 'pending');
	`)
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec("ALTER TABLE lists ADD COLUMN secret TEXT")
	if err != nil {
		log.Println("ℹ️  Колонка secret уже существует")
	}
	rows, _ := db.Query("SELECT id FROM lists WHERE secret IS NULL")
	for rows.Next() {
		var id int
		rows.Scan(&id)
		secret := generateSecret()
		db.Exec("UPDATE lists SET secret=? WHERE id=?", secret, id)
		log.Printf("🔑 Сгенерирован секрет для списка #%d: %s", id, secret)
	}
	rows.Close()
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		db.Exec("INSERT INTO users (id, username, pass_hash) VALUES (1, 'admin', ?)", string(hash))
		log.Println("🔑 Создан дефолтный логин: admin / Пароль: admin")
	}
	log.Println("✅ База данных инициализирована")
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
			rows, err := db.Query("SELECT id, name, port, secret FROM lists")
			if err != nil {
				log.Printf("❌ Ошибка получения списков: %v", err)
				continue
			}
			for rows.Next() {
				var l ProxyList
				if err := rows.Scan(&l.ID, &l.Name, &l.Port, &l.Secret); err == nil {
					lists = append(lists, l)
				}
			}
			rows.Close()
			for _, list := range lists {
				var proxies []Proxy
				rows, err := db.Query("SELECT id, host, port, secret FROM proxies WHERE list_id=?", list.ID)
				if err != nil { continue }
				for rows.Next() {
					var p Proxy
					if err := rows.Scan(&p.ID, &p.Host, &p.Port, &p.Secret); err == nil {
						proxies = append(proxies, p)
					}
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
					log.Printf("[%s] ✅ Лучший прокси: %s:%d (%dms)", list.Name, best.Host, best.Port, best.RTT)
				} else {
					delete(bestProxies, list.ID)
					log.Printf("[%s] ❌ Нет доступных прокси", list.Name)
				}
				mu.Unlock()
			}
		}
	}
}

func startListener(port int, name string) error {
	listenMu.Lock()
	defer listenMu.Unlock()
	if _, exists := activeListen[port]; exists { return nil }
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil { return fmt.Errorf("bind port %d: %w", port, err) }
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

type xorConn struct {
	net.Conn
	table []byte
	idx   int
}

func (c *xorConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	for i := 0; i < n; i++ {
		b[i] ^= c.table[c.idx]
		c.idx = (c.idx + 1) % 256
	}
	return n, err
}

func (c *xorConn) Write(b []byte) (int, error) {
	buf := make([]byte, len(b))
	copy(buf, b)
	for i := range buf {
		buf[i] ^= c.table[c.idx]
		c.idx = (c.idx + 1) % 256
	}
	return c.Conn.Write(buf)
}

func initXorTable(nonce uint32) []byte {
	t := make([]byte, 256)
	for i := range t {
		nonce = (nonce*1103515245 + 12345) & 0xffffffff
		t[i] = byte(nonce & 0xff)
	}
	return t
}

func handleRelay(conn net.Conn, port int, name string) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()
	log.Printf("[%s] 📥 Новое подключение от %s", name, clientAddr)

	var listID int
	var listSecretHex string
	err := db.QueryRow("SELECT id, secret FROM lists WHERE port=?", port).Scan(&listID, &listSecretHex)
	if err != nil {
		log.Printf("[%s] ❌ Не найден список для порта %d", name, port)
		return
	}

	mu.RLock()
	bp, ok := bestProxies[listID]
	mu.RUnlock()
	if !ok {
		log.Printf("[%s] ❌ Нет активного прокси для списка #%d", name, listID)
		return
	}
	log.Printf("[%s] 🎯 Лучший бэкенд: %s:%d", name, bp.Host, bp.Port)

	backend, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", bp.Host, bp.Port), 3*time.Second)
	if err != nil {
		log.Printf("[%s] ❌ Backend connect fail: %v", name, err)
		return
	}
	defer backend.Close()

	buf := make([]byte, 64)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		log.Printf("[%s] ❌ Ошибка чтения hello: %v", name, err)
		return
	}

	needsObfuscation := len(listSecretHex) > 2 && strings.ToLower(listSecretHex[:2]) == "ee"

	if needsObfuscation {
		log.Printf("[%s] 🔐 Обнаружен obfuscated-секрет (ee), инициализируем XOR...", name)
		if _, err := backend.Write(buf); err != nil {
			log.Printf("[%s] ❌ Ошибка отправки hello: %v", name, err)
			return
		}
		resp := make([]byte, 64)
		backend.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(backend, resp); err != nil {
			log.Printf("[%s] ❌ Ошибка чтения ответа бэкенда: %v", name, err)
			return
		}
		backend.SetReadDeadline(time.Time{})
		nonce := binary.LittleEndian.Uint32(resp[:4])
		xorTable := initXorTable(nonce)
		log.Printf("[%s] ✅ XOR handshake завершён, маска: %08x", name, nonce)
		conn = &xorConn{Conn: conn, table: xorTable}
		backend = &xorConn{Conn: backend, table: xorTable}
	} else {
		ourKey, err := decodeMTProxySecret(listSecretHex)
		if err != nil {
			log.Printf("[%s] ❌ Ошибка декодирования секрета: %v", name, err)
			return
		}
		copy(buf[48:64], ourKey)
		if _, err := backend.Write(buf); err != nil {
			log.Printf("[%s] ❌ Ошибка отправки бэкенду: %v", name, err)
			return
		}
	}

	log.Printf("[%s] 🔄 Начинаем relay трафика", name)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(backend, conn) }()
	go func() { defer wg.Done(); io.Copy(conn, backend) }()
	wg.Wait()
	log.Printf("[%s] 🔚 Сессия завершена", name)
}

func initListeners(ctx context.Context) {
	var lists []ProxyList
	rows, _ := db.Query("SELECT id, name, port, secret FROM lists")
	for rows.Next() {
		var l ProxyList
		rows.Scan(&l.ID, &l.Name, &l.Port, &l.Secret)
		lists = append(lists, l)
	}
	rows.Close()
	for _, l := range lists {
		go startListener(l.Port, l.Name)
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var lists []ProxyList
				rows, _ := db.Query("SELECT id, name, port, secret FROM lists")
				for rows.Next() {
					var l ProxyList
					rows.Scan(&l.ID, &l.Name, &l.Port, &l.Secret)
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
				http.SetCookie(w, &http.Cookie{
					Name: "sess", Value: "auth", Path: "/", MaxAge: 86400,
					HttpOnly: true, SameSite: http.SameSiteStrictMode,
				})
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			http.Error(w, "Неверный логин или пароль", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Вход</title><style>body{font-family:sans-serif;padding:40px;background:#f5f7fa}.box{max-width:400px;margin:auto;background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1)}input{width:100%%;padding:10px;margin:10px 0;border:1px solid #ccc;border-radius:4px}button{width:100%%;padding:12px;background:#007bff;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px}</style></head><body><div class="box"><h2>🔐 Вход</h2><form method="post"><input name="username" placeholder="Логин" required><input type="password" name="password" placeholder="Пароль" required><button type="submit">Войти</button></form></div></body></html>`)
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sess", MaxAge: -1, Path: "/"})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	mux.HandleFunc("/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, adminHTML)
	}))
	mux.HandleFunc("/api/lists", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			rows, _ := db.Query("SELECT id, name, port, secret FROM lists")
			defer rows.Close()
			var lists []ProxyList
			for rows.Next() {
				var l ProxyList
				rows.Scan(&l.ID, &l.Name, &l.Port, &l.Secret)
				lists = append(lists, l)
			}
			json.NewEncoder(w).Encode(lists)
		} else if r.Method == "POST" {
			name, portStr := r.FormValue("name"), r.FormValue("port")
			port, _ := strconv.Atoi(portStr)
			secret := generateSecret()
			_, err := db.Exec("INSERT INTO lists (name, port, secret) VALUES (?, ?, ?)", name, port, secret)
			if err == nil {
				go startListener(port, name)
			}
			w.Write([]byte(`{"ok":true}`))
		} else if r.Method == "DELETE" {
			id := r.URL.Query().Get("id")
			var port int
			db.QueryRow("SELECT port FROM lists WHERE id=?", id).Scan(&port)
			listenMu.Lock()
			if port > 0 {
				if ln, ok := activeListen[port]; ok {
					ln.Close()
					delete(activeListen, port)
				}
			}
			listenMu.Unlock()
			db.Exec("DELETE FROM lists WHERE id=?", id)
			db.Exec("DELETE FROM proxies WHERE list_id=?", id)
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	mux.HandleFunc("/api/proxies", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			rows, _ := db.Query("SELECT id, list_id, host, port, secret, rtt, status FROM proxies")
			defer rows.Close()
			var ps []Proxy
			for rows.Next() {
				var p Proxy
				rows.Scan(&p.ID, &p.ListID, &p.Host, &p.Port, &p.Secret, &p.RTT, &p.Status)
				ps = append(ps, p)
			}
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
	go func() {
		log.Println("🌐 Админка: http://<IP>:8080 | Логин: admin / Пароль: admin")
		if err := http.ListenAndServe(":8080", mux); err != nil {
			log.Fatal(err)
		}
	}()
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	os.MkdirAll("/opt/mtproxy-relay/data", 0750)
	initDB()
	initListeners(ctx)
	go startMonitor(ctx)
	setupRoutes(ctx)
	log.Println("🚀 MTProxy Dynamic Relay запущен")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("🛑 Получен сигнал завершения, закрываем соединения...")
	listenMu.Lock()
	for port, ln := range activeListen {
		ln.Close()
		log.Printf("🔌 Закрыт порт %d", port)
	}
	listenMu.Unlock()
	cancel()
	log.Println("✅ Завершение работы")
}