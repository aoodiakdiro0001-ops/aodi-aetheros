// Aodı-AetherOS — topological consensus fabric hub (Go stdlib only).
//
// Honest TEP: we do NOT replace TCP/IP. What ships, for real:
//   - /net/graph     - link-state database: every node announces its
//     measured RTT map (real round-trip probes)
//   - /net/route     - live Dijkstra min-cost routes over that graph
//     (the topological layer, computed not claimed)
//   - /vote/cast + /consensus/head - quorum consensus over matrix epochs:
//     majority (n/2+1) commits the epoch head
//   - optional HMAC-SHA256 request auth (AE_SECRET) for every endpoint
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

const version = "1.0.0"

var (
	mu      sync.RWMutex
	links   = map[string]edge{}     // src -> map[dst]rtt
	cells   = map[string]cellInfo{} // name -> direct info
	votes   = map[int64][]vote{}    // epoch -> votes
	secret  string
	hubName = "hub"
	started = time.Now()
)

type edge struct {
	Src  string             `json:"src"`
	Maps map[string]float64 `json:"rtt_map"` // dst -> ms
}

type cellInfo struct {
	Name   string  `json:"name"`
	URL    string  `json:"url"`
	Direct float64 `json:"direct_rtt_ms"`
	Seen   string  `json:"last_seen"`
}

type vote struct {
	Voter string `json:"voter"`
	Head  string `json:"head"`
	TS    int64  `json:"ts"`
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// ---------- optional HMAC auth ----------
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }

func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if secret != "" {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			r.Body = io.NopCloser(bytes.NewReader(body))
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(body)
			if got := r.Header.Get("X-AE-Sig"); !hmac.Equal(
				[]byte(got), []byte(hex.EncodeToString(mac.Sum(nil)))) {
				writeJSON(w, 401, map[string]string{"error": "bad hmac"})
				return
			}
		}
		next(w, r)
	}
}

// ---------- topology: link-state + Dijkstra ----------
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func graphHandler(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()
	edges := make([]map[string]any, 0, len(links))
	for src, lr := range links {
		edges = append(edges, map[string]any{
			"src": src, "rtt_map": lr.Maps})
	}
	nodes := make([]map[string]any, 0, len(cells))
	for name, c := range cells {
		nodes = append(nodes, map[string]any{
			"name": name, "url": c.URL, "direct_rtt_ms": c.Direct})
	}
	writeJSON(w, 200, map[string]any{"nodes": nodes, "edges": edges})
}

func routeHandler(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	adj := map[string]map[string]float64{}
	for src, lr := range links {
		for dst, ms := range lr.Maps {
			if adj[src] == nil {
				adj[src] = map[string]float64{}
			}
			if adj[dst] == nil {
				adj[dst] = map[string]float64{}
			}
			if adj[src][dst] == 0 || rttGt(adj[src][dst], ms) {
				// symmetric min-cost link (undirected, best of announces)
				adj[src][dst] = ms
				adj[dst][src] = ms
			}
		}
	}
	for name, c := range cells {
		if adj[hubName] == nil {
			adj[hubName] = map[string]float64{}
		}
		if adj[name] == nil {
			adj[name] = map[string]float64{}
		}
		if adj[hubName][name] == 0 {
			adj[hubName][name] = c.Direct
			adj[name][hubName] = c.Direct
		}
	}
	mu.RUnlock()

	src := r.URL.Query().Get("from")
	if src == "" {
		src = getenv("AE_HUB_NAME", hubName)
	}
	dist, via := dijkstra(adj, src)
	table := map[string]map[string]any{}
	for id := range dist {
		if id == src {
			continue
		}
		table[id] = map[string]any{
			"cost_ms": round2(dist[id]), "via": via[id],
			"path": pathTo(via, src, id)}
	}
	writeJSON(w, 200, map[string]any{
		"algorithm": "dijkstra", "source": src, "routes": table,
		"nodes": len(dist), "edges": countEdges(adj)})
}

func rttGt(a, b float64) bool { return a > b+1e-9 }

func countEdges(adj map[string]map[string]float64) int {
	n := 0
	for _, m := range adj {
		n += len(m)
	}
	return n / 2
}

func dijkstra(adj map[string]map[string]float64, src string) (
	map[string]float64, map[string]string) {
	dist := map[string]float64{src: 0}
	via := map[string]string{}
	visited := map[string]bool{}
	for len(visited) < len(adj) {
		minID, minV := "", -1e18
		for id, d := range dist {
			if !visited[id] && (minID == "" || d < minV) {
				minID, minV = id, d
			}
		}
		if minID == "" {
			break
		}
		visited[minID] = true
		for dst, w := range adj[minID] {
			nd := dist[minID] + w
			if dist[dst] == 0 && dst != src {
				dist[dst] = nd
				via[dst] = minID
			} else if nd < dist[dst] {
				dist[dst] = nd
				via[dst] = minID
			}
		}
	}
	return dist, via
}

func pathTo(via map[string]string, src, dst string) []string {
	if _, ok := via[dst]; !ok && dst != src {
		return []string{"unreachable"}
	}
	var rev []string
	cur := dst
	for cur != src && cur != "" {
		rev = append(rev, cur)
		cur = via[cur]
	}
	rev = append(rev, src)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}

// ---------- announcements + consensus ----------
func announceHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string             `json:"name"`
		URL         string             `json:"url"`
		DirectRTTMs float64            `json:"direct_rtt_ms"`
		RTTMap      map[string]float64 `json:"rtt_map"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := json.Unmarshal(body, &in); err != nil || in.Name == "" {
		writeJSON(w, 400, map[string]string{"error": "bad announce"})
		return
	}
	mu.Lock()
	cells[in.Name] = cellInfo{Name: in.Name, URL: in.URL,
		Direct: in.DirectRTTMs, Seen: time.Now().UTC().Format(time.RFC3339)}
	if in.RTTMap != nil {
		links[in.Name] = edge{Src: in.Name, Maps: in.RTTMap}
	}
	mu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "known": len(cells)})
}

func voteCastHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Voter string `json:"voter"`
		Epoch int64  `json:"epoch"`
		Head  string `json:"head"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := json.Unmarshal(body, &in); err != nil || in.Voter == "" ||
		in.Head == "" {
		writeJSON(w, 400, map[string]string{"error": "bad vote"})
		return
	}
	mu.Lock()
	votes[in.Epoch] = append(votes[in.Epoch],
		vote{Voter: in.Voter, Head: in.Head, TS: time.Now().Unix()})
	mu.Unlock()
	writeJSON(w, 202, map[string]any{"ok": true, "voter": in.Voter,
		"epoch": in.Epoch})
}

func consensusHeadHandler(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()
	// honest demo policy: only the LATEST epoch is eligible to commit -
	// stale epochs never out-commit the newest one, and a commit needs a
	// clean majority (n/2 + 1) of unique voters in that exact bucket.
	now := time.Now().Unix()
	latest := int64(0)
	for ep := range votes {
		if ep > latest && now-ep <= 3600 {
			latest = ep
		}
	}
	tally := map[string]int{}
	seen := map[string]bool{}
	for _, v := range votes[latest] {
		if seen[v.Voter] {
			continue
		}
		seen[v.Voter] = true
		tally[v.Head]++
	}
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for h, c := range tally {
		arr = append(arr, kv{h, c})
	}
	if len(arr) == 0 {
		writeJSON(w, 200, map[string]any{"committed": false,
			"reason": "no votes yet"})
		return
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].v > arr[j].v })
	best := arr[0]
	cleanMajority := len(arr) == 1 || best.v > arr[1].v
	members := len(seen)
	quorumRequired := members/2 + 1
	committed := best.v >= 2 && best.v >= quorumRequired && cleanMajority
	writeJSON(w, 200, map[string]any{
		"committed": committed, "epoch": latest, "head": best.k,
		"votes": best.v, "voters_recorded": members,
		"quorum_required": quorumRequired,
		"algorithm":       "majority-quorum (latest epoch)"})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()
	writeJSON(w, 200, map[string]any{
		"service": "aetheros.mesh", "version": version,
		"uptime_seconds": int(time.Since(started).Seconds()),
		"cells":          len(cells), "links": len(links),
		"consensus": "majority-quorum", "routing": "dijkstra",
		"auth": func() string {
			if secret != "" {
				return "hmac-sha256"
			}
			return "open (demo)"
		}()})
}

func main() {
	secret = getenv("AE_SECRET", "")
	hubName = getenv("AE_HUB_NAME", "hub")
	addr := getenv("AE_ADDR", ":9463")
	mux := http.NewServeMux()
	mux.HandleFunc("/net/graph", auth(graphHandler))
	mux.HandleFunc("/net/route", auth(routeHandler))
	mux.HandleFunc("/net/announce", auth(announceHandler))
	mux.HandleFunc("/vote/cast", auth(voteCastHandler))
	mux.HandleFunc("/consensus/head", auth(consensusHeadHandler))
	mux.HandleFunc("/health", auth(healthHandler))
	srv := &http.Server{Addr: addr, Handler: mux,
		ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second}
	fmt.Println("Aodı-AetherOS mesh v"+version, "listening on", addr,
		"routing: dijkstra · consensus: majority-quorum")
	_ = srv.ListenAndServe()
}
