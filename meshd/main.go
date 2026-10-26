// AetherOS meshd — the Go topology beacon.
//
// Small, fast, stdlib-only daemon that lives on every machine and:
//   - heartbeats its peers (parallel probes, honest RTT in ms)
//   - keeps a last-seen view of the mesh (failures detected, not hidden)
//   - serves /mesh/status for the Python orchestrator to consume
//
// This is the measured-RTT layer of "topological mesh consensus" (TEP):
// no invented sub-millisecond transport claims — just numbers we observe.
//
// Build:  go build -o ../bin/aether-meshd .
// Run:    ./aether-meshd -id mac-local -addr :8795 -peers 127.0.0.1:8796
//
// © 2026 Baran Avisat — Professional Programmer
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type PeerState struct {
	ID       string  `json:"id"`
	URL      string  `json:"url"`
	Up       bool    `json:"up"`
	RTTMs    float64 `json:"rtt_ms"`
	LastSeen int64   `json:"last_seen"`
	Error    string  `json:"error,omitempty"`
}

type Mesh struct {
	mu       sync.RWMutex
	selfID   string
	interval time.Duration
	peers    map[string]*PeerState // key = base URL
}

func NewMesh(selfID string, interval time.Duration) *Mesh {
	return &Mesh{selfID: selfID, interval: interval,
		peers: make(map[string]*PeerState)}
}

func (m *Mesh) addPeer(url string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.peers[url]; !ok {
		m.peers[url] = &PeerState{URL: url, Up: false}
	}
}

// probeOne measures a real round-trip to a peer's /healthz.
func (m *Mesh) probeOne(url string) PeerState {
	start := time.Now()
	st := PeerState{URL: url}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url + "/healthz")
	if err != nil {
		st.Error = err.Error()
		st.Up = false
		return st
	}
	defer resp.Body.Close()
	st.RTTMs = float64(time.Since(start).Microseconds()) / 1000.0
	st.Up = resp.StatusCode == 200
	if !st.Up {
		st.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return st
}

// loop probes all peers in parallel every interval.
func (m *Mesh) loop() {
	for {
		m.mu.RLock()
		urls := make([]string, 0, len(m.peers))
		for u := range m.peers {
			urls = append(urls, u)
		}
		m.mu.RUnlock()

		var wg sync.WaitGroup
		results := make([]PeerState, len(urls))
		for i, u := range urls {
			wg.Add(1)
			go func(i int, u string) {
				defer wg.Done()
				results[i] = m.probeOne(u)
			}(i, u)
		}
		wg.Wait()

		m.mu.Lock()
		for _, r := range results {
			p := m.peers[r.URL]
			if p == nil {
				continue
			}
			p.Up = r.Up
			p.RTTMs = r.RTTMs
			p.Error = r.Error
			if r.Up {
				p.LastSeen = time.Now().Unix()
			}
			if r.Error != "" && p.ID != "" {
				// keep last known error for the dashboard, never silent
			}
		}
		m.mu.Unlock()
		time.Sleep(m.interval)
	}
}

func (m *Mesh) snapshot() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	peers := make([]*PeerState, 0, len(m.peers))
	up := 0
	for _, p := range m.peers {
		cp := *p
		peers = append(peers, &cp)
		if p.Up {
			up++
		}
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].URL < peers[j].URL })
	return map[string]interface{}{
		"id": m.selfID, "arch": runtime.GOARCH, "os": runtime.GOOS,
		"pid": os.Getpid(), "peers": peers, "up": up, "total": len(peers),
		"generated_at": time.Now().Unix(),
	}
}

func main() {
	selfID := flag.String("id", hostname(), "node id")
	addr := flag.String("addr", ":8795", "listen address")
	peers := flag.String("peers", "", "comma separated peer base URLs")
	interval := flag.Duration("interval", 5*time.Second, "heartbeat period")
	flag.Parse()

	m := NewMesh(*selfID, *interval)
	for _, u := range strings.Split(*peers, ",") {
		u = strings.TrimSpace(u)
		if u != "" {
			m.addPeer(u)
		}
	}
	go m.loop()

	http.HandleFunc("/mesh/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m.snapshot())
	})
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"ok":true,"id":%q}`, *selfID)
	})

	fmt.Printf("[aether-meshd] %s listening on %s (%s/%s, %d peers)\n",
		*selfID, *addr, runtime.GOOS, runtime.GOARCH,
		len(strings.Split(*peers, ",")))
	if err := http.ListenAndServe(*addr, nil); err != nil {
		fmt.Fprintln(os.Stderr, "meshd:", err)
		os.Exit(1)
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "node"
	}
	return h
}
