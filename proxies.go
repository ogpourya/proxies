// proxies.go
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/spinner"
)

var sources = []string{
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
    "https://github.com/monosans/proxy-list/raw/refs/heads/main/proxies/all.txt",
    "https://github.com/mmpx12/proxy-list/raw/refs/heads/master/proxies.txt",
    "https://github.com/zloi-user/hideip.me/raw/refs/heads/master/http.txt",
    "https://github.com/zloi-user/hideip.me/raw/refs/heads/master/https.txt",
    "https://github.com/zloi-user/hideip.me/raw/refs/heads/master/socks4.txt",
    "https://github.com/zloi-user/hideip.me/raw/refs/heads/master/socks5.txt",
    "https://github.com/iplocate/free-proxy-list/raw/refs/heads/main/all-proxies.txt",
    "https://github.com/Zaeem20/FREE_PROXIES_LIST/raw/refs/heads/master/http.txt",
    "https://github.com/Zaeem20/FREE_PROXIES_LIST/raw/refs/heads/master/https.txt",
    "https://github.com/Zaeem20/FREE_PROXIES_LIST/raw/refs/heads/master/socks4.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
    "https://github.com/rdavydov/proxy-list/raw/refs/heads/main/proxies/http.txt",
    "https://github.com/rdavydov/proxy-list/raw/refs/heads/main/proxies/socks4.txt",
    "https://github.com/rdavydov/proxy-list/raw/refs/heads/main/proxies/socks5.txt",
    "https://github.com/ShiftyTR/Proxy-List/raw/refs/heads/master/proxy.txt",
    "https://github.com/Vann-Dev/proxy-list/raw/refs/heads/main/proxies/http.txt",
    "https://github.com/Vann-Dev/proxy-list/raw/refs/heads/main/proxies/https.txt",
}


// Allowed protocols and defaults
var (
	validProto = map[string]bool{
		"http":  true,
		"https": true,
		"socks4": true,
		"socks5": true,
	}

	defaultPort = map[string]int{
		"http":  80,
		"https": 443,
		"socks4": 1080,
		"socks5": 1080,
	}
)

// regex to validate final normalized proxy like "http://host:port" or "socks5://host:port"
var proxyRegex = regexp.MustCompile(`(?i)^(http|https|socks4|socks5)://[^:/\s]+:\d{1,5}$`)

func protoFromSourceURL(u string) string {
	lu := strings.ToLower(u)
	switch {
	case strings.Contains(lu, "socks5"):
		return "socks5"
	case strings.Contains(lu, "socks4"):
		return "socks4"
	case strings.Contains(lu, "/https") || strings.Contains(lu, "https.txt"):
		return "https"
	case strings.Contains(lu, "/http") || strings.Contains(lu, "http.txt"):
		return "http"
	default:
		return "" // unknown
	}
}

func fetch(ctx context.Context, client *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "proxies-go/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("bad status %d", resp.StatusCode)
	}
	return resp.Body, nil
}

func normalizeLine(raw string, srcProto string) (string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return "", false
	}
	// Remove common comment markers or lines that obviously aren't proxies
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return "", false
	}

	// If the line already contains a scheme (://), parse it and validate
	if idx := strings.Index(line, "://"); idx != -1 {
		p := strings.ToLower(line[:idx])
		if !validProto[p] {
			return "", false
		}
		// Ensure there's a host:port after
		hostPort := line[idx+3:]
		hostPort = strings.TrimSpace(hostPort)
		if hostPort == "" {
			return "", false
		}
		// If no port, append default
		if !strings.Contains(hostPort, ":") {
			def, ok := defaultPort[p]
			if !ok {
				return "", false
			}
			hostPort = hostPort + ":" + strconv.Itoa(def)
		}
		candidate := fmt.Sprintf("%s://%s", p, hostPort)
		if validateProxy(candidate) {
			return candidate, true
		}
		return "", false
	}

	// No scheme present in line.
	// Try to split host and port.
	line = strings.TrimSpace(line)
	// If it's something like "host" (no colon), add default based on srcProto or http
	if !strings.Contains(line, ":") {
		p := srcProto
		if p == "" {
			p = "http"
		}
		def := defaultPort[p]
		candidate := fmt.Sprintf("%s://%s:%d", p, line, def)
		if validateProxy(candidate) {
			return candidate, true
		}
		return "", false
	}

	// Contains colon -> assume host:port
	// split at last colon to allow IPv6 like [::1]:8080 (but we won't fully parse IPv6)
	last := strings.LastIndex(line, ":")
	if last == -1 {
		return "", false
	}
	host := strings.TrimSpace(line[:last])
	portStr := strings.TrimSpace(line[last+1:])
	if host == "" || portStr == "" {
		return "", false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", false
	}

	p := srcProto
	if p == "" {
		p = "http"
	}
	candidate := fmt.Sprintf("%s://%s:%d", p, host, port)
	if validateProxy(candidate) {
		return candidate, true
	}
	return "", false
}

func validateProxy(s string) bool {
	if !proxyRegex.MatchString(s) {
		return false
	}
	// ensure port value is in range
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return false
	}
	pStr := parts[len(parts)-1]
	p, err := strconv.Atoi(pStr)
	if err != nil {
		return false
	}
	return p >= 1 && p <= 65535
}

// fetchAll downloads sources concurrently and returns collected normalized proxies.
func fetchAll(ctx context.Context, srcs []string) []string {
	client := &http.Client{Timeout: 15 * time.Second}
	type result struct {
		url  string
		body []string
		err  error
	}
	ch := make(chan result)
	var wg sync.WaitGroup
	for _, u := range srcs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			bodyRc, err := fetch(ctx, client, url)
			if err != nil {
				ch <- result{url: url, body: nil, err: err}
				return
			}
			defer bodyRc.Close()
			sc := bufio.NewScanner(bodyRc)
			var lines []string
			for sc.Scan() {
				lines = append(lines, sc.Text())
			}
			// ignore scanner error; treat as failure if severe
			ch <- result{url: url, body: lines, err: nil}
		}(u)
	}

	// close channel when done
	go func() {
		wg.Wait()
		close(ch)
	}()

	seen := make(map[string]struct{})
	out := make([]string, 0, 1000)

	for res := range ch {
		// ignore failures
		if res.err != nil {
			// just skip this source
			continue
		}
		srcProto := protoFromSourceURL(res.url)
		for _, raw := range res.body {
			norm, ok := normalizeLine(raw, srcProto)
			if !ok {
				continue
			}
			// normalize case for protocol (lowercase)
			parts := strings.SplitN(norm, "://", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.ToLower(parts[0]) + "://" + parts[1]
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, key)
		}
	}

	// shuffle
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })

	return out
}

// saveToFile writes proxies to proxies.txt in current dir
func saveToFile(proxies []string) error {
	f, err := os.Create("proxies.txt")
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, p := range proxies {
		_, _ = w.WriteString(p + "\n")
	}
	return w.Flush()
}

// Bubble Tea UI
type model struct {
	spinner    spinner.Model
	status     string
	totalSrc   int
	doneCount  int
	errCount   int
	finished   bool
	proxyCount int
	err        error
}

type fetchDoneMsg struct {
	finished bool
	count    int
	err      error
}

func initialModel(total int) model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = s.Style // keep default
	return model{
		spinner:  s,
		status:   "Starting downloads...",
		totalSrc: total,
	}
}

func (m model) Init() tea.Cmd {
	// start spinner and perform download in background
	return tea.Batch(m.spinner.Tick, func() tea.Msg {
		// run the heavy lifting synchronously inside this cmd so bubbletea can receive a message
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// We'll perform fetchAll but we also want to track progress per source.
		// To keep things simple for UI we run fetchAll directly and then return a single done message.
		proxies := fetchAll(ctx, sources)
		if len(proxies) == 0 {
			return fetchDoneMsg{finished: true, count: 0, err: errors.New("no proxies collected (all sources failed or filtered)")}
		}
		if err := saveToFile(proxies); err != nil {
			return fetchDoneMsg{finished: true, count: 0, err: err}
		}
		return fetchDoneMsg{finished: true, count: len(proxies), err: nil}
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case fetchDoneMsg:
		m.finished = true
		m.proxyCount = msg.count
		m.err = msg.err
		if m.err != nil {
			m.status = "Finished with error ❌"
		} else {
			m.status = "All done ✅"
		}
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	default:
		// ignore other messages
		return m, nil
	}
}

func (m model) View() string {
	if m.finished {
		if m.err != nil {
			return fmt.Sprintf("\n💥 %s\n\nerror: %v\n\n", m.status, m.err)
		}
		return fmt.Sprintf("\n%s  🎉\nSaved %d proxies to %s\n\n", m.status, m.proxyCount, "proxies.txt")
	}
	return fmt.Sprintf("\n%s %s\n\n(Downloading sources: %d) — please wait...\n", m.spinner.View(), m.status, m.totalSrc)
}

func main() {
	// quick check: create module warning if no network libs present - but we'll run as-is
	p := tea.NewProgram(initialModel(len(sources)))
	if err := p.Start(); err != nil {
		fmt.Printf("😵 failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println()
	fmt.Println("👉 proxies saved to ./proxies.txt")
	fmt.Println("You can open it with: cat proxies.txt")
}

