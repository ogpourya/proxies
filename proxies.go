// proxies.go
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
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
	"https://github.com/vmheaven/VMHeaven.io-Free-Proxy-List/raw/refs/heads/main/all_proxies.txt",
	"https://github.com/dpangestuw/Free-Proxy/raw/refs/heads/main/All_proxies.txt",
	"https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.txt",
	"https://github.com/VPSLabCloud/VPSLab-Free-Proxy-List/raw/refs/heads/main/all_proxies.txt",
	"https://github.com/hproxy-com/free-proxy-list/raw/refs/heads/main/all.txt",
}

var (
	validProto = map[string]bool{
		"http":   true,
		"https":  true,
		"socks4": true,
		"socks5": true,
	}

	defaultPort = map[string]int{
		"http":   80,
		"https":  443,
		"socks4": 1080,
		"socks5": 1080,
	}
)

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
		return ""
	}
}

func fetch(ctx context.Context, client *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "proxies-go/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// normalizeLine cleans, extracts, and validates proxy specifications without regex overhead.
func normalizeLine(raw string, srcProto string) (string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || line[0] == '#' || line[0] == ';' {
		return "", false
	}

	// Strip trailing comments/whitespace (e.g. CSV fields or trailing notes)
	if idx := strings.IndexAny(line, " \t,;#"); idx != -1 {
		line = line[:idx]
	}

	proto := ""
	hostPort := ""

	if idx := strings.Index(line, "://"); idx != -1 {
		proto = strings.ToLower(line[:idx])
		hostPort = line[idx+3:]
	} else {
		proto = srcProto
		hostPort = line
	}

	if proto == "" {
		proto = "http"
	}

	if !validProto[proto] {
		return "", false
	}

	// Support userinfo (e.g. user:pass@host:port) if present
	userinfo := ""
	if at := strings.LastIndex(hostPort, "@"); at != -1 {
		userinfo = hostPort[:at+1]
		hostPort = hostPort[at+1:]
	}

	// Separate host and port
	var host string
	var port int

	if strings.HasPrefix(hostPort, "[") {
		// IPv6 bracketed: [::1]:8080 or [::1]
		closeBracket := strings.Index(hostPort, "]")
		if closeBracket == -1 {
			return "", false
		}
		host = hostPort[:closeBracket+1]
		remainder := hostPort[closeBracket+1:]
		if remainder == "" {
			port = defaultPort[proto]
		} else if strings.HasPrefix(remainder, ":") {
			p, err := strconv.Atoi(remainder[1:])
			if err != nil || p <= 0 || p > 65535 {
				return "", false
			}
			port = p
		} else {
			return "", false
		}
	} else {
		// IPv4 or hostname
		colon := strings.LastIndex(hostPort, ":")
		if colon == -1 {
			host = hostPort
			port = defaultPort[proto]
		} else {
			host = hostPort[:colon]
			p, err := strconv.Atoi(hostPort[colon+1:])
			if err != nil || p <= 0 || p > 65535 {
				return "", false
			}
			port = p
		}
	}

	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, " /\\?#") {
		return "", false
	}

	return fmt.Sprintf("%s://%s%s:%d", proto, userinfo, host, port), true
}

func newHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
	}
}

// Streamed fetch results for responsive Bubble Tea UI
type srcDoneMsg struct {
	url     string
	proxies []string
	err     error
}

type batchDoneMsg struct {
	count int
	err   error
}

// Bubble Tea UI Model
type model struct {
	spinner    spinner.Model
	totalSrc   int
	completed  int
	failed     int
	collected  int
	finished   bool
	err        error
	subChan    chan srcDoneMsg
	collectedMap map[string]struct{}
	collectedList []string
}

func initialModel(total int) model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	return model{
		spinner:       s,
		totalSrc:      total,
		subChan:       make(chan srcDoneMsg, total),
		collectedMap:  make(map[string]struct{}, 10000),
		collectedList: make([]string, 0, 10000),
	}
}

func (m model) Init() tea.Cmd {
	client := newHTTPClient()
	
	// Start fetching sources concurrently in the background and streaming to subChan
	fetchCmd := func() tea.Msg {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 16) // Concurrency limiter to avoid file descriptor / socket exhaustion

		for _, srcURL := range sources {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				defer cancel()

				bodyRc, err := fetch(ctx, client, u)
				if err != nil {
					m.subChan <- srcDoneMsg{url: u, err: err}
					return
				}
				defer func() { _ = bodyRc.Close() }()

				srcProto := protoFromSourceURL(u)
				var lines []string
				sc := bufio.NewScanner(bodyRc)
				// Allow reading lines up to 64KB
				buf := make([]byte, 64*1024)
				sc.Buffer(buf, 64*1024)

				for sc.Scan() {
					if norm, ok := normalizeLine(sc.Text(), srcProto); ok {
						lines = append(lines, norm)
					}
				}
				m.subChan <- srcDoneMsg{url: u, proxies: lines, err: sc.Err()}
			}(srcURL)
		}

		wg.Wait()
		close(m.subChan)
		return nil
	}

	// Command to listen on the stream channel
	return tea.Batch(m.spinner.Tick, fetchCmd, waitForNextSource(m.subChan))
}

func waitForNextSource(sub chan srcDoneMsg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-sub
		if !ok {
			return batchDoneMsg{}
		}
		return msg
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return m, tea.Quit
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case srcDoneMsg:
		m.completed++
		if msg.err != nil {
			m.failed++
		} else {
			for _, p := range msg.proxies {
				if _, exists := m.collectedMap[p]; !exists {
					m.collectedMap[p] = struct{}{}
					m.collectedList = append(m.collectedList, p)
				}
			}
			m.collected = len(m.collectedList)
		}
		return m, waitForNextSource(m.subChan)

	case batchDoneMsg:
		m.finished = true
		if len(m.collectedList) == 0 {
			m.err = errors.New("no proxies collected (all sources failed or were unreachable)")
			return m, tea.Quit
		}

		// Shuffle using modern crypto-seeded rand
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		rng.Shuffle(len(m.collectedList), func(i, j int) {
			m.collectedList[i], m.collectedList[j] = m.collectedList[j], m.collectedList[i]
		})

		// Atomic write to proxies.txt
		if err := saveAtomic("proxies.txt", m.collectedList); err != nil {
			m.err = err
		}
		return m, tea.Quit

	default:
		return m, nil
	}
}

func (m model) View() string {
	if m.finished {
		if m.err != nil {
			return fmt.Sprintf("\n💥 Finished with error: %v\n\n", m.err)
		}
		return fmt.Sprintf("\nAll done ✅ 🎉\nSaved %d deduplicated proxies to proxies.txt (Sources: %d/%d ok)\n\n",
			len(m.collectedList), m.totalSrc-m.failed, m.totalSrc)
	}

	return fmt.Sprintf("\n%s Downloading & parsing proxy sources (%d/%d done, %d unique found)...\n   Press Ctrl+C to abort\n",
		m.spinner.View(), m.completed, m.totalSrc, m.collected)
}

// saveAtomic writes to a temporary file in the same directory and renames atomically.
func saveAtomic(filename string, proxies []string) error {
	dir := filepath.Dir(filename)
	tmpFile, err := os.CreateTemp(dir, "proxies-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()

	cleanup := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
	}

	w := bufio.NewWriterSize(tmpFile, 64*1024)
	for _, p := range proxies {
		if _, err := w.WriteString(p + "\n"); err != nil {
			cleanup()
			return err
		}
	}

	if err := w.Flush(); err != nil {
		cleanup()
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		cleanup()
		return err
	}

	if err := tmpFile.Close(); err != nil {
		cleanup()
		return err
	}

	return os.Rename(tmpName, filename)
}

func main() {
	p := tea.NewProgram(initialModel(len(sources)))
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "😵 Error running proxies: %v\n", err)
		os.Exit(1)
	}
}
