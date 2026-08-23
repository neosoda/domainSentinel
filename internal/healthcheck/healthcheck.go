package healthcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"domainsentinel/internal/models"
)

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

func extractHTMLTitle(body []byte) string {
	match := titleRegex.FindSubmatch(body)
	if len(match) > 1 {
		title := html.UnescapeString(string(match[1]))
		title = strings.TrimSpace(title)
		title = strings.ReplaceAll(title, "\n", " ")
		title = strings.ReplaceAll(title, "\r", " ")
		// remove multiple spaces
		for strings.Contains(title, "  ") {
			title = strings.ReplaceAll(title, "  ", " ")
		}
		if len(title) > 60 {
			title = title[:57] + "..."
		}
		return title
	}
	return ""
}

// Checker performs HTTP health checks.
type Checker struct {
	timeout     time.Duration
	concurrency int
	transport   *http.Transport
}

// NewChecker creates a healthcheck runner.
func NewChecker(timeout time.Duration, concurrency int) *Checker {
	// Build a custom transport with no KeepAlive to avoid pooling issues
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig: &tls.Config{
			// We check cert validity manually
			InsecureSkipVerify: false,
		},
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 2 * time.Second,
		DisableKeepAlives:     true,
	}

	return &Checker{
		timeout:     timeout,
		concurrency: concurrency,
		transport:   tr,
	}
}

// Check performs an HTTP GET on the given URL and returns an HTTPSnapshot.
func (c *Checker) Check(ctx context.Context, url string) models.HTTPSnapshot {
	snapshot := models.HTTPSnapshot{}

	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		snapshot.Error = fmt.Sprintf("invalid URL: %v", err)
		return snapshot
	}
	req.Header.Set("User-Agent", RandomUserAgent())

	// Follow redirects up to 5 hops
	client := &http.Client{
		Transport: c.transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	snapshot.LatencyMs = int(time.Since(start).Milliseconds())

	if err != nil {
		snapshot.Error = err.Error()
		snapshot.IsUp = false
		return snapshot
	}
	defer resp.Body.Close()

	// Read up to 8KB of body to extract title and allow connection reuse
	buf := make([]byte, 8192)
	n, _ := io.ReadFull(resp.Body, buf)
	if n > 0 {
		snapshot.PageTitle = extractHTMLTitle(buf[:n])
	}

	snapshot.StatusCode = resp.StatusCode
	snapshot.IsUp = models.IsHTTPUp(resp.StatusCode)

	// Capture redirect chain
	if len(resp.Header["Location"]) > 0 {
		snapshot.Redirects = append(snapshot.Redirects, resp.Request.URL.String())
		for _, loc := range resp.Header["Location"] {
			snapshot.Redirects = append(snapshot.Redirects, loc)
		}
	}

	// TLS info
	if resp.TLS != nil {
		snapshot.TLSValid = len(resp.TLS.PeerCertificates) > 0
		if len(resp.TLS.PeerCertificates) > 0 {
			notAfter := resp.TLS.PeerCertificates[0].NotAfter
			snapshot.TLSExpireAt = &notAfter
		}
	} else {
		// Not HTTPS or TLS not available
		snapshot.TLSValid = false
	}

	return snapshot
}

// BatchCheck checks multiple URLs concurrently.
func (c *Checker) BatchCheck(ctx context.Context, urls map[string]string) map[string]models.HTTPSnapshot {
	results := make(map[string]models.HTTPSnapshot)
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, c.concurrency)

	for fqdn, url := range urls {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(fqdn, url string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Use a fresh context with its own timeout
			checkCtx, cancel := context.WithTimeout(ctx, c.timeout+5*time.Second)
			defer cancel()

			result := c.Check(checkCtx, url)
			mu.Lock()
			results[fqdn] = result
			mu.Unlock()
		}(fqdn, url)
	}

	wg.Wait()
	return results
}

// getTLSExpire parses the TLS cert expiration from the connection state.
// (Already included in the Check method via resp.TLS)
func getTLSExpiry(state *tls.ConnectionState) *time.Time {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}
	t := state.PeerCertificates[0].NotAfter
	return &t
}

// CheckCertExpiry checks a specific host:port for TLS certificate expiry.
func CheckCertExpiry(ctx context.Context, host string, port int, timeout time.Duration) (*time.Time, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates")
	}
	t := state.PeerCertificates[0].NotAfter
	return &t, nil
}

// RandomUserAgent returns a random browser-like User-Agent.
func RandomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Safari/537.36",
		"DomainSentinel/1.0 (+https://github.com/techsentinel/domainsentinel)",
	}
	return agents[rand.Intn(len(agents))]
}
