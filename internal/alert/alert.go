package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"domainsentinel/internal/models"
)

type Notifier struct {
	webhookURL string
	client     *http.Client
	mu         sync.Mutex
	lastState  map[string]models.Status
}

func NewNotifier(webhookURL string) *Notifier {
	return &Notifier{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		lastState: make(map[string]models.Status),
	}
}

// CheckAndNotify compares current status against last known state and sends an alert if changed.
func (n *Notifier) CheckAndNotify(ctx context.Context, entry *models.DomainEntry) {
	if n.webhookURL == "" || entry == nil {
		return
	}

	n.mu.Lock()
	prev, exists := n.lastState[entry.FQDN]
	n.lastState[entry.FQDN] = entry.Status
	n.mu.Unlock()

	// Only notify if we had a previous state and it transitioned (e.g. OK -> DOWN or DOWN -> OK)
	if !exists || prev == entry.Status {
		return
	}

	var title, text string
	if entry.Status == models.StatusDown {
		title = fmt.Sprintf("🔴 [ALERTE] Sous-domaine HORS LIGNE : %s", entry.FQDN)
		text = fmt.Sprintf("Le sous-domaine **%s** est désormais inaccessible (Code HTTP: %d, Erreur: %s).",
			entry.FQDN, entry.HTTP.StatusCode, entry.HTTP.Error)
	} else if prev == models.StatusDown && entry.Status == models.StatusOK {
		title = fmt.Sprintf("🟢 [RÉCUPÉRATION] Sous-domaine EN LIGNE : %s", entry.FQDN)
		text = fmt.Sprintf("Le sous-domaine **%s** est de nouveau accessible (Code HTTP: %d, Latence: %dms).",
			entry.FQDN, entry.HTTP.StatusCode, entry.HTTP.LatencyMs)
	} else {
		return
	}

	// Dispatch in background
	go func(title, text string) {
		payload := map[string]any{
			"username": "DomainSentinel",
			"content":  fmt.Sprintf("**%s**\n%s", title, text),
			// Discord embed format fallback
			"embeds": []map[string]any{
				{
					"title":       title,
					"description": text,
					"color": func() int {
						if entry.Status == models.StatusDown {
							return 15158332
						} else {
							return 3066993
						}
					}(),
					"timestamp": time.Now().Format(time.RFC3339),
				},
			},
		}

		data, err := json.Marshal(payload)
		if err != nil {
			return
		}

		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, n.webhookURL, bytes.NewReader(data))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "DomainSentinel/1.0")

		resp, err := n.client.Do(req)
		if err != nil {
			slog.Warn("failed to send webhook alert", "url", n.webhookURL, "error", err)
			return
		}
		defer resp.Body.Close()
	}(title, text)
}
