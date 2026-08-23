package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"domainsentinel/internal/models"
)

type CloudflareScanner struct {
	token    string
	zoneName string
	zoneID   string
	hc       *http.Client
}

func NewCloudflareScanner(token, zoneName string, timeout time.Duration) *CloudflareScanner {
	return &CloudflareScanner{
		token:    token,
		zoneName: zoneName,
		hc: &http.Client{
			Timeout:   timeout,
			Transport: http.DefaultTransport,
		},
	}
}

type cfZoneResponse struct {
	Result []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"result"`
}

type cfRecordResponse struct {
	Result []cfRecord `json:"result"`
}

type cfRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// Scan returns a map of FQDN → CloudflareRecord for our zone
func (s *CloudflareScanner) Scan(ctx context.Context) (map[string]*models.CloudflareRecord, error) {
	if s.token == "" {
		return nil, fmt.Errorf("cloudflare token not configured")
	}

	// Find zone ID
	zones, err := s.listZones(ctx)
	if err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}

	for _, z := range zones {
		for _, zone := range z.Result {
			if zone.Name == s.zoneName {
				s.zoneID = zone.ID
				break
			}
		}
		if s.zoneID != "" {
			break
		}
	}
	if s.zoneID == "" {
		return nil, fmt.Errorf("zone %q not found in Cloudflare", s.zoneName)
	}

	// Fetch all DNS records
	records, err := s.listRecords(ctx)
	if err != nil {
		return nil, fmt.Errorf("list records: %w", err)
	}

	result := make(map[string]*models.CloudflareRecord)
	for _, r := range records {
		// Only A, AAAA, CNAME records for our zone
		if r.Name == s.zoneName || strings.HasSuffix(r.Name, "."+s.zoneName) {
			fqdn := r.Name
			if strings.HasSuffix(fqdn, ".") {
				fqdn = strings.TrimSuffix(fqdn, ".")
			}
			result[fqdn] = &models.CloudflareRecord{
				ID:      r.ID,
				Name:    fqdn,
				Type:    r.Type,
				Content: r.Content,
				TTL:     r.TTL,
				Proxied: r.Proxied,
			}
		}
	}

	return result, nil
}

func (s *CloudflareScanner) do(ctx context.Context, method, url string, body interface{}) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("cloudflare API error: %s", resp.Status)
	}

	var buf []byte
	// simple read
	bs := make([]byte, 1024*64)
	for {
		n, err := resp.Body.Read(bs)
		buf = append(buf, bs[:n]...)
		if n == 0 || err != nil {
			break
		}
	}

	return buf, nil
}

func (s *CloudflareScanner) listZones(ctx context.Context) ([]cfZoneResponse, error) {
	var result []cfZoneResponse
	page := 1
	for {
		url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?page=%d&per_page=50", page)
		data, err := s.do(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		var r cfZoneResponse
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, err
		}
		result = append(result, r)
		if len(r.Result) < 50 {
			break
		}
		page++
	}
	return result, nil
}

func (s *CloudflareScanner) listRecords(ctx context.Context) ([]cfRecord, error) {
	var all []cfRecord
	page := 1
	for {
		url := fmt.Sprintf(
			"https://api.cloudflare.com/client/v4/zones/%s/dns_records?page=%d&per_page=100&type=A&type=AAAA&type=CNAME",
			s.zoneID, page,
		)
		data, err := s.do(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		var r cfRecordResponse
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, err
		}
		all = append(all, r.Result...)
		if len(r.Result) < 100 {
			break
		}
		page++
	}
	return all, nil
}
