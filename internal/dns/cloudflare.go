// Package dns creates the A records that point published domains at the control
// node's exit nodes.
package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultCloudflareBaseURL is the public API endpoint.
const DefaultCloudflareBaseURL = "https://api.cloudflare.com/client/v4"

// RecordComment marks the records this control node manages, so they are
// recognisable in the Cloudflare dashboard and never confused with records that
// were created by hand.
const RecordComment = "managed by noobtunnel"

// Cloudflare manages records through the Cloudflare API with an API token.
type Cloudflare struct {
	Token   string
	BaseURL string
	Client  *http.Client
	// TTL of created records; 1 means "automatic".
	TTL int
	// Comment stored on the record; empty uses RecordComment.
	Comment string
}

// NewCloudflare builds a client for a token.
func NewCloudflare(token string) *Cloudflare {
	return &Cloudflare{
		Token:   token,
		BaseURL: DefaultCloudflareBaseURL,
		Client:  &http.Client{Timeout: 15 * time.Second},
		TTL:     1,
	}
}

// EnsureA makes the A record for hostname point at address.
func (c *Cloudflare) EnsureA(ctx context.Context, hostname, address string) error {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" || address == "" {
		return fmt.Errorf("dns: a hostname and an address are required")
	}
	// An A record holds an IPv4 address. A hostname here means the caller picked
	// the wrong address, and the provider would answer with a confusing error.
	if ip := net.ParseIP(address); ip == nil || ip.To4() == nil {
		return fmt.Errorf("dns: %q is not an IPv4 address, so it cannot be an A record", address)
	}
	zoneID, zoneName, err := c.findZone(ctx, hostname)
	if err != nil {
		return err
	}
	recordName := hostname
	if hostname == zoneName {
		recordName = zoneName
	}
	if err := c.upsertA(ctx, zoneID, recordName, address); err != nil {
		return err
	}
	// Read the record back. Reporting "in sync" from a create that the provider
	// accepted but did not keep is how a domain ends up looking fine with no
	// record in the zone.
	written, err := c.findRecord(ctx, zoneID, recordName)
	if err != nil {
		return err
	}
	if written == nil {
		return fmt.Errorf("dns: the A record for %s is not there after writing it", recordName)
	}
	if !strings.EqualFold(strings.TrimSpace(written.Content), address) {
		return fmt.Errorf("dns: %s reads back as %q, expected %q", recordName, written.Content, address)
	}
	return nil
}

// upsertA creates or updates the record with the address.
func (c *Cloudflare) upsertA(ctx context.Context, zoneID, recordName, address string) error {
	body := map[string]any{
		"type":    "A",
		"name":    recordName,
		"content": address,
		"ttl":     c.ttl(),
		"proxied": false,
		"comment": c.comment(),
	}
	existing, err := c.findRecord(ctx, zoneID, recordName)
	if err != nil {
		return err
	}
	if existing != nil {
		if existing.Content == address && existing.Comment == c.comment() {
			return nil
		}
		return c.request(ctx, http.MethodPut, "/zones/"+zoneID+"/dns_records/"+existing.ID, body, nil)
	}
	err = c.request(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", body, nil)
	if err == nil || !alreadyExists(err) {
		return err
	}
	// The provider says a record with that name exists even though the lookup did
	// not return it (a record type we cannot read, or a filter miss). Find it
	// again and update it instead of failing the sync.
	existing, findErr := c.findRecord(ctx, zoneID, recordName)
	if findErr != nil || existing == nil {
		return err
	}
	return c.request(ctx, http.MethodPut, "/zones/"+zoneID+"/dns_records/"+existing.ID, body, nil)
}

// alreadyExists recognises the provider's "record already exists" answer.
func alreadyExists(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "81057") || strings.Contains(message, "already exists")
}

// Verify checks that a token works and returns the zones it can see.
func (c *Cloudflare) Verify(ctx context.Context) ([]string, error) {
	var zones []struct {
		Name string `json:"name"`
	}
	if err := c.request(ctx, http.MethodGet, "/zones?per_page=50", nil, &zones); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(zones))
	for _, zone := range zones {
		names = append(names, zone.Name)
	}
	return names, nil
}

func (c *Cloudflare) ttl() int {
	if c.TTL <= 0 {
		return 1
	}
	return c.TTL
}

func (c *Cloudflare) comment() string {
	if strings.TrimSpace(c.Comment) == "" {
		return RecordComment
	}
	return c.Comment
}

// findZone walks up the hostname until Cloudflare recognises a zone.
func (c *Cloudflare) findZone(ctx context.Context, hostname string) (string, string, error) {
	labels := strings.Split(hostname, ".")
	for i := 0; i+2 <= len(labels); i++ {
		candidate := strings.Join(labels[i:], ".")
		var zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := c.request(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(candidate), nil, &zones); err != nil {
			return "", "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, zones[0].Name, nil
		}
	}
	return "", "", fmt.Errorf("dns: no Cloudflare zone found for %s (is the domain in this account?)", hostname)
}

type record struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	Comment string `json:"comment"`
}

func (c *Cloudflare) findRecord(ctx context.Context, zoneID, hostname string) (*record, error) {
	var records []record
	// The name is escaped: a wildcard record is literally "*.example.com", and an
	// unescaped "*" is not a query string character.
	query := "/zones/" + zoneID + "/dns_records?type=A&name=" + url.QueryEscape(hostname)
	if err := c.request(ctx, http.MethodGet, query, nil, &records); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	return &records[0], nil
}

// request performs one API call and unpacks the Cloudflare envelope.
func (c *Cloudflare) request(ctx context.Context, method, path string, body any, out any) error {
	base := c.BaseURL
	if base == "" {
		base = DefaultCloudflareBaseURL
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("dns: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	var envelope struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		if response.StatusCode >= 400 {
			return fmt.Errorf("dns: Cloudflare returned %s", response.Status)
		}
		return err
	}
	if !envelope.Success {
		if len(envelope.Errors) > 0 {
			return fmt.Errorf("dns: Cloudflare error %d: %s", envelope.Errors[0].Code, envelope.Errors[0].Message)
		}
		return fmt.Errorf("dns: Cloudflare returned %s", response.Status)
	}
	if out != nil && len(envelope.Result) > 0 {
		if err := json.Unmarshal(envelope.Result, out); err != nil {
			return err
		}
	}
	return nil
}
