// Package geoip answers "where is this address from" with an IP intelligence API
// the operator already runs, instead of a bundled database.
//
// One endpoint does everything: GET <host>/checkip?ip=<address>, answered with
// JSON (see apiResponse). Results are cached, because the proxy asks for a country
// while it is handling a request and the API must not be in that path more than
// once per address.
package geoip

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrNotConfigured means no API is set up; resources with country rules deny
// requests whose countries cannot be determined.
var ErrNotConfigured = errors.New("geoip: no IP API is configured")

const (
	// DecisionTimeout bounds a country lookup that an access rule is waiting for.
	// Cold IP API responses can take several seconds; unknown countries still deny.
	DecisionTimeout = 5 * time.Second
	// warmTimeout bounds a lookup nobody is waiting for. It is generous on purpose:
	// the API may be a published service of this same control node, which makes a
	// cold answer slow, and a country that arrives late is still useful.
	warmTimeout = 20 * time.Second
	// clientTimeout is the cap for one HTTP call. It is longer than lookupTimeout
	// so the settings panel can afford to wait for a slow API while the request
	// path stays bounded by its own context.
	clientTimeout = 20 * time.Second
	// cacheTTL is how long an answer is trusted: allocations and networks do not
	// move often, and the API is spared a call per request.
	cacheTTL = 12 * time.Hour
	// failureTTL is how long a failed lookup is remembered, so an API that is down
	// is not retried on every request. It is short: the answer is usually a slow
	// one rather than a broken one, and waiting a minute to try again is what made
	// countries take minutes to appear.
	failureTTL = 15 * time.Second
	// maxResponse caps what is read from the API.
	maxResponse = 1 << 20
	// warmConcurrency bounds lookups that nobody is waiting for, so a burst of new
	// client addresses cannot open hundreds of calls at once.
	warmConcurrency = 8
	// retryMax caps the retry backoff for an address the API has not answered for.
	retryMax = 5 * time.Minute
)

// Lookup is what the API says about one address.
type Lookup struct {
	Country string `json:"country,omitempty"`
	// CountryFrom names the field the country came from, so an operator can see
	// why a rule matched (allocation, abuse report, or the network's ASN).
	CountryFrom string `json:"countryFrom,omitempty"`
	IsTor       bool   `json:"isTor,omitempty"`
	Hosting     bool   `json:"hosting,omitempty"`
	Proxy       bool   `json:"proxy,omitempty"`
	ASN         string `json:"asn,omitempty"`
	AbuseScore  int    `json:"abuseScore,omitempty"`
}

// API is a client for the operator's IP API. It is safe for concurrent use.
type API struct {
	mu                 sync.Mutex
	host               string
	token              string
	provider           string
	client             *http.Client
	fallback           *API
	publicRetryAt      time.Time
	fallbackLookups    int
	lastFallbackReason string
	// dialAddress is the selected agent's mesh forward, when one is used.
	dialAddress   string
	cache         map[netip.Addr]entry
	cacheFile     string
	cacheTimer    *time.Timer
	responseTotal time.Duration
	responseCount int
	// lookups counts answers fetched from the API, for the settings panel.
	lookups   int
	lastError string
	lastAt    time.Time
	// OnError is told about a failed lookup, so an API that stops answering or
	// sends something unexpected shows up where every other failure does.
	OnError func(error)
	// OnCountry is told when a lookup resolves a country, including lookups
	// started in the background for the request log.
	OnCountry func(netip.Addr, string)
	// warming tracks addresses with a lookup in flight, and warmingAt when the next
	// retry is due for one the API has not answered for.
	warming   map[netip.Addr]bool
	warmingAt map[netip.Addr]time.Time
	// attempts counts how many times an address has failed in a row, for the retry
	// backoff.
	attempts map[netip.Addr]int
	// warmSlots bounds how many background lookups run at once.
	warmSlots chan struct{}
}

type entry struct {
	info Lookup
	err  string
	at   time.Time
}

// New creates a client for a host such as "iplog.example.com". A host given with
// a scheme is used as it is, which is what makes a plain http endpoint usable
// during setup and in tests.
func New(host, token string) *API {
	api := &API{cache: map[netip.Addr]entry{}, client: &http.Client{Timeout: clientTimeout}}
	api.warming = map[netip.Addr]bool{}
	api.warmingAt = map[netip.Addr]time.Time{}
	api.attempts = map[netip.Addr]int{}
	api.warmSlots = make(chan struct{}, warmConcurrency)
	api.Configure(host, token)
	return api
}

// NewPublic uses ipapi.is with a key. Its keyed response includes the country
// and the abuse flag needed by resource security controls.
func NewPublic(token string) *API {
	api := New("https://api.ipapi.is", token)
	api.provider = "ipapi"
	return api
}

// SetFallback keeps a self-hosted API available when the public provider
// fails, including quota and network failures.
func (a *API) SetFallback(fallback *API) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fallback = fallback
}

// FallbackStats reports whether iplog has answered in place of the public API.
func (a *API) FallbackStats() (int, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fallbackLookups, a.lastFallbackReason
}

// NewVia sends requests through a mesh forward while retaining the configured
// URL for the HTTP Host header and TLS certificate verification.
func NewVia(host, token, dialAddress string) *API {
	api := New(host, token)
	api.dialAddress = dialAddress
	if dialAddress == "" {
		api.dialAddress = "unavailable-agent"
	}
	api.client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if dialAddress == "" {
				return nil, fmt.Errorf("selected IP API agent is unavailable")
			}
			// A newly selected agent receives its forward on the next peer push.
			// Give that short setup window a chance to finish during Save and check.
			for {
				conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, dialAddress)
				if err == nil {
					return conn, nil
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(200 * time.Millisecond):
				}
			}
		},
	}
	return api
}

// Configure points the client at an API, dropping anything cached from another.
func (a *API) Configure(host, token string) {
	host = normaliseHost(host)
	a.mu.Lock()
	defer a.mu.Unlock()
	if host != a.host || token != a.token {
		a.cache = map[netip.Addr]entry{}
		a.warming = map[netip.Addr]bool{}
		a.warmingAt = map[netip.Addr]time.Time{}
		a.attempts = map[netip.Addr]int{}
		a.lookups = 0
		a.lastError = ""
		a.responseTotal = 0
		a.responseCount = 0
	}
	a.host, a.token = host, token
}

// normaliseHost accepts "iplog.example.com", "https://iplog.example.com/" and
// "http://127.0.0.1:8080".
func normaliseHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	return strings.TrimSuffix(host, "/")
}

// Configured reports whether an API is set up.
func (a *API) Configured() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.host != ""
}

// Ready reports whether lookups are working: configured, and the last answer was
// not an error.
func (a *API) Ready() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.host != "" && a.lastError == ""
}

// Stats describes the client for the settings panel.
func (a *API) Stats() (host string, cached int, lookups int, lastAt time.Time, lastError string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for addr, hit := range a.cache {
		if time.Since(hit.at) > cacheTTL || (hit.err != "" && time.Since(hit.at) > failureTTL) {
			delete(a.cache, addr)
		} else if hit.err == "" {
			cached++
		}
	}
	return a.host, cached, a.lookups, a.lastAt, a.lastError
}

// AverageResponse reports the mean duration of successful HTTP lookups this run.
func (a *API) AverageResponse() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.responseCount == 0 {
		return 0
	}
	return a.responseTotal / time.Duration(a.responseCount)
}

type diskCache struct {
	Identity [32]byte             `json:"identity"`
	Entries  map[string]diskEntry `json:"entries"`
}
type diskEntry struct {
	Info Lookup    `json:"info"`
	At   time.Time `json:"at"`
}

func (a *API) cacheIdentity() [32]byte {
	identity := a.provider + "\x00" + a.host + "\x00" + a.token + "\x00" + a.dialAddress
	if a.fallback != nil {
		identity += "\x00" + a.fallback.host + "\x00" + a.fallback.token + "\x00" + a.fallback.dialAddress
	}
	return sha256.Sum256([]byte(identity))
}

// SetCacheFile restores valid answers so a control node restart does not cause
// every known address to ask the IP API again. Credentials never enter the file.
func (a *API) SetCacheFile(path string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cacheFile = path
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var saved diskCache
	if json.Unmarshal(raw, &saved) != nil || saved.Identity != a.cacheIdentity() {
		return
	}
	for rawAddr, hit := range saved.Entries {
		addr, err := netip.ParseAddr(rawAddr)
		if err == nil && time.Since(hit.At) < cacheTTL && !hit.At.After(time.Now()) {
			a.cache[addr] = entry{info: hit.Info, at: hit.At}
		}
	}
}

func (a *API) persistCache() {
	a.mu.Lock()
	a.cacheTimer = nil
	path := a.cacheFile
	saved := diskCache{Identity: a.cacheIdentity(), Entries: map[string]diskEntry{}}
	for addr, hit := range a.cache {
		if hit.err == "" && time.Since(hit.at) < cacheTTL {
			saved.Entries[addr.String()] = diskEntry{hit.info, hit.at}
		}
	}
	a.mu.Unlock()
	if path == "" {
		return
	}
	raw, err := json.Marshal(saved)
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(path), 0700) != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, raw, 0600) == nil {
		_ = os.Rename(tmp, path)
	}
}

// Country is the ISO country code for an address, or "" when it is not known yet.
//
// It never waits: a request must not be held up by a lookup, and the answer is
// useful the moment it arrives (the request log fills in every earlier entry from
// that address). A lookup that is not cached is started in the background, with a
// generous timeout and a retry, which is what makes a country appear in seconds
// instead of minutes.
func (a *API) Country(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	addr = addr.Unmap()
	a.mu.Lock()
	configured := a.host != ""
	a.mu.Unlock()
	if !configured {
		return ""
	}
	if hit, _, ok := a.cached(addr); ok {
		return hit.Country
	}
	a.warm(addr)
	return ""
}

// CountryForDecision answers for a decision that cannot be made without it - an
// access rule that tests a country - and waits, briefly, for an answer.
func (a *API) CountryForDecision(ctx context.Context, addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	addr = addr.Unmap()
	if hit, _, ok := a.cached(addr); ok {
		return hit.Country
	}
	if !a.Configured() {
		return ""
	}
	info, err := a.Lookup(ctx, addr)
	if err != nil {
		// The rule sees no country, which the rule itself decides what to do with.
		return ""
	}
	return info.Country
}

// AbuseScoreForDecision returns the IP API's abuse confidence score. Security
// gates wait briefly for a cold lookup; cached addresses return immediately.
func (a *API) AbuseScoreForDecision(ctx context.Context, addr netip.Addr) int {
	if !addr.IsValid() {
		return 0
	}
	addr = addr.Unmap()
	if hit, _, ok := a.cached(addr); ok {
		return hit.AbuseScore
	}
	if !a.Configured() {
		return 0
	}
	info, err := a.Lookup(ctx, addr)
	if err != nil {
		return 0
	}
	return info.AbuseScore
}

// warm looks an address up in the background, at most once at a time, and retries
// with backoff while the API has no answer.
func (a *API) warm(addr netip.Addr) {
	a.mu.Lock()
	if a.warming[addr] {
		a.mu.Unlock()
		return
	}
	if next, ok := a.warmingAt[addr]; ok && time.Now().Before(next) {
		a.mu.Unlock()
		return
	}
	a.warming[addr] = true
	a.mu.Unlock()

	go func() {
		select {
		case a.warmSlots <- struct{}{}:
			defer func() { <-a.warmSlots }()
		case <-time.After(warmTimeout):
			a.mu.Lock()
			delete(a.warming, addr)
			a.mu.Unlock()
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), warmTimeout)
		defer cancel()
		_, err := a.Lookup(ctx, addr)

		a.mu.Lock()
		delete(a.warming, addr)
		if err == nil {
			delete(a.warmingAt, addr)
			delete(a.attempts, addr)
			a.mu.Unlock()
			return
		}
		// Try again soon, further apart each time, without waiting for another
		// request to nudge it: an API that is slow rather than broken answers on one
		// of these, and the country appears.
		attempts := a.attempts[addr] + 1
		if len(a.attempts) > 2048 {
			// A very busy node: keep the maps from growing without bound.
			a.attempts = map[netip.Addr]int{}
			a.warmingAt = map[netip.Addr]time.Time{}
			attempts = 1
		}
		a.attempts[addr] = attempts
		backoff := failureTTL << min(attempts-1, 5)
		if backoff > retryMax {
			backoff = retryMax
		}
		next := time.Now().Add(backoff)
		a.warmingAt[addr] = next
		a.mu.Unlock()
		time.AfterFunc(time.Until(next), func() { a.warm(addr) })
	}()
}

// Lookup answers for one address, using the cache when it can.
func (a *API) Lookup(ctx context.Context, addr netip.Addr) (Lookup, error) {
	if !addr.IsValid() {
		return Lookup{}, fmt.Errorf("geoip: %q is not an address", addr)
	}
	addr = addr.Unmap()
	a.mu.Lock()
	host, token := a.host, a.token
	fallback, retryAt := a.fallback, a.publicRetryAt
	a.mu.Unlock()
	if host == "" {
		return Lookup{}, ErrNotConfigured
	}
	if hit, cachedErr, ok := a.cached(addr); ok {
		// A failure that is still fresh is answered from the cache too: an API
		// that is down should not be asked once per request.
		return hit, cachedErr
	}
	started := time.Now()
	var info Lookup
	var err error
	if time.Now().Before(retryAt) {
		err = fmt.Errorf("geoip: ipapi.is is temporarily unavailable")
	} else {
		primaryCtx := ctx
		cancel := func() {}
		if fallback != nil && fallback.Configured() {
			primaryCtx, cancel = context.WithTimeout(ctx, 750*time.Millisecond)
		}
		info, err = a.fetch(primaryCtx, host, token, addr)
		cancel()
	}
	if err != nil && fallback != nil && fallback.Configured() {
		primaryErr := err
		info, err = fallback.Lookup(ctx, addr)
		if err == nil {
			a.mu.Lock()
			a.fallbackLookups++
			a.lastFallbackReason = primaryErr.Error()
			a.mu.Unlock()
		} else {
			err = fmt.Errorf("primary IP API: %v; iplog fallback: %w", primaryErr, err)
		}
	}
	if err != nil && a.provider == "ipapi" && fallback != nil {
		a.mu.Lock()
		if a.publicRetryAt.Before(time.Now()) {
			a.publicRetryAt = time.Now().Add(30 * time.Second)
		}
		a.mu.Unlock()
	}
	a.remember(addr, info, err, time.Since(started))
	if err != nil {
		a.report(err)
		return Lookup{}, err
	}
	a.reportCountry(addr, info.Country)
	return info, nil
}

// fetch requests the fields country and abuse decisions use. Optional port
// scans, reverse DNS and registration lookups are skipped to keep this path fast.
func (a *API) fetch(ctx context.Context, host, token string, addr netip.Addr) (Lookup, error) {
	if a.provider == "ipapi" {
		return a.fetchPublic(ctx, host, token, addr)
	}
	endpoint := host + "/checkip?ip=" + url.QueryEscape(addr.String()) + "&ports=no&hostname=no&registration=no"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Lookup{}, err
	}
	request.Header.Set("Accept", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := a.client.Do(request)
	if err != nil {
		return Lookup{}, fmt.Errorf("geoip: %s: %w", host, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponse))
	if err != nil {
		return Lookup{}, err
	}
	if response.StatusCode != http.StatusOK {
		return Lookup{}, fmt.Errorf("geoip: %s answered %s: %s", host, response.Status, firstLine(string(body)))
	}
	var parsed apiResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Lookup{}, fmt.Errorf("geoip: %s sent something that is not the documented JSON: %w", host, err)
	}
	return parsed.lookup(), nil
}

func (a *API) fetchPublic(ctx context.Context, host, token string, addr netip.Addr) (Lookup, error) {
	if token == "" {
		return Lookup{}, fmt.Errorf("geoip: ipapi.is requires an API key")
	}
	// POST keeps the key out of URLs and proxy access logs.
	data, err := json.Marshal(map[string]string{"q": addr.String(), "key": token})
	if err != nil {
		return Lookup{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, host, strings.NewReader(string(data)))
	if err != nil {
		return Lookup{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := a.client.Do(request)
	if err != nil {
		return Lookup{}, fmt.Errorf("geoip: ipapi.is: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponse))
	if err != nil {
		return Lookup{}, err
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusForbidden {
			delay := time.Hour
			if seconds, parseErr := strconv.Atoi(response.Header.Get("Retry-After")); parseErr == nil && seconds > 0 {
				delay = min(time.Duration(seconds)*time.Second, 24*time.Hour)
			}
			a.mu.Lock()
			a.publicRetryAt = time.Now().Add(delay)
			a.mu.Unlock()
		}
		return Lookup{}, fmt.Errorf("geoip: ipapi.is answered %s: %s", response.Status, firstLine(string(body)))
	}
	var parsed struct {
		IP       string `json:"ip"`
		Error    string `json:"error"`
		Country  string `json:"country"`
		Location struct {
			CountryCode string `json:"country_code"`
		} `json:"location"`
		ASN struct {
			Org string `json:"org"`
		} `json:"asn"`
		IsTor        bool   `json:"is_tor"`
		IsProxy      bool   `json:"is_proxy"`
		IsDatacenter bool   `json:"is_datacenter"`
		IsAbuser     bool   `json:"is_abuser"`
		Docs         string `json:"docs"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Lookup{}, fmt.Errorf("geoip: ipapi.is sent invalid JSON: %w", err)
	}
	if parsed.Error != "" {
		return Lookup{}, fmt.Errorf("geoip: ipapi.is: %s", parsed.Error)
	}
	if parsed.Docs != "" {
		return Lookup{}, fmt.Errorf("geoip: ipapi.is returned anonymous data; check the API key")
	}
	answeredIP, parseErr := netip.ParseAddr(parsed.IP)
	if parseErr != nil || answeredIP.Unmap() != addr || len(parsed.Location.CountryCode) != 2 {
		return Lookup{}, fmt.Errorf("geoip: ipapi.is returned no country for %s", addr)
	}
	info := Lookup{Country: strings.ToUpper(parsed.Location.CountryCode), CountryFrom: "ipapi.is", ASN: parsed.ASN.Org,
		IsTor: parsed.IsTor, Proxy: parsed.IsProxy, Hosting: parsed.IsDatacenter}
	// ipapi.is exposes an abuse verdict rather than iplog's 0-100 confidence.
	// A positive verdict maps to the existing high-risk threshold of 80.
	if parsed.IsAbuser {
		info.AbuseScore = 100
	}
	return info, nil
}

// remember stores an answer, or the failure, for later requests.
func (a *API) remember(addr netip.Addr, info Lookup, err error, elapsed time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.lastError = err.Error()
		a.cache[addr] = entry{err: err.Error(), at: time.Now()}
		return
	}
	a.lastError = ""
	a.lastAt = time.Now()
	a.lookups++
	a.responseTotal += elapsed
	a.responseCount++
	a.cache[addr] = entry{info: info, at: time.Now()}
	if a.cacheFile != "" && a.cacheTimer == nil {
		a.cacheTimer = time.AfterFunc(2*time.Second, a.persistCache)
	}
}

// report hands a failure to whoever is listening, without holding the lock: the
// callback records an error, and that reads this client's own status.
func (a *API) report(err error) {
	a.mu.Lock()
	callback := a.OnError
	a.mu.Unlock()
	if callback != nil {
		callback(err)
	}
}

func (a *API) reportCountry(addr netip.Addr, country string) {
	if country == "" {
		return
	}
	a.mu.Lock()
	callback := a.OnCountry
	a.mu.Unlock()
	if callback != nil {
		callback(addr, country)
	}
}

// cached returns a remembered outcome while it is still fresh: the answer, the
// failure, or nothing when there is no usable entry.
func (a *API) cached(addr netip.Addr) (Lookup, error, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	hit, ok := a.cache[addr]
	if !ok {
		return Lookup{}, nil, false
	}
	ttl := cacheTTL
	if hit.err != "" {
		ttl = failureTTL
	}
	if time.Since(hit.at) > ttl {
		delete(a.cache, addr)
		return Lookup{}, nil, false
	}
	if hit.err != "" {
		return Lookup{}, errors.New(hit.err), true
	}
	return hit.info, nil, true
}

// Clear forgets every cached answer.
func (a *API) Clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cache = map[netip.Addr]entry{}
	a.lastError = ""
	a.lookups = 0
	a.responseTotal = 0
	a.responseCount = 0
}

// apiResponse is the documented answer from /checkip.
type apiResponse struct {
	Data struct {
		IP    string `json:"ip"`
		IsTor bool   `json:"is_tor"`
		ASNs  []struct {
			ASN         int    `json:"asn"`
			Name        string `json:"name"`
			CountryCode string `json:"country_code"`
		} `json:"asns"`
		Allocation struct {
			CountryCode string `json:"country_code"`
		} `json:"allocation"`
		Abuse struct {
			ConfidenceScore int    `json:"abuse_confidence_score"`
			CountryCode     string `json:"country_code"`
		} `json:"abuse"`
		Registration struct {
			CountryCode string `json:"country_code"`
		} `json:"registration"`
		Security struct {
			Hosting struct {
				Detected bool `json:"detected"`
			} `json:"hosting"`
			Proxy struct {
				Detected bool `json:"detected"`
			} `json:"proxy"`
		} `json:"security"`
	} `json:"data"`
}

// lookup turns the API's answer into the fields country rules use.
//
// The country comes from the first field that has one: the abuse report, then the
// allocation, then the network's ASN. The API has no single "country" field, and
// those three are the ones it fills in; which one answered is reported so an
// operator can see why a rule matched.
func (p apiResponse) lookup() Lookup {
	info := Lookup{
		IsTor:      p.Data.IsTor,
		Hosting:    p.Data.Security.Hosting.Detected,
		Proxy:      p.Data.Security.Proxy.Detected,
		AbuseScore: p.Data.Abuse.ConfidenceScore,
	}
	if len(p.Data.ASNs) > 0 {
		info.ASN = p.Data.ASNs[0].Name
	}
	switch {
	case p.Data.Abuse.CountryCode != "":
		info.Country, info.CountryFrom = strings.ToUpper(p.Data.Abuse.CountryCode), "abuse"
	case p.Data.Allocation.CountryCode != "":
		info.Country, info.CountryFrom = strings.ToUpper(p.Data.Allocation.CountryCode), "allocation"
	case p.Data.Registration.CountryCode != "":
		info.Country, info.CountryFrom = strings.ToUpper(p.Data.Registration.CountryCode), "registration"
	case len(p.Data.ASNs) > 0 && p.Data.ASNs[0].CountryCode != "":
		info.Country, info.CountryFrom = strings.ToUpper(p.Data.ASNs[0].CountryCode), "asn"
	}
	return info
}

// firstLine keeps an error message to one readable line.
func firstLine(raw string) string {
	raw = strings.TrimSpace(raw)
	if index := strings.IndexByte(raw, '\n'); index >= 0 {
		return strings.TrimSpace(raw[:index])
	}
	return raw
}
