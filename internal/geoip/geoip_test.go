package geoip

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const blocksCSV = `network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider
203.0.113.0/24,588,588,,0,0
198.51.100.0/24,,588,,0,0
1.2.0.0/16,,588,,0,0
10.0.0.0/8,999,999,,0,0
`

const locationsCSV = `geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name
588,en,EU,Europe,EE,Estonia
999,en,EU,Europe,XX,Nowhere
`

func tarball(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	archive := tar.NewWriter(gz)
	write := func(name string, body string) {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	write("GeoLite2-Country_20260101/GeoLite2-Country-Blocks-IPv4.csv", blocksCSV)
	write("GeoLite2-Country_20260101/GeoLite2-Country-Locations-en.csv", locationsCSV)
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// zipArchive builds the GeoLite2-Country-CSV style archive MaxMind serves.
func zipArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	archive := zip.NewWriter(&buf)
	write := func(name, body string) {
		w, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	write("GeoLite2-Country-CSV_20260101/GeoLite2-Country-Blocks-IPv4.csv", blocksCSV)
	write("GeoLite2-Country-CSV_20260101/GeoLite2-Country-Locations-en.csv", locationsCSV)
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestLoadZip(t *testing.T) {
	raw := zipArchive(t)
	db := New()
	if err := db.LoadZip(bytes.NewReader(raw), int64(len(raw))); err != nil {
		t.Fatal(err)
	}
	if got := db.Lookup(netip.MustParseAddr("203.0.113.10")); got != "EE" {
		t.Fatalf("lookup = %q, want EE", got)
	}
}

// TestTarballWithoutCSVsExplainsItself covers the exact problem a user hit: the
// GeoLite2-Country tarball only contains the .mmdb, so the error must say which
// download to use instead of looking like a broken download.
func TestTarballWithoutCSVsExplainsItself(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	archive := tar.NewWriter(gz)
	body := "not a csv"
	if err := archive.WriteHeader(&tar.Header{Name: "GeoLite2-Country_20260101/GeoLite2-Country.mmdb", Mode: 0o600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	archive.Close()
	gz.Close()
	err := New().LoadTarball(bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Fatal("a tarball without CSVs should fail")
	}
	if !strings.Contains(err.Error(), "GeoLite2-Country-CSV") {
		t.Fatalf("the error should name the right download: %v", err)
	}
}

func TestLoadTarballAndLookup(t *testing.T) {
	db := New()
	if err := db.LoadTarball(bytes.NewReader(tarball(t))); err != nil {
		t.Fatal(err)
	}
	if !db.Loaded() {
		t.Fatal("the database should be loaded")
	}
	if got := db.Lookup(netip.MustParseAddr("203.0.113.10")); got != "EE" {
		t.Fatalf("lookup = %q, want EE", got)
	}
	// A row without a country code falls back to the locations table.
	if got := db.Lookup(netip.MustParseAddr("198.51.100.7")); got != "EE" {
		t.Fatalf("lookup via geoname_id = %q, want EE", got)
	}
	if got := db.Lookup(netip.MustParseAddr("1.2.3.4")); got != "EE" {
		t.Fatalf("lookup = %q, want EE", got)
	}
	if got := db.Lookup(netip.MustParseAddr("10.1.1.1")); got != "XX" {
		t.Fatalf("lookup = %q, want XX", got)
	}
	if got := db.Lookup(netip.MustParseAddr("8.8.8.8")); got != NotFound {
		t.Fatalf("an address outside the list should be unknown, got %q", got)
	}
	if got := db.Lookup(netip.Addr{}); got != NotFound {
		t.Fatalf("an invalid address should be unknown, got %q", got)
	}
}

func TestLoadDirectoryCSVs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "GeoLite2-Country-Blocks-IPv4.csv"), []byte(blocksCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "GeoLite2-Country-Locations-en.csv"), []byte(locationsCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	db := New()
	if err := db.LoadDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if got := db.Lookup(netip.MustParseAddr("203.0.113.1")); got != "EE" {
		t.Fatalf("lookup = %q", got)
	}
	// A directory with nothing usable is an error, not a silent empty database.
	if err := New().LoadDirectory(t.TempDir()); err == nil {
		t.Fatal("an empty directory should fail to load")
	}
}

// TestDownloadAndCache exercises the download path against a local server: the
// licence key is sent, the archive is cached, and a second run uses the cache
// without another request.
func TestDownloadAndCache(t *testing.T) {
	archive := zipArchive(t)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if key := r.URL.Query().Get("license_key"); key != "test-key" {
			t.Errorf("the licence key was not sent: %q", key)
		}
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	dir := t.TempDir()
	opts := Options{LicenseKey: "test-key", URL: server.URL, Dir: dir}
	db, err := LoadOrDownload(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !db.Loaded() || requests != 1 {
		t.Fatalf("expected one download, got %d requests", requests)
	}
	if _, err := os.Stat(filepath.Join(dir, cacheName)); err != nil {
		t.Fatalf("the archive should be cached: %v", err)
	}
	// A second start uses the cache.
	if _, err := LoadOrDownload(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("the cached archive should be reused, got %d requests", requests)
	}
}

func TestDownloadRejectsBadCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	_, err := LoadOrDownload(context.Background(), Options{LicenseKey: "bad", URL: server.URL, Dir: t.TempDir()})
	if err == nil {
		t.Fatal("a 401 should surface as an error")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("licence key")) {
		t.Fatalf("the error should mention the licence key: %v", err)
	}
	// Without a key there is nothing to try.
	if _, err := Download(context.Background(), Options{Dir: t.TempDir()}); err == nil {
		t.Fatal("a missing licence key should fail fast")
	}
}

func TestBasicAuthWhenAccountIDIsSet(t *testing.T) {
	archive := zipArchive(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "12345" || pass != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(archive)
	}))
	defer server.Close()
	if _, err := LoadOrDownload(context.Background(), Options{
		AccountID: "12345", LicenseKey: "test-key", URL: server.URL, Dir: t.TempDir(),
	}); err != nil {
		t.Fatalf("basic auth download failed: %v", err)
	}
}
