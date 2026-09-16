// Package geoip maps client addresses to countries for resource access rules.
//
// MaxMind ships GeoLite2-Country as a tarball containing both an .mmdb database
// and two CSVs. The CSVs hold the same block-to-country mapping and can be read
// with the standard library, so that is what this package uses: no third party
// dependency, and the same data an .mmdb reader would consult.
package geoip

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// The GeoLite2-Country tarball carries only the .mmdb build, so the CSV edition
// is the one to fetch: it contains the block and location CSVs this package reads.
const (
	// MaxMindDownload is the authenticated download endpoint.
	MaxMindDownload = "https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip"
	// MaxMindLegacyDownload works with a licence key alone.
	MaxMindLegacyDownload = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&suffix=zip&license_key="
	// cacheName is the archive kept between runs.
	cacheName = "GeoLite2-Country-CSV.zip"
)

// Database answers country lookups. It is safe for concurrent use.
type Database struct {
	mu sync.RWMutex
	// blocks are sorted by prefix length (longest first) so the most specific
	// network wins, exactly like a longest-prefix route lookup.
	blocks []block
	loaded time.Time
	source string
}

type block struct {
	prefix  netip.Prefix
	country string
}

// NotFound is the country reported for an address that is not in the database.
const NotFound = ""

// New creates an empty database.
func New() *Database { return &Database{} }

// Loaded reports whether any data is available.
func (d *Database) Loaded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.blocks) > 0
}

// Info describes the loaded data, for the UI and the logs.
func (d *Database) Info() (source string, blocks int, loaded time.Time) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.source, len(d.blocks), d.loaded
}

// Lookup returns the ISO country code for an address, or NotFound.
func (d *Database) Lookup(addr netip.Addr) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !addr.IsValid() {
		return NotFound
	}
	addr = addr.Unmap()
	for _, b := range d.blocks {
		if b.prefix.Contains(addr) {
			return b.country
		}
	}
	return NotFound
}

// LoadDirectory reads GeoLite2-Country CSV files from a directory. Either the
// extracted files or the tarball itself may live there.
func (d *Database) LoadDirectory(dir string) error {
	if raw, err := os.ReadFile(filepath.Join(dir, "GeoLite2-Country-Blocks-IPv4.csv")); err == nil {
		return d.LoadCSVFiles(dir, raw)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case strings.HasSuffix(name, ".zip"):
			file, err := os.Open(filepath.Join(dir, name))
			if err != nil {
				return err
			}
			info, statErr := file.Stat()
			if statErr != nil {
				file.Close()
				return statErr
			}
			err = d.LoadZip(file, info.Size())
			file.Close()
			return err
		case strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz"):
			file, err := os.Open(filepath.Join(dir, name))
			if err != nil {
				return err
			}
			err = d.LoadTarball(file)
			file.Close()
			return err
		}
	}
	return fmt.Errorf("geoip: no GeoLite2-Country CSV or archive in %s", dir)
}

// LoadZip reads the CSVs out of the GeoLite2-Country-CSV download.
func (d *Database) LoadZip(r io.ReaderAt, size int64) error {
	archive, err := zip.NewReader(r, size)
	if err != nil {
		return fmt.Errorf("geoip: %w", err)
	}
	var blocksRaw, locationsRaw []byte
	for _, entry := range archive.File {
		switch {
		case strings.HasSuffix(entry.Name, "GeoLite2-Country-Blocks-IPv4.csv"):
			blocksRaw, err = readZipEntry(entry, 64<<20)
		case strings.HasSuffix(entry.Name, "GeoLite2-Country-Locations-en.csv"):
			locationsRaw, err = readZipEntry(entry, 4<<20)
		}
		if err != nil {
			return err
		}
	}
	if blocksRaw == nil {
		return fmt.Errorf("geoip: the archive does not contain a country block list")
	}
	parsed, err := parseBlocks(blocksRaw, parseLocations(locationsRaw))
	if err != nil {
		return err
	}
	d.store(parsed, "maxmind csv archive")
	return nil
}

func readZipEntry(entry *zip.File, limit int64) ([]byte, error) {
	file, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit))
}

// LoadCSVFiles parses the blocks and locations CSVs.
func (d *Database) LoadCSVFiles(dir string, blocksCSV []byte) error {
	locationsPath := filepath.Join(dir, "GeoLite2-Country-Locations-en.csv")
	locations := map[string]string{}
	name := ""
	if raw, err := os.ReadFile(locationsPath); err == nil {
		locations = parseLocations(raw)
	}
	parsed, err := parseBlocks(blocksCSV, locations)
	if err != nil {
		return err
	}
	d.store(parsed, name)
	return nil
}

// LoadTarball reads the CSVs straight out of the MaxMind archive.
func (d *Database) LoadTarball(r io.Reader) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("geoip: %w", err)
	}
	defer gz.Close()

	var blocksRaw, locationsRaw []byte
	archive := tar.NewReader(gz)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("geoip: %w", err)
		}
		switch {
		case strings.HasSuffix(header.Name, "GeoLite2-Country-Blocks-IPv4.csv"):
			blocksRaw, err = io.ReadAll(io.LimitReader(archive, 64<<20))
			if err != nil {
				return err
			}
		case strings.HasSuffix(header.Name, "GeoLite2-Country-Locations-en.csv"):
			locationsRaw, err = io.ReadAll(io.LimitReader(archive, 4<<20))
			if err != nil {
				return err
			}
		}
	}
	if blocksRaw == nil {
		// The plain GeoLite2-Country tarball carries only the .mmdb build.
		return fmt.Errorf("geoip: that archive has no CSV block list; noobtunnel reads the CSV " +
			"edition (GeoLite2-Country-CSV), or point --geoip-dir at extracted CSVs")
	}
	parsed, err := parseBlocks(blocksRaw, parseLocations(locationsRaw))
	if err != nil {
		return err
	}
	d.store(parsed, "maxmind tarball")
	return nil
}

func (d *Database) store(blocks []block, source string) {
	sort.SliceStable(blocks, func(i, j int) bool {
		return blocks[i].prefix.Bits() > blocks[j].prefix.Bits()
	})
	d.mu.Lock()
	d.blocks = blocks
	d.loaded = time.Now().UTC()
	if source != "" {
		d.source = source
	}
	d.mu.Unlock()
}

// parseBlocks reads "network,geoname_id,..." rows.
func parseBlocks(raw []byte, locations map[string]string) ([]block, error) {
	reader := csv.NewReader(strings.NewReader(string(raw)))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}
	networkCol, geoCol, isoCol := -1, -1, -1
	registeredCol := -1
	for i, name := range header {
		switch strings.TrimSpace(name) {
		case "network":
			networkCol = i
		case "geoname_id":
			geoCol = i
		case "registered_country_geoname_id":
			// This is a geoname id, not an ISO code: it has to be resolved
			// through the locations table.
			registeredCol = i
		case "country_iso_code":
			isoCol = i
		}
	}
	if networkCol < 0 {
		return nil, fmt.Errorf("geoip: the block list has no network column")
	}
	var out []block
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if networkCol >= len(row) {
			continue
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(row[networkCol]))
		if err != nil {
			continue
		}
		country := ""
		if geoCol >= 0 && geoCol < len(row) {
			country = locations[strings.TrimSpace(row[geoCol])]
		}
		if country == "" && registeredCol >= 0 && registeredCol < len(row) {
			country = locations[strings.TrimSpace(row[registeredCol])]
		}
		if country == "" && isoCol >= 0 && isoCol < len(row) {
			country = strings.ToUpper(strings.TrimSpace(row[isoCol]))
		}
		if country == "" || len(country) != 2 {
			continue
		}
		out = append(out, block{prefix: prefix.Masked(), country: country})
	}
	return out, nil
}

// parseLocations maps geoname_id to ISO code.
func parseLocations(raw []byte) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	reader := csv.NewReader(strings.NewReader(string(raw)))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return out
	}
	geoCol, isoCol := -1, -1
	for i, name := range header {
		switch strings.TrimSpace(name) {
		case "geoname_id":
			geoCol = i
		case "country_iso_code":
			isoCol = i
		}
	}
	if geoCol < 0 || isoCol < 0 {
		return out
	}
	for {
		row, err := reader.Read()
		if err != nil {
			break
		}
		if geoCol < len(row) && isoCol < len(row) {
			code := strings.ToUpper(strings.TrimSpace(row[isoCol]))
			if len(code) == 2 {
				out[strings.TrimSpace(row[geoCol])] = code
			}
		}
	}
	return out
}

// Options configures a download.
type Options struct {
	// AccountID and LicenseKey authenticate the request.
	AccountID  string
	LicenseKey string
	// URL overrides the endpoint; tests point it at a local server.
	URL    string
	Client *http.Client
	// Dir is where the tarball is cached between runs.
	Dir string
}

// Download fetches the database, caching the archive in Options.Dir.
func Download(ctx context.Context, opts Options) (path string, err error) {
	if strings.TrimSpace(opts.LicenseKey) == "" {
		return "", fmt.Errorf("geoip: a MaxMind licence key is required")
	}
	if opts.Dir == "" {
		return "", fmt.Errorf("geoip: a cache directory is required")
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return "", err
	}
	endpoint := opts.URL
	if endpoint == "" {
		endpoint = defaultURL(strings.TrimSpace(opts.AccountID), opts.LicenseKey)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(opts.AccountID) != "" {
		request.SetBasicAuth(opts.AccountID, opts.LicenseKey)
	} else if request.URL.Query().Get("license_key") == "" {
		// The public endpoint takes the key as a query parameter.
		query := request.URL.Query()
		query.Set("license_key", opts.LicenseKey)
		request.URL.RawQuery = query.Encode()
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("geoip: download failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("geoip: MaxMind answered %s (check the licence key and account id)", response.Status)
	}
	target := filepath.Join(opts.Dir, cacheName)
	tmp := target + ".new"
	file, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(file, io.LimitReader(response.Body, 128<<20)); err != nil {
		file.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, target); err != nil {
		return "", err
	}
	return target, nil
}

// LoadOrDownload prefers a local copy and only hits the network when there is
// nothing cached, so restarts work offline.
func LoadOrDownload(ctx context.Context, opts Options) (*Database, error) {
	db := New()
	target := filepath.Join(opts.Dir, cacheName)
	if file, err := os.Open(target); err == nil {
		if info, statErr := file.Stat(); statErr == nil {
			err = db.LoadZip(file, info.Size())
		}
		file.Close()
		if err == nil {
			return db, nil
		}
		// A corrupt cache should not stop the download.
	}
	path, err := Download(ctx, opts)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := db.LoadZip(file, info.Size()); err != nil {
		return nil, err
	}
	return db, nil
}
