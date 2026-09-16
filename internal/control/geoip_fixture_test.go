package control_test

import (
	"archive/zip"
	"bytes"
	"testing"
)

// testGeoIPTarball builds a minimal GeoLite2-Country archive so the download path
// can be exercised without touching the network.
func testGeoIPTarball(t *testing.T) []byte {
	t.Helper()
	const blocks = `network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider
203.0.113.0/24,588,588,,0,0
`
	const locations = `geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name
588,en,EU,Europe,EE,Estonia
`
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
	write("GeoLite2-Country-CSV_Test/GeoLite2-Country-Blocks-IPv4.csv", blocks)
	write("GeoLite2-Country-CSV_Test/GeoLite2-Country-Locations-en.csv", locations)
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
