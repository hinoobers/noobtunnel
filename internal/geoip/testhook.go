package geoip

// testURL overrides the download endpoint. It exists so tests can point the
// loader at a local server instead of MaxMind.
var testURL string

// SetDownloadURLForTest overrides the endpoint used when Options.URL is empty.
func SetDownloadURLForTest(url string) { testURL = url }

// defaultURL returns the endpoint to use, honouring the test override.
func defaultURL(accountID, licenseKey string) string {
	if testURL != "" {
		return testURL
	}
	if accountID != "" {
		return MaxMindDownload
	}
	return MaxMindLegacyDownload + licenseKey
}
