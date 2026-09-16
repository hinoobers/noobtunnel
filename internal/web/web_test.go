package web

import (
	"io/fs"
	"strings"
	"testing"
)

func TestAssetsAreEmbedded(t *testing.T) {
	assets := Assets()
	for _, name := range []string{
		"assets/index.html", "assets/app.js", "assets/views.js",
		"assets/users_api.js", "assets/resources_api.js", "assets/exitnodes_api.js", "assets/style.css",
		"assets/dns_api.js", "assets/branding_api.js", "assets/geoip_api.js",
		"assets/logs_api.js",
	} {
		info, err := fs.Stat(assets, name)
		if err != nil {
			t.Fatalf("embedded asset %s is missing: %v", name, err)
		}
		if info.Size() == 0 {
			t.Fatalf("embedded asset %s is empty", name)
		}
	}
}

func TestIndexReferencesExistingAssets(t *testing.T) {
	index, err := Index()
	if err != nil {
		t.Fatal(err)
	}
	page := string(index)
	for _, want := range []string{
		`href="/assets/style.css"`,
		`src="/assets/app.js"`,
		`src="/assets/views.js"`,
		`src="/assets/users_api.js"`,
		`src="/assets/resources_api.js"`,
		`src="/assets/exitnodes_api.js"`,
		`src="/assets/dns_api.js"`,
		`src="/assets/branding_api.js"`,
		`src="/assets/geoip_api.js"`,
		`src="/assets/logs_api.js"`,
		`href="/favicon.svg"`,
		`id="app"`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("index.html is missing %q", want)
		}
	}
	// The scripts must load in order: views.js uses helpers from app.js.
	if strings.Index(page, "app.js") > strings.Index(page, "views.js") {
		t.Fatal("app.js must be loaded before views.js")
	}
}

// TestNoExternalResources keeps the control node usable on a machine without
// internet access and avoids leaking that the UI was opened to a third party.
func TestNoExternalResources(t *testing.T) {
	names := []string{
		"assets/index.html", "assets/app.js", "assets/views.js",
		"assets/users_api.js", "assets/resources_api.js", "assets/exitnodes_api.js", "assets/style.css",
		"assets/dns_api.js", "assets/branding_api.js", "assets/geoip_api.js",
		"assets/logs_api.js",
	}
	for _, name := range names {
		raw, err := files.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		// The SVG namespace URI is not a network fetch; everything else that
		// could pull bytes from a third party is rejected.
		for _, forbidden := range []string{
			`src="http`, `src='http`, `href="http`, `href='http`, `url(http`,
			"@import", "//unpkg", "//jsdelivr", "//cdn", "fonts.googleapis", "fetch(\"http",
		} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("%s references an external resource (%q)", name, forbidden)
			}
		}
	}
}

func TestFaviconIsSVG(t *testing.T) {
	icon := Favicon()
	if !strings.HasPrefix(icon, "<svg") || !strings.HasSuffix(icon, "</svg>") {
		t.Fatal("favicon should be a complete inline SVG")
	}
}
