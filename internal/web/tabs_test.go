package web

import (
	"regexp"
	"strings"
	"testing"
)

// TestSettingsIsSplitIntoTabs checks the Settings page has its own tab group and
// that every tab has a panel to show.
func TestSettingsIsSplitIntoTabs(t *testing.T) {
	index := readAsset(t, "assets/index.html")
	template, err := extractTemplate(index, "tpl-shell")
	if err != nil {
		t.Fatal(err)
	}
	root, err := parseHTML(template)
	if err != nil {
		t.Fatal(err)
	}
	// The country data tab is the operator's own IP API, not a bundled database.
	if !strings.Contains(template, ">IP API<") {
		t.Error("the Settings tab for country lookups should be called IP API")
	}
	for _, gone := range []string{"GeoLite", "MaxMind", "licence key"} {
		if strings.Contains(template, gone) {
			t.Errorf("the settings panel still mentions %q", gone)
		}
	}
	wanted := []string{"mesh", "users", "smtp", "geoip", "branding", "tokens"}
	for _, view := range wanted {
		if !queryMatches(root, `[data-tab="`+view+`"]`) {
			t.Errorf("no Settings tab for %q", view)
		}
		if !queryMatches(root, `[data-tab-panel="`+view+`"]`) {
			t.Errorf("no panel for the %q Settings tab", view)
		}
	}
	// Only the first panel is visible on load, so the page is not a wall of forms.
	section := viewSection(t, index, "settings")
	usersSettings := panelMarkup(t, section, "users")
	if !strings.Contains(usersSettings, `data-form="signup-settings"`) || !strings.Contains(usersSettings, `name="maxUsers"`) {
		t.Error("the Users settings tab must contain signup controls and the registration limit")
	}
	panels := regexp.MustCompile(`<div class="[^"]*" data-tab-panel="([a-z]+)"[^>]*>`).FindAllStringSubmatch(section, -1)
	if len(panels) != len(wanted) {
		t.Fatalf("expected %d settings panels, found %d", len(wanted), len(panels))
	}
	for _, match := range panels {
		line := match[0]
		hidden := strings.Contains(line, "hidden")
		if match[1] == "mesh" && hidden {
			t.Errorf("the mesh Settings panel should be visible: %s", line)
		}
		if match[1] != "mesh" && !hidden {
			t.Errorf("Settings panel %q should start hidden: %s", match[1], line)
		}
	}
}

// TestLogsTabsSitAtPageLevel checks that Logs subtabs are in the sidebar and
// each still controls a panel in the Logs view.
func TestLogsTabsSitAtPageLevel(t *testing.T) {
	index := readAsset(t, "assets/index.html")
	root, err := parseHTML(index)
	if err != nil {
		t.Fatal(err)
	}
	nav := findNode(root, func(n *htmlNode) bool { return n.Tag == "nav" && nodeMatches(n, `[data-subnav="activity"]`) })
	if nav == nil {
		t.Fatal("the sidebar has no Logs subnavigation")
	}
	if nav.Parent == nil || !nodeMatches(nav.Parent, ".sidebar-nav") {
		t.Fatal("the Logs subnavigation should be inside the sidebar")
	}
	section := viewSection(t, index, "activity")
	for _, panel := range []string{"requests", "statistics", "activity", "errors"} {
		if !queryMatches(nav, `[data-tab="`+panel+`"]`) {
			t.Errorf("no Logs tab for %q", panel)
		}
		if !strings.Contains(section, `data-tab-panel="`+panel+`"`) {
			t.Errorf("no panel for the %q Logs tab", panel)
		}
	}
	// The request list and the charts are separate tabs now: the list is what the
	// Requests tab is for, and the charts have their own.
	requestsPanel := panelMarkup(t, section, "requests")
	if !strings.Contains(requestsPanel, "data-request-table") {
		t.Error("the Requests panel should hold the request list")
	}
	if strings.Contains(requestsPanel, "data-request-charts") {
		t.Error("the Requests panel should not hold the charts")
	}
	statisticsPanel := panelMarkup(t, section, "statistics")
	if !strings.Contains(statisticsPanel, "data-request-charts") {
		t.Error("the Statistics panel should hold the charts")
	}
	if strings.Contains(statisticsPanel, "data-request-table") {
		t.Error("the Statistics panel should not hold the request list")
	}
}

// panelMarkup returns the markup of one panel inside a view section.
func panelMarkup(t *testing.T, section, name string) string {
	t.Helper()
	marker := `data-tab-panel="` + name + `"`
	start := strings.Index(section, marker)
	if start < 0 {
		t.Fatalf("no %q panel", name)
	}
	rest := section[start+len(marker):]
	if next := strings.Index(rest, `data-tab-panel="`); next >= 0 {
		return rest[:next]
	}
	return rest
}

// viewSection returns the markup of the <section> panel for a view.
func viewSection(t *testing.T, page, view string) string {
	t.Helper()
	pattern := regexp.MustCompile(`(?s)<section class="view"[^>]*data-view-panel="` + view + `"[^>]*>.*?</section>`)
	section := pattern.FindString(page)
	if section == "" {
		t.Fatalf("no view section for %q", view)
	}
	return section
}

// findNode returns the first node in the tree that matches want.
func findNode(root *htmlNode, want func(*htmlNode) bool) *htmlNode {
	for _, node := range descendants(root) {
		if want(node) {
			return node
		}
	}
	return nil
}

// TestTabsLookLikeTabs checks active sidebar subtabs are visibly selected.
func TestTabsLookLikeTabs(t *testing.T) {
	css := readAsset(t, "assets/style.css")
	tab := ruleBody(css, ".sidebar-sublink")
	active := ruleBody(css, ".sidebar-sublink.is-active")
	if tab == "" || active == "" {
		t.Fatal("the sidebar subtab styles are missing")
	}
	if !strings.Contains(css, ".sidebar-sublink:hover") {
		t.Error("sidebar subtabs should react to hover")
	}
	if !strings.Contains(active, "background") {
		t.Errorf("the active tab should be highlighted, got %q", strings.TrimSpace(active))
	}
	subnav := ruleBody(css, ".sidebar-subnav::before")
	if !strings.Contains(subnav, "background") {
		t.Errorf("the sidebar subtab group should have a guide line, got %q", strings.TrimSpace(subnav))
	}
}
