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
	wanted := []string{"mesh", "geoip", "branding", "tokens"}
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
	panels := regexp.MustCompile(`<div class="[^"]*" data-tab-panel="([a-z]+)"[^>]*>`).FindAllStringSubmatch(section, -1)
	if len(panels) != len(wanted) {
		t.Fatalf("expected %d settings panels, found %d", len(wanted), len(panels))
	}
	for i, match := range panels {
		line := match[0]
		hidden := strings.Contains(line, "hidden")
		if i == 0 && hidden {
			t.Errorf("the first Settings panel should be visible: %s", line)
		}
		if i > 0 && !hidden {
			t.Errorf("Settings panel %q should start hidden: %s", match[1], line)
		}
	}
}

// TestLogsTabsSitAtPageLevel mirrors Settings: the Logs tab row belongs to the
// view itself, sitting above the cards instead of being buried inside one.
func TestLogsTabsSitAtPageLevel(t *testing.T) {
	index := readAsset(t, "assets/index.html")
	root, err := parseHTML(viewSection(t, index, "activity"))
	if err != nil {
		t.Fatal(err)
	}
	nav := findNode(root, func(n *htmlNode) bool { return n.Tag == "nav" && nodeMatches(n, ".tabs") })
	if nav == nil {
		t.Fatal("the Logs view has no tab row")
	}
	if nav.Parent == nil || nav.Parent.Tag != "section" || !nodeMatches(nav.Parent, ".view") {
		t.Fatalf("the Logs tab row should hang off the view section like Settings, found parent <%s>", nav.Parent.Tag)
	}
	for _, panel := range []string{"requests", "activity", "errors"} {
		if !queryMatches(root, `[data-tab="`+panel+`"]`) {
			t.Errorf("no Logs tab for %q", panel)
		}
		if !queryMatches(root, `[data-tab-panel="`+panel+`"]`) {
			t.Errorf("no panel for the %q Logs tab", panel)
		}
	}
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

// TestTabsLookLikeTabs covers the styling complaint: the active tab must carry
// the emphasis that hovering gives, so it reads as selected.
func TestTabsLookLikeTabs(t *testing.T) {
	css := readAsset(t, "assets/style.css")
	tab := ruleBody(css, ".tab")
	active := ruleBody(css, ".tab.is-active")
	if tab == "" || active == "" {
		t.Fatal("the tab styles are missing")
	}
	if !strings.Contains(css, ".tab:hover") {
		t.Error("tabs should react to hover")
	}
	// The active tab has a background and, unlike the others, a visible border.
	if !strings.Contains(active, "background") {
		t.Errorf("the active tab should be highlighted, got %q", strings.TrimSpace(active))
	}
	// A baseline under the row makes the group read as tabs.
	tabs := ruleBody(css, ".tabs")
	if !strings.Contains(tabs, "border-bottom") {
		t.Errorf("the tab row should have a baseline, got %q", strings.TrimSpace(tabs))
	}
}
