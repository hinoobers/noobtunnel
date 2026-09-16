package web

import (
	"regexp"
	"strings"
	"testing"
)

// TestHiddenAttributeAlwaysWins guards a subtle CSS trap: the browser hides
// [hidden] elements with a user-agent rule, but any author rule that sets
// `display` (here `.view { display: grid }`) overrides it. Without an explicit
// author rule the `hidden` attribute does nothing, every view panel renders at
// once, and switching tabs appears to do nothing.
func TestHiddenAttributeAlwaysWins(t *testing.T) {
	css := readAsset(t, "assets/style.css")
	rule := regexp.MustCompile(`(?m)^\s*\[hidden\]\s*\{([^}]*)\}`).FindStringSubmatch(css)
	if rule == nil {
		t.Fatal("style.css needs an explicit [hidden] rule, otherwise author display rules win and hidden panels stay visible")
	}
	body := rule[1]
	if !strings.Contains(body, "display") || !strings.Contains(body, "none") {
		t.Fatalf("[hidden] must set display: none, got %q", strings.TrimSpace(body))
	}
	if !strings.Contains(body, "important") {
		t.Fatalf("[hidden] must use !important so it beats rules like .view { display: grid }, got %q", strings.TrimSpace(body))
	}
}

// TestViewPanelsStartHidden makes sure nothing is dumped on screen before the
// UI switches to a view, and that every panel belongs to a known tab.
func TestViewPanelsStartHidden(t *testing.T) {
	index := readAsset(t, "assets/index.html")
	section := regexp.MustCompile(`(?s)<section class="view"([^>]*)>`)
	matches := section.FindAllStringSubmatch(index, -1)
	if len(matches) < 4 {
		t.Fatalf("expected at least 4 view panels, found %d", len(matches))
	}
	for i, match := range matches {
		attrs := match[1]
		panel := regexp.MustCompile(`data-view-panel="([\w-]+)"`).FindStringSubmatch(attrs)
		if panel == nil {
			t.Fatalf("view panel %d has no data-view-panel attribute", i)
		}
		if i > 0 && !strings.Contains(attrs, "hidden") {
			t.Errorf("view panel %q must start hidden, otherwise it renders on top of the active view", panel[1])
		}
		if !strings.Contains(index, `data-view="`+panel[1]+`"`) {
			t.Errorf("view panel %q has no tab to reach it", panel[1])
		}
	}
}

// TestViewPanelSwitchingIsWired checks the toggle that actually changes views.
func TestViewPanelSwitchingIsWired(t *testing.T) {
	app := readAsset(t, "assets/app.js")
	if !strings.Contains(app, "panel.hidden = !active") {
		t.Error("renderShell must set panel.hidden when switching views")
	}
	if !strings.Contains(app, "setView(tab.dataset.view)") {
		t.Error("clicking a tab must switch the view through setView")
	}
	if !strings.Contains(app, "renderShell()") {
		t.Error("switching a view must re-render the shell")
	}
	// The URL carries the view so a refresh returns to the same tab.
	if !strings.Contains(app, "state.view = view") || !strings.Contains(app, "pushState") {
		t.Error("the view should be reflected in the URL")
	}
}
