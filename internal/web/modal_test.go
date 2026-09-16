package web

import (
	"strings"
	"testing"
)

// TestOverlayClosesOnClickNotMousedown guards a subtle bug: closing on mousedown
// removed the dialog, and the following click then landed on whatever was behind
// it — usually the button that opened it — so the dialog instantly re-appeared
// (and the open animation replayed, which read as a shake).
func TestOverlayClosesOnClickNotMousedown(t *testing.T) {
	app := readAsset(t, "assets/app.js")
	open := functionBody(app, "openModal")
	if open == "" {
		t.Fatal("openModal is missing")
	}
	if strings.Contains(open, "'mousedown'") {
		t.Error("the overlay must not close on mousedown, or the click behind it re-opens the dialog")
	}
	if !strings.Contains(open, "addEventListener('click'") {
		t.Error("the overlay should close on click")
	}
	if !strings.Contains(open, "event.stopPropagation()") {
		t.Error("the closing click must not reach the delegated action handler")
	}
}

// TestActivityListLetsTheCategoryChipHugItsText covers the layout complaint that
// "settings" looked lost inside a fixed width box.
func TestActivityListLetsTheCategoryChipHugItsText(t *testing.T) {
	css := readAsset(t, "assets/style.css")
	rule := ruleBody(css, ".events li")
	if rule == "" {
		t.Fatal("the activity list has no styling")
	}
	if strings.Contains(rule, "100px") {
		t.Fatalf("the category column must size to its content, got %q", strings.TrimSpace(rule))
	}
	if !strings.Contains(rule, "max-content") {
		t.Errorf("the category column should hug its chip, got %q", strings.TrimSpace(rule))
	}
}
