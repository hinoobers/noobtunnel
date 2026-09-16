package web

import (
	"strings"
	"testing"
)

// The agent drawer used to be rebuilt from scratch on every live update, which
// replayed its slide-in animation, and dismissing it (for example by clicking
// outside) left `state.drawer` set, so a later update re-opened it and wiped
// whatever modal the admin had opened in the meantime.

func TestDrawerIsMountedOnceAndUpdatedInPlace(t *testing.T) {
	views := readAsset(t, "assets/views.js")
	drawer := functionBody(views, "renderDrawer")
	if drawer == "" {
		t.Fatal("renderDrawer is missing")
	}
	if strings.Contains(drawer, "openModal(") {
		t.Error("renderDrawer must not recreate the drawer through openModal on every update")
	}
	if !strings.Contains(drawer, "openDrawer(agent)") {
		t.Error("renderDrawer should mount the drawer once via openDrawer")
	}
	if !strings.Contains(drawer, "state.drawerBody.replaceChildren") {
		t.Error("renderDrawer should refresh the drawer body in place")
	}
	if !strings.Contains(drawer, "scrollTop") {
		t.Error("renderDrawer should preserve the drawer scroll position")
	}
}

func TestClosingTheModalLayerAlsoClearsTheDrawer(t *testing.T) {
	app := readAsset(t, "assets/app.js")
	close := functionBody(app, "closeModal")
	if close == "" {
		t.Fatal("closeModal is missing")
	}
	for _, want := range []string{"state.drawer = null", "state.drawerEl = null", "state.drawerBody = null"} {
		if !strings.Contains(close, want) {
			t.Errorf("closeModal must reset the drawer state (%s), otherwise a dismissed drawer re-opens later", want)
		}
	}
	if !strings.Contains(functionBody(app, "openDrawer"), "state.drawerEl = node") {
		t.Error("openDrawer must remember the mounted drawer element")
	}
}

func TestDrawerFillsTheViewportHeight(t *testing.T) {
	css := readAsset(t, "assets/style.css")
	drawerRule := ruleBody(css, ".drawer")
	if drawerRule == "" {
		t.Fatal("the .drawer rule is missing")
	}
	if !strings.Contains(drawerRule, "max-height") {
		t.Fatal("the drawer inherits .modal's max-height (88vh) and would stop short of the bottom; " +
			"it needs its own max-height")
	}
	if !strings.Contains(drawerRule, "100vh") && !strings.Contains(drawerRule, "max-height: none") {
		t.Errorf("the drawer should use the full viewport height, got %q", strings.TrimSpace(drawerRule))
	}
}

// TestLoginClearsTheModalLayer covers an expired session leaving a drawer or
// dialog floating over the login form.
func TestLoginClearsTheModalLayer(t *testing.T) {
	app := readAsset(t, "assets/app.js")
	login := functionBody(app, "mountLogin")
	if !strings.Contains(login, "closeModal()") {
		t.Error("mountLogin must clear the modal layer")
	}
	logout := functionBody(app, "handleGlobalAction")
	if !strings.Contains(logout, "closeModal()") {
		t.Error("signing out must clear the modal layer")
	}
}

// ruleBody returns the declarations of a simple class rule.
func ruleBody(css, selector string) string {
	needle := selector + " {"
	start := strings.Index(css, needle)
	if start < 0 {
		return ""
	}
	rest := css[start+len(needle):]
	end := strings.Index(rest, "}")
	if end < 0 {
		return ""
	}
	return rest[:end]
}
