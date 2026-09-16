package web

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	htmlAction  = regexp.MustCompile(`data-action="([\w-]+)"`)
	jsAction    = regexp.MustCompile(`'data-action':\s*'([\w-]+)'`)
	handledCase = regexp.MustCompile(`(?m)^\s*case '([\w-]+)':`)
)

// TestEveryActionHasAHandler walks every data-action in the markup and in the
// render functions and checks that the delegated click handler knows about it.
// Without this, a button can look perfectly fine and silently do nothing.
func TestEveryActionHasAHandler(t *testing.T) {
	index := readAsset(t, "assets/index.html")
	views := readAsset(t, "assets/views.js")
	app := readAsset(t, "assets/app.js")

	actions := map[string]bool{}
	for _, match := range htmlAction.FindAllStringSubmatch(index, -1) {
		actions[match[1]] = true
	}
	for _, match := range jsAction.FindAllStringSubmatch(views, -1) {
		actions[match[1]] = true
	}
	if len(actions) < 15 {
		t.Fatalf("only found %d actions, the detection is broken", len(actions))
	}

	handled := map[string]bool{}
	for _, match := range handledCase.FindAllStringSubmatch(functionBody(app, "handleGlobalAction"), -1) {
		handled[match[1]] = true
	}

	var unhandled []string
	for action := range actions {
		if !handled[action] {
			unhandled = append(unhandled, action)
		}
	}
	if len(unhandled) > 0 {
		sort.Strings(unhandled)
		t.Fatalf("these buttons are wired to no handler: %s", strings.Join(unhandled, ", "))
	}
}

// TestActionHandlerIsDocumentLevel guards the bug where modals and the drawer,
// which are mounted outside #app, had completely dead buttons.
func TestActionHandlerIsDocumentLevel(t *testing.T) {
	app := readAsset(t, "assets/app.js")
	if !strings.Contains(app, `document.addEventListener('click', handleGlobalAction)`) {
		t.Fatal("click delegation must be installed on the document, not on the shell")
	}
	if strings.Contains(app, `node.addEventListener('click'`) {
		t.Fatal("shell-scoped click delegation would miss the modal and drawer buttons")
	}
}
