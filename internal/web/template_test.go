package web

import (
	"regexp"
	"strings"
	"testing"
)

// TestShellTemplateProvidesEveryElement is a structural guard for the UI: it
// parses the shell template the way a browser would, works out which part
// mountShell actually clones into the page, and checks that every element it then
// looks up exists in that cloned part. This catches bugs such as cloning only the
// first top level element, which silently dropped <main> and left the page blank.
func TestShellTemplateProvidesEveryElement(t *testing.T) {
	index, err := Index()
	if err != nil {
		t.Fatal(err)
	}
	source := readAsset(t, "assets/app.js")
	body := functionBody(source, "mountShell")
	cloned, topLevel, err := clonedRoots(t, string(index), "tpl-shell", body)
	if err != nil {
		t.Fatal(err)
	}
	if cloneStrategy(body) == cloneFirstChild && topLevel > 1 {
		t.Fatalf("mountShell clones only the first top level element but the shell template has %d "+
			"(wrap the template in one element, or clone the whole content)", topLevel)
	}
	selectors := shellSelectors(body)
	if len(selectors) < 10 {
		t.Fatalf("only found %d shell selectors, the detection is broken", len(selectors))
	}
	for _, selector := range selectors {
		if !anyMatch(cloned, selector) {
			t.Errorf("mountShell looks up %q but the shell template has no such element", selector)
		}
	}
}

// TestShellTemplateCoversEveryView checks that each view the tabs switch to
// exists in the cloned shell.
func TestShellTemplateCoversEveryView(t *testing.T) {
	index, err := Index()
	if err != nil {
		t.Fatal(err)
	}
	source := readAsset(t, "assets/app.js")
	cloned, _, err := clonedRoots(t, string(index), "tpl-shell", functionBody(source, "mountShell"))
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range []string{"overview", "agents", "resources", "domains", "users", "activity", "settings"} {
		if !anyMatch(cloned, `[data-view-panel="`+view+`"]`) {
			t.Errorf("view panel %q is missing from the cloned shell", view)
		}
		if !strings.Contains(string(index), `data-view="`+view+`"`) {
			t.Errorf("no tab switches to view %q", view)
		}
	}
}

// TestLoginTemplateHasSingleRoot documents the requirement mountLogin relies on.
func TestLoginTemplateHasSingleRoot(t *testing.T) {
	index, err := Index()
	if err != nil {
		t.Fatal(err)
	}
	source := readAsset(t, "assets/app.js")
	body := functionBody(source, "mountLogin")
	cloned, topLevel, err := clonedRoots(t, string(index), "tpl-login", body)
	if err != nil {
		t.Fatal(err)
	}
	if cloneStrategy(body) != cloneFirstChild {
		t.Skip("mountLogin no longer clones a single element")
	}
	if topLevel != 1 {
		t.Fatalf("mountLogin clones the first child only, but the template has %d top level elements", topLevel)
	}
	if !anyMatch(cloned, `form[data-form=login]`) {
		t.Error("the login form is missing")
	}
}

func readAsset(t *testing.T, name string) string {
	t.Helper()
	raw, err := Assets().(interface {
		ReadFile(string) ([]byte, error)
	}).ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

type cloneStyle int

const (
	cloneUnknown cloneStyle = iota
	cloneFirstChild
	cloneFragment
)

// cloneStrategy reports how a mount function copies a template into the page.
func cloneStrategy(body string) cloneStyle {
	switch {
	case strings.Contains(body, "content.firstElementChild"):
		return cloneFirstChild
	case strings.Contains(body, "content.cloneNode(true)"):
		return cloneFragment
	default:
		return cloneUnknown
	}
}

// clonedRoots returns the nodes a browser would actually insert, plus the number
// of top level elements in the template.
func clonedRoots(t *testing.T, page, templateID, body string) ([]*htmlNode, int, error) {
	t.Helper()
	template, err := extractTemplate(page, templateID)
	if err != nil {
		return nil, 0, err
	}
	root, err := parseHTML(template)
	if err != nil {
		return nil, 0, err
	}
	topLevel := len(root.Children)
	if cloneStrategy(body) == cloneFirstChild {
		if topLevel == 0 {
			return nil, 0, nil
		}
		return root.Children[:1], topLevel, nil
	}
	return root.Children, topLevel, nil
}

func anyMatch(nodes []*htmlNode, selector string) bool {
	for _, node := range nodes {
		if queryMatches(node, selector) || nodeMatches(node, selector) {
			return true
		}
	}
	return false
}

var mountSelector = regexp.MustCompile(`\$\('([^']+)', node\)`)

// shellSelectors extracts the selectors mountShell uses against the shell root.
func shellSelectors(body string) []string {
	var out []string
	for _, match := range mountSelector.FindAllStringSubmatch(body, -1) {
		if !contains(out, match[1]) {
			out = append(out, match[1])
		}
	}
	return out
}

// functionBody returns the source of a top level function declaration.
func functionBody(source, name string) string {
	start := strings.Index(source, "function "+name+"(")
	if start < 0 {
		return ""
	}
	rest := source[start:]
	if next := strings.Index(rest[1:], "\nfunction "); next >= 0 {
		return rest[:next+1]
	}
	return rest
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// --- minimal HTML parsing ---------------------------------------------------

type htmlNode struct {
	Tag      string
	Attrs    map[string]string
	Children []*htmlNode
	Parent   *htmlNode
}

var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true,
	"img": true, "input": true, "link": true, "meta": true, "param": true,
	"source": true, "track": true, "wbr": true,
}

var (
	tagStart    = regexp.MustCompile(`^<([a-zA-Z][\w:-]*)((?:\s+[^>]*?)?)(/?)>`)
	tagEnd      = regexp.MustCompile(`^</([a-zA-Z][\w:-]*)>`)
	attrPattern = regexp.MustCompile(`([\w:.-]+)(?:\s*=\s*"([^"]*)")?`)
)

// parseHTML builds an element tree from a well formed HTML fragment. It is not a
// general parser: it handles the subset the UI templates are written in.
func parseHTML(src string) (*htmlNode, error) {
	root := &htmlNode{Tag: "#root", Attrs: map[string]string{}}
	current := root
	for i := 0; i < len(src); {
		if src[i] != '<' {
			next := strings.IndexByte(src[i:], '<')
			if next < 0 {
				break
			}
			i += next
			continue
		}
		rest := src[i:]
		switch {
		case strings.HasPrefix(rest, "<!--"):
			end := strings.Index(rest, "-->")
			if end < 0 {
				return root, nil
			}
			i += end + 3
		case strings.HasPrefix(rest, "<!"):
			end := strings.IndexByte(rest, '>')
			if end < 0 {
				return root, nil
			}
			i += end + 1
		default:
			if close := tagEnd.FindStringSubmatch(rest); close != nil {
				if current.Parent != nil {
					current = current.Parent
				}
				i += len(close[0])
				continue
			}
			open := tagStart.FindStringSubmatch(rest)
			if open == nil {
				i++
				continue
			}
			node := &htmlNode{Tag: strings.ToLower(open[1]), Attrs: map[string]string{}, Parent: current}
			for _, attr := range attrPattern.FindAllStringSubmatch(open[2], -1) {
				node.Attrs[strings.ToLower(attr[1])] = attr[2]
			}
			current.Children = append(current.Children, node)
			selfClosing := open[3] == "/" || voidElements[node.Tag]
			if !selfClosing {
				current = node
			}
			i += len(open[0])
		}
	}
	return root, nil
}

// queryMatches implements the selector subset used by mountShell.
func queryMatches(root *htmlNode, selector string) bool {
	for _, node := range descendants(root) {
		if nodeMatches(node, selector) {
			return true
		}
	}
	return false
}

func descendants(node *htmlNode) []*htmlNode {
	var out []*htmlNode
	var walk func(*htmlNode)
	walk = func(n *htmlNode) {
		for _, child := range n.Children {
			out = append(out, child)
			walk(child)
		}
	}
	walk(node)
	return out
}

var (
	attrOnly  = regexp.MustCompile(`^\[([\w-]+)\]$`)
	attrEq    = regexp.MustCompile(`^(?:([a-zA-Z][\w-]*))?\[([\w-]+)(?:=["']?([^"'\]]+)["']?)?\]$`)
	classOnly = regexp.MustCompile(`^\.([\w-]+)$`)
)

func nodeMatches(node *htmlNode, selector string) bool {
	if match := attrOnly.FindStringSubmatch(selector); match != nil {
		_, ok := node.Attrs[match[1]]
		return ok
	}
	if match := attrEq.FindStringSubmatch(selector); match != nil {
		if match[1] != "" && node.Tag != strings.ToLower(match[1]) {
			return false
		}
		value, ok := node.Attrs[match[2]]
		return ok && (match[3] == "" || value == match[3])
	}
	if match := classOnly.FindStringSubmatch(selector); match != nil {
		for _, class := range strings.Fields(node.Attrs["class"]) {
			if class == match[1] {
				return true
			}
		}
	}
	return false
}

// extractTemplate returns the inner HTML of <template id="name">.
func extractTemplate(page, name string) (string, error) {
	marker := `<template id="` + name + `">`
	start := strings.Index(page, marker)
	if start < 0 {
		return "", errNotFound(name)
	}
	body := page[start+len(marker):]
	end := strings.Index(body, "</template>")
	if end < 0 {
		return "", errNotFound(name)
	}
	return body[:end], nil
}

type notFoundError string

func (e notFoundError) Error() string { return "template not found: " + string(e) }

func errNotFound(name string) error { return notFoundError(name) }
