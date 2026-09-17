package web

import (
	"strings"
	"testing"
)

// TestResourcePublishPageIsNotAModal keeps the publish flow on its own page: it
// is a form with the type picker, not a dialog.
func TestResourcePublishPageIsNotAModal(t *testing.T) {
	js := readAsset(t, "assets/resources_api.js")
	page := functionBody(js, "resourceEditorPage")
	if page == "" {
		t.Fatal("resourceEditorPage is missing")
	}
	if strings.Contains(page, "modal(") {
		t.Error("the publish form must be a page, not a modal dialog")
	}
	// The type, the strategy and the PROXY protocol all use the card picker.
	if !strings.Contains(page, "cardPicker('protocol'") {
		t.Error("the type picker should use the shared card picker")
	}
	picker := functionBody(js, "cardPicker")
	if !strings.Contains(picker, "type-grid") || !strings.Contains(picker, "type-card") {
		t.Error("the card picker should render selectable cards")
	}
	if !strings.Contains(js, "function openResourceEditor") || !strings.Contains(js, "function closeResourceEditor") {
		t.Error("the editor needs open and close functions that swap the view")
	}
	if strings.Contains(js, "openResourceModal") {
		t.Error("the old modal entry point must be gone")
	}
	// The list panel and the editor must not both be visible.
	render := functionBody(js, "renderResourceEditor")
	if !strings.Contains(render, "shell.resourceList.hidden = true") ||
		!strings.Contains(render, "shell.resourceList.hidden = false") {
		t.Error("opening the editor must hide the list and closing it must bring the list back")
	}
}

// TestDomainIsChosenFromConfiguredDomains checks that the domain field is a
// picker over known domains rather than free text, and that it is only offered
// when it can actually work.
func TestDomainIsChosenFromConfiguredDomains(t *testing.T) {
	js := readAsset(t, "assets/resources_api.js")
	page := functionBody(js, "resourceEditorPage")
	if !strings.Contains(page, "h('select', { name: 'domain' }") {
		t.Fatal("the domain field must be a select over configured domains")
	}
	if strings.Contains(page, "name: 'domain', required: true") ||
		strings.Contains(page, "name: 'domain', spellcheck") {
		t.Error("the domain must not be a free text input")
	}
	if !strings.Contains(page, "domainOptions()") || !strings.Contains(js, "state.data.domains") {
		t.Error("the select should be built from the configured domains")
	}
	if !strings.Contains(page, "domainField.hidden = !usableDomain") {
		t.Error("the domain picker must be hidden when no domains are configured")
	}
	// When there are no domains, the page must explain what to do instead.
	if !strings.Contains(page, "Domains tab") {
		t.Error("the form should point at the Domains tab when no domain exists")
	}
}

func TestProxyProtocolOptions(t *testing.T) {
	js := readAsset(t, "assets/resources_api.js")
	page := functionBody(js, "resourceEditorPage")
	// It is a card picker now, not a dropdown.
	if !strings.Contains(page, "cardPicker('proxyProtocol'") {
		t.Fatal("the PROXY protocol choice should use the same card picker as the type")
	}
	if strings.Contains(page, "h('select', { name: 'proxyProtocol' }") {
		t.Error("the PROXY protocol must not be a dropdown")
	}
	for _, want := range []string{"v1: { label: 'PROXY v1'", "v2: { label: 'PROXY v2'"} {
		if !strings.Contains(js, want) {
			t.Errorf("the PROXY protocol options are missing %s", want)
		}
	}
	// UDP has no PROXY protocol, so the choices must be taken away there.
	if !strings.Contains(page, "setCardEnabled(proxyCards, false)") {
		t.Error("the PROXY protocol cards should be disabled for UDP")
	}
}

// TestSingleAddResourceButton covers the duplicated button the user reported:
// the header button stays for a populated list, the empty state owns it when
// there is nothing to show.
func TestSingleAddResourceButton(t *testing.T) {
	js := readAsset(t, "assets/resources_api.js")
	render := functionBody(js, "renderResources")
	if !strings.Contains(render, "shell.resourcesAdd.hidden = !canAdmin() || resources.length === 0") {
		t.Fatal("the header button must be hidden when no resources exist")
	}
	if !strings.Contains(render, "'data-action': 'add-resource'") {
		t.Fatal("the empty state should offer the add button")
	}
	html := readAsset(t, "assets/index.html")
	if strings.Count(html, `data-action="add-resource"`) != 1 {
		t.Fatalf("the template should contain exactly one add-resource button, found %d",
			strings.Count(html, `data-action="add-resource"`))
	}
}

// TestResourceListShowsProxyProtocol keeps the header visible in the list.
func TestResourceListShowsProxyProtocol(t *testing.T) {
	js := readAsset(t, "assets/resources_api.js")
	if !strings.Contains(functionBody(js, "renderResources"), "PROXY protocol") {
		t.Error("the resource list should show which PROXY protocol a resource uses")
	}
}

// TestEditorReferencedElementsAreDeclared guards a real crash: the publish page
// referenced nameInput before it existed, so opening it threw
// "nameInput is not defined" and the page never rendered.
func TestEditorReferencedElementsAreDeclared(t *testing.T) {
	js := readAsset(t, "assets/resources_api.js")
	page := functionBody(js, "resourceEditorPage")
	for _, element := range []string{"nameInput", "typeCards", "strategyCards", "proxyCards", "targetList", "listenInput", "domainSelect"} {
		if !strings.Contains(page, element) {
			continue
		}
		if !strings.Contains(page, "const "+element+" =") && !strings.Contains(page, "let "+element+" =") {
			t.Errorf("%s is used in the publish page but never declared", element)
		}
	}
}

// TestPublishPageIsSplitIntoSteps keeps the form readable.
func TestPublishPageIsSplitIntoSteps(t *testing.T) {
	js := readAsset(t, "assets/resources_api.js")
	page := functionBody(js, "resourceEditorPage")
	if !strings.Contains(page, "stepTitles") || !strings.Contains(page, "function showStep") {
		t.Fatal("the publish form should be split into steps")
	}
	for _, want := range []string{"'Service'", "'Targets'", "'Publishing'", "'Security'", "'Next'", "'Back'"} {
		if !strings.Contains(page, want) {
			t.Errorf("the step navigation is missing %s", want)
		}
	}
	// The targets live in their own box with the add button in the corner.
	if !strings.Contains(page, "subpanel") || !strings.Contains(page, "'Add target'") {
		t.Error("targets should be a box with an Add target button")
	}
}

// TestHTTPSHasNoPortChoice checks that HTTPS is always published on 443.
func TestHTTPSHasNoPortChoice(t *testing.T) {
	js := readAsset(t, "assets/resources_api.js")
	page := functionBody(js, "resourceEditorPage")
	if !strings.Contains(page, "listenField.hidden = fixedPort") {
		t.Fatal("the listening port must be hidden for HTTPS, which the control node terminates on 443")
	}
	if !strings.Contains(page, "const fixedPort = protocol === 'https'") {
		t.Error("HTTPS should be the protocol with a fixed port")
	}
	// The published toggle exists, and identity control is offered for http(s).
	if !strings.Contains(page, "'identity'") {
		t.Error("the identity control toggle is missing")
	}
	if !strings.Contains(page, "'blockExploits'") || !strings.Contains(page, "'Block common exploits'") {
		t.Error("the common exploit filter toggle is missing")
	}
}
