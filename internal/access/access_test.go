package access

import (
	"net/netip"
	"strings"
	"testing"
)

func mustAddr(t *testing.T, raw string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

// TestCountryRuleBlocksEveryoneElse is the requested shape:
// "If country IS NOT Estonia BLOCK()".
func TestCountryRuleBlocksEveryoneElse(t *testing.T) {
	rules := []Rule{{Field: FieldCountry, Operator: OpIsNot, Values: []string{"ee"}, Action: ActionBlock}}
	if err := rules[0].Validate(); err != nil {
		t.Fatal(err)
	}
	// Lower case input is normalised to an upper case code.
	if rules[0].Values[0] != "EE" {
		t.Fatalf("country code was not normalised: %v", rules[0].Values)
	}

	decision := Evaluate(rules, Request{IP: mustAddr(t, "203.0.113.5"), Country: "EE"})
	if !decision.Allow {
		t.Fatalf("an Estonian client should pass: %+v", decision)
	}
	decision = Evaluate(rules, Request{IP: mustAddr(t, "203.0.113.5"), Country: "DE"})
	if decision.Allow {
		t.Fatalf("a client outside Estonia should be blocked: %+v", decision)
	}
	if !strings.Contains(decision.Reason, "country") || !strings.Contains(decision.Reason, "BLOCK") {
		t.Fatalf("the reason should be readable: %q", decision.Reason)
	}
	// Without a country database the rule cannot be judged, so it is skipped
	// rather than blocking everybody.
	decision = Evaluate(rules, Request{IP: mustAddr(t, "203.0.113.5")})
	if !decision.Allow {
		t.Fatalf("a missing country database must not block traffic: %+v", decision)
	}
}

func TestRuleOrderAndFirstMatchWins(t *testing.T) {
	rules := []Rule{
		{Field: FieldIP, Operator: OpIs, Values: []string{"10.0.0.0/8"}, Action: ActionAllow},
		{Field: FieldCountry, Operator: OpIsNot, Values: []string{"EE"}, Action: ActionBlock},
	}
	// A private client is allowed by the first rule, even though the second would
	// block its country.
	decision := Evaluate(rules, Request{IP: mustAddr(t, "10.1.2.3"), Country: "DE"})
	if !decision.Allow {
		t.Fatalf("the first matching rule should win: %+v", decision)
	}
	// Someone else falls through to the country rule and is blocked.
	decision = Evaluate(rules, Request{IP: mustAddr(t, "203.0.113.9"), Country: "DE"})
	if decision.Allow {
		t.Fatalf("the country rule should block: %+v", decision)
	}
}

func TestAllowListMode(t *testing.T) {
	rules := []Rule{{Field: FieldHost, Operator: OpIs, Values: []string{"admin.example.com"}, Action: ActionAllow}}
	decision := Evaluate(rules, Request{Host: "admin.example.com"})
	if !decision.Allow {
		t.Fatalf("the listed host should pass: %+v", decision)
	}
	// Anything else is denied because an ALLOW rule exists.
	decision = Evaluate(rules, Request{Host: "public.example.com"})
	if decision.Allow {
		t.Fatalf("an unlisted host should be denied in allow-list mode: %+v", decision)
	}
}

func TestSubdomainHostRuleMatches(t *testing.T) {
	rules := []Rule{{Field: FieldHost, Operator: OpIs, Values: []string{"example.com"}, Action: ActionAllow}}
	if d := Evaluate(rules, Request{Host: "app.example.com"}); !d.Allow {
		t.Fatalf("a subdomain should match its parent: %+v", d)
	}
	if d := Evaluate(rules, Request{Host: "notexample.com"}); d.Allow {
		t.Fatalf("a lookalike domain must not match: %+v", d)
	}
}

func TestIPRules(t *testing.T) {
	rules := []Rule{{Field: FieldIP, Operator: OpIs, Values: []string{"203.0.113.7", "198.51.100.0/24"}, Action: ActionBlock}}
	for _, blocked := range []string{"203.0.113.7", "198.51.100.55"} {
		if d := Evaluate(rules, Request{IP: mustAddr(t, blocked)}); d.Allow {
			t.Fatalf("%s should be blocked: %+v", blocked, d)
		}
	}
	if d := Evaluate(rules, Request{IP: mustAddr(t, "203.0.113.8")}); !d.Allow {
		t.Fatalf("an unlisted address should pass: %+v", d)
	}
}

func TestAccountRule(t *testing.T) {
	rules := []Rule{{Field: FieldAccount, Operator: OpIs, Values: []string{"admin"}, Action: ActionAllow}}
	if d := Evaluate(rules, Request{Account: "admin"}); !d.Allow {
		t.Fatalf("the listed account should pass: %+v", d)
	}
	if d := Evaluate(rules, Request{Account: "guest"}); d.Allow {
		t.Fatalf("another account should be denied: %+v", d)
	}
}

func TestRuleValidation(t *testing.T) {
	cases := []Rule{
		{Field: "planet", Operator: OpIs, Values: []string{"earth"}, Action: ActionBlock},
		{Field: FieldCountry, Operator: "contains", Values: []string{"EE"}, Action: ActionBlock},
		{Field: FieldCountry, Operator: OpIs, Values: []string{"EST"}, Action: ActionBlock},
		{Field: FieldIP, Operator: OpIs, Values: []string{"not-an-ip"}, Action: ActionBlock},
		{Field: FieldHost, Operator: OpIs, Values: nil, Action: ActionBlock},
		{Field: FieldHost, Operator: OpIs, Values: []string{"a"}, Action: "drop"},
	}
	for i, rule := range cases {
		if err := rule.Validate(); err == nil {
			t.Fatalf("rule %d should not validate: %+v", i, rule)
		}
	}
	good := Rule{Field: FieldIP, Operator: OpIs, Values: []string{"  10.0.0.1/8 "}, Action: ActionBlock}
	if err := good.Validate(); err != nil {
		t.Fatalf("a valid rule was rejected: %v", err)
	}
	if good.Values[0] != "10.0.0.0/8" {
		t.Fatalf("CIDRs should be masked: %v", good.Values)
	}
}

func TestShadowedRules(t *testing.T) {
	rules := []Rule{
		{Field: FieldCountry, Operator: OpIs, Values: []string{"EE"}, Action: ActionAllow},
		{Field: FieldCountry, Operator: OpIs, Values: []string{"DE"}, Action: ActionBlock},
		{Field: FieldIP, Operator: OpIs, Values: []string{"10.0.0.0/8"}, Action: ActionBlock},
	}
	shadowed := Shadowed(rules)
	if len(shadowed) != 1 || shadowed[0] != 1 {
		t.Fatalf("the second country rule can never match: %v", shadowed)
	}
}

// TestTextOperators covers the comparisons added alongside exact matching:
// contains, starts with, ends with and a regular expression.
func TestTextOperators(t *testing.T) {
	cases := []struct {
		name     string
		field    Field
		operator Operator
		values   []string
		request  Request
		want     bool
	}{
		{"path contains", FieldPath, OpContains, []string{"/admin"}, Request{Path: "/admin/users"}, true},
		{"path contains miss", FieldPath, OpContains, []string{"/admin"}, Request{Path: "/public"}, false},
		{"path starts with", FieldPath, OpStartsWith, []string{"/api/"}, Request{Path: "/api/v1/agents"}, true},
		{"path ends with", FieldPath, OpEndsWith, []string{".php"}, Request{Path: "/index.php"}, true},
		{"host ends with", FieldHost, OpEndsWith, []string{".internal.example.com"}, Request{Host: "nas.internal.example.com"}, true},
		{"host matches", FieldHost, OpMatches, []string{`^admin\..*$`}, Request{Host: "admin.example.com"}, true},
		{"host matches miss", FieldHost, OpMatches, []string{`^admin\..*$`}, Request{Host: "shop.example.com"}, false},
		{"account contains", FieldAccount, OpContains, []string{"ops"}, Request{Account: "ops-team"}, true},
	}
	for _, testCase := range cases {
		rule := Rule{Field: testCase.field, Operator: testCase.operator, Values: testCase.values, Action: ActionBlock}
		if err := rule.Validate(); err != nil {
			t.Fatalf("%s: the rule did not validate: %v", testCase.name, err)
		}
		decision := Evaluate([]Rule{rule}, testCase.request)
		// A BLOCK rule that matches denies, so "allowed" means the rule missed.
		if decision.Allow == testCase.want {
			t.Fatalf("%s: got %v, want the rule to %s", testCase.name, decision, map[bool]string{true: "match", false: "miss"}[testCase.want])
		}
	}
}

// TestPathRuleNormalisation keeps a path rule usable whichever way it is typed.
func TestPathRuleNormalisation(t *testing.T) {
	rule := Rule{Field: FieldPath, Operator: OpIs, Values: []string{"admin"}, Action: ActionAllow}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}
	if rule.Values[0] != "/admin" {
		t.Fatalf("a path should gain its leading slash: %v", rule.Values)
	}
	if d := Evaluate([]Rule{rule}, Request{Path: "/admin"}); !d.Allow {
		t.Fatalf("the path should match: %+v", d)
	}
	// An empty path is the site root, not a missing value, so an unmatched rule
	// still falls through and the request passes.
	if d := Evaluate([]Rule{rule}, Request{Path: ""}); d.Allow {
		t.Fatalf("the root path is not /admin, so the allow rule must not match: %+v", d)
	}
}

// TestOperatorsPerField mirrors the UI: a country code and an address are exact
// values, while the text fields also take the substring comparisons.
func TestOperatorsPerField(t *testing.T) {
	for _, field := range []Field{FieldCountry, FieldIP} {
		operators := OperatorsFor(field)
		if len(operators) != 2 {
			t.Fatalf("%s should only offer exact comparisons, got %v", field, operators)
		}
	}
	for _, field := range []Field{FieldHost, FieldPath, FieldAccount} {
		operators := OperatorsFor(field)
		for _, want := range []Operator{OpContains, OpStartsWith, OpEndsWith, OpMatches} {
			found := false
			for _, op := range operators {
				if op == want {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s should offer %q, got %v", field, want, operators)
			}
		}
	}
	// A comparison that does not belong to the field is refused.
	bad := Rule{Field: FieldCountry, Operator: OpMatches, Values: []string{"EE"}, Action: ActionBlock}
	if err := bad.Validate(); err == nil {
		t.Fatal("a country rule must not accept a regular expression")
	}
	// An invalid expression is caught when the rule is saved, not per request.
	broken := Rule{Field: FieldPath, Operator: OpMatches, Values: []string{"("}, Action: ActionBlock}
	if err := broken.Validate(); err == nil {
		t.Fatal("an invalid regular expression should be rejected")
	}
}
