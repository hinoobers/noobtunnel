// Package access decides whether a request may reach a published resource.
//
// Rules are evaluated in order and the first match decides, which makes an
// expression like "country is not EE -> BLOCK" straightforward. Optional
// allow-list mode: as soon as one ALLOW rule exists, anything that matches no
// rule is denied, so a list of ALLOW rules reads as a whitelist.
package access

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
)

// Field is what a rule looks at.
type Field string

const (
	// FieldCountry compares the client's country (needs a GeoIP database).
	FieldCountry Field = "country"
	// FieldIP compares the client address against addresses or CIDRs.
	FieldIP Field = "ip"
	// FieldHost compares the requested hostname.
	FieldHost Field = "host"
	// FieldPath compares the requested URL path.
	FieldPath Field = "path"
	// FieldAccount compares the signed in control node account.
	FieldAccount Field = "account"
)

// Operator is how a value is compared.
type Operator string

const (
	// OpIs matches when the value is one of the listed values.
	OpIs Operator = "is"
	// OpIsNot matches when the value is none of them.
	OpIsNot Operator = "is-not"
	// OpContains matches when the value contains one of the listed values.
	OpContains Operator = "contains"
	// OpStartsWith matches a prefix.
	OpStartsWith Operator = "starts-with"
	// OpEndsWith matches a suffix.
	OpEndsWith Operator = "ends-with"
	// OpMatches matches a regular expression.
	OpMatches Operator = "matches"
)

// Action is what happens on a match.
type Action string

const (
	// ActionAllow lets the request through.
	ActionAllow Action = "allow"
	// ActionBlock refuses it.
	ActionBlock Action = "block"
)

// Rule is one access rule.
type Rule struct {
	Field    Field    `json:"field"`
	Operator Operator `json:"operator"`
	Values   []string `json:"values"`
	Action   Action   `json:"action"`
}

// ValidField reports whether f is supported.
func ValidField(f Field) bool {
	for _, known := range Fields() {
		if known == f {
			return true
		}
	}
	return false
}

// Fields lists every field a rule can look at.
func Fields() []Field {
	return []Field{FieldCountry, FieldIP, FieldHost, FieldPath, FieldAccount}
}

// ValidOperator reports whether o is a known comparison.
func ValidOperator(o Operator) bool {
	for _, known := range StringOperators() {
		if known == o {
			return true
		}
	}
	return false
}

// StringOperators are the comparisons that work on text.
func StringOperators() []Operator {
	return []Operator{OpIs, OpIsNot, OpContains, OpStartsWith, OpEndsWith, OpMatches}
}

// OperatorsFor lists the comparisons a field supports: a country is an exact
// value, while hostnames, paths and accounts can be matched as text.
func OperatorsFor(field Field) []Operator {
	switch field {
	case FieldCountry, FieldIP:
		return []Operator{OpIs, OpIsNot}
	default:
		return StringOperators()
	}
}

// ValidAction reports whether a is supported.
func ValidAction(a Action) bool { return a == ActionAllow || a == ActionBlock }

// Validate checks a rule and canonicalises its values.
func (r *Rule) Validate() error {
	if !ValidField(r.Field) {
		return fmt.Errorf("a rule needs a field: country, ip, host, path or account")
	}
	if !ValidOperator(r.Operator) {
		return fmt.Errorf("unknown comparison %q", r.Operator)
	}
	supported := false
	for _, allowed := range OperatorsFor(r.Field) {
		if allowed == r.Operator {
			supported = true
			break
		}
	}
	if !supported {
		return fmt.Errorf("%q is not a comparison for a %s rule", r.Operator, r.Field)
	}
	if !ValidAction(r.Action) {
		return fmt.Errorf("a rule action must be ALLOW or BLOCK")
	}
	values := make([]string, 0, len(r.Values))
	for _, raw := range r.Values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		switch r.Field {
		case FieldCountry:
			value = strings.ToUpper(value)
			if len(value) != 2 {
				return fmt.Errorf("%q is not a two letter country code", raw)
			}
		case FieldIP:
			normalised, err := normaliseIP(value)
			if err != nil {
				return err
			}
			value = normalised
		case FieldHost:
			value = strings.ToLower(strings.TrimSuffix(value, "."))
		case FieldPath:
			// An exact path wants its leading slash; a substring comparison is a
			// fragment of one, so ".php" must not become "/.php".
			if (r.Operator == OpIs || r.Operator == OpIsNot) && !strings.HasPrefix(value, "/") {
				value = "/" + value
			}
		case FieldAccount:
			value = strings.ToLower(value)
		}
		if r.Operator == OpMatches {
			if _, err := regexp.Compile(value); err != nil {
				return fmt.Errorf("%q is not a valid regular expression: %v", raw, err)
			}
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		return fmt.Errorf("a rule needs at least one value")
	}
	r.Values = values
	return nil
}

func normaliseIP(raw string) (string, error) {
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return prefix.Masked().String(), nil
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		return addr.Unmap().String(), nil
	}
	return "", fmt.Errorf("%q is not an address or CIDR", raw)
}

// Request describes the traffic being judged.
type Request struct {
	IP      netip.Addr
	Country string
	Host    string
	Path    string
	Account string
}

// Decision is the outcome of evaluating the rules.
type Decision struct {
	Allow bool
	// Rule is the rule that decided, empty when the default applied.
	Rule string
	// Reason explains the decision in one line.
	Reason string
}

// Evaluate applies the rules in order.
func Evaluate(rules []Rule, req Request) Decision {
	allowList := false
	for _, rule := range rules {
		if rule.Action == ActionAllow {
			allowList = true
			break
		}
	}
	for _, rule := range rules {
		matched, known := match(rule, req)
		if !known {
			// The data a rule needs is missing (no GeoIP database, for example).
			// Skipping it keeps a missing database from blocking real users.
			continue
		}
		if !matched {
			continue
		}
		decision := Decision{Rule: describe(rule)}
		if rule.Action == ActionBlock {
			decision.Allow = false
			decision.Reason = "blocked by rule: " + decision.Rule
		} else {
			decision.Allow = true
			decision.Reason = "allowed by rule: " + decision.Rule
		}
		return decision
	}
	if allowList {
		return Decision{Allow: false, Reason: "no rule matched and this resource uses an allow list"}
	}
	return Decision{Allow: true, Reason: "no rule matched"}
}

// match reports whether a rule applies, and whether it could be evaluated at all.
func match(rule Rule, req Request) (matched bool, known bool) {
	switch rule.Field {
	case FieldIP:
		if !req.IP.IsValid() {
			return false, false
		}
		return matchIP(rule, req.IP), true
	case FieldCountry:
		if req.Country == "" {
			return false, false
		}
		return matchString(rule, strings.ToUpper(req.Country)), true
	case FieldHost:
		return matchString(rule, strings.ToLower(strings.TrimSuffix(req.Host, "."))), true
	case FieldPath:
		return matchString(rule, pathOf(req.Path)), true
	case FieldAccount:
		return matchString(rule, strings.ToLower(req.Account)), true
	default:
		return false, false
	}
}

// pathOf normalises a request path.
func pathOf(raw string) string {
	if raw == "" {
		return "/"
	}
	if !strings.HasPrefix(raw, "/") {
		return "/" + raw
	}
	return raw
}

// matchIP compares an address against addresses and CIDRs.
func matchIP(rule Rule, addr netip.Addr) bool {
	found := false
	for _, raw := range rule.Values {
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			if prefix.Contains(addr.Unmap()) {
				found = true
				break
			}
			continue
		}
		if parsed, err := netip.ParseAddr(raw); err == nil && parsed.Unmap() == addr.Unmap() {
			found = true
			break
		}
	}
	if rule.Operator == OpIsNot {
		return !found
	}
	return found
}

// matchString applies a text comparison.
func matchString(rule Rule, value string) bool {
	switch rule.Operator {
	case OpContains:
		for _, raw := range rule.Values {
			if strings.Contains(value, raw) {
				return true
			}
		}
		return false
	case OpStartsWith:
		for _, raw := range rule.Values {
			if strings.HasPrefix(value, raw) {
				return true
			}
		}
		return false
	case OpEndsWith:
		for _, raw := range rule.Values {
			if strings.HasSuffix(value, raw) {
				return true
			}
		}
		return false
	case OpMatches:
		for _, raw := range rule.Values {
			if expr, ok := compiled(raw); ok && expr.MatchString(value) {
				return true
			}
		}
		return false
	case OpIsNot:
		for _, raw := range rule.Values {
			if value == raw {
				return false
			}
		}
		return true
	default:
		for _, raw := range rule.Values {
			if value == raw {
				return true
			}
			// A hostname also covers its subdomains.
			if rule.Field == FieldHost && strings.HasSuffix(value, "."+raw) {
				return true
			}
		}
		return false
	}
}

// compiled caches regular expressions: rules are stored as text, but a request
// should not recompile one on every hit.
var (
	regexCache   = map[string]*regexp.Regexp{}
	regexCacheMu sync.Mutex
)

func compiled(pattern string) (*regexp.Regexp, bool) {
	regexCacheMu.Lock()
	defer regexCacheMu.Unlock()
	if expr, ok := regexCache[pattern]; ok {
		return expr, expr != nil
	}
	expr, err := regexp.Compile(pattern)
	if err != nil {
		regexCache[pattern] = nil
		return nil, false
	}
	if len(regexCache) > 512 {
		regexCache = map[string]*regexp.Regexp{}
	}
	regexCache[pattern] = expr
	return expr, true
}

// describe renders a rule the way the UI shows it.
func describe(rule Rule) string {
	operator := strings.ReplaceAll(string(rule.Operator), "-", " ")
	action := "BLOCK"
	if rule.Action == ActionAllow {
		action = "ALLOW"
	}
	return fmt.Sprintf("%s %s %s → %s", rule.Field, operator, strings.Join(rule.Values, ", "), action)
}

// Shadowed returns the indexes of rules that can never match because an earlier
// rule with the same field decides first, so the UI can warn about them.
func Shadowed(rules []Rule) []int {
	var out []int
	seen := map[Field]bool{}
	for i, rule := range rules {
		if seen[rule.Field] {
			out = append(out, i)
			continue
		}
		seen[rule.Field] = true
	}
	return out
}
