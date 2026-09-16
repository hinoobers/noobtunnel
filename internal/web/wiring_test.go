package web

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// builtinUI names may be called from the UI code without being defined there.
var builtinUI = map[string]bool{
	"fetch": true, "setTimeout": true, "setInterval": true, "clearTimeout": true,
	"parseInt": true, "parseFloat": true, "isNaN": true, "Number": true, "String": true,
	"Boolean": true, "Array": true, "Object": true, "JSON": true, "Date": true,
	"Math": true, "Map": true, "Set": true, "Promise": true, "Error": true, "RegExp": true,
	"document": true, "window": true, "navigator": true, "EventSource": true, "FormData": true,
	"encodeURIComponent": true, "decodeURIComponent": true, "alert": true, "confirm": true,
	"prompt": true, "queueMicrotask": true, "structuredClone": true, "requestAnimationFrame": true,
	"MutationObserver": true, "IntersectionObserver": true, "crypto": true, "TextEncoder": true,
}

var (
	functionDef = regexp.MustCompile(`(?m)^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(`)
	arrowDef    = regexp.MustCompile(`(?m)^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(`)
	callSite    = regexp.MustCompile(`(^|[^\w$.])([A-Za-z_$][\w$]*)\s*\(`)
	paramList   = regexp.MustCompile(`(?:function\s*[A-Za-z_$][\w$]*\s*\(([^)]*)\)|\(([^)]*)\)\s*=>)`)
)

// stripLiterals blanks out comments and string bodies so words inside prose,
// CSS values or hostnames are not mistaken for function calls. A scanner is used
// rather than regexes because comments routinely contain apostrophes.
func stripLiterals(src string) string {
	var out strings.Builder
	out.Grow(len(src))
	const (
		normal = iota
		inLineComment
		inBlockComment
		inSingle
		inDouble
		inBacktick
	)
	state := normal
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch state {
		case normal:
			switch {
			case c == '/' && i+1 < len(src) && src[i+1] == '/':
				state = inLineComment
				out.WriteByte(' ')
				i++
			case c == '/' && i+1 < len(src) && src[i+1] == '*':
				state = inBlockComment
				out.WriteString("  ")
				i++
			case c == '\'':
				state = inSingle
				out.WriteByte('\'')
			case c == '"':
				state = inDouble
				out.WriteByte('"')
			case c == '`':
				state = inBacktick
				out.WriteByte('`')
			default:
				out.WriteByte(c)
			}
		case inLineComment:
			if c == '\n' {
				state = normal
				out.WriteByte('\n')
			} else {
				out.WriteByte(' ')
			}
		case inBlockComment:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				state = normal
				out.WriteString("*/")
				i++
				continue
			}
			if c == '\n' {
				out.WriteByte('\n')
			} else {
				out.WriteByte(' ')
			}
		case inSingle, inDouble, inBacktick:
			if c == '\\' && i+1 < len(src) {
				out.WriteString("  ")
				i++
				continue
			}
			quote := byte('\'')
			switch state {
			case inDouble:
				quote = '"'
			case inBacktick:
				quote = '`'
			}
			if c == quote {
				state = normal
				out.WriteByte(quote)
				continue
			}
			if c == '\n' {
				out.WriteByte('\n')
			} else {
				out.WriteByte(' ')
			}
		}
	}
	return out.String()
}

// TestUIFunctionsResolve catches typos in function names across the two script
// files, which a browser would only surface at runtime.
func TestUIFunctionsResolve(t *testing.T) {
	files := []string{
		"assets/app.js", "assets/views.js", "assets/users_api.js",
		"assets/resources_api.js", "assets/exitnodes_api.js",
		"assets/dns_api.js",
		"assets/branding_api.js",
		"assets/geoip_api.js",
		"assets/logs_api.js",
	}
	defined := map[string]bool{}
	contents := map[string]string{}
	for _, name := range files {
		raw, err := Assets().(interface {
			ReadFile(string) ([]byte, error)
		}).ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		contents[name] = string(raw)
		code := stripLiterals(contents[name])
		for _, match := range functionDef.FindAllStringSubmatch(code, -1) {
			defined[match[1]] = true
		}
		for _, match := range arrowDef.FindAllStringSubmatch(code, -1) {
			defined[match[1]] = true
		}
		// Callback parameters such as onConfirm are callable locals.
		for _, match := range paramList.FindAllStringSubmatch(code, -1) {
			for _, group := range match[1:] {
				for _, param := range strings.Split(group, ",") {
					param = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(param), "..."))
					if param != "" && !strings.ContainsAny(param, " {}=[]<>") && !strings.Contains(param, ":") {
						defined[param] = true
					}
				}
			}
		}
	}
	// Methods attached to objects (foo: function () {}) and class members are
	// also definitions we should recognise.
	methodDef := regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?function`)
	for _, content := range contents {
		for _, match := range methodDef.FindAllStringSubmatch(stripLiterals(content), -1) {
			defined[match[1]] = true
		}
	}

	var missing []string
	for name, content := range contents {
		for _, match := range callSite.FindAllStringSubmatch(stripLiterals(content), -1) {
			callee := match[2]
			switch {
			case defined[callee], builtinUI[callee]:
				continue
			case isKeyword(callee):
				continue
			}
			missing = append(missing, name+": "+callee+"()")
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		unique := missing[:0]
		for i, item := range missing {
			if i == 0 || item != missing[i-1] {
				unique = append(unique, item)
			}
		}
		t.Fatalf("the UI calls functions that are not defined anywhere:\n  %s", strings.Join(unique, "\n  "))
	}
}

func isKeyword(name string) bool {
	switch name {
	case "if", "for", "while", "switch", "catch", "return", "typeof", "function", "new",
		"else", "do", "delete", "await", "async", "yield", "in", "of", "case", "throw", "void":
		return true
	default:
		return false
	}
}
