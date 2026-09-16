// Package web embeds the control node's single page UI. Everything is served
// from the binary: no CDN, no external fonts, no build step.
package web

import (
	"embed"
	"io/fs"
)

//go:embed assets
var files embed.FS

// Assets returns the embedded asset tree, rooted so that /assets/app.js maps to
// assets/app.js.
func Assets() fs.FS { return files }

// Index returns the single page application shell.
func Index() ([]byte, error) { return files.ReadFile("assets/index.html") }

// DefaultLogo is the bundled brand image, used until an operator uploads one.
func DefaultLogo() ([]byte, error) { return files.ReadFile("assets/logo.jpg") }

// StyleSheet is the bundled stylesheet. It pre-fills the custom CSS editor so an
// operator can adjust the look instead of writing a theme from nothing.
func StyleSheet() ([]byte, error) { return files.ReadFile("assets/style.css") }

// Favicon returns the inline SVG favicon.
func Favicon() string {
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#818cf8"/><stop offset="1" stop-color="#22d3ee"/>
</linearGradient></defs>
<rect width="32" height="32" rx="8" fill="#0b1220"/>
<circle cx="16" cy="16" r="4.5" fill="url(#g)"/>
<circle cx="7" cy="8" r="2.6" fill="url(#g)"/>
<circle cx="25" cy="8" r="2.6" fill="url(#g)"/>
<circle cx="7" cy="24" r="2.6" fill="url(#g)"/>
<circle cx="25" cy="24" r="2.6" fill="url(#g)"/>
<g stroke="url(#g)" stroke-width="1.6" opacity="0.85">
<path d="M14 13 8.5 9.6M18 13l5.5-3.4M14 19l-5.5 3.4M18 19l5.5 3.4"/>
</g></svg>`
}
