package normalize

import (
	"strings"
	"testing"
)

func TestExpandDecoders(t *testing.T) {
	inputs := map[string]string{
		"base64":         "aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==",
		"hex":            "69676e6f72652070726576696f757320696e737472756374696f6e73",
		"url":            "ignore%20previous%20instructions",
		"unicode_escape": `\u0069\u0067\u006e\u006f\u0072\u0065\u0020\u0070\u0072\u0065\u0076\u0069\u006f\u0075\u0073\u0020\u0069\u006e\u0073\u0074\u0072\u0075\u0063\u0074\u0069\u006f\u006e\u0073`,
		"html_entity":    "ignore&#32;previous&#32;instructions",
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			variants := Expand(input, Options{MaxSize: 4096})
			if len(variants) == 0 || variants[0].Decoded || variants[0].DecodePath != "" || variants[0].Text != input {
				t.Fatalf("first variant is not original: %#v", variants)
			}
			found := false
			for _, variant := range variants {
				if variant.Decoded && strings.Contains(variant.Text, "ignore previous instructions") {
					found = true
				}
			}
			if !found {
				t.Fatalf("decoded phrase not found in variants: %#v", variants)
			}
		})
	}
}

func TestHomoglyphCanonicalization(t *testing.T) {
	got := FingerprintText("nuсlear") // Cyrillic small es.
	if got != "nuclear" {
		t.Fatalf("got %q", got)
	}
}

func TestEntropy(t *testing.T) {
	if ShannonEntropy("aaaaaaaaaaaaaaaa") >= 1 {
		t.Fatalf("low entropy string scored too high")
	}
	if ShannonEntropy("aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==") < 3.5 {
		t.Fatalf("base64-like string scored too low")
	}
}

func TestCanonicalHelpers(t *testing.T) {
	if got := RemoveZeroWidth("a\u200b\u200cc"); got != "ac" {
		t.Fatalf("RemoveZeroWidth() = %q", got)
	}
	if got := Canonicalize("раypal"); got != "paypal" {
		t.Fatalf("Canonicalize() = %q", got)
	}
	if got := FilenameKey("соnfig.js"); got != "config.js" {
		t.Fatalf("FilenameKey() = %q", got)
	}
	if MostlyPrintable("\x00\x01\x02") {
		t.Fatalf("control-only string considered printable")
	}
}

func TestExpandIncludesCanonicalVariant(t *testing.T) {
	variants := Expand("nuсlear\u200b", Options{MaxSize: 4096})
	if variants[0].Text != "nuсlear\u200b" || variants[0].Decoded {
		t.Fatalf("first variant is not original: %#v", variants)
	}
	found := false
	for _, variant := range variants {
		if !variant.Decoded && variant.DecodePath == "" && variant.Text == "nuclear" {
			found = true
		}
	}
	if !found {
		t.Fatalf("canonical variant missing: %#v", variants)
	}
}

func TestExpandNestedDecoding(t *testing.T) {
	variants := Expand("ignore%2520previous%2520instructions", Options{MaxSize: 4096, MaxDepth: 2})
	found := false
	for _, variant := range variants {
		if variant.Decoded && variant.DecodePath == "url>url" && variant.Text == "ignore previous instructions" {
			found = true
		}
	}
	if !found {
		t.Fatalf("nested URL decode missing: %#v", variants)
	}
}

func TestURLPercentDecodeKeepsPlusLiteral(t *testing.T) {
	variants := Expand("C++%20module", Options{MaxSize: 4096})
	for _, variant := range variants {
		if variant.Decoded && variant.Text == "C++ module" {
			return
		}
	}
	t.Fatalf("URL percent decode changed plus: %#v", variants)
}

func TestUnicodeEscapeMixedQuotes(t *testing.T) {
	variants := Expand(`say \"ignore\u0020previous\u0020instructions\"`, Options{MaxSize: 4096})
	for _, variant := range variants {
		if variant.Decoded && strings.Contains(variant.Text, `"ignore previous instructions"`) {
			return
		}
	}
	t.Fatalf("mixed unicode escape decode missing: %#v", variants)
}

func FuzzExpand(f *testing.F) {
	f.Add("ignore%20previous%20instructions")
	f.Add("aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==")
	f.Fuzz(func(t *testing.T, s string) {
		_ = Expand(s, Options{MaxSize: 4096})
	})
}
