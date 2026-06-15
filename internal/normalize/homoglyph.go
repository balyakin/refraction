package normalize

import (
	"strings"
	"unicode"
)

func RemoveZeroWidth(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF':
			return -1
		default:
			return r
		}
	}, s)
}

func CanonicalizeHomoglyphs(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case 'А', 'Α':
			return 'A'
		case 'а', 'α':
			return 'a'
		case 'В', 'Β':
			return 'B'
		case 'Е', 'Ε':
			return 'E'
		case 'е', 'ε':
			return 'e'
		case 'К', 'Κ':
			return 'K'
		case 'М', 'Μ':
			return 'M'
		case 'Н', 'Η':
			return 'H'
		case 'О', 'Ο':
			return 'O'
		case 'о', 'ο':
			return 'o'
		case 'Р', 'Ρ':
			return 'P'
		case 'р', 'ρ':
			return 'p'
		case 'С':
			return 'C'
		case 'с':
			return 'c'
		case 'Т', 'Τ':
			return 'T'
		case 'Х', 'Χ':
			return 'X'
		case 'х', 'χ':
			return 'x'
		case 'У':
			return 'Y'
		case 'у':
			return 'y'
		case 'І', 'Ι':
			return 'I'
		case 'і', 'ι':
			return 'i'
		case 'Ј':
			return 'J'
		case 'ј':
			return 'j'
		case 'Ѕ':
			return 'S'
		case 'ѕ':
			return 's'
		case 'ꓢ':
			return 'S'
		default:
			return r
		}
	}, s)
}

func Canonicalize(s string) string {
	return CanonicalizeHomoglyphs(RemoveZeroWidth(s))
}

func FingerprintText(s string) string {
	return strings.ToLower(Canonicalize(strings.TrimSpace(s)))
}

func FilenameKey(name string) string {
	canonical := FingerprintText(name)
	var b strings.Builder
	for _, r := range canonical {
		switch {
		case r == '.' || r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}
