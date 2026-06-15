package normalize

import "math"

func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	var entropy float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func MostlyPrintable(s string) bool {
	if s == "" {
		return false
	}
	printable := 0
	total := 0
	for _, r := range s {
		total++
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			printable++
		case r >= 0x20 && r != 0x7f:
			printable++
		}
	}
	return total > 0 && float64(printable)/float64(total) >= 0.85
}
