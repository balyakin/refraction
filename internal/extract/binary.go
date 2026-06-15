package extract

import "github.com/balyakin/refraction/internal/model"

func ExtractBinary(filePath string, data []byte, opts Options) []model.Region {
	regions, _ := ExtractBinaryWithErrors(filePath, data, opts)
	return regions
}

func ExtractBinaryWithErrors(filePath string, data []byte, opts Options) ([]model.Region, []model.ScanError) {
	c := newCollector(filePath, opts)
	start := -1
	for i, b := range data {
		if b >= 0x20 && b <= 0x7e {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 6 {
			c.add(model.RegionBinary, 0, string(data[start:i]))
		}
		start = -1
	}
	if start >= 0 && len(data)-start >= 6 {
		c.add(model.RegionBinary, 0, string(data[start:]))
	}
	return c.result()
}
