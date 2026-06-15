package model

type Region struct {
	FilePath string
	Kind     RegionKind
	Line     int
	Text     string
}

type Variant struct {
	Text       string
	Decoded    bool
	DecodePath string
}
