package report

import (
	"encoding/json"
	"io"
)

func RenderNDJSON(w io.Writer, data Data) error {
	enc := json.NewEncoder(w)
	for _, finding := range data.Findings {
		if err := enc.Encode(finding); err != nil {
			return err
		}
	}
	return nil
}
