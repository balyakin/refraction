package extract

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"

	"github.com/balyakin/refraction/internal/model"
)

func ExtractGo(filePath string, text string, opts Options) ([]model.Region, []model.ScanError) {
	c := newCollector(filePath, opts)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, text, parser.ParseComments)
	if err != nil {
		regions, errs := ExtractGenericWithErrors(filePath, text, opts)
		errs = append(errs, model.ScanError{Path: filePath, Kind: "parse", Message: "go parser fallback: " + err.Error()})
		return regions, errs
	}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			pos := fset.Position(comment.Pos())
			body := comment.Text
			if len(body) >= 2 && body[:2] == "//" {
				body = body[2:]
			} else if len(body) >= 4 && body[:2] == "/*" {
				body = body[2 : len(body)-2]
			}
			c.add(model.RegionComment, pos.Line, body)
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			value = lit.Value
		}
		pos := fset.Position(lit.Pos())
		c.add(model.RegionString, pos.Line, value)
		return true
	})
	extractNonASCIIIdentifierLines(c, text)
	return c.result()
}
