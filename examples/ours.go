package main

import (
	"strings"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
)

// oursComponents translates a scenario's component list into this library's
// []parser.ComponentIdentifier: names starting with "@" become derived
// components, everything else becomes an HTTP field component. Query
// parameter names become "@query-param";name="..." derived components, as
// required by RFC 9421 Section 2.2.8.
func oursComponents(headers []string, queryParams []string) []parser.ComponentIdentifier {
	comps := make([]parser.ComponentIdentifier, 0, len(headers)+len(queryParams))
	for _, h := range headers {
		if strings.HasPrefix(h, "@") {
			comps = append(comps, parser.ComponentIdentifier{Name: h, Type: parser.ComponentDerived})
			continue
		}
		comps = append(comps, parser.ComponentIdentifier{Name: strings.ToLower(h), Type: parser.ComponentField})
	}
	for _, qp := range queryParams {
		comps = append(comps, parser.ComponentIdentifier{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: qp}},
			},
		})
	}
	return comps
}
