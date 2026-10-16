package interactsh

import (
	"encoding/json"
	"regexp"
	"strings"
)

// HTTPDetails is the parsed view of the raw-request line of an HTTP interaction.
type HTTPDetails struct {
	Method     string `json:"method"`
	Path       string `json:"path"`
	Query      string `json:"query"`
	FullPath   string `json:"fullPath"`
	PathLower  string `json:"pathLower"`
	QueryLower string `json:"queryLower"`
}

// Event is one decrypted interaction, structured exactly like the Node bridge output.
type Event struct {
	Raw      string       `json:"raw"`
	Protocol string       `json:"protocol,omitempty"`
	HTTP     *HTTPDetails `json:"http,omitempty"`
	Parsed   any          `json:"parsed,omitempty"`
}

// Filters mirrors the optional poll arguments.
type Filters struct {
	Method        string
	PathContains  string
	QueryContains string
	Protocol      string
	TextContains  string
}

// NonEmpty returns only the filters actually supplied by the caller.
func (f Filters) NonEmpty() map[string]string {
	out := map[string]string{}
	if f.Method != "" {
		out["method"] = f.Method
	}
	if f.PathContains != "" {
		out["path_contains"] = f.PathContains
	}
	if f.QueryContains != "" {
		out["query_contains"] = f.QueryContains
	}
	if f.Protocol != "" {
		out["protocol"] = f.Protocol
	}
	if f.TextContains != "" {
		out["text_contains"] = f.TextContains
	}
	return out
}

var requestLineRe = regexp.MustCompile(`(?m)^([A-Z]+)\s+(\S+)`)

func extractHTTPDetails(rawRequest string) *HTTPDetails {
	m := requestLineRe.FindStringSubmatch(rawRequest)
	if m == nil {
		return nil
	}
	method, rawPath := m[1], m[2]
	path, query, _ := strings.Cut(rawPath, "?")
	return &HTTPDetails{
		Method:     method,
		Path:       path,
		Query:      query,
		FullPath:   rawPath,
		PathLower:  strings.ToLower(path),
		QueryLower: strings.ToLower(query),
	}
}

func parseEvent(raw string) Event {
	var data map[string]any
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return Event{Raw: raw}
	}
	ev := Event{Raw: raw}
	if p, ok := data["protocol"].(string); ok {
		ev.Protocol = p
	}
	rawReq, _ := (data["raw-request"]).(string)
	if rawReq == "" {
		rawReq, _ = (data["rawRequest"]).(string)
	}
	if rawReq != "" {
		ev.HTTP = extractHTTPDetails(rawReq)
	}
	ev.Parsed = data
	return ev
}

// ApplyFilters parses every decrypted event and keeps the ones matching all
// supplied filters (case-insensitive substring semantics, matching the Node bridge).
func ApplyFilters(events []string, f Filters) []Event {
	methodFilter := strings.ToUpper(f.Method)
	protocolFilter := strings.ToLower(f.Protocol)
	pathFilter := strings.ToLower(f.PathContains)
	queryFilter := strings.ToLower(f.QueryContains)
	textFilter := strings.ToLower(f.TextContains)

	var out []Event
	for _, raw := range events {
		ev := parseEvent(raw)
		if methodFilter != "" && (ev.HTTP == nil || ev.HTTP.Method != methodFilter) {
			continue
		}
		if pathFilter != "" && (ev.HTTP == nil || !strings.Contains(ev.HTTP.PathLower, pathFilter)) {
			continue
		}
		if queryFilter != "" && (ev.HTTP == nil || !strings.Contains(ev.HTTP.QueryLower, queryFilter)) {
			continue
		}
		if protocolFilter != "" && strings.ToLower(ev.Protocol) != protocolFilter {
			continue
		}
		if textFilter != "" {
			var parsedJSON string
			if b, err := json.Marshal(ev.Parsed); err == nil {
				parsedJSON = string(b)
			}
			fullPath := ""
			if ev.HTTP != nil {
				fullPath = ev.HTTP.FullPath
			}
			haystack := strings.ToLower(raw + " " + parsedJSON + " " + fullPath)
			if !strings.Contains(haystack, textFilter) {
				continue
			}
		}
		out = append(out, ev)
	}
	if out == nil {
		out = []Event{}
	}
	return out
}
