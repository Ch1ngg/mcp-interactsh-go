package interactsh

import "testing"

func TestApplyFilters(t *testing.T) {
	events := []string{
		`{"protocol":"http","raw-request":"GET /probe?flag=1 HTTP/1.1\r\nHost: abc.oast.pro\r\n"}`,
		`{"protocol":"http","raw-request":"POST /upload HTTP/1.1\r\nHost: abc.oast.pro\r\n"}`,
		`{"protocol":"dns","raw":"dns lookup for xyz"}`,
		`not-json-at-all`,
	}

	tests := []struct {
		name    string
		filters Filters
		want    int
	}{
		{"no filter", Filters{}, 4},
		{"method GET", Filters{Method: "get"}, 1},
		{"method POST", Filters{Method: "POST"}, 1},
		{"path contains probe", Filters{PathContains: "PROBE"}, 1},
		{"query contains flag", Filters{QueryContains: "flag=1"}, 1},
		{"protocol dns", Filters{Protocol: "DNS"}, 1},
		{"text contains dns lookup", Filters{TextContains: "dns lookup"}, 1},
		{"text contains non-json", Filters{TextContains: "not-json"}, 1},
		{"no match", Filters{Method: "DELETE"}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplyFilters(events, tt.filters)
			if len(got) != tt.want {
				t.Fatalf("got %d events, want %d: %+v", len(got), tt.want, got)
			}
		})
	}

	httpEvent := ApplyFilters(events, Filters{Method: "GET"})[0]
	if httpEvent.HTTP == nil || httpEvent.HTTP.Method != "GET" || httpEvent.HTTP.Path != "/probe" || httpEvent.HTTP.Query != "flag=1" {
		t.Fatalf("http details not parsed: %+v", httpEvent.HTTP)
	}

	bad := ApplyFilters([]string{`not-json-at-all`}, Filters{})
	if bad[0].Parsed != nil {
		t.Fatal("non-JSON event must not have parsed field set")
	}
}

func TestFiltersNonEmpty(t *testing.T) {
	f := Filters{Method: "GET", TextContains: "x"}
	got := f.NonEmpty()
	if len(got) != 2 || got["method"] != "GET" || got["text_contains"] != "x" {
		t.Fatalf("unexpected: %+v", got)
	}
	if len((Filters{}).NonEmpty()) != 0 {
		t.Fatal("empty filters must map to empty")
	}
}
