package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/urnetwork/connect"
)

// The initial provider-locations listing carries countries only, so a city
// and region can only match after the search endpoint is queried and merged.
func TestResolveProviderSpecSearchesCityAndRegion(t *testing.T) {
	const (
		usID     = "018bab1d-4ea0-4bd2-d15a-683802e0873e"
		texasID  = "018bab1d-4c7c-60fa-38dc-0d98b581208a"
		dallasID = "018bab1d-4c82-b4f7-1ee1-ff0abf9e74f0"
	)

	queries := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/hello":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/network/provider-locations":
			json.NewEncoder(w).Encode(map[string]any{
				"locations": []map[string]any{
					{"location_id": usID, "location_type": "country", "name": "United States", "provider_count": 100},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/network/find-provider-locations":
			var args FindLocationsArgs
			if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
				t.Errorf("decode search args: %v", err)
			}
			queries = append(queries, args.Query)
			json.NewEncoder(w).Encode(map[string]any{
				"locations": []map[string]any{
					{"location_id": dallasID, "location_type": "city", "name": "Dallas", "provider_count": 23},
					{"location_id": texasID, "location_type": "region", "name": "Texas", "provider_count": 775},
					{"location_id": usID, "location_type": "country", "name": "United States", "provider_count": 100},
				},
			})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	specs, err := resolveProviderSpec(context.Background(), srv.URL, "jwt", "Dallas", "", "Texas", "")
	if err != nil {
		t.Fatalf("resolveProviderSpec: %v", err)
	}
	if len(specs) != 1 || specs[0].LocationId == nil {
		t.Fatalf("specs = %+v, want 1 spec with LocationId", specs)
	}
	if got := specs[0].LocationId.String(); got != dallasID {
		t.Errorf("location id = %s, want Dallas %s", got, dallasID)
	}
	if len(queries) != 2 || queries[0] != "Dallas" || queries[1] != "Texas" {
		t.Errorf("search queries = %v, want [Dallas Texas]", queries)
	}
}

func TestMergeLocationsDeduplicates(t *testing.T) {
	usID, err := connect.ParseId("018bab1d-4ea0-4bd2-d15a-683802e0873e")
	if err != nil {
		t.Fatal(err)
	}
	dallasID, err := connect.ParseId("018bab1d-4c82-b4f7-1ee1-ff0abf9e74f0")
	if err != nil {
		t.Fatal(err)
	}
	us := &LocationResult{LocationId: &usID, LocationType: "country", Name: "United States"}
	dallas := &LocationResult{LocationId: &dallasID, LocationType: "city", Name: "Dallas"}

	base := &FindLocationsResult{Locations: &LocationResultList{}}
	base.Locations.values = []*LocationResult{us}
	extra := &FindLocationsResult{Locations: &LocationResultList{}}
	extra.Locations.values = []*LocationResult{us, dallas, dallas}

	mergeLocations(base, extra)

	got := base.Locations.Values()
	if len(got) != 2 || got[0] != us || got[1] != dallas {
		t.Errorf("merged locations = %+v, want [US Dallas]", got)
	}
}
