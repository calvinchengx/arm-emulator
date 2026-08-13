package arm

// Microsoft.Fabric/capacities: branches the typed SDK does not reach —
// name rules, missing administration, suspend/resume, checkNameAvailability,
// list_usages, and storage failures.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/arm-emulator/internal/store"
)

func fabricScopeFor(name string) string {
	return "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Fabric/capacities/" + name
}

func seedCapacity(t *testing.T, s *Service, name, sku string) {
	t.Helper()
	if err := s.Store.PutResourceGroup(&store.ResourceGroup{Subscription: testSub, Name: "rg1"}); err != nil {
		t.Fatal(err)
	}
	body := `{"location":"westeurope","sku":{"name":"` + sku + `","tier":"Fabric"},` +
		`"properties":{"administration":{"members":["admin@example.com"]}}}`
	w := httptest.NewRecorder()
	s.fabricCapacities(w, req("PUT", "/x", body), fabricScopeFor(name), []string{"capacities", name})
	if w.Code != http.StatusCreated {
		t.Fatalf("seed capacity = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestFabricCapacityLifecycle(t *testing.T) {
	s, _ := newService(t, "")

	// Outside a resource group is refused.
	w := httptest.NewRecorder()
	s.fabricCapacities(w, req("PUT", "/x", `{"location":"westeurope","sku":{"name":"F2","tier":"Fabric"},`+
		`"properties":{"administration":{"members":["a@b.com"]}}}`),
		"/subscriptions/"+testSub, []string{"capacities", "capone"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("capacity without a group = %d %s", w.Code, w.Body.Bytes())
	}

	scope := fabricScopeFor("capone")
	for body, want := range map[string]string{
		"{nope":                     "InvalidRequestContent",
		"{}":                        "LocationRequired",
		`{"location":"westeurope"}`: "InvalidSku",
		`{"location":"westeurope","sku":{"name":"F2","tier":"Fabric"}}`: "InvalidParameter",
		`{"location":"westeurope","sku":{"name":"D2","tier":"Fabric"},` +
			`"properties":{"administration":{"members":["a@b.com"]}}}`: "InvalidSku",
		`{"location":"westeurope","sku":{"name":"F2","tier":"Premium"},` +
			`"properties":{"administration":{"members":["a@b.com"]}}}`: "InvalidSku",
	} {
		w := httptest.NewRecorder()
		s.fabricCapacities(w, req("PUT", "/x", body), scope, []string{"capacities", "capone"})
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), want) {
			t.Fatalf("PUT %q = %d %s", body, w.Code, w.Body.Bytes())
		}
	}

	// An illegal name is refused.
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("PUT", "/x", `{"location":"westeurope","sku":{"name":"F2","tier":"Fabric"},`+
		`"properties":{"administration":{"members":["a@b.com"]}}}`),
		fabricScopeFor("Bad"), []string{"capacities", "Bad"})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "InvalidResourceName") {
		t.Fatalf("illegal name = %d %s", w.Code, w.Body.Bytes())
	}

	// A group that does not exist is refused.
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("PUT", "/x", `{"location":"westeurope","sku":{"name":"F2","tier":"Fabric"},`+
		`"properties":{"administration":{"members":["a@b.com"]}}}`),
		scope, []string{"capacities", "capone"})
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "ResourceGroupNotFound") {
		t.Fatalf("capacity in a missing group = %d %s", w.Code, w.Body.Bytes())
	}

	seedCapacity(t, s, "capone", "F64")

	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), scope, []string{"capacities", "capone"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"F64"`) ||
		!strings.Contains(w.Body.String(), `"Active"`) {
		t.Fatalf("GET capacity = %d %s", w.Code, w.Body.Bytes())
	}

	// An update (same name) is 200, not 201.
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("PUT", "/x", `{"location":"westeurope","sku":{"name":"F128","tier":"Fabric"},`+
		`"properties":{"administration":{"members":["a@b.com"]}}}`),
		scope, []string{"capacities", "capone"})
	if w.Code != http.StatusOK {
		t.Fatalf("PUT update = %d %s", w.Code, w.Body.Bytes())
	}

	// PATCH sku, tags, administration, overage.
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("PATCH", "/x", `{"sku":{"name":"F8","tier":"Fabric"},"tags":{"env":"test"},`+
		`"properties":{"administration":{"members":["other@example.com"]},`+
		`"overage":{"state":"Enabled"}}}`), scope, []string{"capacities", "capone"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"F8"`) ||
		!strings.Contains(w.Body.String(), `"Enabled"`) ||
		!strings.Contains(w.Body.String(), "other@example.com") {
		t.Fatalf("PATCH = %d %s", w.Code, w.Body.Bytes())
	}

	// List by group and by subscription.
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), "/subscriptions/"+testSub+"/resourceGroups/rg1",
		[]string{"capacities"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "capone") {
		t.Fatalf("list by group = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), "/subscriptions/"+testSub, []string{"capacities"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "capone") {
		t.Fatalf("list by subscription = %d %s", w.Code, w.Body.Bytes())
	}

	// Absent GET 404; absent DELETE 204; real DELETE 202.
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), fabricScopeFor("nope"), []string{"capacities", "nope"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("absent capacity = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("DELETE", "/x", ""), fabricScopeFor("nope"), []string{"capacities", "nope"})
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete absent = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("DELETE", "/x", ""), scope, []string{"capacities", "capone"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("delete = %d %s", w.Code, w.Body.Bytes())
	}

	// Unsupported collection method, unknown sub-resource, no subscription.
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("POST", "/x", "{}"), "/subscriptions/"+testSub, []string{"capacities"})
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST to the collection = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), scope, []string{"capacities", "capone", "privateEndpointConnections"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown sub-resource = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), "/", []string{"capacities"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("capacities at the tenant root = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), "/subscriptions/470cdf39-a19d-4440-a4c2-55568885427d",
		[]string{"capacities"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown subscription = %d", w.Code)
	}
}

func TestFabricSuspendResumeAndSkus(t *testing.T) {
	s, _ := newService(t, "")
	seedCapacity(t, s, "pauseme", "F4")
	scope := fabricScopeFor("pauseme")

	w := httptest.NewRecorder()
	s.fabricCapacities(w, req("POST", "/x", ""), scope, []string{"capacities", "pauseme", "suspend"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("suspend = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), scope, []string{"capacities", "pauseme"})
	if !strings.Contains(w.Body.String(), `"Paused"`) {
		t.Fatalf("after suspend = %s", w.Body.Bytes())
	}

	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("POST", "/x", ""), scope, []string{"capacities", "pauseme", "resume"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("resume = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), scope, []string{"capacities", "pauseme"})
	if !strings.Contains(w.Body.String(), `"Active"`) {
		t.Fatalf("after resume = %s", w.Body.Bytes())
	}

	// GET on suspend is refused; absent capacity 404s.
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), scope, []string{"capacities", "pauseme", "suspend"})
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET suspend = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("POST", "/x", ""), fabricScopeFor("nope"), []string{"capacities", "nope", "suspend"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("suspend absent = %d", w.Code)
	}

	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), scope, []string{"capacities", "pauseme", "skus"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"F64"`) {
		t.Fatalf("skus for capacity = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("POST", "/x", ""), scope, []string{"capacities", "pauseme", "skus"})
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST skus = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), fabricScopeFor("nope"), []string{"capacities", "nope", "skus"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("skus for absent = %d", w.Code)
	}

	w = httptest.NewRecorder()
	s.fabricSkus(w, req("GET", "/x", ""), "/subscriptions/"+testSub)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"F2"`) {
		t.Fatalf("list skus = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.fabricSkus(w, req("POST", "/x", ""), "/subscriptions/"+testSub)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST skus = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.fabricSkus(w, req("GET", "/x", ""), "/")
	if w.Code != http.StatusNotFound {
		t.Fatalf("skus at tenant root = %d", w.Code)
	}
}

func TestFabricCheckNameAndUsages(t *testing.T) {
	s, _ := newService(t, "")
	locScope := "/subscriptions/" + testSub
	rest := []string{"locations", "westeurope", "checkNameAvailability"}

	w := httptest.NewRecorder()
	s.fabricLocations(w, req("POST", "/x", `{"name":"azsdktest","type":"Microsoft.Fabric/capacities"}`),
		locScope, rest)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"nameAvailable":true`) {
		t.Fatalf("available name = %d %s", w.Code, w.Body.Bytes())
	}

	w = httptest.NewRecorder()
	s.fabricLocations(w, req("POST", "/x", `{"name":"Bad","type":"Microsoft.Fabric/capacities"}`),
		locScope, rest)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"Invalid"`) {
		t.Fatalf("invalid name = %d %s", w.Code, w.Body.Bytes())
	}

	seedCapacity(t, s, "azsdktest", "F64")
	w = httptest.NewRecorder()
	s.fabricLocations(w, req("POST", "/x", `{"name":"azsdktest","type":"Microsoft.Fabric/capacities"}`),
		locScope, rest)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"AlreadyExists"`) {
		t.Fatalf("taken name = %d %s", w.Code, w.Body.Bytes())
	}

	w = httptest.NewRecorder()
	s.fabricLocations(w, req("GET", "/x", ""), locScope, rest)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET checkName = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.fabricLocations(w, req("POST", "/x", "{nope"), locScope, rest)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed checkName = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.fabricLocations(w, req("GET", "/x", ""), locScope, []string{"locations"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("locations with no operation = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.fabricLocations(w, req("GET", "/x", ""), locScope, []string{"locations", "westeurope", "nope"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown location op = %d", w.Code)
	}

	w = httptest.NewRecorder()
	s.fabricLocations(w, req("GET", "/x", ""), locScope, []string{"locations", "westeurope", "usages"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"currentValue":64`) {
		t.Fatalf("usages = %d %s", w.Code, w.Body.Bytes())
	}
	// A paused capacity does not count; a different location does not either.
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("POST", "/x", ""), fabricScopeFor("azsdktest"),
		[]string{"capacities", "azsdktest", "suspend"})
	w = httptest.NewRecorder()
	s.fabricLocations(w, req("GET", "/x", ""), locScope, []string{"locations", "westeurope", "usages"})
	if !strings.Contains(w.Body.String(), `"currentValue":0`) {
		t.Fatalf("usages after suspend = %s", w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.fabricLocations(w, req("GET", "/x", ""), locScope, []string{"locations", "eastus", "usages"})
	if !strings.Contains(w.Body.String(), `"currentValue":0`) {
		t.Fatalf("usages other region = %s", w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.fabricLocations(w, req("POST", "/x", ""), locScope, []string{"locations", "westeurope", "usages"})
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST usages = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.fabricLocations(w, req("GET", "/x", ""), "/", []string{"locations", "westeurope", "usages"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("usages at tenant root = %d", w.Code)
	}
}

func TestFabricFamilyFeedAndResources(t *testing.T) {
	s, _ := newService(t, "")
	seedCapacity(t, s, "feedcap", "F32")

	w := httptest.NewRecorder()
	s.ServeCapacitiesFeed(w, req("GET", "/_family/capacities", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("feed = %d %s", w.Code, w.Body.Bytes())
	}
	var feed struct {
		Capacities []struct{ ID, Name, SKU, State, ArmID string }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &feed); err != nil || len(feed.Capacities) != 1 {
		t.Fatalf("feed body = %s %v", w.Body.Bytes(), err)
	}
	if feed.Capacities[0].Name != "feedcap" || feed.Capacities[0].SKU != "F32" ||
		feed.Capacities[0].ID == "" || !strings.Contains(feed.Capacities[0].ArmID, "feedcap") {
		t.Fatalf("feed entry = %+v", feed.Capacities[0])
	}

	w = httptest.NewRecorder()
	s.listResources(w, req("GET", "/x?$filter=resourceType%20eq%20'Microsoft.Fabric/capacities'", ""), testSub)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "feedcap") {
		t.Fatalf("resources filter = %d %s", w.Code, w.Body.Bytes())
	}

	// PATCH / GET / DELETE of an absent capacity; PATCH malformed; PATCH bad SKU.
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("PATCH", "/x", `{"sku":{"name":"F2","tier":"Fabric"}}`),
		fabricScopeFor("nope"), []string{"capacities", "nope"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("PATCH absent = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("PATCH", "/x", "{nope"), fabricScopeFor("feedcap"),
		[]string{"capacities", "feedcap"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("PATCH malformed = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("PATCH", "/x", `{"sku":{"name":"D2","tier":"Fabric"}}`),
		fabricScopeFor("feedcap"), []string{"capacities", "feedcap"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("PATCH bad sku = %d", w.Code)
	}

	// HEAD is refused.
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("HEAD", "/x", ""), fabricScopeFor("feedcap"),
		[]string{"capacities", "feedcap"})
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD = %d", w.Code)
	}
}

func TestFabricStorageFailures(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	seedCapacity(t, s, "gone", "F2")
	scope := fabricScopeFor("gone")

	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE fabric_capacities`); err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(w http.ResponseWriter){
		"list": func(w http.ResponseWriter) {
			s.fabricCapacities(w, req("GET", "/x", ""), scope, []string{"capacities"})
		},
		"get": func(w http.ResponseWriter) {
			s.fabricCapacities(w, req("GET", "/x", ""), scope, []string{"capacities", "gone"})
		},
		"delete": func(w http.ResponseWriter) {
			s.fabricCapacities(w, req("DELETE", "/x", ""), scope, []string{"capacities", "gone"})
		},
		"put": func(w http.ResponseWriter) {
			s.fabricCapacities(w, req("PUT", "/x", `{"location":"westeurope","sku":{"name":"F2","tier":"Fabric"},`+
				`"properties":{"administration":{"members":["a@b.com"]}}}`),
				scope, []string{"capacities", "gone"})
		},
		"patch": func(w http.ResponseWriter) {
			s.fabricCapacities(w, req("PATCH", "/x", `{"tags":{"a":"b"}}`), scope,
				[]string{"capacities", "gone"})
		},
		"suspend": func(w http.ResponseWriter) {
			s.fabricCapacities(w, req("POST", "/x", ""), scope, []string{"capacities", "gone", "suspend"})
		},
		"skus": func(w http.ResponseWriter) {
			s.fabricCapacities(w, req("GET", "/x", ""), scope, []string{"capacities", "gone", "skus"})
		},
		"check": func(w http.ResponseWriter) {
			s.fabricLocations(w, req("POST", "/x", `{"name":"gone","type":"Microsoft.Fabric/capacities"}`),
				"/subscriptions/"+testSub, []string{"locations", "westeurope", "checkNameAvailability"})
		},
		"usages": func(w http.ResponseWriter) {
			s.fabricLocations(w, req("GET", "/x", ""), "/subscriptions/"+testSub,
				[]string{"locations", "westeurope", "usages"})
		},
		"feed": func(w http.ResponseWriter) {
			s.ServeCapacitiesFeed(w, req("GET", "/_family/capacities", ""))
		},
		"resources": func(w http.ResponseWriter) {
			s.listResources(w, req("GET", "/x?api-version=2022-09-01", ""), testSub)
		},
	}
	for name, call := range cases {
		w := httptest.NewRecorder()
		call(w)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s with the capacities table dropped = %d %s", name, w.Code, w.Body.Bytes())
		}
	}
}

func TestFabricResumeAbsentAndPatchEmpty(t *testing.T) {
	s, _ := newService(t, "")
	w := httptest.NewRecorder()
	s.fabricCapacities(w, req("POST", "/x", ""), fabricScopeFor("nope"),
		[]string{"capacities", "nope", "resume"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("resume absent = %d", w.Code)
	}

	seedCapacity(t, s, "keepme", "F2")
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("PATCH", "/x", `{}`), fabricScopeFor("keepme"),
		[]string{"capacities", "keepme"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"F2"`) {
		t.Fatalf("empty PATCH = %d %s", w.Code, w.Body.Bytes())
	}

	// A SKU with no tier is accepted (the provider fills Fabric).
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("PUT", "/x", `{"location":"westeurope","sku":{"name":"F4"},`+
		`"properties":{"administration":{"members":["a@b.com"]}}}`),
		fabricScopeFor("notier"), []string{"capacities", "notier"})
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT without sku.tier = %d %s", w.Code, w.Body.Bytes())
	}

	w = httptest.NewRecorder()
	s.fabricSkus(w, req("GET", "/x", ""), "/subscriptions/470cdf39-a19d-4440-a4c2-55568885427d")
	if w.Code != http.StatusNotFound {
		t.Fatalf("skus unknown subscription = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.fabricLocations(w, req("GET", "/x", ""), "/subscriptions/470cdf39-a19d-4440-a4c2-55568885427d",
		[]string{"locations", "westeurope", "usages"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("usages unknown subscription = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), fabricScopeFor("keepme"),
		[]string{"capacities", "keepme", "resume"})
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET resume = %d", w.Code)
	}

	w = httptest.NewRecorder()
	s.listResources(w, req("GET", "/x?$filter=name%20eq%20'keepme'", ""), testSub)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "keepme") {
		t.Fatalf("resources name filter = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestFabricInFlightAndWriteFailures(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	s.Cfg.LRODelaySeconds = 60
	s.Store.Clock.Freeze()
	seedCapacity(t, s, "inflight", "F16")
	w := httptest.NewRecorder()
	s.fabricCapacities(w, req("GET", "/x", ""), fabricScopeFor("inflight"),
		[]string{"capacities", "inflight"})
	if !strings.Contains(w.Body.String(), `"Preparing"`) ||
		!strings.Contains(w.Body.String(), `"Updating"`) {
		t.Fatalf("in-flight create body = %s", w.Body.Bytes())
	}

	// Unreadable stored documents still render rather than failing the GET.
	body := s.fabricCapacityBody(&store.FabricCapacity{
		Subscription: testSub, ResourceGroup: "rg", Name: "c", SKUName: "F2",
		TagsJSON: "not-json", PropertiesJSON: "not-json",
	})
	props := body["properties"].(map[string]any)
	if props["state"] != "Active" || props["provisioningState"] != "Succeeded" {
		t.Fatalf("defaults = %+v", props)
	}

	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE operations`); err != nil {
		t.Fatal(err)
	}
	putBody := `{"location":"westeurope","sku":{"name":"F2","tier":"Fabric"},` +
		`"properties":{"administration":{"members":["a@b.com"]}}}`
	for name, call := range map[string]func(http.ResponseWriter){
		"put": func(w http.ResponseWriter) {
			s.fabricCapacities(w, req("PUT", "/x", putBody), fabricScopeFor("inflight"),
				[]string{"capacities", "inflight"})
		},
		"patch": func(w http.ResponseWriter) {
			s.fabricCapacities(w, req("PATCH", "/x", `{"tags":{"a":"b"}}`), fabricScopeFor("inflight"),
				[]string{"capacities", "inflight"})
		},
		"suspend": func(w http.ResponseWriter) {
			s.fabricCapacities(w, req("POST", "/x", ""), fabricScopeFor("inflight"),
				[]string{"capacities", "inflight", "suspend"})
		},
	} {
		w := httptest.NewRecorder()
		call(w)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s with the operations table dropped = %d %s", name, w.Code, w.Body.Bytes())
		}
	}
	// DELETE removes the row before recording the LRO, so it has to run last.
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("DELETE", "/x", ""), fabricScopeFor("inflight"),
		[]string{"capacities", "inflight"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("delete with the operations table dropped = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestFabricWriteTriggers(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	seedCapacity(t, s, "locked", "F2")
	db, err := sql.Open("sqlite", filepath.Join(dir, "arm-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER no_mut BEFORE UPDATE ON fabric_capacities
BEGIN SELECT RAISE(ABORT, 'update refused'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER no_del BEFORE DELETE ON fabric_capacities
BEGIN SELECT RAISE(ABORT, 'delete refused'); END`); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.fabricCapacities(w, req("DELETE", "/x", ""), fabricScopeFor("locked"),
		[]string{"capacities", "locked"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("delete trigger = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("POST", "/x", ""), fabricScopeFor("locked"),
		[]string{"capacities", "locked", "resume"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("resume trigger = %d %s", w.Code, w.Body.Bytes())
	}
	w = httptest.NewRecorder()
	s.fabricCapacities(w, req("PATCH", "/x", `{"tags":{"a":"b"}}`), fabricScopeFor("locked"),
		[]string{"capacities", "locked"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("patch trigger = %d %s", w.Code, w.Body.Bytes())
	}
}
