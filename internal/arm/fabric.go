package arm

// Microsoft.Fabric/capacities: the ARM resource fabric-emulator consumes.
// Capacities are billed, SKU'd resources on management.azure.com; the Fabric
// REST plane (api.fabric.microsoft.com) only lists and assigns them. This
// emulator owns the ARM half. It does not meter jobs or throttle — SKU is
// an assignable label and a CU count for list_usages, nothing more.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/calvinchengx/arm-emulator/internal/store"
)

// fabricSKUNames is the F-series Microsoft documents for Fabric capacities.
// The sample on the REST reference lists a subset; the full ladder is what
// azure-mgmt-fabric and the portal offer.
var fabricSKUNames = []string{
	"F2", "F4", "F8", "F16", "F32", "F64", "F128", "F256", "F512", "F1024", "F2048",
}

var fabricSKUSet = func() map[string]int {
	m := map[string]int{}
	for _, n := range fabricSKUNames {
		cu, _ := strconv.Atoi(strings.TrimPrefix(n, "F"))
		m[n] = cu
	}
	return m
}()

// Capacity names: 3–63 chars, start with a letter, lowercase alphanumeric.
// From the 2023-11-01 REST reference.
var fabricCapacityNameRE = regexp.MustCompile(`^[a-z][a-z0-9]{2,62}$`)

type fabricSKU struct {
	Name string `json:"name"`
	Tier string `json:"tier"`
}

type fabricCapacityProperties struct {
	Administration    *fabricAdministration `json:"administration,omitempty"`
	ProvisioningState string                `json:"provisioningState,omitempty"`
	State             string                `json:"state,omitempty"`
	Overage           json.RawMessage       `json:"overage,omitempty"`
}

type fabricAdministration struct {
	Members []string `json:"members"`
}

func fabricCapacityID(sub, rg, name string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Fabric/capacities/%s",
		sub, rg, name)
}

func (s *Service) fabricCapacityBody(c *store.FabricCapacity) map[string]any {
	tags := map[string]string{}
	_ = json.Unmarshal([]byte(c.TagsJSON), &tags)
	var props fabricCapacityProperties
	_ = json.Unmarshal([]byte(c.PropertiesJSON), &props)
	if props.Administration == nil {
		props.Administration = &fabricAdministration{Members: []string{}}
	} else if props.Administration.Members == nil {
		props.Administration.Members = []string{}
	}
	props.ProvisioningState = "Succeeded"
	props.State = orDefault(props.State, "Active")
	if inFlight, err := s.Store.OperationInFlight(fabricCapacityID(c.Subscription, c.ResourceGroup, c.Name)); err == nil && inFlight {
		props.ProvisioningState = "Updating"
		if props.State == "Active" {
			props.State = "Preparing"
		}
	}
	body := map[string]any{
		"id":       fabricCapacityID(c.Subscription, c.ResourceGroup, c.Name),
		"name":     c.Name,
		"type":     "Microsoft.Fabric/capacities",
		"location": c.Location,
		"tags":     tags,
		"sku":      fabricSKU{Name: c.SKUName, Tier: orDefault(c.SKUTier, "Fabric")},
		"properties": map[string]any{
			"administration":    props.Administration,
			"provisioningState": props.ProvisioningState,
			"state":             props.State,
		},
	}
	if len(props.Overage) > 0 && string(props.Overage) != "null" {
		var overage any
		if json.Unmarshal(props.Overage, &overage) == nil {
			body["properties"].(map[string]any)["overage"] = overage
		}
	}
	return body
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func fabricCapacityNotFound(w http.ResponseWriter, name string) {
	writeErr(w, http.StatusNotFound, "ResourceNotFound",
		fmt.Sprintf("The Resource 'Microsoft.Fabric/capacities/%s' was not found.", name))
}

// fabricCapacities dispatches Microsoft.Fabric/capacities paths beneath a scope.
// rest is everything after `providers/Microsoft.Fabric`.
func (s *Service) fabricCapacities(w http.ResponseWriter, r *http.Request, scope string, rest []string) {
	sub := SubscriptionOf(scope)
	if sub == "" || !s.checkSubscription(w, sub) {
		if sub == "" {
			writeErr(w, http.StatusNotFound, "InvalidResourceId",
				"Microsoft.Fabric resources live under a subscription.")
		}
		return
	}
	rg := ResourceGroupOf(scope)

	if len(rest) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, r.Method)
			return
		}
		cs, err := s.Store.ListFabricCapacities(sub, rg)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		items := make([]map[string]any, 0, len(cs))
		for _, c := range cs {
			items = append(items, s.fabricCapacityBody(c))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": items})
		return
	}

	name := rest[1]
	if len(rest) >= 3 {
		switch strings.ToLower(rest[2]) {
		case "suspend":
			s.suspendCapacity(w, r, sub, name)
			return
		case "resume":
			s.resumeCapacity(w, r, sub, name)
			return
		case "skus":
			s.listSkusForCapacity(w, r, sub, name)
			return
		default:
			writeErr(w, http.StatusBadRequest, "NoRegisteredProviderFound",
				fmt.Sprintf("No registered resource provider found for type '%s'.", strings.Join(rest, "/")))
			return
		}
	}

	switch r.Method {
	case http.MethodPut:
		s.putCapacity(w, r, sub, rg, name)
	case http.MethodGet:
		c, err := s.Store.GetFabricCapacity(sub, name)
		if errors.Is(err, store.ErrNotFound) {
			fabricCapacityNotFound(w, name)
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.fabricCapacityBody(c))
	case http.MethodPatch:
		s.patchCapacity(w, r, sub, rg, name)
	case http.MethodDelete:
		s.deleteCapacity(w, r, sub, name)
	default:
		methodNotAllowed(w, r.Method)
	}
}

func (s *Service) putCapacity(w http.ResponseWriter, r *http.Request, sub, rg, name string) {
	if rg == "" {
		writeErr(w, http.StatusNotFound, "InvalidResourceId",
			"A capacity must be created inside a resource group.")
		return
	}
	if !fabricCapacityNameRE.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "InvalidResourceName",
			"The capacity name must be 3 to 63 lowercase alphanumeric characters and start with a letter.")
		return
	}
	var body struct {
		Location   string                   `json:"location"`
		Tags       map[string]string        `json:"tags"`
		SKU        fabricSKU                `json:"sku"`
		Properties fabricCapacityProperties `json:"properties"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "InvalidRequestContent",
			"The request content was invalid and could not be deserialized.")
		return
	}
	if body.Location == "" {
		writeErr(w, http.StatusBadRequest, "LocationRequired",
			"The location property is required for this definition.")
		return
	}
	if err := validateFabricSKU(body.SKU); err != nil {
		writeErr(w, http.StatusBadRequest, "InvalidSku", err.Error())
		return
	}
	if body.Properties.Administration == nil || len(body.Properties.Administration.Members) == 0 {
		writeErr(w, http.StatusBadRequest, "InvalidParameter",
			"properties.administration.members is required.")
		return
	}
	if _, err := s.Store.GetResourceGroup(sub, rg); errors.Is(err, store.ErrNotFound) {
		rgNotFound(w, rg)
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}

	_, getErr := s.Store.GetFabricCapacity(sub, name)
	existed := getErr == nil
	if getErr != nil && !errors.Is(getErr, store.ErrNotFound) {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", getErr.Error())
		return
	}

	props := body.Properties
	props.ProvisioningState = "Succeeded"
	props.State = orDefault(props.State, "Active")
	raw, err := json.Marshal(props)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	c := &store.FabricCapacity{
		Subscription: sub, ResourceGroup: rg, Name: name,
		Location: body.Location, SKUName: body.SKU.Name, SKUTier: body.SKU.Tier,
		PropertiesJSON: string(raw),
	}
	if body.Tags != nil {
		t, _ := json.Marshal(body.Tags)
		c.TagsJSON = string(t)
	}
	if err := s.Store.PutFabricCapacity(c); err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	op, err := s.startOperation("CreateCapacity", sub, fabricCapacityID(sub, rg, name))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	s.asyncHeaders(w, r, op)
	status := http.StatusCreated
	if existed {
		status = http.StatusOK
	}
	writeJSON(w, status, s.fabricCapacityBody(c))
}

func (s *Service) patchCapacity(w http.ResponseWriter, r *http.Request, sub, rg, name string) {
	c, err := s.Store.GetFabricCapacity(sub, name)
	if errors.Is(err, store.ErrNotFound) {
		fabricCapacityNotFound(w, name)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	var body struct {
		Tags       map[string]string        `json:"tags"`
		SKU        *fabricSKU               `json:"sku"`
		Properties fabricCapacityProperties `json:"properties"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "InvalidRequestContent",
			"The request content was invalid and could not be deserialized.")
		return
	}
	if body.SKU != nil {
		if err := validateFabricSKU(*body.SKU); err != nil {
			writeErr(w, http.StatusBadRequest, "InvalidSku", err.Error())
			return
		}
		c.SKUName, c.SKUTier = body.SKU.Name, body.SKU.Tier
	}
	if body.Tags != nil {
		t, _ := json.Marshal(body.Tags)
		c.TagsJSON = string(t)
	}
	var props fabricCapacityProperties
	_ = json.Unmarshal([]byte(c.PropertiesJSON), &props)
	if body.Properties.Administration != nil {
		props.Administration = body.Properties.Administration
	}
	if len(body.Properties.Overage) > 0 && string(body.Properties.Overage) != "null" {
		props.Overage = body.Properties.Overage
	}
	raw, err := json.Marshal(props)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	c.PropertiesJSON = string(raw)
	if rg != "" {
		c.ResourceGroup = rg
	}
	if err := s.Store.PutFabricCapacity(c); err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	op, err := s.startOperation("UpdateCapacity", sub, fabricCapacityID(c.Subscription, c.ResourceGroup, c.Name))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	s.asyncHeaders(w, r, op)
	writeJSON(w, http.StatusOK, s.fabricCapacityBody(c))
}

func (s *Service) deleteCapacity(w http.ResponseWriter, r *http.Request, sub, name string) {
	c, err := s.Store.GetFabricCapacity(sub, name)
	if errors.Is(err, store.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if err := s.Store.DeleteFabricCapacity(sub, name); err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	op, err := s.startOperation("DeleteCapacity", sub, fabricCapacityID(sub, c.ResourceGroup, name))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	s.accept202(w, r, op)
}

func (s *Service) suspendCapacity(w http.ResponseWriter, r *http.Request, sub, name string) {
	s.setCapacityState(w, r, sub, name, "Paused", "SuspendCapacity")
}

func (s *Service) resumeCapacity(w http.ResponseWriter, r *http.Request, sub, name string) {
	s.setCapacityState(w, r, sub, name, "Active", "ResumeCapacity")
}

func (s *Service) setCapacityState(w http.ResponseWriter, r *http.Request, sub, name, state, kind string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r.Method)
		return
	}
	c, err := s.Store.GetFabricCapacity(sub, name)
	if errors.Is(err, store.ErrNotFound) {
		fabricCapacityNotFound(w, name)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	var props fabricCapacityProperties
	_ = json.Unmarshal([]byte(c.PropertiesJSON), &props)
	props.State = state
	raw, err := json.Marshal(props)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	c.PropertiesJSON = string(raw)
	if err := s.Store.PutFabricCapacity(c); err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	op, err := s.startOperation(kind, sub, fabricCapacityID(sub, c.ResourceGroup, name))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	s.accept202(w, r, op)
}

func validateFabricSKU(sku fabricSKU) error {
	if sku.Name == "" {
		return fmt.Errorf("sku.name is required.")
	}
	if _, ok := fabricSKUSet[sku.Name]; !ok {
		return fmt.Errorf("sku.name '%s' is not a Fabric F-series SKU.", sku.Name)
	}
	if sku.Tier != "" && !strings.EqualFold(sku.Tier, "Fabric") {
		return fmt.Errorf("sku.tier must be 'Fabric'.")
	}
	return nil
}

func (s *Service) fabricSkus(w http.ResponseWriter, r *http.Request, scope string) {
	sub := SubscriptionOf(scope)
	if sub == "" || !s.checkSubscription(w, sub) {
		if sub == "" {
			writeErr(w, http.StatusNotFound, "InvalidResourceId",
				"Microsoft.Fabric resources live under a subscription.")
		}
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r.Method)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": fabricSKUList("westeurope")})
}

func (s *Service) listSkusForCapacity(w http.ResponseWriter, r *http.Request, sub, name string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r.Method)
		return
	}
	if _, err := s.Store.GetFabricCapacity(sub, name); errors.Is(err, store.ErrNotFound) {
		fabricCapacityNotFound(w, name)
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(fabricSKUNames))
	for _, n := range fabricSKUNames {
		items = append(items, map[string]any{
			"resourceType": "Microsoft.Fabric/capacities",
			"sku":          fabricSKU{Name: n, Tier: "Fabric"},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": items})
}

func fabricSKUList(location string) []map[string]any {
	out := make([]map[string]any, 0, len(fabricSKUNames))
	for _, n := range fabricSKUNames {
		out = append(out, map[string]any{
			"name":         n,
			"locations":    []string{location},
			"resourceType": "Capacities",
		})
	}
	return out
}

// fabricLocations handles subscription-level Microsoft.Fabric/locations/{loc}/…
// operations: checkNameAvailability and list_usages.
func (s *Service) fabricLocations(w http.ResponseWriter, r *http.Request, scope string, rest []string) {
	sub := SubscriptionOf(scope)
	if sub == "" || !s.checkSubscription(w, sub) {
		if sub == "" {
			writeErr(w, http.StatusNotFound, "InvalidResourceId",
				"Microsoft.Fabric resources live under a subscription.")
		}
		return
	}
	if len(rest) < 3 {
		writeErr(w, http.StatusBadRequest, "NoRegisteredProviderFound",
			fmt.Sprintf("No registered resource provider found for type '%s'.", strings.Join(rest, "/")))
		return
	}
	location, op := rest[1], strings.ToLower(rest[2])
	switch op {
	case "checknameavailability":
		s.checkCapacityName(w, r, sub)
	case "usages":
		s.listCapacityUsages(w, r, sub, location)
	default:
		writeErr(w, http.StatusBadRequest, "NoRegisteredProviderFound",
			fmt.Sprintf("No registered resource provider found for type '%s'.", strings.Join(rest, "/")))
	}
}

func (s *Service) checkCapacityName(w http.ResponseWriter, r *http.Request, sub string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r.Method)
		return
	}
	var body struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "InvalidRequestContent",
			"The request content was invalid and could not be deserialized.")
		return
	}
	if !fabricCapacityNameRE.MatchString(body.Name) {
		writeJSON(w, http.StatusOK, map[string]any{
			"nameAvailable": false,
			"reason":        "Invalid",
			"message":       "The capacity name must be 3 to 63 lowercase alphanumeric characters and start with a letter.",
		})
		return
	}
	_, err := s.Store.GetFabricCapacity(sub, body.Name)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"nameAvailable": true})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nameAvailable": false,
		"reason":        "AlreadyExists",
		"message":       fmt.Sprintf("A capacity named '%s' already exists.", body.Name),
	})
}

func (s *Service) listCapacityUsages(w http.ResponseWriter, r *http.Request, sub, location string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r.Method)
		return
	}
	cs, err := s.Store.ListFabricCapacities(sub, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	want := normalizeLocation(location)
	var used int
	for _, c := range cs {
		if normalizeLocation(c.Location) != want {
			continue
		}
		var props fabricCapacityProperties
		_ = json.Unmarshal([]byte(c.PropertiesJSON), &props)
		if props.State != "" && !strings.EqualFold(props.State, "Active") {
			continue
		}
		used += fabricSKUSet[c.SKUName]
	}
	// Provisioned CU, not consumed compute. The emulator does not meter
	// jobs; list_usages reports how much F-SKU is allocated in the location.
	writeJSON(w, http.StatusOK, map[string]any{
		"value": []map[string]any{{
			"name":         map[string]string{"value": "CapacityQuota", "localizedValue": "CapacityQuota"},
			"unit":         "CU",
			"currentValue": used,
			"limit":        100000,
		}},
	})
}

func normalizeLocation(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
}

// ServeCapacitiesFeed is GET /_family/capacities — unauthenticated, like the
// authorization feed: a localhost coordination channel so fabric-emulator
// can list ARM-created capacities without impersonating an ARM client.
func (s *Service) ServeCapacitiesFeed(w http.ResponseWriter, r *http.Request) {
	cs, err := s.Store.ListFabricCapacities(s.Cfg.SubscriptionID, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(cs))
	for _, c := range cs {
		var props fabricCapacityProperties
		_ = json.Unmarshal([]byte(c.PropertiesJSON), &props)
		admins := []string{}
		if props.Administration != nil && props.Administration.Members != nil {
			admins = props.Administration.Members
		}
		items = append(items, map[string]any{
			"id":          c.FabricID,
			"armId":       fabricCapacityID(c.Subscription, c.ResourceGroup, c.Name),
			"name":        c.Name,
			"displayName": c.Name,
			"sku":         c.SKUName,
			"region":      c.Location,
			"state":       orDefault(props.State, "Active"),
			"admins":      admins,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated":  s.Store.Now(),
		"capacities": items,
	})
}
