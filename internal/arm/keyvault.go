package arm

// Microsoft.KeyVault/vaults: the vault resource itself — where access
// policies, purge protection and the RBAC-authorization switch are configured
// in real Azure, and therefore where azure-keyvault-emulator's data plane
// gets them from.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/calvinchengx/arm-emulator/internal/store"
)

// AccessPolicyEntry is one entry of a vault's access-policy list.
type AccessPolicyEntry struct {
	TenantID    string `json:"tenantId,omitempty"`
	ObjectID    string `json:"objectId"`
	Permissions struct {
		Keys         []string `json:"keys,omitempty"`
		Secrets      []string `json:"secrets,omitempty"`
		Certificates []string `json:"certificates,omitempty"`
		Storage      []string `json:"storage,omitempty"`
	} `json:"permissions"`
}

// vaultProperties is the part of the vault document this emulator models.
// Unmodelled members round-trip through Extra so a client's document comes
// back as it went in.
type vaultProperties struct {
	TenantID                string              `json:"tenantId,omitempty"`
	SKU                     json.RawMessage     `json:"sku,omitempty"`
	AccessPolicies          []AccessPolicyEntry `json:"accessPolicies"`
	VaultURI                string              `json:"vaultUri,omitempty"`
	EnableSoftDelete        *bool               `json:"enableSoftDelete,omitempty"`
	SoftDeleteRetention     *int                `json:"softDeleteRetentionInDays,omitempty"`
	EnableRbacAuthorization *bool               `json:"enableRbacAuthorization,omitempty"`
	EnablePurgeProtection   *bool               `json:"enablePurgeProtection,omitempty"`
	ProvisioningState       string              `json:"provisioningState,omitempty"`
}

func vaultID(sub, rg, name string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.KeyVault/vaults/%s",
		sub, rg, name)
}

func (s *Service) vaultBody(v *store.Vault) map[string]any {
	tags := map[string]string{}
	_ = json.Unmarshal([]byte(v.TagsJSON), &tags)
	var props vaultProperties
	_ = json.Unmarshal([]byte(v.PropertiesJSON), &props)
	if props.AccessPolicies == nil {
		props.AccessPolicies = []AccessPolicyEntry{}
	}
	props.ProvisioningState = "Succeeded"
	if props.VaultURI == "" {
		props.VaultURI = fmt.Sprintf("https://%s.vault.azure.net/", v.Name)
	}
	if props.TenantID == "" {
		props.TenantID = s.Cfg.TenantID
	}
	return map[string]any{
		"id":         vaultID(v.Subscription, v.ResourceGroup, v.Name),
		"name":       v.Name,
		"type":       "Microsoft.KeyVault/vaults",
		"location":   v.Location,
		"tags":       tags,
		"properties": props,
	}
}

func vaultNotFound(w http.ResponseWriter, name string) {
	writeErr(w, http.StatusNotFound, "ResourceNotFound",
		fmt.Sprintf("The Resource 'Microsoft.KeyVault/vaults/%s' was not found.", name))
}

// vaults dispatches the Microsoft.KeyVault provider paths beneath a scope.
// rest is everything after `providers/Microsoft.KeyVault`.
func (s *Service) vaults(w http.ResponseWriter, r *http.Request, scope string, rest []string) {
	sub := SubscriptionOf(scope)
	if sub == "" || !s.checkSubscription(w, sub) {
		if sub == "" {
			writeErr(w, http.StatusNotFound, "InvalidResourceId",
				"Microsoft.KeyVault resources live under a subscription.")
		}
		return
	}
	rg := ResourceGroupOf(scope)

	// Collection: list by resource group, or by subscription when the scope
	// names no group.
	if len(rest) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, r.Method)
			return
		}
		vs, err := s.Store.ListVaults(sub, rg)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		items := make([]map[string]any, 0, len(vs))
		for _, v := range vs {
			items = append(items, s.vaultBody(v))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": items})
		return
	}

	name := rest[1]
	// The accessPolicies sub-operation: PUT .../accessPolicies/{add|replace|remove}.
	if len(rest) >= 3 && strings.EqualFold(rest[2], "accesspolicies") {
		if len(rest) < 4 {
			writeErr(w, http.StatusNotFound, "InvalidResourceId",
				"An access-policy operation kind (add, replace or remove) is required.")
			return
		}
		s.updateAccessPolicy(w, r, sub, rg, name, rest[3])
		return
	}
	if len(rest) > 2 {
		writeErr(w, http.StatusBadRequest, "NoRegisteredProviderFound",
			fmt.Sprintf("No registered resource provider found for type '%s'.", strings.Join(rest, "/")))
		return
	}

	switch r.Method {
	case http.MethodPut:
		s.putVault(w, r, sub, rg, name)
	case http.MethodGet:
		v, err := s.Store.GetVault(sub, name)
		if errors.Is(err, store.ErrNotFound) {
			vaultNotFound(w, name)
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.vaultBody(v))
	case http.MethodDelete:
		err := s.Store.DeleteVault(sub, name)
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		methodNotAllowed(w, r.Method)
	}
}

func (s *Service) putVault(w http.ResponseWriter, r *http.Request, sub, rg, name string) {
	if rg == "" {
		writeErr(w, http.StatusNotFound, "InvalidResourceId",
			"A vault must be created inside a resource group.")
		return
	}
	var body struct {
		Location   string            `json:"location"`
		Tags       map[string]string `json:"tags"`
		Properties vaultProperties   `json:"properties"`
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
	// The resource group must exist, as ARM requires before creating in it.
	if _, err := s.Store.GetResourceGroup(sub, rg); errors.Is(err, store.ErrNotFound) {
		rgNotFound(w, rg)
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	props := body.Properties
	if props.AccessPolicies == nil {
		props.AccessPolicies = []AccessPolicyEntry{}
	}
	if props.TenantID == "" {
		props.TenantID = s.Cfg.TenantID
	}
	props.VaultURI = fmt.Sprintf("https://%s.vault.azure.net/", name)
	props.ProvisioningState = "Succeeded"
	raw, err := json.Marshal(props)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	v := &store.Vault{
		Subscription: sub, ResourceGroup: rg, Name: name,
		Location: body.Location, PropertiesJSON: string(raw),
	}
	if body.Tags != nil {
		t, _ := json.Marshal(body.Tags)
		v.TagsJSON = string(t)
	}
	if err := s.Store.PutVault(v); err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	// Real ARM runs this as an LRO; the emulator completes it inline and
	// answers 200 with a terminal provisioningState, which SDK pollers accept.
	writeJSON(w, http.StatusOK, s.vaultBody(v))
}

// updateAccessPolicy is PUT .../vaults/{name}/accessPolicies/{add|replace|remove},
// the operation `az keyvault set-policy` and `delete-policy` call.
func (s *Service) updateAccessPolicy(w http.ResponseWriter, r *http.Request, sub, rg, name, kind string) {
	if r.Method != http.MethodPut {
		methodNotAllowed(w, r.Method)
		return
	}
	switch strings.ToLower(kind) {
	case "add", "replace", "remove":
	default:
		writeErr(w, http.StatusBadRequest, "BadRequest",
			fmt.Sprintf("Unsupported access policy operation kind '%s'.", kind))
		return
	}
	v, err := s.Store.GetVault(sub, name)
	if errors.Is(err, store.ErrNotFound) {
		vaultNotFound(w, name)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	var body struct {
		Properties struct {
			AccessPolicies []AccessPolicyEntry `json:"accessPolicies"`
		} `json:"properties"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "InvalidRequestContent",
			"The request content was invalid and could not be deserialized.")
		return
	}
	var props vaultProperties
	_ = json.Unmarshal([]byte(v.PropertiesJSON), &props)
	props.AccessPolicies = applyPolicyOp(props.AccessPolicies, body.Properties.AccessPolicies, strings.ToLower(kind))

	raw, err := json.Marshal(props)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	v.PropertiesJSON = string(raw)
	if err := s.Store.PutVault(v); err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	// The operation echoes the resulting policy list, not the whole vault.
	writeJSON(w, http.StatusOK, map[string]any{
		"id":   vaultID(sub, rg, name) + "/accessPolicies/" + strings.ToLower(kind),
		"type": "Microsoft.KeyVault/vaults/accessPolicies",
		"name": strings.ToLower(kind),
		"properties": map[string]any{
			"accessPolicies": props.AccessPolicies,
		},
	})
}

// applyPolicyOp implements the three operation kinds: add merges each entry
// into the existing list (replacing the same objectId), replace swaps the
// whole list, remove drops the named objectIds.
func applyPolicyOp(current, incoming []AccessPolicyEntry, kind string) []AccessPolicyEntry {
	if current == nil {
		current = []AccessPolicyEntry{}
	}
	switch kind {
	case "replace":
		if incoming == nil {
			return []AccessPolicyEntry{}
		}
		return incoming
	case "remove":
		drop := map[string]bool{}
		for _, e := range incoming {
			drop[strings.ToLower(e.ObjectID)] = true
		}
		out := []AccessPolicyEntry{}
		for _, e := range current {
			if !drop[strings.ToLower(e.ObjectID)] {
				out = append(out, e)
			}
		}
		return out
	default: // add
		out := append([]AccessPolicyEntry{}, current...)
		for _, e := range incoming {
			replaced := false
			for i := range out {
				if strings.EqualFold(out[i].ObjectID, e.ObjectID) {
					out[i] = e
					replaced = true
					break
				}
			}
			if !replaced {
				out = append(out, e)
			}
		}
		return out
	}
}

// VaultConfig is the vault-resource configuration a data plane needs: not
// just who may do what, but how the vault itself is set up. In Azure these
// are properties of the ARM resource, so this is where they belong.
type VaultConfig struct {
	Exists                  bool                `json:"exists"`
	AccessPolicies          []AccessPolicyEntry `json:"accessPolicies"`
	EnableRbacAuthorization bool                `json:"enableRbacAuthorization"`
	EnablePurgeProtection   *bool               `json:"enablePurgeProtection,omitempty"`
	EnableSoftDelete        *bool               `json:"enableSoftDelete,omitempty"`
	SoftDeleteRetentionDays *int                `json:"softDeleteRetentionInDays,omitempty"`
}

// VaultConfigAt returns the configuration of the vault a scope names. A scope
// that is not a vault, or a vault that does not exist, yields Exists=false —
// the data plane then keeps its own defaults rather than being reconfigured
// by an absent resource.
func (s *Service) VaultConfigAt(scope string) (VaultConfig, error) {
	out := VaultConfig{AccessPolicies: []AccessPolicyEntry{}}
	sub := SubscriptionOf(scope)
	name := vaultNameOf(scope)
	if sub == "" || name == "" {
		return out, nil
	}
	v, err := s.Store.GetVault(sub, name)
	if errors.Is(err, store.ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	var props vaultProperties
	if err := json.Unmarshal([]byte(v.PropertiesJSON), &props); err != nil {
		return out, err
	}
	out.Exists = true
	if props.AccessPolicies != nil {
		out.AccessPolicies = props.AccessPolicies
	}
	out.EnableRbacAuthorization = props.EnableRbacAuthorization != nil && *props.EnableRbacAuthorization
	out.EnablePurgeProtection = props.EnablePurgeProtection
	out.EnableSoftDelete = props.EnableSoftDelete
	out.SoftDeleteRetentionDays = props.SoftDeleteRetention
	return out, nil
}

// vaultNameOf returns the vault name in a scope, or "".
func vaultNameOf(scope string) string {
	parts := strings.Split(strings.Trim(scope, "/"), "/")
	for i, p := range parts {
		if strings.EqualFold(p, "vaults") && i+1 < len(parts) &&
			i > 0 && strings.EqualFold(parts[i-1], "Microsoft.KeyVault") {
			return parts[i+1]
		}
	}
	return ""
}
