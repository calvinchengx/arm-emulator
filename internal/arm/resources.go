package arm

// Microsoft.Resources: tenants, subscriptions and resource groups — the
// discovery surface every ARM client walks before it touches a provider.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/calvinchengx/arm-emulator/internal/store"
)

func (s *Service) listTenants(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"value": []map[string]any{{
		"id":          "/tenants/" + s.Cfg.TenantID,
		"tenantId":    s.Cfg.TenantID,
		"displayName": "Emulator Tenant",
		"tenantType":  "AAD",
	}}})
}

func (s *Service) subscriptionBody() map[string]any {
	return map[string]any{
		"id":                   "/subscriptions/" + s.Cfg.SubscriptionID,
		"subscriptionId":       s.Cfg.SubscriptionID,
		"tenantId":             s.Cfg.TenantID,
		"displayName":          "Emulator Subscription",
		"state":                "Enabled",
		"subscriptionPolicies": map[string]any{"quotaId": "EmulatorQuota", "spendingLimit": "Off"},
		"authorizationSource":  "RoleBased",
	}
}

func (s *Service) listSubscriptions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"value": []map[string]any{s.subscriptionBody()}})
}

func (s *Service) getSubscription(w http.ResponseWriter, r *http.Request, id string) {
	if !strings.EqualFold(id, s.Cfg.SubscriptionID) {
		writeErr(w, http.StatusNotFound, "SubscriptionNotFound",
			fmt.Sprintf("The subscription '%s' could not be found.", id))
		return
	}
	writeJSON(w, http.StatusOK, s.subscriptionBody())
}

// checkSubscription refuses any resource path under an unknown subscription,
// as ARM does before reaching a provider.
func (s *Service) checkSubscription(w http.ResponseWriter, sub string) bool {
	if strings.EqualFold(sub, s.Cfg.SubscriptionID) {
		return true
	}
	writeErr(w, http.StatusNotFound, "SubscriptionNotFound",
		fmt.Sprintf("The subscription '%s' could not be found.", sub))
	return false
}

func (s *Service) rgBody(g *store.ResourceGroup) map[string]any {
	tags := map[string]string{}
	_ = json.Unmarshal([]byte(g.TagsJSON), &tags)
	return map[string]any{
		"id":         fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", g.Subscription, g.Name),
		"name":       g.Name,
		"type":       "Microsoft.Resources/resourceGroups",
		"location":   g.Location,
		"tags":       tags,
		"properties": map[string]any{"provisioningState": "Succeeded"},
	}
}

func (s *Service) listResourceGroups(w http.ResponseWriter, r *http.Request, sub string) {
	if !s.checkSubscription(w, sub) {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r.Method)
		return
	}
	gs, err := s.Store.ListResourceGroups(sub)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(gs))
	for _, g := range gs {
		items = append(items, s.rgBody(g))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": items})
}

// resourceGroup handles PUT (create/update), GET and DELETE on one group.
func (s *Service) resourceGroup(w http.ResponseWriter, r *http.Request, sub, name string) {
	if !s.checkSubscription(w, sub) {
		return
	}
	switch r.Method {
	case http.MethodPut:
		var body struct {
			Location string            `json:"location"`
			Tags     map[string]string `json:"tags"`
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
		g := &store.ResourceGroup{Subscription: sub, Name: name, Location: body.Location}
		if body.Tags != nil {
			raw, _ := json.Marshal(body.Tags)
			g.TagsJSON = string(raw)
		}
		if err := s.Store.PutResourceGroup(g); err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, s.rgBody(g))
	case http.MethodGet:
		g, err := s.Store.GetResourceGroup(sub, name)
		if errors.Is(err, store.ErrNotFound) {
			rgNotFound(w, name)
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.rgBody(g))
	case http.MethodDelete:
		// ARM deletes groups asynchronously: 202 naming a Location to poll,
		// or 204 when there was nothing to delete. The poller follows
		// Location until it stops answering 202 (see operations.go).
		err := s.Store.DeleteResourceGroup(sub, name)
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		op, err := s.startOperation("DeleteResourceGroup", sub,
			fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", sub, name))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		s.accept202(w, r, op)
	default:
		methodNotAllowed(w, r.Method)
	}
}

func rgNotFound(w http.ResponseWriter, name string) {
	writeErr(w, http.StatusNotFound, "ResourceGroupNotFound",
		fmt.Sprintf("Resource group '%s' could not be found.", name))
}

func methodNotAllowed(w http.ResponseWriter, method string) {
	writeErr(w, http.StatusMethodNotAllowed, "MethodNotAllowed",
		fmt.Sprintf("The http method '%s' is not allowed on this resource.", method))
}

// ServeMetadata is GET /metadata/endpoints — the cloud-discovery document
// real ARM serves ANONYMOUSLY, and the first thing `az cloud register` (and
// every SDK doing cloud discovery) fetches. It advertises where to
// authenticate and which audiences this cloud accepts, which is how the CLI
// learns to send its tokens to entra-emulator.
func (s *Service) ServeMetadata(w http.ResponseWriter, r *http.Request) {
	// The login endpoint is the issuer's origin: the issuer is
	// {origin}/{tenant}/v2.0, and the CLI appends the tenant itself.
	authority := s.Cfg.Issuers()[0]
	if i := strings.Index(authority, "/"+s.Cfg.TenantID); i > 0 {
		authority = authority[:i]
	} else {
		authority = strings.TrimSuffix(strings.TrimSuffix(authority, "/"), "/v2.0")
	}
	self := "https://" + r.Host
	writeJSON(w, http.StatusOK, map[string]any{
		"galleryEndpoint": self + "/gallery",
		"graphEndpoint":   authority,
		"graphAudience":   authority + "/",
		"portalEndpoint":  self + "/portal",
		"authentication": map[string]any{
			"loginEndpoint": authority + "/",
			"audiences": []string{
				"https://management.core.windows.net/",
				"https://management.azure.com/",
			},
			"tenant":           s.Cfg.TenantID,
			"identityProvider": "AAD",
		},
		"suffixes": map[string]any{
			"keyVaultDns":                  "vault.azure.net",
			"storage":                      "core.windows.net",
			"sqlServerHostname":            "database.windows.net",
			"azureFrontDoorEndpointSuffix": "azurefd.net",
		},
		"resourceManager": self,
		"name":            "EmulatorCloud",
	})
}
