package arm

// Deleted-vault recovery. Key Vault does not destroy a vault on DELETE — it
// moves to a recoverable state, keeps holding its name, and is destroyed
// only by an explicit purge. That is the behaviour that makes an accidental
// `az keyvault delete` survivable, so an emulator that hard-deletes teaches
// the opposite lesson to the one production teaches.
//
// The retention window runs on the controllable clock: advance past
// scheduledPurgeDate and the vault is gone, without waiting ninety days.

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/calvinchengx/arm-emulator/internal/store"
)

func (s *Service) deletedVaultBody(d *store.DeletedVault) map[string]any {
	return map[string]any{
		"id": fmt.Sprintf("/subscriptions/%s/providers/Microsoft.KeyVault/locations/%s/deletedVaults/%s",
			d.Subscription, d.Location, d.Name),
		"name": d.Name,
		"type": "Microsoft.KeyVault/deletedVaults",
		"properties": map[string]any{
			"vaultId":                vaultID(d.Subscription, d.ResourceGroup, d.Name),
			"location":               d.Location,
			"deletionDate":           rfc3339(d.DeletedAt),
			"scheduledPurgeDate":     rfc3339(d.ScheduledPurgeAt),
			"purgeProtectionEnabled": false,
		},
	}
}

// deletedVaults serves the deletedVaults collection and its members:
//
//	GET  /subscriptions/{sub}/providers/Microsoft.KeyVault/deletedVaults
//	GET  .../locations/{loc}/deletedVaults/{name}
//	POST .../locations/{loc}/deletedVaults/{name}/purge
//
// rest is everything after `providers/Microsoft.KeyVault`.
func (s *Service) deletedVaults(w http.ResponseWriter, r *http.Request, scope string, rest []string) {
	sub := SubscriptionOf(scope)
	if sub == "" || !s.checkSubscription(w, sub) {
		if sub == "" {
			writeErr(w, http.StatusNotFound, "InvalidResourceId",
				"Microsoft.KeyVault resources live under a subscription.")
		}
		return
	}

	// Subscription-wide list: providers/Microsoft.KeyVault/deletedVaults
	if len(rest) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, r.Method)
			return
		}
		ds, err := s.Store.ListDeletedVaults(sub)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		items := make([]map[string]any, 0, len(ds))
		for _, d := range ds {
			items = append(items, s.deletedVaultBody(d))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": items})
		return
	}

	// Location-qualified: locations/{loc}/deletedVaults/{name}[/purge]
	if !strings.EqualFold(rest[0], "locations") || len(rest) < 4 ||
		!strings.EqualFold(rest[2], "deletedvaults") {
		writeErr(w, http.StatusBadRequest, "NoRegisteredProviderFound",
			fmt.Sprintf("No registered resource provider found for type '%s'.", strings.Join(rest, "/")))
		return
	}
	name := rest[3]
	purge := len(rest) >= 5 && strings.EqualFold(rest[4], "purge")

	switch {
	case purge && r.Method == http.MethodPost:
		s.purgeVault(w, r, sub, name)
	case !purge && r.Method == http.MethodGet:
		d, err := s.Store.GetDeletedVault(sub, name)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "VaultNotFound",
				fmt.Sprintf("The deleted vault '%s' was not found.", name))
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.deletedVaultBody(d))
	default:
		methodNotAllowed(w, r.Method)
	}
}

// purgeVault destroys a soft-deleted vault permanently — asynchronous in
// real ARM, so it answers 202 and a Location to poll like every other
// long-running operation here.
func (s *Service) purgeVault(w http.ResponseWriter, r *http.Request, sub, name string) {
	if _, err := s.Store.GetDeletedVault(sub, name); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "VaultNotFound",
			fmt.Sprintf("The deleted vault '%s' was not found.", name))
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if err := s.Store.PurgeVault(sub, name); err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	op, err := s.startOperation("PurgeVault", sub,
		fmt.Sprintf("/subscriptions/%s/providers/Microsoft.KeyVault/deletedVaults/%s", sub, name))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	s.accept202(w, r, op)
}
