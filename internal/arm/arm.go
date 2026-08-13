// Package arm serves the Azure Resource Manager control plane: the resource-ID
// grammar, the ARM error envelope, api-version validation, ARM-audience token
// validation, and the providers the emulator family needs —
// Microsoft.Resources (subscriptions, resource groups) and
// Microsoft.Authorization (role definitions, role assignments).
//
// Routing is path-parsed rather than mux-registered: an ARM scope is a
// variable-length resource ID with the provider path appended, which no
// pattern router expresses. Parsing the ID is what ARM itself does.
package arm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/calvinchengx/arm-emulator/internal/auth"
	"github.com/calvinchengx/arm-emulator/internal/config"
	"github.com/calvinchengx/arm-emulator/internal/store"
)

// Service is the ARM handler.
type Service struct {
	Store *store.Store
	Auth  *auth.Validator
	Cfg   *config.Config

	mu           sync.Mutex
	throttleNext int
	rejectNext   int
}

// New wires the service.
func New(cfg *config.Config, st *store.Store, v *auth.Validator) *Service {
	return &Service{Store: st, Auth: v, Cfg: cfg}
}

// SetFaults configures fault switches; negative values leave a field as-is.
func (s *Service) SetFaults(throttleNext, rejectNext int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if throttleNext >= 0 {
		s.throttleNext = throttleNext
	}
	if rejectNext >= 0 {
		s.rejectNext = rejectNext
	}
}

// ---- wire shapes ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr emits the ARM error envelope: {"error":{"code","message"}}.
func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// apiVersionRE accepts ARM's date-based versions, with optional -preview.
var apiVersionRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(-preview)?$`)

// ServeHTTP validates the request envelope, then dispatches on the parsed
// resource path.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("x-ms-request-id", store.NewGUID())
	w.Header().Set("x-ms-correlation-request-id", store.NewGUID())

	s.mu.Lock()
	switch {
	case s.rejectNext > 0:
		s.rejectNext--
		s.mu.Unlock()
		writeErr(w, http.StatusInternalServerError, "InternalServerError", "Injected fault.")
		return
	case s.throttleNext > 0:
		s.throttleNext--
		s.mu.Unlock()
		w.Header().Set("Retry-After", "1")
		writeErr(w, http.StatusTooManyRequests, "TooManyRequests", "Injected throttling; retry the request.")
		return
	}
	s.mu.Unlock()

	// ARM returns 401 with a WWW-Authenticate pointing at the authority —
	// the same bearer challenge shape the data planes use.
	if r.Header.Get("Authorization") == "" {
		s.challenge(w, "Authentication failed. The 'Authorization' header is missing.")
		return
	}
	p, err := s.Auth.ValidateRequest(r)
	if err != nil {
		s.challenge(w, err.Error())
		return
	}

	if v := r.URL.Query().Get("api-version"); v == "" {
		writeErr(w, http.StatusBadRequest, "MissingApiVersionParameter",
			"The api-version query parameter (?api-version=) is required for all requests.")
		return
	} else if !apiVersionRE.MatchString(v) {
		writeErr(w, http.StatusBadRequest, "InvalidApiVersionParameter",
			fmt.Sprintf("The api version '%s' is invalid. The supported versions are date-based (e.g. 2022-04-01).", v))
		return
	}

	s.route(w, r, p)
}

func (s *Service) challenge(w http.ResponseWriter, msg string) {
	authority := strings.TrimSuffix(strings.TrimSuffix(s.Cfg.Issuers()[0], "/"), "/v2.0")
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer authorization_uri=%q, error="invalid_token"`, authority))
	writeErr(w, http.StatusUnauthorized, "AuthenticationFailed", msg)
}

// segments splits a request path into non-empty segments.
func segments(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// splitProvider finds the trailing `providers/{namespace}/{type}[/{name}]`
// portion of a path, returning the scope before it and the provider segments
// after it. ok is false when the path has no provider portion.
//
// The LAST "providers" wins: a resource-scoped role assignment reads
// /subscriptions/s/resourceGroups/g/providers/Microsoft.KeyVault/vaults/v/providers/Microsoft.Authorization/roleAssignments/n
// where the scope itself contains a providers segment.
func splitProvider(segs []string) (scope string, rest []string, ok bool) {
	last := -1
	for i, s := range segs {
		if strings.EqualFold(s, "providers") {
			last = i
		}
	}
	if last < 0 || last+1 >= len(segs) {
		return "", nil, false
	}
	return "/" + strings.Join(segs[:last], "/"), segs[last+1:], true
}

// route dispatches an authenticated, version-checked request.
func (s *Service) route(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	segs := segments(r.URL.Path)

	// Tenant/subscription discovery — what `az login` and every SDK call
	// first.
	if len(segs) == 1 && strings.EqualFold(segs[0], "tenants") {
		s.listTenants(w, r)
		return
	}
	if len(segs) == 1 && strings.EqualFold(segs[0], "subscriptions") {
		s.listSubscriptions(w, r)
		return
	}
	if len(segs) == 2 && strings.EqualFold(segs[0], "subscriptions") {
		s.getSubscription(w, r, segs[1])
		return
	}

	// Asynchronous-operation polling. Both shapes hang off the subscription,
	// and a client only ever follows the URL we handed it in a header.
	if len(segs) == 4 && strings.EqualFold(segs[0], "subscriptions") {
		switch {
		case strings.EqualFold(segs[2], "operationresults"):
			s.operationResults(w, r, segs[1], segs[3])
			return
		case strings.EqualFold(segs[2], "operationstatuses"):
			s.operationStatuses(w, r, segs[1], segs[3])
			return
		}
	}

	// Provider paths: Microsoft.Authorization lives under any scope.
	if scope, rest, ok := splitProvider(segs); ok {
		if strings.EqualFold(rest[0], "microsoft.authorization") && len(rest) >= 2 {
			switch {
			case strings.EqualFold(rest[1], "roledefinitions"):
				s.roleDefinitions(w, r, scope, rest[2:])
				return
			case strings.EqualFold(rest[1], "roleassignments"):
				s.roleAssignments(w, r, scope, rest[2:], p)
				return
			case strings.EqualFold(rest[1], "denyassignments"):
				s.denyAssignments(w, r, scope, rest[2:])
				return
			}
		}
		if strings.EqualFold(rest[0], "microsoft.keyvault") && len(rest) >= 2 {
			switch {
			case strings.EqualFold(rest[1], "vaults"):
				s.vaults(w, r, scope, rest[1:])
				return
			// A deleted vault is addressed either subscription-wide or
			// under its location, as Key Vault addresses it.
			case strings.EqualFold(rest[1], "deletedvaults"), strings.EqualFold(rest[1], "locations"):
				s.deletedVaults(w, r, scope, rest[1:])
				return
			}
		}
		if strings.EqualFold(rest[0], "microsoft.fabric") && len(rest) >= 2 {
			switch {
			case strings.EqualFold(rest[1], "capacities"):
				s.fabricCapacities(w, r, scope, rest[1:])
				return
			case strings.EqualFold(rest[1], "skus"):
				s.fabricSkus(w, r, scope)
				return
			case strings.EqualFold(rest[1], "locations"):
				s.fabricLocations(w, r, scope, rest[1:])
				return
			}
		}
		writeErr(w, http.StatusBadRequest, "NoRegisteredProviderFound",
			fmt.Sprintf("No registered resource provider found for location and API version for type '%s'.",
				strings.Join(rest, "/")))
		return
	}

	// The subscription-wide tracked-resource list.
	if len(segs) == 3 && strings.EqualFold(segs[0], "subscriptions") &&
		strings.EqualFold(segs[2], "resources") {
		s.listResources(w, r, segs[1])
		return
	}

	// Resource groups.
	if len(segs) >= 3 && strings.EqualFold(segs[0], "subscriptions") &&
		strings.EqualFold(segs[2], "resourcegroups") {
		sub := segs[1]
		switch len(segs) {
		case 3:
			s.listResourceGroups(w, r, sub)
		case 4:
			s.resourceGroup(w, r, sub, segs[3])
		default:
			writeErr(w, http.StatusNotFound, "InvalidResourceId",
				fmt.Sprintf("The resource id '%s' is not valid.", r.URL.Path))
		}
		return
	}

	writeErr(w, http.StatusNotFound, "InvalidResourceId",
		fmt.Sprintf("The resource id '%s' is not valid.", r.URL.Path))
}
