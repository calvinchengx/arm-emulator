package arm

// The family's authorization DECISION, in one call.
//
// The feed hands a data plane the raw material — assignments, role
// dataActions, denies, conditions — and leaves the matching to it. That is
// the right division for propagation, but it leaves the hardest part of the
// model (ABAC conditions) unevaluated at the only place that knows how to
// parse them. So the decision itself is available here: a caller supplies the
// action and the attributes it knows about the request, and gets back the
// answer ARM's own model would give, with the reason it gave it.
//
// The order is Azure's: a role assignment must grant the action, its
// condition must be satisfied, and a deny assignment overrides both.

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/calvinchengx/arm-emulator/internal/abac"
)

// EvaluateRequest is what a data plane asks about one operation.
type EvaluateRequest struct {
	Scope string `json:"scope"`
	// PrincipalIDs is the caller's object id plus every group it belongs to,
	// since membership is resolved where the token is read, not here.
	PrincipalIDs []string       `json:"principalIds"`
	Action       string         `json:"action"`
	SubOperation string         `json:"subOperation,omitempty"`
	Attributes   map[string]any `json:"attributes,omitempty"`
}

// EvaluateResult is the decision, with enough detail to explain itself.
type EvaluateResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	// GrantedBy names the assignment that allowed it, empty when nothing did.
	GrantedBy *EffectiveAssignment `json:"grantedBy,omitempty"`
	// DeniedBy names the deny assignment that overrode a grant.
	DeniedBy string `json:"deniedBy,omitempty"`
	// ConditionFailed lists assignments that would have granted the action
	// but for their condition — the difference between "you have no role"
	// and "your role did not apply to this resource", which is the whole
	// point of writing a condition and the thing hardest to debug without it.
	ConditionFailed []string `json:"conditionFailed,omitempty"`
}

// Evaluate answers one authorization question.
func (s *Service) Evaluate(req EvaluateRequest) (EvaluateResult, error) {
	// Denies are consulted FIRST because they override everything: if one
	// applies, no amount of granting changes the answer, and computing the
	// grants would only be work whose result is discarded.
	denies, err := s.DenyAssignmentsAt(req.Scope)
	if err != nil {
		return EvaluateResult{}, err
	}
	for _, d := range denies {
		if d.DeniesAction(req.PrincipalIDs, req.Action, true) {
			return EvaluateResult{
				Allowed: false, DeniedBy: d.Name,
				Reason: "a deny assignment overrides every role assignment granting this action",
			}, nil
		}
	}

	eff, err := s.EffectiveAt(req.Scope)
	if err != nil {
		return EvaluateResult{}, err
	}
	ctx := abac.NewContext(req.Action, req.Attributes)
	ctx.SubOperation = req.SubOperation

	var granted *EffectiveAssignment
	var failed []string
	for i := range eff {
		a := eff[i]
		if !holdsPrincipal(req.PrincipalIDs, a.PrincipalID) {
			continue
		}
		if !grantsAction(a, req.Action) {
			continue
		}
		if a.Condition != "" {
			cond, err := abac.Parse(a.Condition)
			// A stored condition that no longer parses cannot be satisfied;
			// EffectiveAt has already dropped it, so this is belt and braces.
			if err != nil || !cond.Evaluate(ctx) {
				failed = append(failed, a.RoleName+" at "+a.Scope)
				continue
			}
		}
		granted = &a
		break
	}

	switch {
	case granted != nil:
		return EvaluateResult{Allowed: true, GrantedBy: granted,
			Reason: "granted by " + granted.RoleName + " at " + granted.Scope}, nil
	case len(failed) > 0:
		return EvaluateResult{Allowed: false, ConditionFailed: failed,
			Reason: "a role grants this action, but its condition was not satisfied"}, nil
	default:
		return EvaluateResult{Allowed: false,
			Reason: "no role assignment grants this action at this scope"}, nil
	}
}

func holdsPrincipal(held []string, principal string) bool {
	for _, id := range held {
		if id != "" && strings.EqualFold(id, principal) {
			return true
		}
	}
	return false
}

// grantsAction applies the role's own permission arithmetic: a dataAction
// matches and no notDataAction carves it back out.
func grantsAction(a EffectiveAssignment, action string) bool {
	matched := false
	for _, p := range a.DataActions {
		if abac.Glob(p, action) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, p := range a.NotDataActions {
		if abac.Glob(p, action) {
			return false
		}
	}
	return true
}

// ServeEvaluate is POST /_family/authorization/evaluate — unauthenticated,
// like the rest of the family channel.
func (s *Service) ServeEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r.Method)
		return
	}
	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "InvalidRequestContent",
			"The request content was invalid and could not be deserialized.")
		return
	}
	if strings.TrimSpace(req.Scope) == "" || strings.TrimSpace(req.Action) == "" {
		writeErr(w, http.StatusBadRequest, "BadParameter", "scope and action are required")
		return
	}
	res, err := s.Evaluate(req)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
