package arm

// ARM's asynchronous-operation protocol, the half of the contract a
// synchronous emulator never exercises.
//
// Real ARM answers a long-running request with 202 and a header naming a URL
// to poll, and Microsoft's SDK pollers branch on WHICH header they got:
//
//   Location             → poll until the status stops being 202; the final
//                          status IS the result. DELETE uses this.
//   Azure-AsyncOperation → poll a status DOCUMENT until status is terminal,
//                          then re-GET the resource for the result. PUT uses
//                          this.
//
// Both are served here, and both complete on the controllable clock: with
// the default zero delay an operation is already terminal on its first poll
// (fast, deterministic CI), while --lro-delay or a frozen clock holds it
// InProgress for as long as a test wants to watch a real poller spin.

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/calvinchengx/arm-emulator/internal/store"
)

// startOperation records a long-running operation for a resource.
func (s *Service) startOperation(kind, sub, resourceID string) (*store.Operation, error) {
	op := &store.Operation{Kind: kind, Subscription: sub, ResourceID: resourceID}
	op.CompleteAt = s.Store.Now() + s.Cfg.LRODelaySeconds
	if err := s.Store.CreateOperation(op); err != nil {
		return nil, err
	}
	return op, nil
}

// pollURL builds an absolute poll URL on this host, carrying the caller's
// api-version through as ARM does.
func (s *Service) pollURL(r *http.Request, sub, kind, id string) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/subscriptions/%s/%s/%s?api-version=%s",
		scheme, r.Host, sub, kind, id, r.URL.Query().Get("api-version"))
}

// accept202 writes the Location-style 202: the shape a DELETE poller follows.
func (s *Service) accept202(w http.ResponseWriter, r *http.Request, op *store.Operation) {
	w.Header().Set("Location", s.pollURL(r, op.Subscription, "operationresults", op.ID))
	w.Header().Set("Retry-After", strconv.Itoa(s.Cfg.RetryAfterSeconds))
	w.WriteHeader(http.StatusAccepted)
}

// asyncHeaders adds the Azure-AsyncOperation-style headers to a 200/201
// response whose body still reports a non-terminal provisioningState — the
// shape a PUT poller follows.
func (s *Service) asyncHeaders(w http.ResponseWriter, r *http.Request, op *store.Operation) {
	w.Header().Set("Azure-AsyncOperation", s.pollURL(r, op.Subscription, "operationstatuses", op.ID))
	w.Header().Set("Retry-After", strconv.Itoa(s.Cfg.RetryAfterSeconds))
}

// operationResults is the Location-style poll: 202 while the operation runs,
// then the terminal status. A poller stops at the first non-202.
func (s *Service) operationResults(w http.ResponseWriter, r *http.Request, sub, id string) {
	op, ok := s.lookupOperation(w, sub, id)
	if !ok {
		return
	}
	switch op.StatusAt(s.Store.Now()) {
	case store.OpInProgress:
		w.Header().Set("Location", s.pollURL(r, sub, "operationresults", id))
		w.Header().Set("Retry-After", strconv.Itoa(s.Cfg.RetryAfterSeconds))
		w.WriteHeader(http.StatusAccepted)
	case store.OpFailed:
		writeErr(w, http.StatusConflict, op.FailWith, "The asynchronous operation failed.")
	default:
		// ARM answers a completed delete with 200 and no body.
		w.WriteHeader(http.StatusOK)
	}
}

// operationStatuses is the Azure-AsyncOperation-style poll: a status document
// the poller reads until `status` is terminal.
func (s *Service) operationStatuses(w http.ResponseWriter, r *http.Request, sub, id string) {
	op, ok := s.lookupOperation(w, sub, id)
	if !ok {
		return
	}
	status := op.StatusAt(s.Store.Now())
	body := map[string]any{
		"id":        fmt.Sprintf("/subscriptions/%s/operationstatuses/%s", sub, id),
		"name":      id,
		"status":    status,
		"startTime": rfc3339(op.CreatedAt),
	}
	if status != store.OpInProgress {
		body["endTime"] = rfc3339(op.CompleteAt)
	}
	if status == store.OpFailed {
		body["error"] = map[string]string{
			"code": op.FailWith, "message": "The asynchronous operation failed.",
		}
	}
	if status == store.OpInProgress {
		w.Header().Set("Retry-After", strconv.Itoa(s.Cfg.RetryAfterSeconds))
	}
	writeJSON(w, http.StatusOK, body)
}

// lookupOperation resolves an operation, writing ARM's not-found envelope
// when it is unknown or belongs to another subscription.
func (s *Service) lookupOperation(w http.ResponseWriter, sub, id string) (*store.Operation, bool) {
	op, err := s.Store.GetOperation(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "OperationNotFound",
			fmt.Sprintf("The operation '%s' could not be found.", id))
		return nil, false
	}
	if !strings.EqualFold(op.Subscription, sub) {
		writeErr(w, http.StatusNotFound, "OperationNotFound",
			fmt.Sprintf("The operation '%s' could not be found.", id))
		return nil, false
	}
	return op, true
}
