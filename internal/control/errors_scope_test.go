package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

func TestErrorsAreScopedToTheirOwner(t *testing.T) {
	s := &Server{errors: newErrorLog()}
	s.errors.recordOwned("account-a", "resource", "alice's service failed", "connection refused", "check target")
	s.errors.recordOwned("account-b", "resource", "bob's service failed", "secret backend", "check target")
	s.errors.record("wireguard", "hub failed", "global detail", "check hub")
	alice := principal{UserID: "account-a", Role: store.RoleOwner}
	request := httptest.NewRequest(http.MethodGet, "/api/errors", nil)
	request = request.WithContext(context.WithValue(request.Context(), principalKey{}, alice))
	response := httptest.NewRecorder()
	s.handleErrors(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET returned %d", response.Code)
	}
	var body struct {
		Errors []ErrorEntry `json:"errors"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Errors) != 1 || body.Errors[0].Message != "alice's service failed" {
		t.Fatalf("regular account saw unrelated errors: %+v", body.Errors)
	}
	if strings.Contains(response.Body.String(), "ownerId") {
		t.Fatal("the response exposed internal account IDs")
	}
	adminErrors := s.errorsFor(principal{UserID: "account-a", Role: store.RoleAdmin})
	if len(adminErrors) != 2 || adminErrors[0].Message == "bob's service failed" || adminErrors[1].Message == "bob's service failed" {
		t.Fatalf("administrator saw another account's error: %+v", adminErrors)
	}
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/errors", nil)
	deleteRequest = deleteRequest.WithContext(context.WithValue(deleteRequest.Context(), principalKey{}, alice))
	denied := httptest.NewRecorder()
	s.handleErrors(denied, deleteRequest)
	if denied.Code != http.StatusForbidden || len(s.errors.recent()) != 3 {
		t.Fatal("regular account cleared the shared error log")
	}
}
