package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInvalidJSON(t *testing.T) {
	inputTest(t, DefaultAuthorizer,
		[]byte(`{bad json}`))
}

func TestInvalidResourceKind(t *testing.T) {
	inputTest(t, DefaultAuthorizer,
		[]byte(
			`{
			"kind":"NotASubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{
				"resourceAttributes":{
					"namespace":"kube-system",
					"verb":"get",
					"version":"v1",
					"resource":"secrets",
					"name":"important-creds"
				},
				"user":"kubernetes-admin",
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestInvalidAPIVersion(t *testing.T) {
	inputTest(t, DefaultAuthorizer,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"v0",
			"spec":{
				"resourceAttributes":{
					"namespace":"kube-system",
					"verb":"get",
					"version":"v1",
					"resource":"secrets",
					"name":"important-creds"
				},
				"user":"kubernetes-admin",
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestEmptySpec(t *testing.T) {
	inputTest(t, DefaultAuthorizer,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{},
			"status":{
				"allowed":false
			}
			}`))
}

func TestBadAttributesFields(t *testing.T) {
	inputTest(t, DefaultAuthorizer,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{
				"resourceAttributes":{
					"namespace":0,
					"verb":0,
					"version":0,
					"resource":0,
					"name":0
				},
				"user":"kubernetes-admin",
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestBadUser(t *testing.T) {
	inputTest(t, DefaultAuthorizer,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{
				"resourceAttributes":{
					"namespace":"kube-system",
					"verb":"get",
					"version":"v1",
					"resource":"secrets",
					"name":"important-creds"
				},
				"user":0,
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func inputTest(t *testing.T, authorizer func(w http.ResponseWriter, r *http.Request), jsonData []byte) {
	data := bytes.NewBuffer(jsonData)
	req := httptest.NewRequest(http.MethodPost, "/authorize", data)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	authorizer(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Error("Expected 400 error")
	}
}
