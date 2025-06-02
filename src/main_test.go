package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

var defaultProtectedNamespaces = []string{"kube-system", "openstack-system"}
var defaultAdditionalPrivilegedUsers = []string{}

var defaultAuthorizer func(w http.ResponseWriter, r *http.Request) = CreateWebhookAuthorizer(defaultProtectedNamespaces, defaultAdditionalPrivilegedUsers, false, 0)

func TestSystemUserAllowed(t *testing.T) {
	accessTest(t, defaultAuthorizer, false,
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
				"user":"system:kube-controller-manager",
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestNamespaceServiceAccountAllowed(t *testing.T) {
	accessTest(t, defaultAuthorizer, false,
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
				"user":"system:serviceaccount:kube-system:good-service-account",
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestCrossProtectedNamespaceServiceAccountAccessAllowed(t *testing.T) {
	accessTest(t, defaultAuthorizer, false,
		[]byte(
			`{"kind":"SubjectAccessReview","apiVersion":"authorization.k8s.io/v1","metadata":{"creationTimestamp":null},"spec":{"resourceAttributes":{"namespace":"openstack-system","verb":"create","group":"apps","version":"v1","resource":"controllerrevisions"},"user":"system:serviceaccount:kube-system:daemon-set-controller","groups":["system:serviceaccounts","system:serviceaccounts:kube-system","system:authenticated"],"extra":{"authentication.kubernetes.io/credential-id":["JTI=3cf7d9de-5324-4df7-9447-47adb900f846"]},"uid":"cb35e0b5-1cfb-432f-acdf-5b5a0f924211"},"status":{"allowed":false}}`))
}

func TestWrongNamespaceServiceAccountDenied(t *testing.T) {
	accessTest(t, defaultAuthorizer, true,
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
				"user":"system:serviceaccount:othernamespace:bad-service-account",
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestSystemAnonymousDenied(t *testing.T) {
	accessTest(t, defaultAuthorizer, true,
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
				"user":"system:anonymous",
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestInvalidJSONDenied(t *testing.T) {
	data := bytes.NewBuffer([]byte("{ bad json }"))
	req := httptest.NewRequest(http.MethodPost, "/authorize", data)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	defaultAuthorizer(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Error("Expected 400 error for invalid JSON")
	}
}

func TestPrivilegedUserAllowed(t *testing.T) {
	authorizer := CreateWebhookAuthorizer(defaultProtectedNamespaces, []string{"kubernetes-admin"}, false, 0)
	accessTest(t, authorizer, false,
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
				"user":"kubernetes-admin",
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestUnprivilegedUserDenied(t *testing.T) {
	accessTest(t, defaultAuthorizer, true,
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
				"user":"kubernetes-not-admin",
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestReadUnprotectedSecretsAllowed(t *testing.T) {
	accessTest(t, defaultAuthorizer, false,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{
				"resourceAttributes":{
					"namespace":"safe-namespace",
					"verb":"get",
					"version":"v1",
					"resource":"secrets",
					"name":"important-creds"
				},
				"user":"kubernetes-not-admin",
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestReadProtectedNonSecretsAllowed(t *testing.T) {
	accessTest(t, defaultAuthorizer, false,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{
				"resourceAttributes":{
					"namespace":"kube-system",
					"verb":"get",
					"version":"v1",
					"resource":"pods",
					"name":"system-pod"
				},
				"user":"kubernetes-not-admin",
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestWriteProtectedNonSecretsDenied(t *testing.T) {
	accessTest(t, defaultAuthorizer, true,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{
				"resourceAttributes":{
					"namespace":"kube-system",
					"verb":"delete",
					"version":"v1",
					"resource":"pods",
					"name":"system-pod"
				},
				"user":"kubernetes-not-admin",
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestWriteUnprotectedResourcesAllowed(t *testing.T) {
	accessTest(t, defaultAuthorizer, false,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{
				"resourceAttributes":{
					"namespace":"safe-namespace",
					"verb":"delete",
					"version":"v1",
					"resource":"pods",
					"name":"generic-pod"
				},
				"user":"kubernetes-not-admin",
				"groups":["system:authenticated"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestEmptyNamespacesRequestsDenied(t *testing.T) {
	accessTest(t, defaultAuthorizer, true,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{
				"resourceAttributes":{
					"namespace":"",
					"verb":"get",
					"version":"v1",
					"resource":"secrets",
					"name":"important-creds"
				},
				"user":"not-admin",
				"groups":["group1"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestAllNamespacesRequestsDenied(t *testing.T) {
	accessTest(t, defaultAuthorizer, true,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{
				"resourceAttributes":{
					"namespace":"all",
					"verb":"get",
					"version":"v1",
					"resource":"secrets",
					"name":"important-creds"
				},
				"user":"not-admin",
				"groups":["group1"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestProtectedReadAllRequestsDenied(t *testing.T) {
	accessTest(t, defaultAuthorizer, true,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{
				"resourceAttributes":{
					"namespace":"kube-system",
					"verb":"get",
					"version":"v1",
					"resource":"*",
					"name":"important-creds"
				},
				"user":"not-admin",
				"groups":["group1"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestProtectedWriteAllRequestsDenied(t *testing.T) {
	accessTest(t, defaultAuthorizer, true,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{
				"resourceAttributes":{
					"namespace":"kube-system",
					"verb":"delete",
					"version":"v1",
					"resource":"*",
					"name":"important-creds"
				},
				"user":"not-admin",
				"groups":["group1"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestProtectedAllVerbRequestsDenied(t *testing.T) {
	accessTest(t, defaultAuthorizer, true,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{
				"resourceAttributes":{
					"namespace":"kube-system",
					"verb":"*",
					"version":"v1",
					"resource":"secrets",
					"name":"important-creds"
				},
				"user":"not-admin",
				"groups":["group1"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func TestProtectedAllVerbNonSecretRequestsDenied(t *testing.T) {
	accessTest(t, defaultAuthorizer, true,
		[]byte(
			`{
			"kind":"SubjectAccessReview",
			"apiVersion":"authorization.k8s.io/v1",
			"spec":{
				"resourceAttributes":{
					"namespace":"kube-system",
					"verb":"*",
					"version":"v1",
					"resource":"pods",
					"name":"important-creds"
				},
				"user":"not-admin",
				"groups":["group1"]
			},
			"status":{
				"allowed":false
			}
			}`))
}

func accessTest(t *testing.T, authorizer func(w http.ResponseWriter, r *http.Request), expectDenied bool, jsonData []byte) {
	data := bytes.NewBuffer(jsonData)
	req := httptest.NewRequest(http.MethodPost, "/authorize", data)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	authorizer(resp, req)
	var sarResponse SubjectAccessReviewHTTPResponse
	_ = json.NewDecoder(resp.Body).Decode(&sarResponse)
	if sarResponse.Status.Denied != expectDenied {
		var expectedResp string
		if expectDenied {
			expectedResp = "denied"
		} else {
			expectedResp = "allowed"
		}
		t.Errorf("Expected request to be %s\n", expectedResp)
	}
}
