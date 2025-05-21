package main

import (
	"encoding/json"
	"flag"
	"fmt"
	authorizationv1 "k8s.io/api/authorization/v1"
	"net/http"
	"net/http/httputil"
	"os"
	"slices"
	"strings"
)

var readonlyVerbs = []string{"get", "list", "watch", "proxy"}

func createAuthorizer(protectedNamespaces []string, unprivilegedGroup string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		fmt.Printf("Request received from %s\n:", r.RemoteAddr)

		// Print dump for logging
		dump, dumperr := httputil.DumpRequest(r, true)
		if dumperr != nil {
			fmt.Println("Error dumping request:", dumperr)
			return
		}
		fmt.Println(string(dump))

		var sar authorizationv1.SubjectAccessReview
		err := json.NewDecoder(r.Body).Decode(&sar)
		if err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		defer r.Body.Close()

		isUnprivilegedUser := slices.Contains(sar.Spec.Groups, unprivilegedGroup)
		isProtectedNamespace := sar.Spec.ResourceAttributes != nil && slices.Contains(protectedNamespaces, sar.Spec.ResourceAttributes.Namespace) // TODO: test if you can bypass with empty or all namespaces
		isSecret := sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Resource == "secrets"                                       //TODO: test if you can bypass with * or singular nouns
		isReadonlyVerb := sar.Spec.ResourceAttributes != nil && slices.Contains(readonlyVerbs, sar.Spec.ResourceAttributes.Verb)

		status := new(authorizationv1.SubjectAccessReviewStatus)
		if isUnprivilegedUser && isProtectedNamespace && isSecret {
			status.Allowed = false
			status.Reason = "Cannot access secrets in protected namespace"
		} else if isUnprivilegedUser && isProtectedNamespace && !isReadonlyVerb {
			status.Allowed = false
			status.Reason = "Cannot write to protected namespace"
		} else {
			status.Allowed = true
			status.Reason = ""
		}
		//todo: add status.EvaluationError handling

		sar.Status = *status

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sar)
	}
}

func main() {
	var unprivelegedGroup = flag.String("unpriveleged-group", "oidc:/platform-users", "Name of group which should have their permissions restricted for protected namespaces")
	var protectedNamespacesCSL = flag.String("protected-namespaces", "kube-system,openstack-system", "Comma separated list of namespaces which unprivileged users will have limited permissions for")
	flag.Parse()

	protectedNamespaces := strings.Split(*protectedNamespacesCSL, ",")

	http.HandleFunc("/authorize", createAuthorizer(protectedNamespaces, *unprivelegedGroup))
	fmt.Printf("Server started\n")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
