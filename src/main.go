package main

import (
	"fmt"
	"net/http"
    authorizationv1 "k8s.io/api/authorization/v1"
	"encoding/json"
	"os"
	"slices"
	"flag"
	"strings"
)

var readonlyVerbs = []string {"get", "list", "watch", "proxy"}

func createAuthorizer(protectedNamespaces []string, unprivilegedGroup string) func(w http.ResponseWriter, r *http.Request){
	return func(w http.ResponseWriter, r *http.Request){
		var sar authorizationv1.SubjectAccessReview
		err := json.NewDecoder(r.Body).Decode(&sar)
		if err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		isUnprivilegedUser := slices.Contains(sar.Spec.Groups, unprivilegedGroup)
		isProtectedNamespace := slices.Contains(protectedNamespaces, sar.Spec.ResourceAttributes.Namespace) // TODO: test if you can bypass with empty or all namespaces
		isSecret := sar.Spec.ResourceAttributes.Resource == "secrets" //TODO: test if you can bypass with * or singular nouns
		isReadonlyVerb := slices.Contains(readonlyVerbs, sar.Spec.ResourceAttributes.Verb)
		
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

	protectedNamespaces := strings.Split(*protectedNamespacesCSL,",")

	http.HandleFunc("/authorize", createAuthorizer(protectedNamespaces,*unprivelegedGroup))
	fmt.Printf("Server started\n")
	err := http.ListenAndServe(":8080", nil)
	if (err != nil) { 
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
