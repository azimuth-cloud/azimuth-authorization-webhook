package main

import (
	"encoding/json"
	"flag"
	"fmt"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"net/http/httputil"
	"os"
	"slices"
	"strings"
)

// Creating mirror of authorizationv1.SubjectAccessReview struct but with modified Spec
// to account for disparity in name of group key between Go ('Groups') and HTTP ('Group') API
// causing issues with JSON unmarshalling
type SubjectAccessReviewAPI struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec SubjectAccessReviewSpecAPI

	Status authorizationv1.SubjectAccessReviewStatus
}
type SubjectAccessReviewSpecAPI struct {
	ResourceAttributes *authorizationv1.ResourceAttributes
	NonResourceAttributes *authorizationv1.NonResourceAttributes
	User string
	Group []string
	Groups []string
	Extra map[string]authorizationv1.ExtraValue
	UID string
}

var readonlyVerbs = []string{"get", "list", "watch", "proxy"}

func createAuthorizer(protectedNamespaces []string, unprivilegedGroup string,opinionMode bool,logLevel int) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		if(logLevel >= 2) { fmt.Printf("Request received from %s\n:", r.RemoteAddr) }

		// Print dump for logging
		dump, dumperr := httputil.DumpRequest(r, true)
		if dumperr != nil {
			fmt.Println("Error dumping request:", dumperr)
			return
		}

		if(logLevel >= 2) { fmt.Println(string(dump)) }

		var sar SubjectAccessReviewAPI
		err := json.NewDecoder(r.Body).Decode(&sar)
		if err != nil {
			fmt.Println("[ERROR] ",err.Error())
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		defer r.Body.Close()

		isUnprivilegedUser := slices.Contains(sar.Spec.Groups, unprivilegedGroup) || slices.Contains(sar.Spec.Group, unprivilegedGroup)
		isProtectedNamespace := sar.Spec.ResourceAttributes != nil && slices.Contains(protectedNamespaces, sar.Spec.ResourceAttributes.Namespace) // TODO: test if you can bypass with empty or all namespaces
		isSecret := sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Resource == "secrets"                                       //TODO: test if you can bypass with * or singular nouns
		isReadonlyVerb := sar.Spec.ResourceAttributes != nil && slices.Contains(readonlyVerbs, sar.Spec.ResourceAttributes.Verb)

		status := new(authorizationv1.SubjectAccessReviewStatus)
		status.Allowed = false
		if isUnprivilegedUser && isProtectedNamespace && isSecret {
			status.Denied = true
			status.Reason = "Cannot access secrets in protected namespace"
		} else if isUnprivilegedUser && isProtectedNamespace && !isReadonlyVerb {
			status.Denied = true
			status.Reason = "Cannot write to protected namespace"
		} else {
			status.Allowed = opinionMode
			if(!opinionMode){ status.Reason = "Webhook doesn't give opinion, delegated to other authorizers" }
		}
		//todo: add status.EvaluationError handling

		sar.Status = *status

		if(status.Denied && logLevel == 1) { fmt.Println(string(dump)) }
		if(status.Denied && logLevel >= 1){ fmt.Printf("[DENIED] Reason: %s\n",status.Reason) }

		if(status.Denied){ w.WriteHeader(http.StatusUnauthorized) }
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sar)
	}
}

func main() {
	var unprivelegedGroup = flag.String("unpriveleged-group", "oidc:/platform-users", "Name of group which should have their permissions restricted for protected namespaces")
	var protectedNamespacesCSL = flag.String("protected-namespaces", "kube-system,openstack-system", "Comma separated list of namespaces which unprivileged users will have limited permissions for")
	var logLevel = flag.Int("log-level", 1, "Verbosity of logs. Values: [0-2]")
	var opinionMode = flag.Bool("allow-opinion-mode",false,"Specifies if this webhook should give its opinion on requests which it doesn't deny. If true, will set 'allowed' to true in SubjectAccessReview.")
	flag.Parse()

	protectedNamespaces := strings.Split(*protectedNamespacesCSL, ",")

	http.HandleFunc("/authorize", createAuthorizer(protectedNamespaces, *unprivelegedGroup, *opinionMode, *logLevel))
	fmt.Printf("Server started\n")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
