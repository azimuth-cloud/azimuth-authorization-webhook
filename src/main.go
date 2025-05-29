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
	"regexp"
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
	ResourceAttributes    *authorizationv1.ResourceAttributes
	NonResourceAttributes *authorizationv1.NonResourceAttributes
	User                  string
	Group                 []string
	Groups                []string
	Extra                 map[string]authorizationv1.ExtraValue
	UID                   string
}

type SubjectAccessReviewHTTPResponse struct {
	ApiVersion string                                    `json:"apiVersion"`
	Kind       string                                    `json:"kind"`
	Status     authorizationv1.SubjectAccessReviewStatus `json:"status"`
}

var readonlyVerbs = []string{"get", "list", "watch", "proxy"}

func isPrivilegedForNamespace(user string, namespace string) bool {

	systemAccountRegex, _ := regexp.Compile("system:.+")
	namespaceServiceAccountRegex, err := regexp.Compile("system:serviceaccount:" + namespace + ":.+")
	if err != nil {
		fmt.Printf("Error compiling regex " + "\"system:serviceaccount:" + namespace + ":.+\": " + err.Error())
	}

	if user == "system:anonymous" {
		return false
	} else if namespaceServiceAccountRegex.MatchString(user) {
		return true
	} else if systemAccountRegex.MatchString(user) {
		return true
	}

	return false
}

func createAuthorizer(protectedNamespaces []string, additionalPrivilegedUsers []string, opinionMode bool, logLevel int) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		// Print dump for logging
		dump, dumperr := httputil.DumpRequest(r, true)
		if dumperr != nil {
			fmt.Println("Error dumping request:", dumperr)
			return
		}

		var sar SubjectAccessReviewAPI
		err := json.NewDecoder(r.Body).Decode(&sar)
		if err != nil {
			fmt.Println("[ERROR] ", err.Error())
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		defer r.Body.Close()

		isPrivilegedUser := slices.Contains(additionalPrivilegedUsers, sar.Spec.User)
		userPrivilegedForNamespace := sar.Spec.ResourceAttributes != nil && isPrivilegedForNamespace(sar.Spec.User, sar.Spec.ResourceAttributes.Namespace)
		isProtectedNamespace := sar.Spec.ResourceAttributes != nil && slices.Contains(protectedNamespaces, sar.Spec.ResourceAttributes.Namespace) // TODO: test if you can bypass with empty or all namespaces
		isSecret := sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Resource == "secrets"                                       //TODO: test if you can bypass with * or singular nouns
		isReadonlyVerb := sar.Spec.ResourceAttributes != nil && slices.Contains(readonlyVerbs, sar.Spec.ResourceAttributes.Verb)

		status := new(authorizationv1.SubjectAccessReviewStatus)
		status.Allowed = false
		if isPrivilegedUser {
			status.Denied = false
			status.Allowed = opinionMode
		} else if !userPrivilegedForNamespace && isProtectedNamespace && isSecret {
			status.Denied = true
			status.Reason = "Cannot access secrets in protected namespace"
		} else if !userPrivilegedForNamespace && isProtectedNamespace && !isReadonlyVerb {
			status.Denied = true
			status.Reason = "Cannot write to protected namespace"
		} else {
			status.Denied = false
			status.Allowed = opinionMode
		}
		//todo: add status.EvaluationError handling

		if !opinionMode && !status.Denied {
			status.Reason = "Webhook doesn't give opinion, delegated to other authorizers"
		}

		responseReview := new(SubjectAccessReviewHTTPResponse)
		responseReview.ApiVersion = "authorization.k8s.io/v1"
		responseReview.Kind = "SubjectAccessReview"
		responseReview.Status = *status

		var deniedLogOutput string
		if status.Denied {
			deniedLogOutput = "Denied"
		} else {
			deniedLogOutput = "Allowed"
		}
		if logLevel >= 1 && sar.Spec.NonResourceAttributes != nil {
			fmt.Printf("%s non-resource request from \"%s\". Reason: %s\n", deniedLogOutput, sar.Spec.User, status.Reason)
		}
		if logLevel >= 1 && sar.Spec.ResourceAttributes != nil {
			fmt.Printf("%s request from \"%s\" to \"%s\" \"%s\" in namespace \"%s\". Reason: %s \n",
				deniedLogOutput, sar.Spec.User, sar.Spec.ResourceAttributes.Verb, sar.Spec.ResourceAttributes.Resource, sar.Spec.ResourceAttributes.Namespace, status.Reason)
		}
		if logLevel >= 2 {
			fmt.Println("HTTP Dump:")
			fmt.Println(string(dump))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(responseReview)
	}
}

func main() {
	var additionalPrivilegedUsersCSL = flag.String("additional-privileged-users", "kubernetes-admin", "Comma separated list of users that should be allowed to write to protected namespaces, excluding 'system:*' users")
	var protectedNamespacesCSL = flag.String("protected-namespaces", "kube-system,openstack-system", "Comma separated list of namespaces which unprivileged users will have limited permissions for")
	var logLevel = flag.Int("log-level", 1, "Verbosity of logs. Values: [0-2]")
	var opinionMode = flag.Bool("allow-opinion-mode", false, "Specifies if this webhook should give its opinion on requests which it doesn't deny. If true, will set 'allowed' to true in SubjectAccessReview.")
	flag.Parse()

	protectedNamespaces := strings.Split(*protectedNamespacesCSL, ",")
	additionalPrivilegedUsers := strings.Split(*additionalPrivilegedUsersCSL, ",")

	http.HandleFunc("/authorize", createAuthorizer(protectedNamespaces, additionalPrivilegedUsers, *opinionMode, *logLevel))
	fmt.Printf("Server started\n")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
