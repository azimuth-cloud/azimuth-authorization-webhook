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
// Should not be written as HTTP response
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


// Minimal SubjectAccessReview HTTP response
type SubjectAccessReviewHTTPResponse struct {
	ApiVersion string                                    `json:"apiVersion"`
	Kind       string                                    `json:"kind"`
	Status     authorizationv1.SubjectAccessReviewStatus `json:"status"`
}

var readonlyVerbs = []string{"get", "list", "watch", "proxy"}

// Returns true if user is a service account with correct privileges or a privileged internal K8s system user
func isPrivilegedSystemUser(user string, protectedNamespaces []string) bool {

	systemAccountRegex, _ := regexp.Compile("system:.+")
	serviceAccountRegex, _ := regexp.Compile("system:serviceaccount:.+")

	if user == "system:anonymous" {
		return false
	} else if serviceAccountRegex.MatchString(user) {
		// Allows service accounts if they originate from protected namespaces
		serviceAccountNamespace := strings.Split(user, ":")[2]
		return slices.Contains(protectedNamespaces, serviceAccountNamespace)
	} else if systemAccountRegex.MatchString(user) {
		// All other system accounts allowed
		return true
	}

	return false
}

// Returns true if request passes webhook's resource access checks. If false, string with reason for rejection will also be returned, otherwise nil string
func isRequestAuthorized(sar SubjectAccessReviewAPI,protectedNamespaces []string,additionalPrivilegedUsers []string) (bool, string) {
	isPrivilegedUser := slices.Contains(additionalPrivilegedUsers, sar.Spec.User)
	isPrivilegedSystemUser := sar.Spec.ResourceAttributes != nil && isPrivilegedSystemUser(sar.Spec.User, protectedNamespaces)
	isProtectedNamespace := sar.Spec.ResourceAttributes != nil && slices.Contains(protectedNamespaces, sar.Spec.ResourceAttributes.Namespace)
	isSecret := sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Resource == "secrets"
	isReadonlyVerb := sar.Spec.ResourceAttributes != nil && slices.Contains(readonlyVerbs, sar.Spec.ResourceAttributes.Verb)
	isAllNamespaceRequest := sar.Spec.ResourceAttributes != nil && (sar.Spec.ResourceAttributes.Namespace == "" || sar.Spec.ResourceAttributes.Namespace == "all")
	isAllResourceRequest := sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Resource == "*"

	var denyReason string
	authorized := false
	if isPrivilegedUser {
		authorized = true
	} else if !isPrivilegedSystemUser && isAllNamespaceRequest {
		authorized = false
		denyReason = "Cannot make all namespace requests"
	} else if isProtectedNamespace && !isPrivilegedSystemUser && isAllResourceRequest {
		authorized = false
		denyReason = "Cannot make all resource requests in protected namespace"
	} else if isProtectedNamespace && !isPrivilegedSystemUser && isSecret {
		authorized = false
		denyReason = "Cannot access secrets in protected namespace"
	} else if isProtectedNamespace && !isPrivilegedSystemUser && !isReadonlyVerb {
		authorized = false
		denyReason = "Cannot write to protected namespace"
	} else {
		authorized = true
	}
	return authorized, denyReason
}


// Returns HTTP request handler to handle SubjectAccessReview API requests
func CreateWebhookAuthorizer(protectedNamespaces []string, additionalPrivilegedUsers []string, opinionMode bool, logLevel int) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		dump, dumperr := httputil.DumpRequest(r, true)
		if dumperr != nil {
			fmt.Println("Error dumping request:", dumperr)
			return
		}

		var sar SubjectAccessReviewAPI
		err := json.NewDecoder(r.Body).Decode(&sar)
		if err != nil {
			fmt.Println("JSON decoding error: ", err.Error())
			http.Error(w, "JSON decoding error: "+err.Error(), http.StatusBadRequest)
			return
		}

		defer r.Body.Close()

		authorized, denyReason := isRequestAuthorized(sar,protectedNamespaces,additionalPrivilegedUsers)
		
		status := new(authorizationv1.SubjectAccessReviewStatus)
		status.Denied = !authorized
		
		if(status.Denied){
			status.Reason = denyReason
		}else if(!opinionMode){
			status.Allowed = false
			status.Reason = "Webhook doesn't give opinion, delegated to other authorizers"
		}else{
			status.Allowed = true
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

	http.HandleFunc("/authorize", CreateWebhookAuthorizer(protectedNamespaces, additionalPrivilegedUsers, *opinionMode, *logLevel))
	fmt.Printf("Server started\n")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
