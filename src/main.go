package main

import (
	"encoding/json"
	"flag"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"
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

	requiredUsers := []string{"system:kube-controller-manager", "system:kube-scheduler", "kubernetes-admin", "kube-apiserver-kubelet-client"}
	serviceAccountRegex, _ := regexp.Compile("system:serviceaccount:.+")
	nodeAccountRegex, _ := regexp.Compile("system:node:.+")
	bootstrapAccountRegex, _ := regexp.Compile("system:bootstrap:.+")

	if slices.Contains(requiredUsers, user) {
		return true
	} else if serviceAccountRegex.MatchString(user) {
		// Allows service accounts if they originate from protected namespaces
		serviceAccountNamespace := strings.Split(user, ":")[2]
		return slices.Contains(protectedNamespaces, serviceAccountNamespace)
	} else if nodeAccountRegex.MatchString(user) || bootstrapAccountRegex.MatchString(user) {
		// All node and bootstrap accounts allowed
		return true
	}

	return false
}

// Returns true if request passes webhook's resource access checks. If false, string with reason for rejection will also be returned, otherwise nil string
func isRequestAuthorized(sar SubjectAccessReviewAPI, protectedNamespaces []string, additionalPrivilegedUsers []string) (bool, string) {
	isPrivilegedUser := slices.Contains(additionalPrivilegedUsers, sar.Spec.User)
	isPrivilegedSystemUser := sar.Spec.ResourceAttributes != nil && isPrivilegedSystemUser(sar.Spec.User, protectedNamespaces)
	isProtectedNamespace := sar.Spec.ResourceAttributes != nil && slices.Contains(protectedNamespaces, sar.Spec.ResourceAttributes.Namespace)
	isSecret := sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Resource == "secrets"
	isReadonlyVerb := sar.Spec.ResourceAttributes != nil && slices.Contains(readonlyVerbs, sar.Spec.ResourceAttributes.Verb)
	isAllNamespaceRequest := sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Namespace == ""
	isAllResourceRequest := sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Resource == "*"

	var denyReason string
	authorized := false
	if isPrivilegedUser {
		authorized = true
	} else if isProtectedNamespace && !isPrivilegedSystemUser && isAllResourceRequest {
		authorized = false
		denyReason = "Cannot make * resource requests in protected namespace"
	} else if (isAllNamespaceRequest || isProtectedNamespace) && !isPrivilegedSystemUser && isSecret {
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

func inputIsSanitised(sar SubjectAccessReviewAPI, httpWriter http.ResponseWriter) bool {
	inputError := false
	var errString string
	if sar.APIVersion != "authorization.k8s.io/v1" {
		errString = sar.APIVersion + " not supported. Currently support apiVersions: 'authorization.k8s.io/v1'"
		inputError = true
	}
	// Most other issues will have been caught as JSON decoding errors
	if sar.Kind != "SubjectAccessReview" || sar.Spec.User == "" {
		errString = "Malformed SubjectAccessReview"
		inputError = true
	}
	if inputError {
		log.Println(errString)
		http.Error(httpWriter, errString, http.StatusBadRequest)
		return false
	} else {
		return true
	}
}

// Returns HTTP request handler to handle SubjectAccessReview API requests
func CreateWebhookAuthorizer(protectedNamespaces []string, additionalPrivilegedUsers []string, opinionMode bool, logLevel int) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		dump, dumperr := httputil.DumpRequest(r, true)
		if dumperr != nil {
			log.Println("Error dumping request:", dumperr)
			return
		}

		var sar SubjectAccessReviewAPI
		err := json.NewDecoder(r.Body).Decode(&sar)
		if err != nil {
			jsonErrString := "JSON decoding error: " + err.Error()
			log.Println(jsonErrString)
			http.Error(w, jsonErrString, http.StatusBadRequest)
			return
		}

		defer r.Body.Close()

		if !inputIsSanitised(sar, w) {
			return
		}

		authorized, denyReason := isRequestAuthorized(sar, protectedNamespaces, additionalPrivilegedUsers)

		status := new(authorizationv1.SubjectAccessReviewStatus)
		status.Denied = !authorized
		status.Allowed = opinionMode && authorized

		if status.Denied {
			status.Reason = denyReason
		} else if !opinionMode {
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

		// TODO: find way to map cluster IPs from X-Forward headers to clusters
		if logLevel >= 1 && sar.Spec.NonResourceAttributes != nil {
			log.Println("[Cluster: " + r.Header.Get("X-Forwarded-For") + "] " + deniedLogOutput + " non-resource request from " + sar.Spec.User + ". Reason: " + status.Reason)
		}
		if logLevel >= 1 && sar.Spec.ResourceAttributes != nil {
			log.Println("[Cluster: " + r.Header.Get("X-Forwarded-For") + "] " + deniedLogOutput + " request from " + sar.Spec.User + " to " + sar.Spec.ResourceAttributes.Verb + " " + sar.Spec.ResourceAttributes.Resource + " in namespace " + sar.Spec.ResourceAttributes.Namespace + ". Reason: " + status.Reason)
		}
		if logLevel >= 2 {
			log.Printf("HTTP Dump: \n%s\n", string(dump))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(responseReview)
	}
}

func main() {
	var additionalPrivilegedUsersCSL = flag.String("additional-privileged-users", "", "Comma separated list of users that should be allowed to write to protected namespaces, excluding 'system:*' users")
	var protectedNamespacesCSL = flag.String("protected-namespaces", "kube-system,openstack-system", "Comma separated list of namespaces which unprivileged users will have limited permissions for")
	var logLevel = flag.Int("log-level", 1, "Verbosity of logs. Values: [0-2]")
	var opinionMode = flag.Bool("allow-opinion-mode", false, "Specifies if this webhook should give its opinion on requests which it doesn't deny. If true, will set 'allowed' to true in SubjectAccessReview.")
	flag.Parse()

	protectedNamespaces := strings.Split(*protectedNamespacesCSL, ",")
	additionalPrivilegedUsers := strings.Split(*additionalPrivilegedUsersCSL, ",")

	http.HandleFunc("/authorize", CreateWebhookAuthorizer(protectedNamespaces, additionalPrivilegedUsers, *opinionMode, *logLevel))
	log.Printf("Server started\n")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
