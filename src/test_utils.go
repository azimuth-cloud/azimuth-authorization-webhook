package main

import (
	"net/http"
)

var DefaultProtectedNamespaces = []string{"kube-system", "openstack-system"}
var DefaultAdditionalPrivilegedUsers = []string{}

var DefaultAuthorizer func(w http.ResponseWriter, r *http.Request) = CreateWebhookAuthorizer(DefaultProtectedNamespaces, DefaultAdditionalPrivilegedUsers, false, 0)
