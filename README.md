# Azimuth Authorization Webhook

A Kubernetes authorization webhook to protect sensitive namespaces when users require
read-write access to all other cluster resources (e.g when they wish to install arbitrary CRDS).

Policy:
- Users cannot read secrets in protected namespaces by default
- Users cannot write any other resource in protected namespaces by default
- Internal K8s `system:` users may read/write to protected namespaces, excluding service accounts and `system:anonymous`
- Service accounts in protected namespaces may read/write to all protected namespaces
- Users specified as privileged may read/write to protected namespaces

## Flags
| Flag | Arguments |
| --- | --- |
| `--allow-opinion-mode` | Specifies if the webhook should give its opinion on requests which it doesn't deny. If true, will set 'allowed' to `true` in SubjectAccessReview response. Default: `false` |
| `--additional-privileged-users` | Comma separate listed of users to be given read/write access to protected namespaces. Default: `""` |
| `--log-level` | Verbosity of logs <br>`0`: Internal errors only. <br>`1`: Logs high level requests info. <br>`2`: Logs HTTP dumps of requests. <br>Default: `1` |
| `--protected-namespaces` | Comma separated list of protected namespaces. Default: `kube-system,openstack-system` |
