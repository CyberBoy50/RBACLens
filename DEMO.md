# RBACLens — Demo and Write-up

Run on 25 November 2026, against the test manifests in `test_manifests/`
(planted flaws only — no real cluster, no real repository).

**v1.1 note:** the same scan now also runs live — `python run.py live`
audits your own cluster through one read-only `kubectl get`, with the
exact same 25 rules. Tested with a fake `kubectl` (step 8): same 16
objects, same 46 findings, score 0/100.

## 1. The bad folder — everything planted is found

```bash
$ python run.py scan test_manifests/bad
RBACLens — scan complete
Objects: 16  (Roles 2, ClusterRoles 3, Bindings 5, Workloads 5)
Score: 0/100 (grade F)
Findings: 46  (critical 7, high 17, medium 11, low 11)
[+] Report saved: report_bad.txt
[+] JSON report saved: report_bad.json
# exit code 2 — critical findings
```

Top of the report (`report_bad.txt`):

```
Score: 0/100  (grade F)
Findings: 46 total — 7 critical, 17 high, 11 medium, 11 low

[CRITICAL] RBAC-001 — Binding grants the cluster-admin role
Object:    ClusterRoleBinding/superadmin (-)
File:      test_manifests/bad/rbac-bad.yaml
Evidence:  roleRef: ClusterRole/cluster-admin granted to ServiceAccount/superadmin (kube-system)
Fix:       Replace cluster-admin with a scoped Role that lists only the verbs and resources the subject needs.

[CRITICAL] RBAC-002 — Wildcard verbs in a role rule
Object:    ClusterRole/god-mode (-)
Evidence:  rule #1 of ClusterRole/god-mode (-): verbs=['*'] resources=['*'] apiGroups=['*']
Fix:       List the exact verbs the role needs (get, list, watch, ...) instead of '*'.

[CRITICAL] WL-001 — Privileged container
Object:    Deployment/debug-app (default)
Evidence:  container 'app' of Deployment/debug-app (default): securityContext.privileged: true
Fix:       Remove privileged: true. A privileged container is root on the host.
```

## 2. The clean folder — hardened manifests pass

```bash
$ python run.py scan test_manifests/clean
RBACLens — scan complete
Objects: 5  (Roles 1, ClusterRoles 0, Bindings 1, Workloads 1)
Score: 100/100 (grade A)
Findings: 0  (critical 0, high 0, medium 0, low 0)
[+] Report saved: report_clean.txt
# exit code 0
```

## 3. One finding, explained

**Finding:** the `ClusterRoleBinding/superadmin` grants the `cluster-admin`
role to `ServiceAccount/superadmin` in `kube-system`.

**Why it is real, not a coincidence:** the tool does not guess — it reads
the binding's `roleRef` (`kind: ClusterRole`, `name: cluster-admin`) and
lists the subject from the binding's own `subjects` field. `cluster-admin`
is Kubernetes' built-in super-user role: whoever holds it can do anything
in the cluster. The same scan also flags the second binding
(`RoleBinding/dev-admin` in namespace `dev`, user `alice@example.com`) —
same role, smaller scope, same Critical severity — and it does *not* flag
the least-privilege binding (`RoleBinding/app-reader` → `Role/pod-reader`,
only `get`/`list` on `pods`), which proves the check is the role, not the
binding shape.

**Why it matters:** a ServiceAccount token is a credential. If the
`superadmin` ServiceAccount runs in a pod and that pod is compromised
(for example through the privileged `debug-app` Deployment in the same
test folder — privileged container, hostNetwork, docker.sock mounted),
the attacker inherits cluster-admin: read every Secret, create pods
anywhere, change RBAC itself. One bad binding turns a pod escape into a
full cluster takeover.

**The fix:** replace `cluster-admin` with a scoped Role. If the service
only reads pods in one namespace, a Role with `get`/`list` on `pods` in
that namespace is enough — exactly what the clean manifests do.

## 4. Defensive lesson — least privilege in RBAC

**The rule:** give every subject only the permissions it needs, nothing
more. A binding to `cluster-admin` hands over the whole cluster.

**Why it matters:** RBAC is the cluster's access control. The moment a
subject holds more than it needs, every other flaw — a vulnerable app, a
leaked token, a privileged pod — becomes a cluster-wide breach instead of
a contained one.

**How to follow it:** (1) start from no permissions and add only what the
workload demonstrably calls; (2) use Roles (namespaced) instead of
ClusterRoles wherever the work is namespaced; (3) never bind the `default`
ServiceAccount — create a dedicated one per workload; (4) audit bindings
regularly — that is what this tool is for.
