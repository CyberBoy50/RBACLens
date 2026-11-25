# RBACLens — Step-by-Step Build Guide

The PDF's 7 build steps. Each step was written, then tested, before the
next one started. All tests live in `test_rbaclens.py` — run them with:

```bash
python run.py test
```

## Step 1 — Parse one manifest

**Write:** a script that loads a multi-document YAML file and prints every
object's kind and name.

`rbaclens.py` uses `yaml.load_all(..., Loader=StrictLoader)` — `safe_load`
would only read the first document, and the strict loader rejects duplicate
keys (PyYAML silently keeps the last one). Empty documents are skipped, and
`kind: List` wrappers are flattened into their items.

**Test:** run it on `test_manifests/bad/rbac-bad.yaml` — all 10 objects
print (3 ClusterRoles, 2 ClusterRoleBindings, 2 Roles, 3 RoleBindings).

## Step 2 — RBAC inventory

**Write:** collect Roles, ClusterRoles and bindings into an inventory with
subjects listed. `Inventory` indexes roles by (namespace, name) and
cluster-roles by name, and keeps every binding, ServiceAccount, workload
and NetworkPolicy.

**Test:** print the inventory for the bad test folder and check it by hand
against the files — 2 Roles, 3 ClusterRoles, 3 RoleBindings, 2
ClusterRoleBindings, 1 ServiceAccount, 5 workloads, 0 NetworkPolicies.
(`--inventory` prints it: `python rbaclens.py --inventory test_manifests/bad`.)

## Step 3 — Cluster-admin detection

**Write:** flag any binding that grants the cluster-admin role, naming the
subject. The check reads `roleRef.kind` + `roleRef.name` and the binding's
`subjects` — a RoleBinding to cluster-admin is flagged too (namespace
scope, same role).

**Test:** plant one cluster-admin binding and one least-privilege binding —
only the first is flagged. Bad folder: `superadmin` (ServiceAccount) and
`dev-admin` (user alice) are flagged; clean folder's `app-reader`
(`get`/`list` on `pods`) is not.

## Step 4 — Wildcard detection

**Write:** flag rules with wildcard verbs, resources or API groups — three
separate rules (RBAC-002/003/004) so the report says *which* field is a
wildcard.

**Test:** plant one wildcard rule and one specific rule — only the wildcard
is flagged. `ClusterRole/god-mode` (`*` everywhere) fires all three;
clean `Role/pod-reader` fires none.

## Step 5 — Workload checks

**Write:** walk every workload's pod template (`spec.template.spec`;
CronJobs nest one level deeper) and check the security context and volume
settings — privileged, allowPrivilegeEscalation, hostNetwork/hostPID/
hostIPC, hostPath, runAsNonRoot (pod value merged with container value),
resource limits/requests, token auto-mount, capabilities, readOnlyRootFS —
plus image tag/digest per container.

**Test:** a test Deployment with three planted flaws — all three are
reported, and a clean Deployment passes. Bad `debug-app` reports
privileged, hostNetwork, hostPID, docker.sock hostPath, missing
runAsNonRoot, missing limits and more; clean `web` reports nothing.

## Step 6 — CLI arguments and report

**Write:** `argparse` for the manifest folder/file and output file
(`-o`, `--json`, `--min-severity`, `--fail-on`, `--check`,
`--skip-check`, `--inventory`, `--list-checks`, `-q`, `--no-color`,
`--version`), and save the full report — object, severity, evidence and
fix for every finding, plus score and grade.

**Test:** run the tool on two different test folders and check both
reports are complete — `report_bad.txt` (46 findings, score 0, grade F)
and `report_clean.txt` (0 findings, score 100, grade A), plus the JSON
report for the bad folder.

## Step 7 — Full run on a test folder

**Write:** run the complete tool on a folder of manifests with planted
misconfigurations.

**Test:** read the saved report from start to finish — every planted flaw
appears with the right severity. Step 7 of the test suite asserts all 24
rules fire on the bad folder (46 findings), the score is 0 with grade F,
and the clean folder scores 100 with zero findings.

## Step 8 — Live cluster mode (v1.1, PDF ke baad ka upgrade)

**Write:** the same 25 rules, but the objects come from a live cluster
instead of files — one read-only `kubectl get` (nothing is written to
the cluster), parsed by the same StrictLoader, scanned by the same
checks. Findings are tagged `live-cluster` instead of a file name.

**Run it:** `python run.py live` (all namespaces), `python run.py live
--namespace kube-system`, or menu option 8. Needs `kubectl` on PATH and
a working kubeconfig — a local `minikube` / `kind` cluster is enough.
`python run.py doctor` reports whether kubectl and a cluster are there.

**Test:** step 8 of the test suite runs the live path against a fake
`kubectl` that prints the bad test manifests as a `kind: List` dump —
same 16 objects, same 46 findings, score 0/100. A missing kubectl and a
failing kubectl both raise a loud error instead of scanning nothing.
