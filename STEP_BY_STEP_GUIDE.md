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

**Test:** run it on `test_manifests/bad/rbac-bad.yaml` — all 11 objects
print (4 ClusterRoles, 2 ClusterRoleBindings, 2 Roles, 3 RoleBindings).

## Step 2 — RBAC inventory

**Write:** collect Roles, ClusterRoles and bindings into an inventory with
subjects listed. `Inventory` indexes roles by (namespace, name) and
cluster-roles by name, and keeps every binding, ServiceAccount, workload
and NetworkPolicy.

**Test:** print the inventory for the bad test folder and check it by hand
against the files — 2 Roles, 4 ClusterRoles, 3 RoleBindings, 2
ClusterRoleBindings, 4 ServiceAccounts, 6 workloads, 0 NetworkPolicies.
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
reports are complete — `report_bad.txt` (62 findings, score 0, grade F)
and `report_clean.txt` (0 findings, score 100, grade A), plus the JSON
report for the bad folder.

## Step 7 — Full run on a test folder

**Write:** run the complete tool on a folder of manifests with planted
misconfigurations.

**Test:** read the saved report from start to finish — every planted flaw
appears with the right severity. Step 7 of the test suite asserts all 32
rules fire on the bad folder (62 findings), the score is 0 with grade F,
and the clean folder scores 100 with zero findings.

## Step 8 — Live cluster mode (v1.1, PDF ke baad ka upgrade)

**Write:** the same 32 rules, but the objects come from a live cluster
instead of files — one read-only `kubectl get` (nothing is written to
the cluster), parsed by the same StrictLoader, scanned by the same
checks. Findings are tagged `live-cluster` instead of a file name.

**Run it:** `python run.py live` (all namespaces), `python run.py live
--namespace kube-system`, or menu option 8. Needs `kubectl` on PATH and
a working kubeconfig — a local `minikube` / `kind` cluster is enough.
`python run.py doctor` reports whether kubectl and a cluster are there.

**Test:** step 8 of the test suite runs the live path against a fake
`kubectl` that prints the bad test manifests as a `kind: List` dump —
same 21 objects, same 62 findings, score 0/100. A missing kubectl and a
failing kubectl both raise a loud error instead of scanning nothing.

## Step 9 — Pod Security Standards (v1.2, PDF ke baad ka upgrade)

**What:** Kubernetes ships an official baseline for how locked-down a
pod must be — the Pod Security Standards, levels privileged / baseline /
restricted. The restricted profile is the strictest, and most of it is
already covered by the workload rules (privileged WL-001,
allowPrivilegeEscalation WL-002, host namespaces WL-003/004/005, hostPath
WL-006, runAsNonRoot WL-007, readOnlyRootFilesystem WL-011). v1.2 adds
only the three genuinely new checks: PSS-001 (seccompProfile missing or
not RuntimeDefault/Localhost, Medium, one finding per workload), PSS-002
(capabilities.drop does not include ALL, High, one finding per
container), PSS-003 (a capability added other than NET_BIND_SERVICE,
High, one finding per container — never double-counting what WL-010
already flags).

**How:** the checks live in `check_workloads`, next to the rules they
extend — PSS-001 in the per-workload block (pod `securityContext`), PSS-002
and PSS-003 in the per-container loop, reusing the `capabilities.add`
list WL-010 already computed. The clean fixture passes all three
(seccompProfile RuntimeDefault, drop ALL, no adds); the bad fixture has
no seccompProfile anywhere, no drop ALL anywhere, and one CHOWN add on
the debug-app container, so it fails them 5 + 5 + 1 times.

**Test:** Step 9 — synthetic workloads built in-memory: a bare pod fires
PSS-001 + PSS-002, a fully restricted pod fires nothing, `Unconfined`
seccomp fails PSS-001 while `Localhost` passes it, SYS_ADMIN fires WL-010
only (no PSS-003 double-count), CHOWN fires PSS-003, and
NET_BIND_SERVICE alone does not. The bad folder is now 62 findings
(8 critical, 23 high, 20 medium, 11 low); the clean folder still scores
100 with zero findings; the fake-kubectl live test finds the same 62.

## Step 10 — Zero limits (v1.4, PDF ke baad ka upgrade)

**What:** every remaining gap from the v1.3 report, closed:

- **Image CVE lookup (CVE-001).** `--cve` looks each distinct image up
  in the NVD API 2.0 (CPE match on the image name + exact x.y.z tag).
  OSV was tried first and ruled out — its API works but it does not
  index container images (ecosystem "Docker" is rejected, `pkg:docker`
  purls return nothing). Images with no CPE mapping, or with a tag that
  is not an exact version (`:latest`, `redis:7`, `alpine:3.19`), are
  reported as *skipped with a reason*, never as clean. If NVD is
  unreachable or rate-limited (5 requests/30 s without a key — the tool
  waits 6.5 s between requests, 0.7 s with `RBACLENS_NVD_API_KEY`), the
  check is marked *offline* in the report and JSON, findings are not
  invented, and the scan never crashes. CVE-001 is High, or Critical
  when the highest CVSS is ≥ 9.0. Real result on the bad folder:
  `busybox:1.37.0` has 2 CVEs (CVE-2025-46394, CVE-2025-60876),
  `nginx:1.27.4` has none.
- **Cloud IAM (IAM-001/002/003).** Manifest-level checks on
  ServiceAccounts (and pod templates): workload-identity annotations —
  EKS IRSA (`eks.amazonaws.com/role-arn`), GKE Workload Identity
  (`iam.gke.io/gcp-service-account`), Azure Workload Identity
  (`azure.workload.identity/client-id`) — fire IAM-001 (Medium: the pod
  inherits the cloud role); an over-broad cloud role (AdministratorAccess,
  a wildcard ARN, Owner/Editor/Contributor/admin) fires IAM-002
  (Critical); the retired Azure pod-identity annotation
  (`aadpodidentity.k8s.io/identity`) fires IAM-003 (Medium). GKE emails
  and Azure client IDs carry no role info, so they are never judged
  over-broad — IAM-001 only. New fixture `test_manifests/bad/cloud-bad.yaml`
  plants one of each; the bad folder gains 5 IAM findings (62 total).
- **RBAC-010 aggregation expansion.** The aggregated role's
  `matchLabels` selectors are now expanded against the ClusterRoles in
  the scan: the evidence names the matched roles (the bad fixture's
  `aggregated-view` names `view-extra`, added for this), and if a matched
  role brings wildcard or dangerous verbs the finding escalates from Low
  to High. `matchExpressions` selectors are reported as not expanded.
- **Enforcement, not just audit.** `--admission-out FILE` writes a
  Kyverno ClusterPolicy (`validationFailureAction: Enforce`) blocking the
  flagged patterns; `--gatekeeper-out FILE` writes an OPA Gatekeeper
  bundle (ConstraintTemplate + Constraints, Rego) for the same patterns;
  `--fix-out DIR` writes corrected copies of the manifests (privileged /
  host namespaces / allowPrivilegeEscalation off, runAsNonRoot,
  readOnlyRootFilesystem, drop ALL, seccomp RuntimeDefault, token mount
  off, default resource requests/limits) plus a `FIXES.md` listing what
  needs a human (hostPath, cluster-admin, wildcards, image tags,
  NetworkPolicy, cloud IAM, CVEs). Menu option 9 does all three at once.
  A clean scan generates the full baseline policy instead of an empty one.
- **Empty-folder guard.** A scan that finds no manifests now exits 2
  with a loud error and writes no report — v1.3 scored an empty folder
  100/A. A folder with objects but nothing auditable (no roles, bindings
  or workloads) gets a WARNING line in the report.
- **Live mode completeness.** `replicasets` added to the kubectl fetch
  list (ReplicaSet is a workload kind the tool checks); all v1.4 checks
  run live too, since live mode uses the same `run_all_checks`.

**Test:** Step 10 — IAM on the fixtures (3/1/1) and synthetic SAs
(scoped vs wildcard ARN, Azure WI, pod-template annotation); CVE with a
stub fetcher (critical at CVSS 9.8, high at 5.0, clean, NVD down, unmapped
image, imprecise tag, version parsing) plus a best-effort live NVD check
and a CLI `--cve` run; RBAC-010 expansion (benign aggregate stays Low,
wildcard aggregate escalates to High, no match says so); Kyverno and
Gatekeeper output parsed as YAML with the expected rules; `--fix-out`
re-scanned (mechanical flaws gone, hostPath still flagged, originals
untouched); empty folder exits 2 with no report. 125 checks total,
all pass.
