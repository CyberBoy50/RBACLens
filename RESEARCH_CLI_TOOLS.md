# Kubernetes Audit Tools — Research Report for RBACScope

**Research date:** 25 Nov 2026. **Method:** each tool's actual GitHub README was read (plus official docs/check lists where the README was thin).

## ⚠️ First: the name "RBACScope" is already taken

A tool named **RBAC-Scope** exists: https://github.com/Alevsk/rbac-scope — created May 2025, Go, MIT, 8 stars, 134 commits, 3 releases. Self-description: *"A curated database of RBAC policies used by popular Kubernetes Operators, with security annotations highlighting their permissions, potential risks, and abuse scenarios."* It has a CLI (`./bin/rbac-scope`), a REST API server (`rbac-scope serve`), extractors that analyse manifests, and a Docker image. It is a different kind of tool (a curated database of *operators'* RBAC policies, not a general manifest auditor), but the name, the Kubernetes RBAC domain, and even the binary name collide directly. **Recommendation: do not ship under the name RBACScope / rbac-scope** — it will collide in GitHub search, package registries, and user confusion. Pick a distinct name and re-check the final candidate on GitHub/PyPI before committing. (Incidental uses of the string also exist — a `RBACScope` type in the Weaviate Go client, a Terraform variable in an AKS module, an enum in Istio's ztunnel — but the Alevsk repo is the real collision.)

## 1. kubeaudit — Shopify

**Source:** https://github.com/Shopify/kubeaudit · **Language:** Go · **Install:** `brew install kubeaudit`, binaries from GitHub Releases, `go get`, or as a kubectl plugin (`kubectl-audit`). Docker images discontinued.

**Status:** README carries a deprecation notice — planned deprecation by Oct 2024, Shopify seeking new maintainers, recommends transition to kube-bench. Effectively unmaintained — a strong argument for building a replacement.

**What it checks:** 15 named auditors, each its own subcommand: `nonroot` (runAsNonRoot), `privileged`, `privesc` (allowPrivilegeEscalation), `capabilities`, `rootfs`, `hostns` (hostNetwork/hostPID/hostIPC), `mounts` (sensitive hostPath), `image` (tag-based only), `limits`, `netpols` (namespaces without default-deny NetworkPolicy), `asat` (automountServiceAccountToken with default SA), `apparmor`, `seccomp`, `deprecatedapis`. **No RBAC coverage at all** — no cluster-admin or wildcard checks. No image-digest check.

**Interface:** CLI args only, no menu. Three modes: manifest (`-f`), local (kubeconfig), cluster (in-cluster). Subcommands per auditor or `all`; plus `autofix` (rewrites manifests). Flags: `-f/--manifest`, `--kubeconfig`, `-c/--context`, `-n/--namespace`, `-m/--minseverity` (error/warning/info), `--format` (pretty/logrus/json/sarif), `--no-color`, `-e/--exitcode` (default 2 on error findings). Config file with `enabledAuditors:` + per-auditor settings.

```bash
kubeaudit all -f "./deploy/deployment.yaml"
kubeaudit all --kubeconfig "/path/to/config" --format json --minseverity warning
kubeaudit autofix -f manifest.yml -o fixed/
```
Output (pretty): per-object results with `-- [error] AutomountServiceAccountTokenTrueAndDefaultSA` + message; clean run prints `All checks completed. 0 high-risk vulnerabilities found`. Severities: Error/Warning/Info.

**Copy:** per-check subcommands; `autofix`; override labels that downgrade a finding to Info with a recorded reason; YAML config file; three input modes; JSON + SARIF; configurable exit code. **Avoid:** deprecated; zero RBAC; verbose log-like output, no overall score/grade; config file only works with `all`/`autofix`.

## 2. KubeLinter — StackRox / Red Hat

**Source:** https://github.com/stackrox/kube-linter (docs: https://docs.kubelinter.io) · **Language:** Go · **Install:** `go install golang.stackrox.io/kube-linter/cmd/kube-linter@latest`, `brew install kube-linter`, nix, Docker (cosign-signed), binary, GitHub Action, pre-commit hook. Actively maintained.

**What it checks:** static linter for K8s YAML, Helm charts, Kustomize — **files only, never a live cluster**. ~63 built-in checks, 31 on by default. Default-on: `privileged-container`, `privilege-escalation-container`, `run-as-non-root`, `no-read-only-root-fs`, `host-network`, `host-pid`, `host-ipc`, `docker-sock`, `sensitive-host-mounts` (`/`, `/etc`, `/proc`, `/sys`), `latest-tag`, `unset-cpu-requirements`, `unset-memory-requirements`, `env-var-secret`. **RBAC checks exist but are OFF by default** (opt-in via config): `cluster-admin-role-binding`, `wildcard-in-rules`, `access-to-secrets`, `access-to-create-pods`, `default-service-account`. No missing-NetworkPolicy check, no automountServiceAccountToken check, no digest check.

**Interface:** CLI args only, no menu. Commands: `lint <path>`, `checks list`, `templates list`, `version`. Auto-detects Helm/Kustomize dirs. Config `.kube-linter.yaml` (enable/disable checks, custom checks via templates). Flags: `--format` (plain/json/sarif), `--output` (repeatable — multiple formats in one run), `--fail-on-invalid-resource`. No CLI severity filter (config only).

```bash
kube-linter lint pod.yaml
kube-linter lint --format json --output report.json --config .kube-linter.yaml deployments/
kube-linter checks list
```
Output (plain): one line per finding with check name + remediation, e.g. `pod.yaml: (object: /security-context-demo /v1, Kind=Pod) container "sec-ctx-demo" does not have a read-only root file system (check: no-read-only-root-fs, remediation: Set readOnlyRootFilesystem to true ...)` then `Error: found 3 lint errors`.

**Copy:** file-only (ideal for CI); Helm/Kustomize auto-detection; remediation with every finding; `checks list` self-documentation; multiple simultaneous output formats; custom checks; GitHub Action + pre-commit. **Avoid:** the most important RBAC checks are disabled by default; no severity flag; no score/grade — flat list; no NetworkPolicy/automountServiceAccountToken checks; no auto-fix.

## 3. Polaris — FairwindsOps

**Source:** https://github.com/FairwindsOps/polaris (docs: https://polaris.docs.fairwinds.com) · **Language:** Go · **Install:** `brew tap FairwindsOps/tap && brew install FairwindsOps/tap/polaris`, binary, Helm chart, container image, GitHub Action. Actively maintained (v10.x).

**What it checks:** 30+ built-in checks (Security/Efficiency/Reliability) + custom checks via JSON Schema. Three modes: dashboard (web UI over live cluster), admission controller (webhook), CLI (local YAML for CI). Relevant checks: `runAsRootAllowed`, `privilegedContainers`, `privilegeEscalationAllowed`, `dangerousCapabilities`, `hostIPCSet`/`hostPIDSet`, `hostNetworkSet`, `cpuLimitsMissing`/`memoryLimitsMissing`/requests, `tagNotSpecified` (missing or `:latest`), `automountServiceAccountToken`, `missingNetworkPolicy`, plus RBAC checks (v8.0+): `clusterrolebindingClusterAdmin`, `rolebindingClusterAdminClusterRole`, `rolebindingClusterAdminRole`, pod exec/attach checks. **No wildcard-specific check found; no image-digest check.** Also probes, hostPort, sensitive env vars.

**Interface:** CLI args only, no menu. Commands: `audit`, `fix` (auto-remediates YAML), `dashboard`, `version`. Flags: `--audit-path`, `--format` (json default/yaml/pretty/score), `--config`, `--checks` (run only named checks), `--severity` (e.g. `danger`), `--only-show-failed-tests`, `--set-exit-code-on-danger`, `--set-exit-code-below-score <1-100>`, `--output-file`, `--helm-chart`/`--helm-values`, `--color`. Only raw YAML is auditable — Helm must be pre-rendered with `helm template`.

```bash
polaris audit --audit-path ./deploy/ --format=pretty
polaris audit --audit-path ./deploy/ --set-exit-code-on-danger --set-exit-code-below-score 90
polaris fix --files-path ./deploy/ --checks=all
```
Output (pretty): `✗ runAsRootAllowed — Danger / Container should not be allowed to run as root`. Dashboard shows an overall **health score (0–100), a letter grade, and a "weather report"**; CLI `--format=score` outputs just the score. Severities: danger/warning/ignore, configurable per check, with exemptions.

**Copy:** the **score + letter grade** — the most user-friendly idea of any tool here; per-check severity config + exemptions; CI gate flags; `fix`; `--only-show-failed-tests`; broadest coverage incl. cluster-admin. **Avoid:** heaviest to run (dashboard/admission need a live cluster + Helm + webhook); README nearly empty (docs on separate site); image registry moved (old instructions break); no wildcard/digest checks; Helm needs pre-render.

## 4. kube-bench — Aqua Security

**Source:** https://github.com/aquasecurity/kube-bench · **Language:** Go · **Install:** binary tarball (Linux x86-64), Docker (`aquasec/kube-bench`, run with `--pid=host`, `/etc` + `/var` mounted read-only), Kubernetes Job manifests in repo, build from source. Needs root/sudo.

**What it checks:** a **node, not workloads** — runs the CIS Kubernetes Benchmark against the control plane/worker node it stands on: component start-up flags, config-file permissions/ownership, running processes. Checks are YAML data (`cfg/<benchmark>/`), auto-detects K8s version → CIS version. CIS §5 "Policies" (cluster-admin minimised, wildcard verbs/resources) exists but is largely **manual** — reported as `[WARN]`, it does not parse Role/ClusterRole YAML. Pod-spec fields (privileged, hostPath, hostNetwork, runAsNonRoot, limits, images, automountServiceAccountToken) are **not checked**; NetworkPolicy only as a manual CIS 5.3.x item. **Wrong model for workload-manifest auditing; right model for node/control-plane auditing.**

**Interface:** CLI only, no menu. Subcommands: `run`, `version`. Flags: `--version`/`--benchmark`, `run --targets master,node,etcd,controlplane,policies`, `-c/--check 1.1.1`, `-g/--group`, `--skip`, `--json`/`--junit`/`--outputfile`, `--scored`, `--exit-code 42`, `--noresults`/`--noremediations`/`--nototals`, `--config`, `--asff`, `--pgsql`. No input-path flag for manifests, no severity filter, no YAML output.

```bash
kube-bench run --targets master,node
kube-bench run --benchmark cis-1.12 --targets master --check 1.4.1
docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -t aquasec/kube-bench:latest --version 1.18
```
Output: `[PASS]`/`[FAIL]`/`[WARN]`/`[INFO]` per check ID with a `== Remediations ==` section naming the exact file/flag to change. JSON has totals (pass/fail/warn counts).

**Copy:** YAML-defined checks (benchmark updates without code changes); one check = one ID + text + remediation; scored vs manual distinction; `--check`/`--group`/`--skip` granularity; `--exit-code` for CI; JSON + JUnit; Job YAML pattern. **Avoid:** no workload/YAML scanning; no severity filter, no percentage score; `[WARN]` noise from manual checks; version mapping lags new K8s releases; Linux-only; needs privileged host access; cannot inspect managed control planes.

## 5. Checkov — Bridgecrew / Prisma Cloud

**Source:** https://github.com/bridgecrewio/checkov · **Language:** Python (3.10–3.13) · **Install:** `pip3 install checkov`, `brew install checkov`, Docker (`bridgecrew/checkov`), VS Code extension, GitHub Action. **The closest architectural cousin to the new Python CLI.**

**What it checks:** static IaC scanner, files only, never talks to a cluster. 1,000+ built-in policies across Terraform, CloudFormation, K8s YAML, Helm, Kustomize, Dockerfile, etc.; ~119 K8s rules. Each finding has a stable ID (`CKV_K8S_*`), a remediation-guide link, file + line numbers, and a code excerpt. K8s coverage: `CKV_K8S_20`/`28` privileged/allowPrivilegeEscalation, `CKV_K8S_35`/`43`/`40` runAsNonRoot/root/high UID, `CKV_K8S_11`/`12` CPU/memory limits (+ `10`/`13` requests), `CKV_K8S_15` image `:latest`, `CKV_K8S_19`/`17`/`18` hostNetwork/hostPID/hostIPC, hostPath flagged (no stable ID verified), `CKV_K8S_38` automountServiceAccountToken, `CKV2_K8S_6` missing NetworkPolicy (graph check — needs the NetworkPolicy file in the same directory scan). **RBAC cluster-admin/wildcard: no dedicated ID verified — weak/unverified, a known gap.** (Note: some check IDs have shifted across versions, e.g. `CKV_K8S_20`; verify with `checkov -l`.)

**Interface:** CLI only, no menu. Input file or directory, framework auto-detected or forced. Flags: `-d/--directory`, `-f/--file` (repeatable), `--framework kubernetes`, `-o/--output` (cli/json/junitxml/sarif/csv/cyclonedx/spdx/github_failed_only/gitlab_sast — repeatable), `--output-file-path`, `-c/--check` / `--skip-check` (by ID **and** by severity LOW/MEDIUM/HIGH/CRITICAL), `-l/--list`, `--quiet`, `--compact`, `-s/--soft-fail` / `--hard-fail-on`, `--skip-path`, `--external-checks-dir`, `--config-file` / `--create-config` / `--show-config`, `--skip-download`. Exit 1 on any failure by default (CI gate out of the box). Suppression inline: `checkov.io/skip1: CKV_K8S_20=<reason>` annotation.

```bash
checkov -d ./k8s/ --framework kubernetes
checkov -f bad-pod.yaml --framework kubernetes --compact --quiet
checkov -d . --check CKV_K8S_20,CKV_K8S_35
checkov -d . -o cli -o sarif --output-file-path console,results.sarif
```
Output: `Passed Checks: 1, Failed Checks: 1, Suppressed Checks: 0`, then per check `Check: CKV_K8S_20: "Containers should not run with allowPrivilegeEscalation" / FAILED for resource: Pod.default.my-pod / File: /your_input.yaml:1-10 / Guide: https://...`. No percentage score/grade — counts only.

**Copy:** file/directory input model; stable check IDs with guide links; `--check`/`--skip-check` by ID and severity; many output formats in one run; `--quiet`/`--compact`; inline suppression with a reason; `.checkov.yaml` config; exit-1-by-default with `--soft-fail` escape; graph (`CKV2_*`) cross-file checks; Python + pip = lowest-friction install. **Avoid:** very noisy by default (lists every passed check; 15–22 failures on one bad Pod); no score/grade; no auto-fix; RBAC weak; renumbered/duplicate IDs; unparseable files silently not analysed (check `parsing_errors` in JSON); severity gating effectively needs a Prisma API key; heavy dependency footprint.

## 6. Kubescape — ARMO (CNCF incubating)

**Source:** https://github.com/kubescape/kubescape · **Language:** Go · **Install:** one-line install script, `brew install kubescape`, `kubectl krew install kubescape`, binary, `yay`/`nix`/`choco`/`scoop`/Ubuntu PPA, Helm for the operator. No pip.

**What it checks:** the broadest of all tools here. CLI scans a **live cluster, YAML files, Helm charts, Kustomize dirs, Git repos, or container images**; in-cluster Operator adds continuous scanning, eBPF runtime monitoring, NetworkPolicy generation. Controls are Rego rules from `kubescape/regolibrary` (200+ controls), grouped into frameworks: NSA-CISA, MITRE ATT&CK, CIS, SOC2, ArmoBest, DevOpsBest. Checklist coverage: `C-0185` cluster-admin role only where required, `C-0035` Administrative Roles, `C-0015` list secrets, `C-0007` delete capabilities; wildcards covered at framework level (no single named wildcard control verified); `C-0057` privileged container; `C-0048`/`C-0045` hostPath; `C-0041` hostNetwork, `C-0038` host PID/IPC; `C-0013` non-root; `C-0016` allowPrivilegeEscalation; `C-0009`/`C-0004`/`C-0050` resource limits; `C-0075` image pull policy on latest tag; **no standalone image-digest control verified**; `C-0030` ingress/egress blocked (NetworkPolicy), `C-0034` automountServiceAccountToken. Also image CVE scanning (Grype/Syft), attack-path analysis, `fix`/`patch`.

**Interface:** CLI only, no menu (only interactive element: `fix --interactive`, a per-resource confirm prompt). Subcommands: `scan` (`scan framework <name>`, `scan control <ID>`, `scan image <img>`), `fix`, `patch`, `list`, `download`, `config`, `operator`, `vap`, `mcpserver`. Flags: positional target (cluster/files/git/image), `--format json|junit|sarif|html|pdf|csv` + `--output`, `--severity-threshold high`, `--compliance-threshold 80` (exit 1 below threshold), `--include-namespaces`/`--exclude-namespaces`, `--kubeconfig`, `-v/--verbose`, `--view resource|control`, `--hide`/`--encrypt`, `--use-artifacts-from` (offline). **By default it downloads frameworks/controls from regolibrary at scan time** (Sigstore-signed in v4) — offline use needs `kubescape download artifacts` first.

```bash
kubescape scan
kubescape scan framework nsa --exclude-namespaces kube-system,kube-public
kubescape scan /path/to/manifests/
kubescape scan control C-0005 -v
kubescape scan --severity-threshold high --format json --output results.json
kubescape fix results.json --dry-run
```
Output: grouped tables plus **compliance scores per framework** (e.g. `MITRE: 80.03%`, `NSA: 75.93%`) and a per-control table with severity, failed/all resources, `% RISK-SCORE`. Note the confusing inversion: risk score 0% = very secure, while compliance % higher = better. Verbose mode adds per-resource blocks with severity, doc link, and assisted remediation as `path=value` (e.g. `spec.template.spec.automountServiceAccountToken=false`).

**Copy:** the single most useful model for the new tool — same controls for live cluster **and** plain YAML/Helm/Git; framework grouping with per-framework compliance score; `--severity-threshold` + `--compliance-threshold` CI gating; `--format json|sarif|junit|html|pdf|csv`; `list frameworks`/`list controls` discoverability; verbose assisted remediation; `fix` with `--dry-run`/`--interactive`; offline artifacts; namespace include/exclude. **Avoid:** biggest/heaviest — a platform, not a focused scanner (operator, eBPF, MCP server, VAP, image patching); needs control-bundle download at scan time; opaque control IDs (`C-0057`) with overlapping CIS duplicates; risk-score vs compliance-% inversion confuses users; no dedicated digest control; host CIS controls skipped without the operator's host scanner; `fix` for a cluster scan only prints patched manifests (never applies them); repo/version moves (v1→v3/v4) broke old examples.

## 7. kube-score — zegl

**Source:** https://github.com/zegl/kube-score · **Language:** Go · **Install:** pre-built binaries (macOS/Linux/Windows), `brew install kube-score`, Docker (`zegl/kube-score`), kubectl plugin via Krew (`kubectl krew install score`). ~3,100 stars, MIT, actively maintained.

**What it checks:** static analysis of workload YAML, ~35 checks, **offline on files** (or pipe a `kubectl` dump in). `container-security-context-privileged`, `container-security-context-user-group-id` (requires UID **and** GID ≥ 10000 — stricter than `runAsNonRoot`, but a UID-number check, not the field), `container-resources` (CPU/memory requests + limits), `container-image-tag` (explicit non-`latest`), `container-image-pull-policy` (`Always`), `pod-networkpolicy` (every Pod must be targeted by a NetworkPolicy), readiness/liveness probes, PodDisruptionBudget, podAntiAffinity, deprecated apiVersions, Service type not NodePort. **No RBAC at all; no hostPath/hostNetwork/hostPID/hostIPC; no automountServiceAccountToken; no image-digest check.**

**Interface:** CLI args only, no menu. Subcommands: `score`, `list` (CSV of all checks), `version`. Input: file paths, globs, or `-` for stdin. Flags: `-o/--output-format` (human/json/ci/sarif), `--output-version`, `--exit-one-on-warning`, `--ignore-test` (repeatable), `--enable-optional-test`, `--ignore-container-cpu-limit`, `--ignore-container-memory-limit`, `--kubernetes-version`, `--threshold-ok` (1–10 score threshold), `-v`. Per-object suppression via `kube-score/ignore` annotation. No severity filter flag.

```bash
helm template my-app | kube-score score -
kube-score score my-app/*.yaml
kube-score score my-app/deployment.yaml --output-format ci
```
Output (human): per object a ✅ / 💥 / `?` grade marker, findings `[CRITICAL]`/`[WARNING]`/`[OK]` with a fix hint, e.g. `[CRITICAL] Container Image Tag · podinfo -> Image with latest tag / Using a fixed tag is recommended...`. `ci` format is one line per check; JSON v2 and SARIF for machines.

**Copy:** the best install story (binary + brew + Docker + krew); stdin/file/glob input composing with `helm template` and `kustomize build`; multiple output formats incl. SARIF; per-check IDs with `--ignore-test` and annotation suppression; exit-code CI contract; per-object graded summary with fix hint; `list` self-documentation. **Avoid:** no RBAC; no hostPath/host*/automountServiceAccountToken/digest; human output verbose on large manifests; no severity filter; NetworkPolicy check can false-positive when policies aren't correlated (wants all apps of a namespace as input together).

## 8. rbac-lookup — FairwindsOps

**Source:** https://github.com/FairwindsOps/rbac-lookup · **Language:** Go · **Install:** Homebrew, ASDF, Krew (`kubectl krew install rbac-lookup`), pre-built binaries. ~983 stars, Apache-2.0.

**What it checks:** a **reverse RBAC lookup**, not a scorer: give it a user/group/service account and it prints every Role/ClusterRole bound to that identity. Cluster-admin is only listed if present — **not flagged** (no severity, you must spot it yourself). Wildcards never inspected (it reads bindings, not Role contents). No workload checks at all. GKE mode also lists Google Cloud IAM roles (effective access = IAM ∪ RBAC). Partial/substring matching.

**Interface:** CLI args only, no menu. Subject is a positional argument; no subcommand. Flags: `-k/--kind` (user/group/serviceaccount), `-o/--output` (normal/wide), `--context`, `--kubeconfig`, `--gke`. No JSON output, no severity filter, no file input. **Requires a live cluster.**

```bash
rbac-lookup rob
rbac-lookup rob --output wide
rbac-lookup my-service-account --kind serviceaccount
```
Output (normal, then wide):
```
SUBJECT                   SCOPE             ROLE
rob@example.com           cluster-wide      ClusterRole/view
```
Wide adds subject kind and the exact source binding (`ClusterRoleBinding/rob-cluster-view`).

**Copy:** single-question UX — one argument, one table, instant answer; the `SCOPE` column (cluster-wide vs namespace); wide mode showing the *source binding* (provenance); substring matching; GKE IAM-union idea. **Avoid:** live cluster required; no risk judgement at all; no JSON; does not expand aggregated ClusterRoles; narrow scope — must be paired with another tool for a real audit.

## 9. Krane — Appvia

**Source:** https://github.com/appvia/krane · **Language:** Ruby (gem) · **Install:** Helm chart, Docker image, or `docker-compose` (which provisions its **FalkorDB graph-database dependency**). No standalone binary, no Homebrew, no pip. ~749 stars, Apache-2.0, Beta, latest v0.1.6.

**What it checks:** RBAC **static analysis + visualisation**. Indexes all RBAC objects into a graph DB and evaluates ~50 built-in YAML-defined risk rules (severity danger/warning/info, each with mitigation text). Wildcard coverage is the most thorough of any tool here: `risky-any-verb-*` rules (danger) for `verbs: ['*']` on secrets, pods, deployments, daemonsets, statefulsets, jobs, cronjobs, roles, clusterroles, bindings, users, groups; `risky-any-resource-*` for `apiGroups: ['*']` + `resources: ['*']`. Cluster-admin-equivalent via `subjects-with-open-cluster-wide-access` (danger). Also `unauthenticated-subject-access` (danger, `system:anonymous`/`system:unauthenticated`, with legitimate baselines excluded), `risky-get/list-secrets`, `risky-impersonate-privileged-groups` (`system:masters`), `subjects-with-rbac-management`, `subjects-with-non-existing-roles`. Rules deliberately skip K8s default roles and managed-control-plane roles (EKS/GKE/AKS/OpenShift) to kill unactionable noise; whitelisting by role/subject name. **No workload/pod checks at all.** PSP-coupled rules are obsolete on K8s ≥ 1.25.

**Interface:** CLI args only for `report`; plus a `dashboard` subcommand (web server, port 8000) — no interactive CLI menu. Commands: `krane report`, `krane dashboard`. Report flags: `-k <context>`, `-c <cluster-name>`, `-d <directory>` (local RBAC YAML/JSON — expects files named `roles`, `clusterroles`, `rolebindings`, `clusterrolebindings`), `--incluster`, `--ci` (non-zero exit + details on `danger`). No severity filter flag. Report output is machine-readable JSON (default) or YAML, grouped by rule with severity, affected subjects/roles, mitigation; Slack alerts for medium/high. Dashboard adds Overview, Findings, an RBAC tree ("Namespace kube-system admits Group system:bootstrappers…"), a graph view, and ad-hoc CypherQL queries.

```bash
krane report -k <context>
krane report -d /path/to/rbac-directory
krane report --ci -d /path/to/rbac-directory
krane dashboard
```

**Copy:** the rule model — declarative YAML rules (id, severity, mitigation, match rules), custom rules, macros; severity taxonomy with mitigation on every rule; the wildcard matrices; default/vendor-role noise filtering + whitelists; `--ci` fail-on-danger; machine-readable reports + Slack; the dashboard's "read the path back as a sentence" RBAC tree. **Avoid:** **FalkorDB dependency** — you cannot just run a binary (and FalkorDB is SSPL-licensed, not OSI open source); heaviest install of its group; Beta, ~55 open issues; no workload checks; dashboard has **no authentication** (README warns: do not expose directly); rigid directory file-naming convention; Ruby is an unusual choice for a K8s CLI.

## 10. kubectl-who-can — Aqua Security

**Source:** https://github.com/aquasecurity/kubectl-who-can · **Language:** Go · **Install:** `kubectl krew install who-can` (recommended), release tarball on `$PATH`, or `go install`. 928 stars, Apache-2.0.

**What it checks:** one reverse question — *"Who has RBAC permission to VERB [TYPE | TYPE/NAME | NONRESOURCEURL]?"* Walks RoleBindings/ClusterRoleBindings and reports subjects granted that permission. **Not a manifest scanner, not a general auditor.** No pod/manifest fields at all. Cluster-admin/wildcards only found indirectly (e.g. `kubectl who-can '*' '*'`, `kubectl who-can get secrets`, `kubectl who-can impersonate users`). Reports what RBAC *grants*, not what is exploitable; no escalation-chain evaluation.

**Interface:** CLI args only — no menu, no JSON/YAML output, no severity filter, no scoring. Flags: `-n/--namespace`, `-A/--all-namespaces`, `--subresource`.

```bash
kubectl who-can get secret -n default
kubectl who-can delete pods --namespace foo
kubectl who-can '*' '*'
```
Output: two plain-text tables (RoleBindings, ClusterRoleBindings) with `ROLEBINDING | NAMESPACE | SUBJECT | TYPE | SA-NAMESPACE`, plus a "No subjects found…" line when empty.

**Copy:** the reverse-lookup UX — one verb+resource question, one immediate answer; the two-table subject listing is the clearest RBAC answer format of any tool reviewed; krew distribution. **Avoid:** live cluster **required** (and enough RBAC to list roles/bindings — a low-privilege credential cannot complete a full audit); no offline/file mode; no JSON for CI; no severity/scoring/filtering; no wildcard/cluster-admin finding as a first-class check (you must already know which dangerous verb/resource to ask about); no manifest checks; only 3 flags.

## 11. rbac-tool — Alcide (now Rapid7)

**Source:** https://github.com/alcideio/rbac-tool · **Language:** Go · **Install:** `curl .../download.sh | bash`, release binary, or `kubectl krew install rbac-tool`. 1,086 stars, Apache-2.0, latest v1.15.0.

**What it checks:** the broadest RBAC-only suite. Subcommands: `analysis`, `auditgen`, `viz`, `who-can`, `lookup`, `policy-rules`, `gen`, `show`, `whoami`, `version`. `analysis` evaluates every subject's *effective* permissions against a bundled rule set (15 rules, CEL expressions) with severity: Secret Readers (HIGH), Workload Creators & Editors (HIGH), Privilege Escalators via `impersonate` (CRITICAL) and `bind`/`escalate` on roles (CRITICAL), Storage & Data (HIGH), Networking writes (HIGH), Admission Controller modification (CRITICAL), CRDs (MEDIUM), Node Proxy (CRITICAL), Exec into Pod (HIGH), Ephemeral Containers (HIGH). Custom rule sets via `--config`; exclusions with expiry. `who-can` = reverse lookup; `lookup`/`policy-rules` = subject's roles/rules (JSON + JMESPath filterable); `auditgen` = generates least-privilege Roles from K8s audit logs; `gen` = generates explicit (wildcard-expanded) Roles with `--deny-resources`/`--allowed-verbs`; `viz` = RBAC graph as DOT/HTML. **No pod/manifest checks at all.**

**Interface:** CLI subcommands only — no menu. `analysis` output: `--output table|json|yaml` (default yaml). `lookup` is an ASCII table (`SUBJECT | SUBJECT TYPE | SCOPE | NAMESPACE | ROLE | BINDING`); `policy-rules` is a table or JSON.

```bash
rbac-tool analysis -o table
rbac-tool analysis --config myruleset.yaml
rbac-tool who-can get secrets
rbac-tool lookup -e '.*myname.*'
rbac-tool auditgen -f audit.log | rbac-tool viz -f -
rbac-tool gen --deny-resources=secrets.,services. --allowed-verbs=get,list
```

**Copy:** the `analysis` model — named rules with **severity (LOW/MEDIUM/HIGH/CRITICAL)**, customisable YAML rule set (CEL), exclusions, `table/json/yaml` output — the closest existing design to a proper audit report; `gen`'s wildcard-expansion idea (turn `*` into an explicit list) as a remediation aid; `viz` graph; `auditgen` closing the loop from observed behaviour to least-privilege policy. **Avoid:** live cluster required for almost everything (no offline scan of exported RBAC YAML); no pod-security/manifest checks; no severity filter flag on `analysis`; no interactive mode; `viz` PNG needs Graphviz separately; generated policies need review (audit logs only cover observed calls).

## 12. KubeSec — Control Plane

**Source:** https://github.com/controlplaneio/kubesec · **Language:** Go · **Install:** release tarball, `go install github.com/controlplaneio/kubesec/v2@latest`, Docker (`kubesec/kubesec:v2`), kubectl plugin, admission controller, hosted service at `v2.kubesec.io/scan` (README warns: do not submit sensitive YAML to the public service). 1,489 stars, Apache-2.0, v2.14.2.

**What it checks:** static risk analysis of manifests (Pod, Deployment, StatefulSet, DaemonSet) with a **numeric score per resource**. 26 rules, counted from `pkg/ruler/ruleset.go`: `Privileged` −30, `CapSysAdmin` −30, `HostNetwork`/`HostPID`/`HostIPC` −9 each, `DockerSock` −9 (hostPath `/var/run/docker.sock`), `ProcMount` −9 (hostPath `/proc`), `AllowPrivilegeEscalation` −7, `RunAsNonRoot` +1, `RunAsUser`/`RunAsGroup` +1, `ReadOnlyRootFilesystem` +1, `CapDropAny`/`CapDropAll` +1, `LimitsCPU`/`LimitsMemory`/`RequestsCPU`/`RequestsMemory` +1, `ServiceAccountName` +3, `AutomountServiceAccountToken` +1 (when `false`), seccomp/AppArmor rules. Checklist: privileged ✓, hostNetwork/PID/IPC ✓, runAsNonRoot ✓, limits ✓, automountServiceAccountToken ✓, **hostPath only partially** (only the two named dangerous paths; generic `hostPath: /` or `/etc` is *not* flagged). **Not covered:** RBAC/cluster-admin/wildcards, image `:latest`/digest, missing NetworkPolicy. Also validates manifests against a K8s JSON schema via kubeconform (`--kubernetes-version`, `--schema-location` for air-gapped use).

**Interface:** CLI args only — no menu. Commands: `scan`, `print-rules`, `http` (server mode). Flags: `--format/-f` (json default/table/template via `--template`), `--rules` (run a subset by name).

```bash
kubesec scan kubesec-test.yaml
kubesec scan ./deployment.yaml --format json
cat file.json | kubesec scan -
helm template -f values.yaml ./chart | kubesec scan /dev/stdin
kubesec scan --rules CapSysAdmin kubesec-test.yaml
kubesec print-rules
```
Output (JSON, default): one report per object — `object`, `valid`, `message` ("Failed with a score of -30 points"), `score`, and `scoring` with `critical`/`passed`/`advise` buckets, each finding carrying a `selector` (exact field checked), a human `reason`, and `points`. Works entirely offline on files/stdin; multi-document YAML and Helm-template input.

**Copy:** the **score + critical/passed/advise buckets** — a single number per object plus per-rule reasons is the best report model reviewed, and maps directly onto CI gating (`jq '.[0].score > 10'`); works entirely offline; `--rules` subset selector; `print-rules` self-documentation; schema validation. **Avoid:** fixed, opinionated rule set — **no way to customise/disable/add rules without forking** (contrast rbac-tool's CEL config, Conftest's Rego); no severity filter (only `--rules` by name); scores are arbitrary weights (+1/−30) with no severity label per finding; generic hostPath, `:latest`/digest, NetworkPolicy, and all RBAC checks absent; needs network access to fetch schemas by default; no interactive mode.

## 13. audit2rbac — liggitt

**Source:** https://github.com/liggitt/audit2rbac · **Language:** Go · **Install:** pre-built binaries from Releases; from source Go 1.17+, `go get -d ... && make install-deps && make install`. 1,113 stars, no licence file asserted, 58 commits. Upstream docs are stale (still list audit v1alpha1/v1beta1, removed in K8s 1.24).

**What it is:** **not an auditor — a generator.** Takes a K8s **audit log** (JSON) and a username/service account, and generates the minimal Role/ClusterRole + Binding covering all API requests that user actually made. Checks nothing on the checklist directly. Its value is the inverse of auditing — produce least-privilege policy from observed behaviour (rbac-tool's `auditgen` is built on this prior work).

**Interface:** CLI args only — no menu, no severity, no scoring, no JSON output (output is YAML RBAC objects on stdout).

```bash
audit2rbac -f https://git.io/v51iG --user alice > alice-roles.yaml
audit2rbac -f ./kube-apiserver-audit.log --serviceaccount default:dan-sa > dan-policy.yaml
```
Output: Role + RoleBinding annotated `audit2rbac.liggitt.net/generated: "true"`, with explicit resource/verb lists.

**Copy:** the *observe-then-generate* concept — least-privilege roles from real audit events; `--user` vs `--serviceaccount ns:name` input model; labels marking generated objects. **Avoid:** requires audit logging enabled on the API server and a representative run — you must first *grant broad access* (ideally dev only), and anything not exercised (error paths, rare jobs) is silently omitted; it never flags a bad binding, never scores, never looks at a manifest; single-purpose and lightly maintained.

## 14. Conftest — Open Policy Agent

**Source:** https://github.com/open-policy-agent/conftest · **Language:** Go (OPA/Rego engine) · **Install:** release binaries, `brew install conftest`, `CGO_ENABLED=0 go install github.com/open-policy-agent/conftest@latest`, Docker, pre-commit hook. 3,302 stars, 102 releases.

**What it is:** a generic CLI for **testing structured config files against policies written in Rego**. Not K8s-specific and ships **no built-in K8s rules at all** — every checklist item must be written as Rego by the user. Most flexible tool here and, out of the box, least useful: it can check *all* checklist items *if* someone writes the Rego, and checks *none* by default. Parses YAML, JSON, INI, TOML, HOCON, HCL, CUE, Dockerfile, EDN, XML. Its README example is the canonical pattern to steal:
```rego
package main
deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "Containers must not run as root"
}
```

**Interface:** CLI args only — no menu. Commands: `test`, `verify` (unit-test policies), `parse`, `pull`/`push` (policy bundles via OCI), kubectl plugin mode. Flags: `--policy/-p` (default `policy/`), `--output/-o`, `--namespace`, `--input/-i`, `--combine` (merge files into one input), `--data/-d` (extra data, e.g. allow-lists), `--fail-on-warn`, `--trace`. Output formats: **stdout, json, tap, table, junit, github, azuredevops, sarif** — the widest CI set reviewed. Plaintext: `FAIL - deployment.yaml - Containers must not run as root` + `2 tests, 0 passed, 0 warnings, 2 failures, 0 exceptions`. Exit code non-zero on any `deny`. Two severities only: `deny` (fail) vs `warn`.

```bash
conftest test deployment.yaml
conftest test deployment.yaml --policy policy/ --output json
conftest test manifests/ --policy policy/ --output table
conftest verify --policy policy/
```

**Copy:** policy-as-code extensibility (users add rules without forking — the fix for KubeSec's biggest flaw); the output-format range and non-zero exit on failure are the CI gold standard; `--combine`/`--data` for cross-file checks (e.g. "every Deployment must have a NetworkPolicy in the same directory"); `verify` for unit-testing policies; works fully offline on files. **Avoid:** **no built-in rules** — a new user gets zero findings until they write Rego (real learning curve); no scoring/grades; only two severities; no line numbers in findings; no RBAC-specific helpers (effective-permission computation would have to be hand-built in Rego).

## Master comparison table

| Tool | Language | Install | Files vs live cluster | Output formats | RBAC checks | Workload checks |
|---|---|---|---|---|---|---|
| kubeaudit | Go | brew / binary / `go get` / kubectl plugin | Both (manifest + kubeconfig + in-cluster) | pretty / json / SARIF | ❌ none | ✅ privileged, hostNS, nonRoot, limits, image tag, NetworkPolicy, ASAT |
| KubeLinter | Go | `go install` / brew / Docker / binary / GitHub Action | **Files only** | plain / json / SARIF | ⚠️ cluster-admin + wildcards exist, **off by default** | ✅ privileged, hostNS, nonRoot, limits, latest tag, host mounts |
| Polaris | Go | brew / binary / Helm / container | Both (files via `--audit-path`, live via dashboard/webhook) | json / yaml / pretty / score | ✅ cluster-admin bindings; ❌ no wildcards | ✅ privileged, hostNS, nonRoot, limits, latest tag, NetworkPolicy, ASAT |
| kube-bench | Go | binary / Docker / K8s Job | **Live node only** (config files + processes) | text PASS/FAIL/WARN/INFO, json, junit | ⚠️ CIS §5 only, mostly manual `[WARN]` | ❌ none (node/control-plane only) |
| Checkov | **Python** | **`pip install checkov`** / brew / Docker | **Files only** | cli / json / junit / SARIF / csv / CycloneDX / SPDX | ⚠️ weak/unverified — no dedicated cluster-admin/wildcard ID | ✅ nearly all (privileged, hostNS, nonRoot, limits, latest, hostPath, NetworkPolicy, ASAT) |
| Kubescape | Go | install script / brew / krew / Helm | Both (cluster + files/Helm/Git/images) | json / junit / SARIF / html / pdf / csv | ✅ cluster-admin (C-0185); wildcards framework-level only | ✅ nearly all incl. hostPath, NetworkPolicy, ASAT; ❌ no digest control |
| kube-score | Go | binary / brew / Docker / krew | **Files only** (stdin/globs) | human / json / ci / SARIF | ❌ none | ✅ privileged, limits, latest tag, NetworkPolicy; ❌ no hostNS/hostPath/ASAT/digest |
| rbac-lookup | Go | brew / asdf / krew / binary | **Live cluster only** | table (normal/wide) only | ⚠️ lists bindings only, no flagging | ❌ none |
| Krane | Ruby | Helm / Docker / docker-compose (needs FalkorDB) | Both (live + `-d` dir) | json / yaml + web dashboard | ✅ best-in-class wildcards + cluster-admin-equivalent | ❌ none (RBAC only) |
| kubectl-who-can | Go | krew / binary / `go install` | **Live cluster only** | plain tables only | ⚠️ reverse lookup only (query `* *`) | ❌ none |
| rbac-tool | Go | binary / krew | **Live cluster mostly** | table / json / yaml | ✅ best-in-class (`analysis`: escalation, wildcards, exec, secrets) | ❌ none (RBAC only) |
| KubeSec | Go | binary / `go install` / Docker / kubectl plugin | **Files only** (stdin) | json (default) / table / template | ❌ none | ✅ privileged, hostNS, nonRoot, limits, ASAT; hostPath partial (2 paths); ❌ latest/digest/NetworkPolicy |
| audit2rbac | Go | binary / source | Audit log file (not manifests) | YAML RBAC out only | ❌ generates, doesn't flag | ❌ none (generator, not auditor) |
| Conftest | Go (Rego) | binary / brew / `go install` / Docker | **Files only** | stdout / json / tap / table / junit / github / azuredevops / SARIF | Only if you write the Rego | Only if you write the Rego |

**Interface note (all 14 tools): every one is CLI-args-only. None has a menu/interactive mode** (Kubescape's only interactive element is `fix --interactive`, a per-resource confirm prompt). A menu mode would be a genuine differentiator for the new tool.

## Design takeaways for the new Python CLI

1. **Be file-first like KubeSec/Conftest/Checkov, not cluster-first like who-can/rbac-tool.** The single biggest usability gap in the RBAC tools is requiring a live cluster and cluster-admin read access. Scanning exported YAML works in CI, air-gapped labs, and without credentials — live-cluster mode can be added later as an option.
2. **Combine the two halves no single tool has:** rbac-tool/Krane's `analysis` (effective-permission rules with severity: cluster-admin, wildcards, `bind`/`escalate`/`impersonate`, `pods/exec`, `nodes/proxy`, secret readers) **plus** KubeSec/Checkov's manifest checks (privileged, host namespaces, hostPath, runAsNonRoot, limits, automountServiceAccountToken) **plus the gaps all of them leave**: generic hostPath (KubeSec only flags 2 paths), image **digest** pinning (verified in none of them), and missing NetworkPolicy.
3. **RBAC checks must be ON by default.** KubeLinter hides cluster-admin/wildcards behind opt-in config; Checkov's RBAC coverage is unverified; kubeaudit/kube-score have none. This is the new tool's headline feature.
4. **Copy the report shapes that work:** KubeSec's per-object score + critical/passed/advise buckets with a `reason` and exact field/selector; Polaris/Kubescape's overall score + letter grade / compliance %; rbac-tool's severity scale (CRITICAL/HIGH/MEDIUM/LOW); Conftest's output range (JSON + table + JUnit + SARIF) and non-zero exit on failure; kube-bench/Checkov's stable check IDs with `--check`/`--skip-check` and `--min-severity`/`--fail-on` filtering.
5. **Copy the flag surface that works:** `-d`/`-f` input, `--framework`/`--check`/`--skip-check`, `-o json|sarif|junit` with `--output`, `--quiet`/`--compact`, `--severity-threshold`, `--compliance-threshold`, `--soft-fail`, `--rules` subset selector, `list`/`print-rules` self-documentation, per-finding remediation (`path=value`, à la Kubescape verbose mode), and suppression with a reason (annotation or inline comment).
6. **Copy rbac-tool's `gen`/`auditgen` idea as a second mode:** after flagging a wildcard/cluster-admin role, offer to emit a least-privilege replacement — that turns an audit report into a fix. (Polaris `fix` / kubeaudit `autofix` / Kubescape `fix` show the same pattern on the workload side.)
7. **Make custom rules plain YAML/Python config, not Rego/CEL** — Conftest's fatal flaw is shipping no built-in rules and requiring Rego; KubeSec's is no customisation without forking. Ship built-in rules **and** a low-bar custom-rule path.
8. **Avoid their failure modes:** no mandatory network download at scan time (Kubescape); no passed-check noise by default (Checkov); no manual/WARN-only checks presented as failures (kube-bench); no heavyweight dependency like Krane's FalkorDB or kube-bench's root access; no schema fetch at scan time (KubeSec's air-gap wart); keep install to `pip install` / `pipx` with zero compiled dependencies (Checkov proves this is the lowest-friction path for a Python CLI).
9. **The winning combination no single existing tool offers:** Python + pip install, file-first auditing, RBAC checks (cluster-admin **and** wildcards) on by default, image-digest checking, a Polaris-style score/grade, JSON/SARIF output, and an interactive menu mode (which none of the 14 incumbents has).
