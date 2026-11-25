# RBACScope — Research Report: How Kubernetes Manifest Auditing Is Implemented in Python

Researched 2026-11-25 (web + GitHub: real READMEs, docs and code — kubeaudit, KubeLinter, Polaris, Checkov, Kubesec, kube-bench, rbac-tool, k8s-policy-guard, kubelint-mcp, KubiScan).

## 1. Parsing multi-document Kubernetes YAML in Python

- `yaml.safe_load()` reads only the first document. `yaml.safe_load_all()` returns a generator — the correct call for manifests.
- `safe_load_all()` yields `None` for empty documents (trailing `---`, blank sections, comment-only docs). Skip `None`.
- Never use `yaml.load()` / `yaml.load_all()` without `SafeLoader` — arbitrary Python objects via tags like `!!python/object/apply:os.system` (RCE on untrusted manifests).

### kind: List — the gotcha most first implementations miss

`kubectl get -o yaml` and `helm template` output wrap objects in one document with `kind: List` and an `items:` array. Flatten it:

```python
def _docs(text):
    out = []
    for d in yaml.safe_load_all(text):
        if isinstance(d, dict) and d.get("kind") == "List":
            out += [x for x in d.get("items") or [] if isinstance(x, dict)]
        elif isinstance(d, dict) and d.get("kind") and d.get("apiVersion"):
            out.append(d)
    return out
```

### Other gotchas (PyYAML 6.0.x)

| Gotcha | Behaviour | Consequence for an auditor |
|---|---|---|
| Duplicate keys | `a: 1` then `a: 2` → `{'a': 2}` — silently keeps the last value, no error. PyYAML has no strict mode. | A second `resources:` or `securityContext:` block quietly replaces the first. Mitigation: subclass `yaml.SafeLoader`, override `construct_mapping` to raise on a repeated key. |
| Anchors / merge keys | `&name` / `*name` and `<<` merge key are resolved by PyYAML. | Check duplicates on the original mapping keys before merge expansion. |
| YAML 1.1 scalar typing | `on`/`yes`/`no`/`off` parse as booleans, `0755` parses as octal 493. | Quote strings that look like booleans/numbers. `runAsUser: 010` would silently become 8. |
| Tabs | Tab indentation is a hard `ScannerError`. | Treat as a parse error, not a finding. |
| Unknown fields | `safe_load` accepts any keys — no schema validation. A typo like `runAsNonroot: true` loads fine and is silently ignored. | Pair with schema validation (kubeconform). Kubesec validates with kubeconform before scoring. |
| Helm/Kustomize output | `helm template` emits `# Source:` comments and `---` separators. | Parse the rendered output, not the chart. |

### Recommended code pattern

```python
import yaml

class StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys."""
    def construct_mapping(self, node, deep=False):
        keys = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in keys:
                raise yaml.YAMLError(f"duplicate key: {key!r} (line {key_node.start_mark.line + 1})")
            keys.add(key)
        return super().construct_mapping(node, deep=deep)

def load_manifests(path):
    """Yield one resource dict per object; flattens kind: List, skips empties."""
    with open(path, encoding="utf-8") as fh:
        try:
            docs = yaml.load_all(fh, Loader=StrictLoader)
        except yaml.YAMLError as exc:
            raise ValueError(f"{path}: invalid YAML: {exc}") from exc
        for doc in docs:
            if doc is None:
                continue
            if not isinstance(doc, dict):
                continue
            if doc.get("kind") == "List":
                for item in doc.get("items") or []:
                    if isinstance(item, dict):
                        yield item
                continue
            if doc.get("kind") and doc.get("apiVersion"):
                yield doc
```

## 2. How existing tools implement each check

### (a) Resolving RoleBinding / ClusterRoleBinding → role → subjects, flagging cluster-admin

1. Index all `Role` (namespaced) and `ClusterRole` (cluster-scoped) by name.
2. For each binding, read `roleRef` (`kind` + `name`): `ClusterRole` → look up by name (a RoleBinding may reference a ClusterRole — grant still limited to the binding's namespace); `Role` → look up in the binding's own namespace (only valid for RoleBinding).
3. List `subjects[]` (`kind: User|Group|ServiceAccount`, `name`, `namespace`). A ServiceAccount subject with no namespace defaults to the binding's namespace. Flag `system:authenticated`, `system:unauthenticated`, `system:anonymous` and the `default` ServiceAccount specially.
4. Flag `roleRef.name == "cluster-admin"` (with `roleRef.kind: ClusterRole`): **Critical**.

How the tools do it:
- **kube-bench (CIS 4.1.1–4.1.3)**: 4.1.1 flags every cluster-admin binding subject except Group `system:masters` / `system:nodes`; 4.1.2 minimise secrets access; 4.1.3 minimise wildcards.
- **rbac-tool `analysis`** (Go, Alcide): computes each subject's effective permissions, evaluates against CEL rules. Live cluster only.
- **kubelint-mcp `rbac_review`** (pure Python, file-based): K8S3003 error = ClusterRoleBinding to cluster-admin; K8S3004 warning = RoleBinding to cluster-admin; K8S3006 error = `escalate`/`bind`/`impersonate`; K8S3008 error = anonymous/unauthenticated; K8S3009 warning = `system:authenticated`.
- **Checkov**: graph check `CKV2_K8S_1`; RBAC coverage thin.
- **Gotcha:** aggregated ClusterRoles (`aggregationRule` with label selectors) silently expand a role's rules at runtime. File-based tools must at least flag "role uses aggregationRule — rules may be incomplete".

### (b) Wildcard detection in rules

For every rule in `role.rules[]`: `"*" in rule.verbs`, `"*" in rule.resources`, `"*" in rule.apiGroups` (`resourceNames` is NOT a wildcard vector — it restricts). Severity consistently high: kube-bench CIS 4.1.3 (scored FAIL); kubelint-mcp K8S3001 wildcard verbs = error, K8S3002 wildcard resources = error.

### (c) Workload checks

All tools walk: `Deployment/StatefulSet/DaemonSet/Job/CronJob/Pod → spec.template.spec` (CronJob nests one level deeper: `spec.jobTemplate.spec.template.spec`), then `containers[]` + `initContainers[]`. Pod-level and container-level `securityContext` merge: container wins if set, otherwise the pod value applies.

| Check | KubeLinter | Polaris | Checkov | kubeaudit |
|---|---|---|---|---|
| Privileged container | `privileged-container` | `runAsPrivileged` — danger | CKV_K8S_16 | `priv` — error |
| runAsNonRoot missing | `run-as-non-root` | `runAsRootAllowed` — warning | CKV_K8S_35/43/40 | `sc` — error |
| allowPrivilegeEscalation | `privilege-escalation-container` | `privilegeEscalationAllowed` — danger | CKV_K8S_20 | `sc` — error |
| hostNetwork / hostPID / hostIPC | `host-network`, `host-pid`, `host-ipc` | hostNetwork warning, hostPID/hostIPC danger | CKV_K8S_17, CKV_K8S_1–4 | `sc` |
| hostPath volumes | `writable-host-mount` (opt-in); `docker-sock` | — | hostPath checks | `sc` |
| readOnlyRootFilesystem | `no-read-only-root-fs` | `notReadOnlyRootFilesystem` — warning | CKV_K8S_22/30 | `rootfs` — error |
| Capabilities | NET_RAW via privilege-escalation family | `dangerousCapabilities` danger | CKV_K8S_28/37 | `sc` — error if ALL not dropped |
| Missing CPU/memory requests & limits | `unset-cpu-requirements`, `unset-memory-requirements` | `cpu/memoryRequestsMissing`, `cpu/memoryLimitsMissing` — warning | CKV_K8S_10–13 | `resources` |

### (d) automountServiceAccountToken — pod level and ServiceAccount level

Effective rule: `pod.spec.automountServiceAccountToken` if set, else the referenced ServiceAccount's value if set, else **true (Kubernetes default)**. Dangerous combination: default ServiceAccount + token mounted.
- **kubeaudit `asat` auditor**: `AutomountServiceAccountTokenTrueAndDefaultSA` = error.
- **Checkov**: `CKV_K8S_38` (pod-level); `CKV_K8S_41` (default ServiceAccount object itself).
- **Polaris**: warning by default.

### (e) Image tag `:latest` and missing digest

- **KubeLinter `latest-tag`**: BlockList regexes — `.*:(latest)$`, `^[^:]*$` (no tag), `(.*/[^:]+)$` (registry path, no tag).
- **Polaris `tagNotSpecified`**: danger.
- **Checkov**: `CKV_K8S_14` (latest); `CKV_K8S_43` (no digest).
- **kubeaudit `image` auditor**: checks against an expected tag given with `-i`; does NOT flag `:latest` on its own.
- **Digest detection:** `"@sha256:" in image` (tag + digest together, `repo:tag@sha256:...`, is valid and the gold standard). A bare tag, even a version tag, is mutable; only the digest is immutable.

### (f) NetworkPolicy presence per namespace

- **Checkov `CKV2_K8S_6`**: graph check — every namespace should have a NetworkPolicy; a deny-all policy scoped to the workload's labels passes.
- **kubeaudit `np` auditor**: flags namespaces with no NetworkPolicy.
- **Polaris**: a fully clean score (100) requires a NetworkPolicy selecting the workload.
- Implementation: group resources by namespace (default `default`); pass if ≥1 NetworkPolicy exists in that namespace; stronger variant: pass only if a policy's `podSelector` matches the workload's pod labels, or a default-deny policy (`podSelector: {}`) exists.

## 3. Example vulnerable manifests (each < 20 lines)

### 3.1 ClusterRoleBinding to cluster-admin
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: superadmin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: superadmin
    namespace: kube-system
```

### 3.2 Wildcard Role (verbs + resources + apiGroups all `*`)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: god-mode
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
```

### 3.3 Privileged Deployment with hostPath (incl. docker.sock)
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: debug-app
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
      volumes:
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
```

### 3.4 Pod without runAsNonRoot and without resource limits
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: worker
spec:
  containers:
    - name: worker
      image: busybox:1.37.0
      command: ["sleep", "3600"]
      # no securityContext.runAsNonRoot, no resources.requests/limits
```

### 3.5 Image with `:latest`
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: docker.io/library/nginx:latest
```

## 4. Severities and scoring — what the real tools do

| Tool | Severity scale | How it grades |
|---|---|---|
| Polaris | danger / warning / ignore | Score 0–100 = % of passing checks, letter grade (77% → C+); `--set-exit-code-below-score N`, `--set-exit-code-on-danger` |
| Kubesec | points: critical (negative), passed (positive), advise (0) | Total score = sum of points. `privileged: true` = −30, `hostNetwork: true` = −9, `readOnlyRootFilesystem: true` = +1 |
| kubeaudit | Error / Warning / Info | Exit code 2 if any error-level result; `--minSeverity` filters. Planned for deprecation (Oct 2024) — effectively unmaintained |
| KubeLinter | None — pass/fail per named check + remediation | Non-zero exit on findings; per-check ignore via annotation |
| kube-bench | PASS / FAIL / WARN / INFO per check | Compliance score = pass / (pass + fail) × 100 over scored checks |
| Checkov | Pass/fail per check ID | Exit code 1 on any failure |
| kubelint-mcp | error / warning / info per rule | Rule IDs K8S1000–K8S1040 (lint), K8S2001–K8S2017 (cross-refs), K8S3001–K8S3011 (RBAC) |
| k8s-policy-guard | Critical / High / Medium / Low | `--fail-on high` CI gate; JSON/HTML/SARIF output |

### Recommended severity mapping for RBACScope (synthesised)

| Finding | Suggested severity |
|---|---|
| ClusterRoleBinding → cluster-admin | Critical |
| Wildcard verbs/resources (`*:*`) | Critical (verbs) / High (resources) |
| Privileged container | Critical |
| hostPath of `/var/run/docker.sock` (or `/`) | Critical |
| hostPID / hostIPC | High |
| hostNetwork | High |
| `escalate` / `bind` / `impersonate` verbs | Critical |
| automountServiceAccountToken (default SA) | High |
| runAsNonRoot not set / runAsUser: 0 | High |
| Image `:latest` / untagged | Medium |
| Image without digest | Low (Info) |
| Missing CPU/memory requests or limits | Medium |
| No NetworkPolicy in namespace | Medium |
| Secrets read access / pods/exec | High |

### Scoring recommendation

Polaris's percentage score + Kubesec's weighted points: score = `100 + Σ(points)`, clamped 0–100, Critical = −25, High = −10, Medium = −5, Low = −2; grades A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60; non-zero exit when score < threshold or any Critical exists.

## 5. Python projects that already audit RBAC from files

| Project | Language | File-based RBAC? | What it does |
|---|---|---|---|
| k8s-policy-guard (v1.0.0, Mar 2026) | Python (Click CLI) | Yes — closest match | 50+ rules, 8 categories; PG-RBAC-001–011; PG-IMG-001–004; JSON/HTML/SARIF; `--fail-on` gate |
| kubelint-mcp (Nov 2026) | Python (pure mcp + pyyaml, offline) | Yes | 76 rules; `rbac_review` K8S3001–K8S3011; rule ID, severity, `file:line`, fix; multi-doc + `kind: List` |
| rbac-audit.py (systemshardening.com) | Python script | Yes | `yaml.safe_load_all`, `HIGH_RISK_RULES`, `audit_rbac()` + `check_clusterrolebindings()` |
| Checkov | Python | Yes (files), RBAC thin | 119 K8s checks; strong workloads/images, weak RBAC |
| KubiScan | Python | No — live cluster only | Risky roles/bindings/SAs/pods via K8s API |
| rbac-tool (Alcide) | Go | No — live cluster | `analysis` (CEL rules over effective permissions), `viz`, `who-can` |
| Trivy (`trivy config`) | Go | Yes | Misconfig scanning of K8s YAML/Helm, Critical/High/Medium/Low |
| kube-bench / kubeaudit / KubeLinter / Polaris / Kubesec | Go | kubeaudit, KubeLinter, Polaris, Kubesec: yes (manifest mode); kube-bench: no | Established reference tools; kubeaudit deprecated Oct 2024 |

**Gap confirmed:** no mature, widely-used Python tool does full file-based RBAC graph resolution (bindings → roles → subjects → effective permissions) combined with workload checks. The two closest Python projects (k8s-policy-guard, kubelint-mcp) are both from 2026, small and new. Established tools are all Go and either live-cluster-only or linters without RBAC depth (KubeLinter has no RBAC checks; Polaris none — workload-only). RBACScope fills: **Python + files-only + RBAC resolution as the headline feature**, workload checks second.

## Key sources

- PyYAML/multi-doc: https://python.bradpenney.io/essentials/yaml/ · https://www.ursakit.com/blog/yaml-pitfalls · https://git.aryansingh.cc/aryansingh/DryDock/src/commit/2fcf0398c72237a05c96ed9b4e50b55dee96ff7b/src/drydock/backends/kubernetes.py
- kubeaudit: https://pkg.go.dev/github.com/Shopify/Kubeaudit
- KubeLinter: https://github.com/stackrox/kube-linter/blob/HEAD/docs/generated/checks.md
- Polaris: https://polaris.docs.fairwinds.com/checks/security/ · https://polaris.docs.fairwinds.com/cli/
- Checkov: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/DefaultServiceAccount.py
- Kubesec scoring: https://deepwiki.com/controlplaneio/kubesec/3.3-reporting-system
- kube-bench / CIS: https://raw.githubusercontent.com/aquasecurity/kube-bench/main/cfg/aks-1.7/policies.yaml
- Python file-based tools: https://pypi.org/project/k8s-policy-guard/1.0.0/ · http://glama.ai/mcp/servers/0xmortuex/kubelint-mcp · https://deepwiki.com/alcideio/rbac-tool/2.4-analyzing-rbac-security
