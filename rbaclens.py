#!/usr/bin/env python3
"""
RBACLens — Kubernetes RBAC and Workload Auditor
================================================
A command-line tool, written in Python, that reads a folder of Kubernetes
YAML manifests and finds the permissions and workload settings attackers
abuse: cluster-admin bindings, wildcard verbs/resources, privileged
containers, hostPath volumes, host networking, missing runAsNonRoot,
missing resource limits, service-account tokens, image tags and digests,
and missing NetworkPolicies.

It works on FILES ONLY — no live cluster, no credentials, no network.
Point it at your own manifests (or a folder you exported with kubectl),
never at a real cluster or a repository you do not own.

Version: 1.0
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime

VERSION = "1.0"
AUTHOR = "CyberBoy50"

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

try:
    import colorama
    colorama.init()
except Exception:  # pragma: no cover
    pass


# ---------------------------------------------------------------- colours
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        for attr in ("RED", "GREEN", "YELLOW", "BLUE", "CYAN", "BOLD", "DIM", "RESET"):
            setattr(cls, attr, "")


def ok(msg):
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def warn(msg):
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def err(msg):
    print(f"{C.RED}[-]{C.RESET} {msg}")


def info(msg):
    print(f"{C.CYAN}[*]{C.RESET} {msg}")


def sep(char="-", width=64):
    print(C.DIM + char * width + C.RESET)


def banner():
    print()
    print(f"{C.BOLD}{C.BLUE}  ____  ____    _    ____ _                    {C.RESET}")
    print(f"{C.BOLD}{C.BLUE} |  _ \\| __ )  / \\  / ___| |    ___ _ __  ___ {C.RESET}")
    print(f"{C.BOLD}{C.BLUE} | |_) |  _ \\ / _ \\| |   | |   / _ \\ '_ \\/ __|{C.RESET}")
    print(f"{C.BOLD}{C.BLUE} |  _ <| |_) / ___ \\ |___| |__|  __/ | | \\__ \\{C.RESET}")
    print(f"{C.BOLD}{C.BLUE} |_| \\_\\____/_/   \\_\\____|_____\\___|_| |_|___/{C.RESET}")
    print()
    print(f"{C.CYAN}  RBACLens — Kubernetes RBAC and Workload Auditor{C.RESET}")
    print(f"{C.DIM}  Version {VERSION}  |  Author: {AUTHOR}{C.RESET}")
    print(f"{C.YELLOW}  [!] LAB USE ONLY — audit only your own manifests, never a real cluster{C.RESET}")
    print()


# ---------------------------------------------------------------- severities
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_POINTS = {"critical": -25, "high": -10, "medium": -5, "low": -2}

# Rule catalogue: id -> (title, severity, remediation)
RULES = {
    "RBAC-001": ("Binding grants the cluster-admin role", "critical",
                 "Replace cluster-admin with a scoped Role that lists only the verbs and resources the subject needs."),
    "RBAC-002": ("Wildcard verbs in a role rule", "critical",
                 "List the exact verbs the role needs (get, list, watch, ...) instead of '*'."),
    "RBAC-003": ("Wildcard resources in a role rule", "high",
                 "List the exact resources the role needs instead of '*'."),
    "RBAC-004": ("Wildcard API groups in a role rule", "high",
                 "List the exact API groups the role needs instead of '*'."),
    "RBAC-005": ("Dangerous verbs: escalate, bind or impersonate", "critical",
                 "Remove escalate/bind/impersonate unless the subject is a real RBAC administrator."),
    "RBAC-006": ("Role can read secrets", "high",
                 "Scope secret access to the exact secret names (resourceNames) and the smallest verb set."),
    "RBAC-007": ("Role can exec into pods", "high",
                 "Remove create on pods/exec — it is a shell inside every pod."),
    "RBAC-008": ("Binding grants access to anonymous / authenticated users", "critical",
                 "Bind roles to named users, groups or service accounts — never to system:anonymous or system:authenticated."),
    "RBAC-009": ("Default ServiceAccount is bound to a role", "medium",
                 "Create a dedicated ServiceAccount for the workload and bind the role to it."),
    "RBAC-010": ("ClusterRole uses aggregationRule", "low",
                 "Aggregated rules expand at runtime — review the roles matching the label selector; the audit may under-report this role."),
    "RBAC-011": ("Binding references a role that does not exist", "medium",
                 "Fix the roleRef name, or create the role — a dangling binding grants nothing today but breaks silently when a role with that name appears."),
    "WL-001": ("Privileged container", "critical",
                 "Remove privileged: true. A privileged container is root on the host."),
    "WL-002": ("allowPrivilegeEscalation is true", "high",
                 "Set allowPrivilegeEscalation: false in the container securityContext."),
    "WL-003": ("hostNetwork is true", "high",
                 "Remove hostNetwork: true — the pod shares the node's network namespace."),
    "WL-004": ("hostPID is true", "high",
                 "Remove hostPID: true — the pod can see and signal host processes."),
    "WL-005": ("hostIPC is true", "high",
                 "Remove hostIPC: true — the pod shares the node's IPC namespace."),
    "WL-006": ("hostPath volume mounted", "high",
                 "Avoid hostPath. If a host path is truly needed, mount it read-only and only the exact directory."),
    "WL-007": ("Container can run as root (runAsNonRoot not set)", "high",
                 "Set runAsNonRoot: true (pod and container securityContext) and runAsUser to a non-zero UID."),
    "WL-008": ("Missing CPU/memory requests or limits", "medium",
                 "Set resources.requests and resources.limits for CPU and memory on every container."),
    "WL-009": ("Service account token auto-mounted", "high",
                 "Set automountServiceAccountToken: false on the pod or the ServiceAccount if the workload does not call the API."),
    "WL-010": ("Dangerous Linux capability added", "high",
                 "Drop the capability. Drop ALL capabilities and add back only what the container needs."),
    "WL-011": ("Root filesystem is writable", "low",
                 "Set readOnlyRootFilesystem: true and use an emptyDir volume for any writable path."),
    "IMG-001": ("Image uses :latest or has no tag", "medium",
                 "Pin the image to an exact version tag, e.g. nginx:1.27.4, never latest and never untagged."),
    "IMG-002": ("Image is not pinned by digest", "low",
                 "Pin the image by digest (image@sha256:...) — tags are mutable, digests are not."),
    "NET-001": ("Namespace has workloads but no NetworkPolicy", "medium",
                 "Add a NetworkPolicy for the namespace (a default-deny policy is a good start)."),
}

DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL", "DAC_OVERRIDE",
    "SETUID", "SETGID", "NET_RAW", "SYS_MODULE", "SYS_TIME",
}
BUILTIN_ROLES = {"cluster-admin", "admin", "edit", "view"}
WORKLOAD_KINDS = {
    "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
    "Job", "CronJob", "Pod", "ReplicationController",
}


def grade_for(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


# ---------------------------------------------------------------- YAML parsing
class StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys.

    PyYAML silently keeps the LAST value for a duplicate key, so a second
    ``resources:`` or ``securityContext:`` block would quietly replace the
    first and the audit would see only one of them. Fail loudly instead.
    """


def _construct_mapping(loader, node, deep=False):
    keys = set()
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in keys:
            raise yaml.YAMLError(
                "duplicate key: %r (line %d)" % (key, key_node.start_mark.line + 1)
            )
        keys.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


StrictLoader.construct_mapping = _construct_mapping


def load_manifest_file(path):
    """Yield one resource dict per object in a file.

    Handles multi-document files, skips empty documents, and flattens
    ``kind: List`` wrappers (kubectl / helm output).
    """
    with open(path, encoding="utf-8") as fh:
        try:
            docs = yaml.load_all(fh, Loader=StrictLoader)
            docs = list(docs)
        except yaml.YAMLError as exc:
            raise ValueError("%s: invalid YAML: %s" % (path, exc)) from exc
    for doc in docs:
        if doc is None:
            continue  # empty document (trailing ---, blank section)
        if not isinstance(doc, dict):
            continue  # stray scalar / list document
        if doc.get("kind") == "List":
            for item in doc.get("items") or []:
                if isinstance(item, dict):
                    yield item
            continue
        if doc.get("kind") and doc.get("apiVersion"):
            yield doc


def collect_manifests(path):
    """Walk a file or a folder; return (objects, errors).

    Each object is a dict with one extra private key, ``__file__``, holding
    the manifest file it came from (used in findings, never in output).
    """
    files = []
    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            for name in sorted(names):
                if name.endswith((".yaml", ".yml", ".json")):
                    files.append(os.path.join(root, name))
    else:
        raise ValueError("no such file or folder: %s" % path)

    objects, errors = [], []
    for fname in files:
        if fname.endswith(".json"):
            try:
                with open(fname, encoding="utf-8") as fh:
                    data = json.load(fh)
                docs = data.get("items") if isinstance(data, dict) else data
                docs = docs if isinstance(docs, list) else [data]
                for doc in docs:
                    if isinstance(doc, dict) and doc.get("kind"):
                        doc = dict(doc)
                        doc["__file__"] = fname
                        objects.append(doc)
            except (ValueError, OSError) as exc:
                errors.append("%s: %s" % (fname, exc))
            continue
        try:
            for obj in load_manifest_file(fname):
                obj = dict(obj)
                obj["__file__"] = fname
                objects.append(obj)
        except (ValueError, OSError) as exc:
            errors.append("%s" % exc)
    return objects, errors


# ---------------------------------------------------------------- inventory
def obj_name(obj):
    return (obj.get("metadata") or {}).get("name", "<no-name>")


def obj_ns(obj):
    return (obj.get("metadata") or {}).get("namespace", "default")


def obj_id(obj):
    kind = obj.get("kind", "?")
    ns = obj_ns(obj) if obj.get("kind") not in ("ClusterRole", "ClusterRoleBinding") else "-"
    return "%s/%s (%s)" % (kind, obj_name(obj), ns)


class Inventory:
    """Index of every object in the scanned manifests."""

    def __init__(self, objects):
        self.objects = objects
        self.roles = {}          # (namespace, name) -> Role
        self.cluster_roles = {}  # name -> ClusterRole
        self.role_bindings = []
        self.cluster_role_bindings = []
        self.service_accounts = {}  # (namespace, name) -> ServiceAccount
        self.workloads = []
        self.network_policies = []
        for obj in objects:
            kind = obj.get("kind")
            if kind == "Role":
                self.roles[(obj_ns(obj), obj_name(obj))] = obj
            elif kind == "ClusterRole":
                self.cluster_roles[obj_name(obj)] = obj
            elif kind == "RoleBinding":
                self.role_bindings.append(obj)
            elif kind == "ClusterRoleBinding":
                self.cluster_role_bindings.append(obj)
            elif kind == "ServiceAccount":
                self.service_accounts[(obj_ns(obj), obj_name(obj))] = obj
            elif kind in WORKLOAD_KINDS:
                self.workloads.append(obj)
            elif kind == "NetworkPolicy":
                self.network_policies.append(obj)

    def counts(self):
        return {
            "objects": len(self.objects),
            "roles": len(self.roles),
            "cluster_roles": len(self.cluster_roles),
            "role_bindings": len(self.role_bindings),
            "cluster_role_bindings": len(self.cluster_role_bindings),
            "service_accounts": len(self.service_accounts),
            "workloads": len(self.workloads),
            "network_policies": len(self.network_policies),
        }

    def resolve_role(self, binding):
        """Return (role_obj or None, role_kind, role_name) for a binding."""
        ref = binding.get("roleRef") or {}
        kind, name = ref.get("kind"), ref.get("name")
        if kind == "ClusterRole":
            return self.cluster_roles.get(name), kind, name
        if kind == "Role":
            return self.roles.get((obj_ns(binding), name)), kind, name
        return None, kind, name


def print_inventory(inv):
    print()
    print(f"{C.BOLD}RBAC INVENTORY{C.RESET}")
    sep()
    c = inv.counts()
    for label, key in (("Objects parsed", "objects"), ("Roles", "roles"),
                       ("ClusterRoles", "cluster_roles"),
                       ("RoleBindings", "role_bindings"),
                       ("ClusterRoleBindings", "cluster_role_bindings"),
                       ("ServiceAccounts", "service_accounts"),
                       ("Workloads", "workloads"),
                       ("NetworkPolicies", "network_policies")):
        print(f"  {label:<22} {c[key]}")
    sep()
    if inv.role_bindings or inv.cluster_role_bindings:
        print(f"{C.BOLD}Bindings:{C.RESET}")
        for b in inv.role_bindings + inv.cluster_role_bindings:
            ref = b.get("roleRef") or {}
            subs = ", ".join(
                "%s/%s" % (s.get("kind"), s.get("name"))
                for s in b.get("subjects") or []
            ) or "(no subjects)"
            print("  %s -> %s/%s  [%s]" % (
                obj_id(b), ref.get("kind"), ref.get("name"), subs))
    print()


# ---------------------------------------------------------------- findings
def make_finding(rule, obj, evidence, namespace=None):
    title, severity, remediation = RULES[rule]
    return {
        "rule": rule,
        "title": title,
        "severity": severity,
        "points": SEVERITY_POINTS[severity],
        "object": obj_id(obj) if isinstance(obj, dict) else str(obj),
        "namespace": namespace if namespace is not None else (
            obj_ns(obj) if isinstance(obj, dict) else "default"),
        "file": obj.get("__file__", "") if isinstance(obj, dict) else "",
        "evidence": evidence,
        "remediation": remediation,
    }


def subject_label(subject, binding_ns):
    kind, name = subject.get("kind"), subject.get("name")
    ns = subject.get("namespace", binding_ns if kind == "ServiceAccount" else "")
    return "%s/%s%s" % (kind, name, (" (" + ns + ")") if ns else "")


# ---------------------------------------------------------------- RBAC checks
def check_rbac(inv):
    findings = []
    for binding in inv.role_bindings + inv.cluster_role_bindings:
        ref = binding.get("roleRef") or {}
        ref_kind, ref_name = ref.get("kind"), ref.get("name")
        subjects = binding.get("subjects") or []
        labels = ", ".join(subject_label(s, obj_ns(binding)) for s in subjects) \
            or "(no subjects)"

        # RBAC-001 — binding grants cluster-admin
        if ref_kind == "ClusterRole" and ref_name == "cluster-admin":
            findings.append(make_finding(
                "RBAC-001", binding,
                "roleRef: ClusterRole/cluster-admin granted to %s" % labels))

        # RBAC-008 — anonymous / authenticated users
        for s in subjects:
            if s.get("kind") in ("User", "Group") and s.get("name") in (
                    "system:anonymous", "system:unauthenticated"):
                findings.append(make_finding(
                    "RBAC-008", binding,
                    "subject %s has access to %s/%s" % (
                        s.get("name"), ref_kind, ref_name)))
            elif s.get("kind") == "Group" and s.get("name") == "system:authenticated":
                f = make_finding(
                    "RBAC-008", binding,
                    "subject system:authenticated (every authenticated user) "
                    "has access to %s/%s" % (ref_kind, ref_name))
                f["severity"] = "high"
                f["points"] = SEVERITY_POINTS["high"]
                findings.append(f)

        # RBAC-009 — default ServiceAccount bound
        for s in subjects:
            if s.get("kind") == "ServiceAccount" and s.get("name") == "default":
                findings.append(make_finding(
                    "RBAC-009", binding,
                    "the default ServiceAccount is bound to %s/%s" % (
                        ref_kind, ref_name)))

        # RBAC-011 — binding references a role that does not exist
        role_obj, _, _ = inv.resolve_role(binding)
        if role_obj is None and ref_name not in BUILTIN_ROLES \
                and not str(ref_name or "").startswith("system:"):
            findings.append(make_finding(
                "RBAC-011", binding,
                "roleRef %s/%s does not exist in the scanned manifests" % (
                    ref_kind, ref_name)))

    # Rules inside Roles and ClusterRoles
    for role in list(inv.roles.values()) + list(inv.cluster_roles.values()):
        if role.get("aggregationRule"):
            findings.append(make_finding(
                "RBAC-010", role,
                "ClusterRole uses aggregationRule with selector %s — "
                "its effective rules expand at runtime" % (
                    (role.get("aggregationRule") or {}).get("clusterRoleSelectors"),)))
        for idx, rule in enumerate(role.get("rules") or [], start=1):
            verbs = rule.get("verbs") or []
            resources = rule.get("resources") or []
            api_groups = rule.get("apiGroups") or []
            where = "rule #%d of %s" % (idx, obj_id(role))
            if "*" in verbs:
                findings.append(make_finding(
                    "RBAC-002", role,
                    "%s: verbs=%s resources=%s apiGroups=%s" % (
                        where, verbs, resources, api_groups)))
            if "*" in resources:
                findings.append(make_finding(
                    "RBAC-003", role,
                    "%s: verbs=%s resources=%s apiGroups=%s" % (
                        where, verbs, resources, api_groups)))
            if "*" in api_groups:
                findings.append(make_finding(
                    "RBAC-004", role,
                    "%s: verbs=%s resources=%s apiGroups=%s" % (
                        where, verbs, resources, api_groups)))
            dangerous = sorted(set(verbs) & {"escalate", "bind", "impersonate"})
            if dangerous:
                findings.append(make_finding(
                    "RBAC-005", role,
                    "%s: verbs include %s" % (where, dangerous)))
            if "secrets" in resources and set(verbs) & {"get", "list", "watch", "*"}:
                findings.append(make_finding(
                    "RBAC-006", role,
                    "%s: verbs=%s on secrets" % (where, verbs)))
            if "pods/exec" in resources and set(verbs) & {"create", "*"}:
                findings.append(make_finding(
                    "RBAC-007", role,
                    "%s: verbs=%s on pods/exec" % (where, verbs)))
    return findings


# ---------------------------------------------------------------- workload checks
def pod_spec(obj):
    """Return the pod spec of a workload object (or a Pod itself)."""
    kind = obj.get("kind")
    spec = obj.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return ((spec.get("jobTemplate") or {}).get("spec") or {}).get(
            "template", {}).get("spec")
    template = spec.get("template") or {}
    return template.get("spec")


def effective_sc(pod_sc, container_sc, key):
    """Container securityContext wins; otherwise the pod value applies."""
    if key in container_sc:
        return container_sc[key]
    return pod_sc.get(key)


def split_image(image):
    """Return (repository, tag or None, has_digest)."""
    digest = "@sha256:" in image
    base = image.split("@")[0]
    if ":" in base.rsplit("/", 1)[-1]:
        return base.rsplit(":", 1)[0], base.rsplit(":", 1)[1], digest
    return base, None, digest


def check_workloads(inv):
    findings = []
    for obj in inv.workloads:
        spec = pod_spec(obj)
        if not spec:
            continue
        pod_sc = spec.get("securityContext") or {}
        containers = []
        for c in spec.get("containers") or []:
            containers.append((c, False))
        for c in spec.get("initContainers") or []:
            containers.append((c, True))

        # Host namespaces — one finding per workload, not per container.
        if spec.get("hostNetwork") is True:
            findings.append(make_finding(
                "WL-003", obj, "spec.hostNetwork: true"))
        if spec.get("hostPID") is True:
            findings.append(make_finding(
                "WL-004", obj, "spec.hostPID: true"))
        if spec.get("hostIPC") is True:
            findings.append(make_finding(
                "WL-005", obj, "spec.hostIPC: true"))

        # hostPath volumes — docker.sock and / are the worst.
        for vol in spec.get("volumes") or []:
            host_path = (vol.get("hostPath") or {}).get("path")
            if host_path is None:
                continue
            f = make_finding(
                "WL-006", obj,
                "volume '%s' mounts hostPath '%s'" % (
                    vol.get("name"), host_path))
            if host_path in ("/var/run/docker.sock", "/"):
                f["severity"] = "critical"
                f["points"] = SEVERITY_POINTS["critical"]
                f["evidence"] += " — full host access (docker socket / root filesystem)"
            findings.append(f)

        # Service account token — pod flag wins, else the SA flag, else true.
        sa_name = spec.get("serviceAccountName") or spec.get("serviceAccount") \
            or "default"
        sa_obj = inv.service_accounts.get((obj_ns(obj), sa_name))
        pod_flag = spec.get("automountServiceAccountToken")
        sa_flag = (sa_obj or {}).get("automountServiceAccountToken")
        mounted = pod_flag if pod_flag is not None else (
            sa_flag if sa_flag is not None else True)
        if mounted is True:
            f = make_finding(
                "WL-009", obj,
                "service account token auto-mounted for '%s' "
                "(pod flag: %s, ServiceAccount flag: %s)" % (
                    sa_name, pod_flag, sa_flag))
            if sa_name != "default":
                f["severity"] = "medium"
                f["points"] = SEVERITY_POINTS["medium"]
            findings.append(f)

        for container, is_init in containers:
            cname = container.get("name", "?") + (" (init)" if is_init else "")
            csc = container.get("securityContext") or {}
            where = "container '%s' of %s" % (cname, obj_id(obj))

            # WL-001 privileged
            if csc.get("privileged") is True:
                findings.append(make_finding(
                    "WL-001", obj,
                    "%s: securityContext.privileged: true" % where))
            # WL-002 allowPrivilegeEscalation (skipped when privileged:
            # privileged already implies it, one finding is enough)
            if csc.get("privileged") is not True and \
                    effective_sc(pod_sc, csc, "allowPrivilegeEscalation") is True:
                findings.append(make_finding(
                    "WL-002", obj,
                    "%s: allowPrivilegeEscalation: true" % where))
            # WL-007 run as root
            run_non_root = effective_sc(pod_sc, csc, "runAsNonRoot")
            run_user = effective_sc(pod_sc, csc, "runAsUser")
            if run_non_root is not True:
                findings.append(make_finding(
                    "WL-007", obj,
                    "%s: runAsNonRoot is %s, runAsUser is %s" % (
                        where, run_non_root, run_user)))
            # WL-010 dangerous capabilities
            caps = (csc.get("capabilities") or {}).get("add") or []
            bad_caps = sorted(set(caps) & DANGEROUS_CAPABILITIES)
            if bad_caps:
                findings.append(make_finding(
                    "WL-010", obj,
                    "%s: capabilities.add includes %s" % (where, bad_caps)))
            # WL-011 writable root filesystem
            if effective_sc(pod_sc, csc, "readOnlyRootFilesystem") is not True:
                findings.append(make_finding(
                    "WL-011", obj,
                    "%s: readOnlyRootFilesystem is not true" % where))
            # WL-008 resource requests / limits
            resources = container.get("resources") or {}
            limits = resources.get("limits") or {}
            requests = resources.get("requests") or {}
            missing = []
            for label, group, key in (("cpu limits", limits, "cpu"),
                                      ("memory limits", limits, "memory"),
                                      ("cpu requests", requests, "cpu"),
                                      ("memory requests", requests, "memory")):
                if key not in group:
                    missing.append(label)
            if missing:
                findings.append(make_finding(
                    "WL-008", obj,
                    "%s: missing %s" % (where, ", ".join(missing))))
            # IMG-001 / IMG-002 image tag and digest
            image = container.get("image", "")
            if image:
                _repo, tag, has_digest = split_image(image)
                if tag == "latest" or tag is None:
                    findings.append(make_finding(
                        "IMG-001", obj,
                        "%s: image '%s' uses :latest or has no tag" % (
                            where, image)))
                if not has_digest:
                    findings.append(make_finding(
                        "IMG-002", obj,
                        "%s: image '%s' is not pinned by digest" % (
                            where, image)))
    return findings


def check_network_policies(inv):
    """NET-001 — a namespace with workloads but no NetworkPolicy."""
    findings = []
    by_ns = {}
    for obj in inv.workloads:
        by_ns.setdefault(obj_ns(obj), []).append(obj_name(obj))
    np_ns = {obj_ns(p) for p in inv.network_policies}
    for ns in sorted(by_ns):
        if ns not in np_ns:
            fake = {"kind": "Namespace", "metadata": {"name": ns}}
            findings.append(make_finding(
                "NET-001", fake,
                "namespace '%s' runs workloads (%s) but has no NetworkPolicy" % (
                    ns, ", ".join(sorted(by_ns[ns]))),
                namespace=ns))
    return findings


def run_all_checks(inv):
    findings = check_rbac(inv) + check_workloads(inv) + check_network_policies(inv)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["rule"], f["object"]))
    return findings


def score_findings(findings):
    score = 100 + sum(f["points"] for f in findings)
    return max(0, min(100, score))


# ---------------------------------------------------------------- reports
def summary_counts(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def build_text_report(path, inv, findings, score, grade, errors):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c = inv.counts()
    counts = summary_counts(findings)
    lines = []
    lines.append("=" * 64)
    lines.append("RBACLens Report — Kubernetes RBAC and Workload Audit")
    lines.append("=" * 64)
    lines.append("Date: %s" % now)
    lines.append("Tool: RBACLens %s (author: %s)" % (VERSION, AUTHOR))
    lines.append("Scanned: %s" % path)
    lines.append("")
    lines.append("Inventory: %d objects (%d Roles, %d ClusterRoles, "
                 "%d RoleBindings, %d ClusterRoleBindings, %d ServiceAccounts, "
                 "%d workloads, %d NetworkPolicies)" % (
                     c["objects"], c["roles"], c["cluster_roles"],
                     c["role_bindings"], c["cluster_role_bindings"],
                     c["service_accounts"], c["workloads"],
                     c["network_policies"]))
    if errors:
        lines.append("Parse errors: %d" % len(errors))
        for e in errors:
            lines.append("  - %s" % e)
    lines.append("")
    lines.append("Score: %d/100  (grade %s)" % (score, grade))
    lines.append("Findings: %d total — %d critical, %d high, %d medium, %d low" % (
        len(findings), counts["critical"], counts["high"],
        counts["medium"], counts["low"]))
    lines.append("")
    if not findings:
        lines.append("No findings. All checks passed.")
    else:
        for i, f in enumerate(findings, start=1):
            lines.append("-" * 64)
            lines.append("[%s] %s — %s" % (
                f["severity"].upper(), f["rule"], f["title"]))
            lines.append("Object:    %s" % f["object"])
            if f["file"]:
                lines.append("File:      %s" % f["file"])
            lines.append("Evidence:  %s" % f["evidence"])
            lines.append("Fix:       %s" % f["remediation"])
    lines.append("-" * 64)
    lines.append("")
    lines.append("Defensive lesson — least privilege in RBAC: give every subject "
                 "only the permissions it needs, nothing more. A binding to "
                 "cluster-admin hands over the whole cluster: read every secret, "
                 "run code in any pod, change RBAC itself. Scope roles to exact "
                 "verbs, resources and namespaces instead.")
    lines.append("")
    lines.append("Lab use only — audit only manifests you own or have written "
                 "permission to audit.")
    return "\n".join(lines) + "\n"


def build_json_report(path, inv, findings, score, grade, errors):
    return {
        "tool": "RBACLens",
        "version": VERSION,
        "author": AUTHOR,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "path": path,
        "inventory": inv.counts(),
        "parse_errors": errors,
        "score": score,
        "grade": grade,
        "summary": summary_counts(findings),
        "total_findings": len(findings),
        "findings": findings,
    }


def print_summary(inv, findings, score, grade, quiet=False):
    counts = summary_counts(findings)
    print()
    print(f"{C.BOLD}RBACLens — scan complete{C.RESET}")
    sep()
    c = inv.counts()
    print("Objects: %d  (Roles %d, ClusterRoles %d, Bindings %d, Workloads %d)" % (
        c["objects"], c["roles"], c["cluster_roles"],
        c["role_bindings"] + c["cluster_role_bindings"], c["workloads"]))
    colour = C.GREEN if score >= 90 else C.YELLOW if score >= 70 else C.RED
    print("Score: %s%d/100 (grade %s)%s" % (colour, score, grade, C.RESET))
    print("Findings: %d  (critical %d, high %d, medium %d, low %d)" % (
        len(findings), counts["critical"], counts["high"],
        counts["medium"], counts["low"]))
    if quiet:
        return
    for f in findings:
        col = {"critical": C.RED, "high": C.YELLOW,
               "medium": C.CYAN, "low": C.DIM}[f["severity"]]
        print("%s[%s]%s %s — %s" % (
            col, f["severity"].upper(), C.RESET, f["rule"], f["title"]))
        print("     %s" % f["object"])
        print("     Evidence: %s" % f["evidence"])
    print()


def scan_path(path, args):
    """Run a full scan. Returns (exit_code, findings, score, grade)."""
    if yaml is None:
        err("PyYAML is not installed. Run: python run.py setup")
        err("  or: pip install pyyaml")
        return 2, [], 0, "F"
    try:
        objects, errors = collect_manifests(path)
    except ValueError as exc:
        err(str(exc))
        return 2, [], 0, "F"
    if not objects and not errors:
        warn("No Kubernetes manifests found in %s" % path)
        return 0, [], 100, "A"
    inv = Inventory(objects)
    findings = run_all_checks(inv)
    score = score_findings(findings)
    grade = grade_for(score)

    # Filters: --min-severity hides lower findings from the display/report;
    # the score always reflects every finding.
    shown = findings
    if args.min_severity:
        level = SEVERITY_ORDER[args.min_severity]
        shown = [f for f in findings if SEVERITY_ORDER[f["severity"]] <= level]
    if args.check:
        wanted = set(args.check.split(","))
        shown = [f for f in shown if f["rule"] in wanted]
    if args.skip_check:
        skipped = set(args.skip_check.split(","))
        shown = [f for f in shown if f["rule"] not in skipped]

    print_summary(inv, shown, score, grade, quiet=args.quiet)

    report = build_text_report(path, inv, shown, score, grade, errors)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)
    ok("Report saved: %s" % args.output)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(build_json_report(path, inv, shown, score, grade, errors),
                      fh, indent=2)
        ok("JSON report saved: %s" % args.json)
    for e in errors:
        warn("Parse error: %s" % e)

    # Exit code: 0 clean, 1 findings, 2 any critical (or --fail-on hit).
    if not findings:
        return 0, findings, score, grade
    if args.fail_on and args.fail_on != "none":
        level = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f["severity"]] <= level for f in findings):
            return 2, findings, score, grade
        return 0, findings, score, grade
    if counts := summary_counts(findings):
        if counts["critical"]:
            return 2, findings, score, grade
    return 1, findings, score, grade


def list_checks():
    print()
    print(f"{C.BOLD}RBACLens checks ({len(RULES)} rules){C.RESET}")
    sep()
    for rule in sorted(RULES):
        title, severity, _fix = RULES[rule]
        col = {"critical": C.RED, "high": C.YELLOW,
               "medium": C.CYAN, "low": C.DIM}[severity]
        print("  %-10s %s%-9s%s %s" % (
            rule, col, severity.upper(), C.RESET, title))
    print()
    print("Use --check RBAC-001,WL-001 to run only some rules,")
    print("or --skip-check NET-001 to skip some.")
    print()


# ---------------------------------------------------------------- menu
def ask(prompt, default=""):
    try:
        value = input(f"{C.CYAN}[?]{C.RESET} {prompt} ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise
    return value or default


def menu_scan(args, default_path, default_output):
    path = ask("Manifest folder or file:", default_path)
    if not path:
        path = default_path
    out = ask("Report file:", default_output)
    args.output = out or default_output
    return scan_path(path, args)


def menu(args):
    base = os.path.dirname(os.path.abspath(__file__))
    bad = os.path.join(base, "test_manifests", "bad")
    clean = os.path.join(base, "test_manifests", "clean")
    while True:
        banner()
        print(f" {C.BOLD}[ 1]{C.RESET} Scan a folder of manifests")
        print(f" {C.BOLD}[ 2]{C.RESET} Quick scan: test manifests (bad — planted flaws)")
        print(f" {C.BOLD}[ 3]{C.RESET} Quick scan: test manifests (clean — should pass)")
        print(f" {C.BOLD}[ 4]{C.RESET} Show RBAC inventory of a folder")
        print(f" {C.BOLD}[ 5]{C.RESET} List all checks")
        print(f" {C.BOLD}[ 6]{C.RESET} Run step tests")
        print(f" {C.BOLD}[ 0]{C.RESET} Exit")
        print()
        try:
            choice = ask("Select option:", "1")
        except (EOFError, KeyboardInterrupt):
            print(f"{C.YELLOW}[!]{C.RESET} Exit")
            return 0
        if choice == "0":
            return 0
        if choice == "1":
            code, _f, _s, _g = menu_scan(args, ".", "rbaclens_report.txt")
            print("Exit code: %d" % code)
        elif choice == "2":
            args.output = "report_bad.txt"
            code, _f, _s, _g = scan_path(bad, args)
            print("Exit code: %d" % code)
        elif choice == "3":
            args.output = "report_clean.txt"
            code, _f, _s, _g = scan_path(clean, args)
            print("Exit code: %d" % code)
        elif choice == "4":
            path = ask("Manifest folder or file:", bad)
            try:
                objects, errors = collect_manifests(path or bad)
            except ValueError as exc:
                err(str(exc))
                objects, errors = [], []
            if objects:
                print_inventory(Inventory(objects))
            for e in errors:
                warn("Parse error: %s" % e)
        elif choice == "5":
            list_checks()
        elif choice == "6":
            import test_rbaclens
            test_rbaclens.run_all_tests()
        else:
            warn("Unknown option: %s" % choice)
        try:
            input("Press enter to continue...")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0


# ---------------------------------------------------------------- CLI
def build_parser():
    p = argparse.ArgumentParser(
        prog="rbaclens",
        description="RBACLens — Kubernetes RBAC and Workload Auditor "
                    "(files only, no live cluster).")
    p.add_argument("path", nargs="?", default=None,
                   help="manifest file or folder to audit")
    p.add_argument("-o", "--output", default="rbaclens_report.txt",
                   help="text report file (default: rbaclens_report.txt)")
    p.add_argument("--json", default=None, metavar="FILE",
                   help="also write a JSON report to FILE")
    p.add_argument("--min-severity", default=None,
                   choices=["critical", "high", "medium", "low"],
                   help="show only findings at or above this severity")
    p.add_argument("--fail-on", default=None,
                   choices=["critical", "high", "medium", "low", "none"],
                   help="exit 2 if any finding at or above this severity")
    p.add_argument("--check", default=None, metavar="RULES",
                   help="run only these rules, e.g. RBAC-001,WL-001")
    p.add_argument("--skip-check", default=None, metavar="RULES",
                   help="skip these rules, e.g. NET-001")
    p.add_argument("--inventory", action="store_true",
                   help="print the RBAC inventory and exit")
    p.add_argument("--list-checks", action="store_true",
                   help="list all checks and exit")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="only the summary, score and report path")
    p.add_argument("--batch", action="store_true",
                   help="never ask, use defaults (for scripts)")
    p.add_argument("-i", "--interactive", "--menu", action="store_true",
                   help="open the numbered menu")
    p.add_argument("--version", action="store_true",
                   help="print the version and exit")
    p.add_argument("--no-color", action="store_true",
                   help="plain output without colours")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_color:
        C.disable()
    if args.version:
        print("RBACLens %s" % VERSION)
        return 0
    if args.list_checks:
        list_checks()
        return 0
    if args.inventory:
        if not args.path:
            err("Give a manifest file or folder for --inventory.")
            return 2
        try:
            objects, errors = collect_manifests(args.path)
        except ValueError as exc:
            err(str(exc))
            return 2
        if objects:
            print_inventory(Inventory(objects))
        for e in errors:
            warn("Parse error: %s" % e)
        return 0
    if args.interactive or args.path is None:
        return menu(args)
    code, _findings, _score, _grade = scan_path(args.path, args)
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!]{C.RESET} Exit")
        sys.exit(130)
