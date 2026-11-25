#!/usr/bin/env python3
"""
RBACLens — Kubernetes RBAC and Workload Auditor
================================================
A command-line tool, written in Python, that reads a folder of Kubernetes
YAML manifests and finds the permissions and workload settings attackers
abuse: cluster-admin bindings, wildcard verbs/resources, privileged
containers, hostPath volumes, host networking, missing runAsNonRoot,
missing resource limits, service-account tokens, image tags and digests,
missing NetworkPolicies, cloud workload-identity annotations, and —
with --cve — known CVEs in the images themselves (NVD lookup).

It works on FILES — a folder of manifests — or LIVE on your own cluster
via kubectl (read-only `kubectl get`, nothing is written to the cluster).
Point it at your own manifests or your own cluster, never at a cluster
or a repository you do not own.

It also enforces, not just audits: --admission-out writes Kyverno
policies and --gatekeeper-out writes OPA Gatekeeper constraints that
block the flagged patterns, and --fix-out writes corrected copies of
the manifests with the safe fixes applied.

Version: 1.4
"""
import argparse
import copy
import io
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

VERSION = "1.4"
AUTHOR = "CyberBoy50"

DISCLAIMER = ("DISCLAIMER — AUTHORIZED USE ONLY. This tool was built for "
              "ethical, authorized security testing only. You are using it "
              "on your own responsibility. The authors are not responsible "
              "for how you use it, or for anything that happens because of "
              "your use. Only test systems, code, and data you own or have "
              "explicit written permission to test — testing anything else "
              "may be illegal (for example, PECA 2016 in Pakistan).")

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
# TraceRecon style, like SSTIProbe: one class, short names.
class C:
    RST = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[1;31m"
    GRN = "\033[1;32m"
    YEL = "\033[1;33m"
    BLU = "\033[1;34m"
    MAG = "\033[1;35m"
    CYN = "\033[1;36m"
    WHT = "\033[1;37m"
    # Old names, kept working.
    GREEN = GRN
    YELLOW = YEL
    BLUE = BLU
    CYAN = CYN
    BOLD = BLD
    RESET = RST

    @classmethod
    def disable(cls):
        for attr in ("RST", "BLD", "DIM", "RED", "GRN", "YEL", "BLU", "MAG",
                     "CYN", "WHT", "GREEN", "YELLOW", "BLUE", "CYAN",
                     "BOLD", "RESET"):
            setattr(cls, attr, "")


RED = C.RED
GREEN = C.GRN
YELLOW = C.YEL
CYAN = C.CYN
BOLD = C.BLD
RESET = C.RST


def clear():
    """Clear the screen — GhostTrack / TraceRecon pattern.
    Windows: cls, macOS/Linux: clear."""
    os.system("cls" if os.name == "nt" else "clear")


def sep(color=C.GRN, char="─", width=58):
    """A rule line, TraceRecon style: sep(C.GRN, '─') / sep(C.GRN, '═')."""
    print(f"{color}{char * width}{C.RST}")


def header(title, color=C.GRN):
    """A titled section header with rule lines above and below."""
    sep(color)
    print(f"{color} {title}{C.RST}")
    sep(color)


def ok(msg):
    """[+] success line: ' [+] message' — white brackets, green plus."""
    print(f" {C.WHT}[{C.GRN}+{C.WHT}]{C.RST} {msg}")


def warn(msg):
    """[!] warning line, yellow."""
    print(f" {C.WHT}[{C.YEL}!{C.WHT}]{C.RST} {C.YEL}{msg}{C.RST}")


def err(msg):
    """[x] error line, red."""
    print(f" {C.WHT}[{C.RED}x{C.WHT}]{C.RST} {C.RED}{msg}{C.RST}")


def info(label, value=None, label_color=C.WHT, val_color=C.GRN):
    """One aligned field — TraceRecon style:
    ' Target                : value' (label 22 chars, white; value green).
    Called with one argument it prints a plain [*] line, like before."""
    if value is None:
        print(f"{C.CYN}[*]{C.RST} {label}")
        return
    print(f" {label_color}{label:<22}{C.RST}: {val_color}{value}{C.RST}")


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
    print(
        f"{C.YELLOW}  [!] LEGAL DISCLAIMER: Only audit manifests you own or have{C.RESET}"
    )
    print(
        f"{C.YELLOW}      written permission to audit — your own files or lab.{C.RESET}"
    )
    # TraceRecon-style box under the banner, like SSTIProbe.
    print(f"{C.GRN}")
    print("┌" + "─" * 50 + "┐")
    print("│" + ("RBACLens v" + VERSION + " — files + live cluster (kubectl)").center(50) + "│")
    print("│" + "For authorized use only".center(50) + "│")
    print("│" + "─" * 50 + "│")
    for line in textwrap.wrap(DISCLAIMER, 48):
        print("│" + line.center(50) + "│")
    print("└" + "─" * 50 + "┘")
    print(f"{C.RST}", end="")
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
    "PSS-001": ("Pod Security Standards: seccompProfile is missing or not RuntimeDefault/Localhost", "medium",
                 "Set spec.securityContext.seccompProfile.type to RuntimeDefault."),
    "PSS-002": ("Pod Security Standards: capabilities.drop does not include ALL", "high",
                 "Add capabilities.drop: [ALL] to the container."),
    "PSS-003": ("Pod Security Standards: capability added other than NET_BIND_SERVICE", "high",
                 "Remove the added capabilities; the restricted profile allows only NET_BIND_SERVICE."),
    "IAM-001": ("ServiceAccount is bound to a cloud workload identity", "medium",
                 "Review the cloud identity mapping: the pod inherits whatever the cloud role can do. Scope the cloud role to the exact permissions the workload needs and no more."),
    "IAM-002": ("Cloud workload identity references an over-broad cloud role", "critical",
                 "Replace the over-broad cloud role (AdministratorAccess, Owner/Editor/Contributor, or a wildcard role) with a narrowly scoped role that lists only the permissions the workload needs."),
    "IAM-003": ("Deprecated cloud pod-identity annotation in use", "medium",
                 "Migrate from the deprecated Azure pod-identity annotation (aadpodidentity) to Azure Workload Identity (azure.workload.identity/client-id); pod-identity is retired and no longer receives security fixes."),
    "CVE-001": ("Container image has known CVEs (NVD lookup)", "high",
                 "Upgrade the image to a patched version (check the CVE IDs in the evidence), or replace it. Pin the new version by digest."),
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

# Cloud workload-identity annotations, by provider. A ServiceAccount (or
# a pod template) carrying one of these hands the pod a cloud identity:
# whatever the cloud role can do, the pod can do too.
CLOUD_IDENTITY_ANNOTATIONS = {
    # AWS EKS — IAM Roles for Service Accounts (IRSA)
    "eks.amazonaws.com/role-arn": "AWS EKS IRSA",
    # Google GKE — Workload Identity
    "iam.gke.io/gcp-service-account": "GKE Workload Identity",
    # Azure — Workload Identity (current mechanism)
    "azure.workload.identity/client-id": "Azure Workload Identity",
}
# Retired mechanism: Azure AD Pod Identity (aadpodidentity). No longer
# receiving security fixes — IAM-003 flags it separately.
DEPRECATED_IDENTITY_ANNOTATIONS = {
    "aadpodidentity.k8s.io/identity": "Azure AD Pod Identity (deprecated)",
}
# Cloud role names that are over-broad by definition: a pod holding one
# of these is effectively an administrator of the cloud account/project.
BROAD_CLOUD_ROLES = {
    "administratoraccess", "admin", "administrator", "superadmin",
    "owner", "editor", "contributor",
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


# ---------------------------------------------------------------- live cluster
# Resource types the checks understand. kubectl -o yaml returns them as
# one kind: List document, which the same StrictLoader parses.
LIVE_RESOURCES = (
    "roles,clusterroles,rolebindings,clusterrolebindings,"
    "serviceaccounts,deployments,daemonsets,statefulsets,"
    "replicasets,jobs,cronjobs,pods,networkpolicies"
)


def collect_live(kubectl="kubectl", namespace=None, context=None):
    """Fetch resources from a live cluster and return (objects, errors)
    — the same shape as collect_manifests(), so the same checks run.

    Read-only: a single `kubectl get <resources> -o yaml`. Nothing is
    created, changed or deleted on the cluster. Each object gets
    __file__ = "live-cluster" (used in findings, never in output).

    Raises ValueError if kubectl is missing, the cluster cannot be
    reached, or the output is not valid YAML.
    """
    if shutil.which(kubectl) is None:
        raise ValueError(
            "kubectl not found on PATH — install kubectl and configure a "
            "cluster (minikube / kind / kubeconfig), or scan manifest "
            "files instead.")
    cmd = [kubectl, "get", LIVE_RESOURCES]
    if namespace:
        cmd += ["-n", namespace]
    else:
        cmd += ["-A"]
    if context:
        cmd += ["--context", context]
    cmd += ["-o", "yaml"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise ValueError(
            "kubectl timed out after 120s — is the cluster reachable?")
    if proc.returncode != 0:
        raise ValueError("kubectl failed: %s" % (
            proc.stderr.strip() or "unknown error"))
    try:
        docs = list(yaml.load_all(io.StringIO(proc.stdout),
                                  Loader=StrictLoader))
    except yaml.YAMLError as exc:
        raise ValueError(
            "kubectl output is not valid YAML: %s" % exc) from exc
    objects, errors = [], []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        items = doc.get("items") if doc.get("kind") == "List" else [doc]
        for item in items or []:
            if isinstance(item, dict) and item.get("kind"):
                item = dict(item)
                item["__file__"] = "live-cluster"
                objects.append(item)
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


def expand_aggregation(role, inv):
    """Expand an aggregated ClusterRole's selectors (v1.4).

    Returns (matched_roles, note). Only matchLabels selectors are
    expanded — matchExpressions selectors are reported in the note so
    the audit never silently claims a full expansion it did not do.
    """
    selectors = (role.get("aggregationRule") or {}).get(
        "clusterRoleSelectors") or []
    matched, expr_note = [], False
    for sel in selectors:
        if sel.get("matchExpressions"):
            expr_note = True
        labels = sel.get("matchLabels") or {}
        if not labels:
            continue
        for other in inv.cluster_roles.values():
            if other is role:
                continue
            other_labels = (other.get("metadata") or {}).get("labels") or {}
            if all(other_labels.get(k) == v for k, v in labels.items()):
                if other not in matched:
                    matched.append(other)
    note = ""
    if expr_note:
        note = "matchExpressions selectors are not expanded — review them manually"
    return matched, note


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
            matched, expr_note = expand_aggregation(role, inv)
            evidence = ("ClusterRole uses aggregationRule with selector %s — "
                        "its effective rules expand at runtime" % (
                            (role.get("aggregationRule") or {}).get("clusterRoleSelectors"),))
            if matched:
                evidence += " — aggregates %d role(s): %s" % (
                    len(matched),
                    ", ".join("ClusterRole/%s" % obj_name(m) for m in matched))
            else:
                evidence += " — no ClusterRole in these manifests matches the selector"
            if expr_note:
                evidence += " (%s)" % expr_note
            f = make_finding("RBAC-010", role, evidence)
            # If an aggregated role brings in wildcard verbs/resources or
            # dangerous verbs, the aggregate is as dangerous as its parts:
            # escalate the finding instead of under-reporting it (v1.4).
            bad_parts = []
            for m in matched:
                for rule in m.get("rules") or []:
                    verbs = rule.get("verbs") or []
                    resources = rule.get("resources") or []
                    if "*" in verbs or "*" in resources or \
                            set(verbs) & {"escalate", "bind", "impersonate"}:
                        bad_parts.append("%s: verbs=%s resources=%s" % (
                            obj_name(m), verbs, resources))
            if bad_parts:
                f["severity"] = "high"
                f["points"] = SEVERITY_POINTS["high"]
                f["evidence"] += " — aggregated rules include: %s" % (
                    "; ".join(bad_parts))
            findings.append(f)
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

        # PSS-001 seccompProfile (restricted profile) — one per workload.
        seccomp = (pod_sc.get("seccompProfile") or {}).get("type")
        if seccomp not in ("RuntimeDefault", "Localhost"):
            findings.append(make_finding(
                "PSS-001", obj,
                "%s: seccompProfile.type is %s (restricted profile needs RuntimeDefault or Localhost)" % (
                    obj_id(obj), seccomp)))

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
            # PSS-002 capabilities.drop must include ALL
            drop = (csc.get("capabilities") or {}).get("drop") or []
            if "ALL" not in drop:
                findings.append(make_finding(
                    "PSS-002", obj,
                    "%s: capabilities.drop is %s (restricted profile needs drop: [ALL])" % (
                        where, drop)))
            # PSS-003 only NET_BIND_SERVICE may be added — and never
            # double-count what WL-010 already flags.
            extra = sorted(set(caps) - DANGEROUS_CAPABILITIES
                           - {"NET_BIND_SERVICE"})
            if extra:
                findings.append(make_finding(
                    "PSS-003", obj,
                    "%s: capabilities.add includes %s (restricted profile allows only NET_BIND_SERVICE)" % (
                        where, extra)))
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
        by_ns.setdefault(obj_ns(obj), []).append(obj)
    np_ns = {obj_ns(p) for p in inv.network_policies}
    for ns in sorted(by_ns):
        if ns not in np_ns:
            # The finding is about a namespace, not one object — point
            # it at the first workload in that namespace, so the report
            # shows where it came from (and live mode tags it live-cluster).
            fake = {"kind": "Namespace", "metadata": {"name": ns},
                    "__file__": by_ns[ns][0].get("__file__", "")}
            findings.append(make_finding(
                "NET-001", fake,
                "namespace '%s' runs workloads (%s) but has no NetworkPolicy" % (
                    ns, ", ".join(sorted(obj_name(o) for o in by_ns[ns]))),
                namespace=ns))
    return findings


# ---------------------------------------------------------------- cloud IAM
def _cloud_annotations(obj):
    """(identity_annotations, deprecated_annotations) on one object.

    identity_annotations: {annotation_key: (provider_label, value)} for
    current workload-identity mechanisms; deprecated_annotations the
    same for retired mechanisms (Azure pod-identity).
    """
    annotations = (obj.get("metadata") or {}).get("annotations") or {}
    identity, deprecated = {}, {}
    for key, value in annotations.items():
        if key in CLOUD_IDENTITY_ANNOTATIONS:
            identity[key] = (CLOUD_IDENTITY_ANNOTATIONS[key], value)
        elif key in DEPRECATED_IDENTITY_ANNOTATIONS:
            deprecated[key] = (DEPRECATED_IDENTITY_ANNOTATIONS[key], value)
    return identity, deprecated


def _broad_cloud_role(value):
    """Return the reason a cloud role reference is over-broad, or None.

    Judged only from the reference itself: a wildcard ARN, the AWS
    AdministratorAccess managed policy, or a role whose name is one of
    the known over-broad roles (Owner / Editor / Contributor / admin).
    GKE service-account emails and Azure client IDs carry no role
    information in the annotation, so they are never judged here — a
    scoped GKE/Azure identity fires IAM-001 only.
    """
    text = str(value or "")
    if "*" in text:
        return "wildcard '*' in the cloud role reference '%s'" % text
    lowered = text.lower()
    if "administratoraccess" in lowered:
        return "references the AWS AdministratorAccess policy '%s'" % text
    # AWS ARN: ...:role/<name> (or ...:role/service-role/<name>);
    # judge the role name only, never the account id or path.
    role_name = text.rsplit("/", 1)[-1].lower() if ":role/" in text else ""
    if role_name in BROAD_CLOUD_ROLES:
        return "references the over-broad cloud role '%s'" % text
    return None


def check_cloud_iam(inv):
    """IAM-001/002/003 — cloud workload-identity annotations (v1.4).

    Scans ServiceAccounts (where the annotations normally live) and
    workload pod templates (some setups annotate the pod). A pod that
    runs as a ServiceAccount mapped to a cloud role inherits that
    role's permissions in the cloud account — a cluster compromise
    becomes a cloud-account compromise.
    """
    findings = []
    targets = []
    for sa in inv.service_accounts.values():
        targets.append((sa, "ServiceAccount"))
    for obj in inv.workloads:
        spec = pod_spec(obj)
        if not spec:
            continue
        template = ((obj.get("spec") or {}).get("template") or {}).get(
            "metadata") or {}
        if obj.get("kind") == "Pod":
            template = obj.get("metadata") or {}
        if obj.get("kind") == "CronJob":
            template = ((((obj.get("spec") or {}).get("jobTemplate") or {})
                         .get("spec") or {}).get("template") or {}).get(
                             "metadata") or {}
        if template.get("annotations"):
            fake = {"kind": obj.get("kind"),
                    "metadata": {"name": obj_name(obj),
                                 "namespace": obj_ns(obj),
                                 "annotations": template.get("annotations")},
                    "__file__": obj.get("__file__", "")}
            targets.append((fake, "pod template of %s" % obj_id(obj)))
    for obj, where in targets:
        identity, deprecated = _cloud_annotations(obj)
        for key, (provider, value) in sorted(identity.items()):
            findings.append(make_finding(
                "IAM-001", obj,
                "%s of %s carries %s annotation '%s: %s' — the pod "
                "inherits the cloud role's permissions" % (
                    where, obj_id(obj), provider, key, value)))
            broad = _broad_cloud_role(value)
            if broad:
                findings.append(make_finding(
                    "IAM-002", obj,
                    "%s of %s %s" % (where, obj_id(obj), broad)))
        for key, (provider, value) in sorted(deprecated.items()):
            findings.append(make_finding(
                "IAM-001", obj,
                "%s of %s carries %s annotation '%s: %s' — the pod "
                "inherits the cloud role's permissions" % (
                    where, obj_id(obj), provider, key, value)))
            findings.append(make_finding(
                "IAM-003", obj,
                "%s of %s uses deprecated %s annotation '%s: %s'" % (
                    where, obj_id(obj), provider, key, value)))
    return findings


# ---------------------------------------------------------------- image CVEs
# Map an image repository (last path segment, without registry) to the
# NVD CPE product(s) to look up, in order. Only well-known public images
# are mapped — an unmapped image is reported as "no CPE mapping", never
# guessed at. (OSV was tried first: its API works, but it does not index
# container images — ecosystem "Docker" is rejected and pkg:docker purls
# return nothing — so the lookup uses the NVD API 2.0 instead.)
IMAGE_CPE_MAP = {
    "nginx": [("a", "f5", "nginx"), ("a", "nginx", "nginx")],
    "redis": [("a", "redis", "redis")],
    "postgres": [("a", "postgresql", "postgresql")],
    "mysql": [("a", "oracle", "mysql"), ("a", "mysql", "mysql")],
    "mongo": [("a", "mongodb", "mongodb")],
    "busybox": [("a", "busybox", "busybox")],
    "alpine": [("o", "alpinelinux", "alpine_linux")],
    "python": [("a", "python", "python")],
    "node": [("a", "nodejs", "node.js")],
    "golang": [("a", "golang", "go")],
    "go": [("a", "golang", "go")],
    "httpd": [("a", "apache", "http_server")],
    "memcached": [("a", "memcached", "memcached")],
    "rabbitmq": [("a", "rabbitmq", "rabbitmq")],
    "elasticsearch": [("a", "elastic", "elasticsearch")],
    "kibana": [("a", "elastic", "kibana")],
    "grafana": [("a", "grafana", "grafana")],
    "prometheus": [("a", "prometheus", "prometheus")],
    "traefik": [("a", "traefik", "traefik")],
    "vault": [("a", "hashicorp", "vault")],
    "consul": [("a", "hashicorp", "consul")],
    "wordpress": [("a", "wordpress", "wordpress")],
    "php": [("a", "php", "php")],
    "openjdk": [("a", "oracle", "openjdk")],
    "tomcat": [("a", "apache", "tomcat")],
    "envoy": [("a", "envoyproxy", "envoy")],
}

# NVD API 2.0 allows 5 requests per 30 seconds without an API key, so
# requests are spaced 6.5s apart; with RBACLENS_NVD_API_KEY set the
# limit is 50 per 30 seconds and 0.7s spacing is enough.
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY_NO_KEY = 6.5
NVD_DELAY_WITH_KEY = 0.7
NVD_TIMEOUT = 20


def _image_repo_tag(image):
    """Return (repo_last_segment, tag or None) for an image reference."""
    base = image.split("@")[0]
    repo = base.rsplit(":", 1)[0] if ":" in base.rsplit("/", 1)[-1] \
        else base
    tag = base.rsplit(":", 1)[1] if ":" in base.rsplit("/", 1)[-1] else None
    return repo.rsplit("/", 1)[-1].lower(), tag


def _precise_version(tag):
    """Return the leading exact dotted version (x.y.z) of a tag, or None.

    Only an exact version can be matched in NVD. 'latest', untagged,
    '7' and '3.19' return None — NVD would silently return nothing for
    those, which must never be reported as 'no CVEs'. A suffix such as
    '-alpine' is stripped: the query uses the leading version only.
    """
    if not tag or tag == "latest":
        return None
    match = re.match(r"(\d+\.\d+\.\d+)", tag)
    return match.group(1) if match else None


def _max_cvss(vuln):
    """Highest CVSS base score in an NVD vulnerability entry, or None."""
    metrics = (vuln.get("cve") or {}).get("metrics") or {}
    best = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key) or []:
            score = (entry.get("cvssData") or {}).get("baseScore")
            if isinstance(score, (int, float)):
                best = score if best is None else max(best, score)
    return best


def nvd_query_cpe(part, vendor, product, version, timeout=NVD_TIMEOUT):
    """Query the NVD API 2.0 for one CPE. Returns the parsed JSON dict.

    Raises ValueError on any network, HTTP or parse failure — the
    caller turns that into 'offline — CVE check skipped', never into
    invented data. A 429 (rate limit) is a ValueError too.
    """
    cpe = "cpe:2.3:%s:%s:%s:%s:*:*:*:*:*:*:*" % (
        part, vendor, product, version)
    url = "%s?%s" % (NVD_API_URL, urllib.parse.urlencode(
        {"cpeName": cpe, "resultsPerPage": 10}))
    headers = {"User-Agent": "RBACLens/%s (authorized security audit)"
               % VERSION}
    api_key = os.environ.get("RBACLENS_NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        raise ValueError("NVD API HTTP %s" % exc.code) from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ValueError("NVD API unreachable: %s" % exc) from exc


def check_cve(inv, fetcher=None):
    """CVE-001 — known CVEs for the images in the inventory (v1.4).

    Returns (findings, status). status is a dict with an overall
    'state' ('ok', 'offline' or 'not-run'), a human 'note', and a
    per-image record: 'checked' (with CVE count + top IDs), 'skipped'
    (reason: no CPE mapping / version not precise), or 'error'.

    fetcher(part, vendor, product, version) -> NVD JSON dict is
    injectable for tests; the default fetcher is nvd_query_cpe with
    the NVD rate-limit delay between requests. On ANY lookup failure
    the remaining images are marked 'error' and the state becomes
    'offline' — the scan never crashes and never claims 'no CVEs'
    for an image it could not actually check.
    """
    fetcher = fetcher or nvd_query_cpe
    delay = NVD_DELAY_WITH_KEY if os.environ.get("RBACLENS_NVD_API_KEY") \
        else NVD_DELAY_NO_KEY
    findings, per_image, state, note = [], {}, "ok", ""
    # Phase 1 — one lookup per distinct image, whatever uses it.
    images = []
    for obj in inv.workloads:
        spec = pod_spec(obj)
        if not spec:
            continue
        for container in (spec.get("containers") or []) + \
                (spec.get("initContainers") or []):
            image = container.get("image", "")
            if image and image not in images:
                images.append(image)
    first_request = True
    for image in images:
        repo, tag = _image_repo_tag(image)
        cands = IMAGE_CPE_MAP.get(repo)
        if not cands:
            per_image[image] = {"status": "skipped",
                                "reason": "no CPE mapping for image '%s' — CVE lookup not applicable" % repo}
            continue
        version = _precise_version(tag)
        if not version:
            per_image[image] = {
                "status": "skipped",
                "reason": "tag '%s' is not an exact version — pin an exact x.y.z tag for a CVE lookup" % tag}
            continue
        if state == "offline":
            per_image[image] = {"status": "error",
                                "reason": "CVE lookup stopped: NVD unreachable"}
            continue
        vulns, max_score = [], None
        try:
            for part, vendor, product in cands:
                # NVD rate limit: sleep between requests, never
                # before the first one.
                if not first_request:
                    time.sleep(delay)
                first_request = False
                data = fetcher(part, vendor, product, version)
                vulns = (data or {}).get("vulnerabilities") or []
                if vulns:
                    break
        except ValueError as exc:
            state, note = "offline", str(exc)
            per_image[image] = {"status": "error", "reason": str(exc)}
            continue
        ids = [(v.get("cve") or {}).get("id", "?") for v in vulns]
        for v in vulns:
            score = _max_cvss(v)
            if score is not None:
                max_score = score if max_score is None else max(
                    max_score, score)
        per_image[image] = {"status": "checked", "cves": len(ids),
                            "cve_ids": ids[:5],
                            "max_cvss": max_score}
    # Phase 2 — one CVE-001 finding per container using a vulnerable image.
    for obj in inv.workloads:
        spec = pod_spec(obj)
        if not spec:
            continue
        for container in (spec.get("containers") or []) + \
                (spec.get("initContainers") or []):
            image = container.get("image", "")
            record = per_image.get(image) or {}
            if record.get("status") != "checked" or not record.get("cves"):
                continue
            ids = record["cve_ids"]
            total = record["cves"]
            max_score = record.get("max_cvss")
            f = make_finding(
                "CVE-001", obj,
                "image '%s' has %d known CVE(s) (NVD): %s%s" % (
                    image, total, ", ".join(ids),
                    " (showing 5 of %d)" % total if total > 5 else ""))
            if max_score is not None:
                f["evidence"] += " — highest CVSS %.1f" % max_score
            if max_score is not None and max_score >= 9.0:
                f["severity"] = "critical"
                f["points"] = SEVERITY_POINTS["critical"]
            findings.append(f)
    if state == "offline":
        note = "CVE check incomplete — %s. Images not checked are " \
               "marked 'error', never reported as clean." % note
    elif not per_image:
        note = "no container images found to check"
    else:
        checked = sum(1 for v in per_image.values()
                      if v["status"] == "checked")
        note = "%d image(s) checked against NVD, %d skipped (%s)" % (
            checked, len(per_image) - checked,
            "no CPE mapping or no exact version tag")
    return findings, {"state": state, "note": note, "images": per_image}


def run_all_checks(inv, cve_findings=None):
    findings = check_rbac(inv) + check_workloads(inv) \
        + check_network_policies(inv) + check_cloud_iam(inv)
    if cve_findings:
        findings += cve_findings
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["rule"], f["object"]))
    return findings


def score_findings(findings):
    score = 100 + sum(f["points"] for f in findings)
    return max(0, min(100, score))


# ---------------------------------------------------------------- enforcement
# Admission-control policies and fixed manifests (v1.4). The audit is
# report-only no longer: from the findings, RBACLens can generate
# Kyverno ClusterPolicies and OPA Gatekeeper constraints that BLOCK the
# flagged patterns at admission time, and corrected copies of the
# manifests with the safe fixes applied.
#
# Kyverno JMESPath shapes: a Pod keeps its containers at spec.containers,
# a Deployment/StatefulSet/DaemonSet/Job at spec.template.spec, and a
# CronJob one level deeper (spec.jobTemplate.spec.template.spec). The
# expressions below try each shape in turn (JMESPath || falls through
# null/empty values), so one rule covers all of them.
def _containers_expr():
    return ("(request.object.spec.template.spec.containers || "
            "request.object.spec.containers || "
            "request.object.spec.jobTemplate.spec.template.spec.containers "
            "|| `[]`)")


def _podspec_expr():
    return ("(request.object.spec.template.spec || "
            "request.object.spec.jobTemplate.spec.template.spec || "
            "request.object.spec)")


def _volumes_expr():
    return ("(request.object.spec.template.spec.volumes || "
            "request.object.spec.volumes || "
            "request.object.spec.jobTemplate.spec.template.spec.volumes "
            "|| `[]`)")


WORKLOAD_MATCH_KINDS = ["Deployment", "StatefulSet", "DaemonSet", "Job",
                        "CronJob", "Pod", "ReplicaSet",
                        "ReplicationController"]


def _kyverno_rule(name, message, conditions, kinds=None):
    """One Kyverno validation rule with a deny block.

    conditions is a list of (key_jmespath, operator, value) tuples;
    a single condition goes under 'any', several under 'all'.
    """
    conds = [{"key": "{{ %s }}" % key, "operator": op, "value": value}
             for key, op, value in conditions]
    block = {"any": conds} if len(conds) == 1 else {"all": conds}
    return {
        "name": name,
        "match": {"any": [{"resources": {
            "kinds": kinds or WORKLOAD_MATCH_KINDS}}]},
        "validate": {"message": message, "deny": {"conditions": block}},
    }


def _kyverno_rules_for(categories):
    """Kyverno rules for the given enforcement categories."""
    c = _containers_expr()
    p = _podspec_expr()
    v = _volumes_expr()
    rules = []
    if "privileged" in categories:
        rules.append(_kyverno_rule(
            "block-privileged-containers",
            "RBACLens WL-001: privileged containers are not allowed.",
            [("%s[?securityContext.privileged == `true`] | length(@)"
              % c, "GreaterThan", 0)]))
    if "host-namespaces" in categories:
        for field, rule_id in (("hostNetwork", "WL-003"),
                               ("hostPID", "WL-004"),
                               ("hostIPC", "WL-005")):
            rules.append(_kyverno_rule(
                "block-host-%s" % field[4:].lower(),
                "RBACLens %s: %s is not allowed." % (rule_id, field),
                [("%s.%s" % (p, field), "Equals", True)]))
    if "hostpath" in categories:
        rules.append(_kyverno_rule(
            "block-hostpath-volumes",
            "RBACLens WL-006: hostPath volumes are not allowed.",
            [("%s[?hostPath] | length(@)" % v, "GreaterThan", 0)]))
    if "privilege-escalation" in categories:
        rules.append(_kyverno_rule(
            "block-privilege-escalation",
            "RBACLens WL-002: allowPrivilegeEscalation must be false.",
            [("%s[?securityContext.allowPrivilegeEscalation == `true`] "
              "| length(@)" % c, "GreaterThan", 0)]))
    if "run-as-root" in categories:
        # Container-level runAsNonRoot wins in Kubernetes; pod-level is
        # the fallback. Deny only when neither is true — a container
        # with an explicit runAsNonRoot: false under a pod-level true
        # is NOT caught by this rule (see the policy annotation).
        rules.append(_kyverno_rule(
            "require-run-as-non-root",
            "RBACLens WL-007: containers must run as non-root "
            "(runAsNonRoot: true).",
            [("%s[?securityContext.runAsNonRoot != `true`] | length(@)"
              % c, "GreaterThan", 0),
             ("%s.securityContext.runAsNonRoot" % p, "NotEquals", True)]))
    if "capabilities" in categories:
        rules.append(_kyverno_rule(
            "require-drop-all-capabilities",
            "RBACLens PSS-002: containers must drop ALL capabilities.",
            [("%s[?!contains(securityContext.capabilities.drop || `[]`, "
              "'ALL')] | length(@)" % c, "GreaterThan", 0)]))
        any_conds = []
        for cap in sorted(DANGEROUS_CAPABILITIES - {"ALL"}):
            any_conds.append({
                "key": "{{ %s[?contains(securityContext.capabilities.add "
                       "|| `[]`, '%s')] | length(@) }}" % (c, cap),
                "operator": "GreaterThan", "value": 0})
        rules.append({
            "name": "block-dangerous-capabilities",
            "match": {"any": [{"resources": {
                "kinds": WORKLOAD_MATCH_KINDS}}]},
            "validate": {
                "message": "RBACLens WL-010: dangerous Linux capabilities "
                           "are not allowed.",
                "deny": {"conditions": {"any": any_conds}}},
        })
    if "readonly-rootfs" in categories:
        rules.append(_kyverno_rule(
            "require-readonly-root-filesystem",
            "RBACLens WL-011: readOnlyRootFilesystem must be true.",
            [("%s[?securityContext.readOnlyRootFilesystem != `true`] "
              "| length(@)" % c, "GreaterThan", 0)]))
    if "seccomp" in categories:
        rules.append(_kyverno_rule(
            "require-seccomp-profile",
            "RBACLens PSS-001: seccompProfile.type must be "
            "RuntimeDefault or Localhost.",
            [("%s.securityContext.seccompProfile.type" % p,
              "NotEquals", "RuntimeDefault"),
             ("%s.securityContext.seccompProfile.type" % p,
              "NotEquals", "Localhost")]))
    if "image-latest" in categories:
        rules.append(_kyverno_rule(
            "block-latest-images",
            "RBACLens IMG-001: images must use an exact version tag, "
            "never :latest and never untagged.",
            [("%s[?ends_with(image, ':latest') || "
              "!contains(split(image, '/')[-1], ':')] | length(@)" % c,
              "GreaterThan", 0)]))
    if "sa-token" in categories:
        rules.append(_kyverno_rule(
            "block-service-account-token-mount",
            "RBACLens WL-009: automountServiceAccountToken must be false.",
            [("%s.automountServiceAccountToken" % p, "Equals", True)]))
    if "cluster-admin" in categories:
        rules.append({
            "name": "block-cluster-admin-bindings",
            "match": {"any": [{"resources": {
                "kinds": ["ClusterRoleBinding", "RoleBinding"]}}]},
            "validate": {
                "message": "RBACLens RBAC-001: bindings to the "
                           "cluster-admin role are not allowed.",
                "pattern": {"roleRef": {"name": "!cluster-admin"}}},
        })
    return rules


# Finding rule -> enforcement category. Categories with no rule in the
# findings are still generated when the scan is clean (baseline policy).
ADMISSION_CATEGORIES = {
    "privileged": {"WL-001"},
    "host-namespaces": {"WL-003", "WL-004", "WL-005"},
    "hostpath": {"WL-006"},
    "privilege-escalation": {"WL-002"},
    "run-as-root": {"WL-007"},
    "capabilities": {"WL-010", "PSS-002", "PSS-003"},
    "readonly-rootfs": {"WL-011"},
    "seccomp": {"PSS-001"},
    "image-latest": {"IMG-001"},
    "sa-token": {"WL-009"},
    "cluster-admin": {"RBAC-001"},
}


def admission_categories_for(findings):
    """Categories to enforce: those the findings prove are needed, or
    all of them when the scan is clean (baseline policy)."""
    found = {f["rule"] for f in findings}
    cats = {cat for cat, rules in ADMISSION_CATEGORIES.items()
            if found & rules}
    return cats or set(ADMISSION_CATEGORIES)


def build_kyverno_policy(findings):
    """Return a Kyverno ClusterPolicy (YAML text) enforcing the
    categories the findings call for. validationFailureAction is
    Enforce: matching objects are blocked at admission."""
    cats = admission_categories_for(findings)
    policy = {
        "apiVersion": "kyverno.io/v1",
        "kind": "ClusterPolicy",
        "metadata": {
            "name": "rbaclens-enforce",
            "annotations": {
                "policies.kyverno.io/title":
                    "RBACLens enforcement (generated by RBACLens %s)" % VERSION,
                "policies.kyverno.io/description":
                    "Blocks the patterns RBACLens flagged in this scan "
                    "(%d finding(s)). Generated from a scan — review "
                    "before applying with kubectl apply -f. Note: the "
                    "require-run-as-non-root rule does not catch a "
                    "container with an explicit runAsNonRoot: false "
                    "under a pod-level runAsNonRoot: true."
                    % len(findings),
                "rbaclens/categories": ",".join(sorted(cats)),
            },
        },
        "spec": {
            "validationFailureAction": "Enforce",
            "background": True,
            "rules": _kyverno_rules_for(cats),
        },
    }
    return yaml.safe_dump(policy, sort_keys=False, allow_unicode=True)


# ---------------------------------------------------------------- Gatekeeper
GATEKEEPER_REGO = '''package rbaclens

# One template covers the workload categories; a second one (below the
# --- separator, in the same bundle) covers RBAC bindings. Containers
# and pod specs are collected from every shape: plain Pods, workloads
# with a pod template, and CronJobs (one level deeper).

container(c) if {
    c := input.review.object.spec.containers[_]
}

container(c) if {
    c := input.review.object.spec.template.spec.containers[_]
}

container(c) if {
    c := input.review.object.spec.jobTemplate.spec.template.spec.containers[_]
}

podspec(s) if {
    s := input.review.object.spec
}

podspec(s) if {
    s := input.review.object.spec.template.spec
}

podspec(s) if {
    s := input.review.object.spec.jobTemplate.spec.template.spec
}

volumes(v) if {
    v := input.review.object.spec.volumes[_]
}

volumes(v) if {
    v := input.review.object.spec.template.spec.volumes[_]
}

volumes(v) if {
    v := input.review.object.spec.jobTemplate.spec.template.spec.volumes[_]
}

violation contains {"msg": msg} if {
    input.parameters.categories[_] == "privileged"
    container(c)
    c.securityContext.privileged == true
    msg := sprintf("RBACLens WL-001: privileged container %v is not allowed", [c.name])
}

violation contains {"msg": msg} if {
    input.parameters.categories[_] == "host-namespaces"
    podspec(s)
    s.hostNetwork == true
    msg := "RBACLens WL-003: hostNetwork is not allowed"
}

violation contains {"msg": msg} if {
    input.parameters.categories[_] == "host-namespaces"
    podspec(s)
    s.hostPID == true
    msg := "RBACLens WL-004: hostPID is not allowed"
}

violation contains {"msg": msg} if {
    input.parameters.categories[_] == "host-namespaces"
    podspec(s)
    s.hostIPC == true
    msg := "RBACLens WL-005: hostIPC is not allowed"
}

violation contains {"msg": msg} if {
    input.parameters.categories[_] == "hostpath"
    volumes(v)
    v.hostPath
    msg := sprintf("RBACLens WL-006: hostPath volume %v is not allowed", [v.name])
}

violation contains {"msg": msg} if {
    input.parameters.categories[_] == "privilege-escalation"
    container(c)
    c.securityContext.allowPrivilegeEscalation == true
    msg := sprintf("RBACLens WL-002: allowPrivilegeEscalation on container %v must be false", [c.name])
}

violation contains {"msg": msg} if {
    input.parameters.categories[_] == "run-as-root"
    container(c)
    c.securityContext.runAsNonRoot != true
    podspec(s)
    s.securityContext.runAsNonRoot != true
    msg := sprintf("RBACLens WL-007: container %v must run as non-root (runAsNonRoot: true)", [c.name])
}

violation contains {"msg": msg} if {
    input.parameters.categories[_] == "capabilities"
    container(c)
    not "ALL" in object.get(c.securityContext.capabilities, "drop", [])
    msg := sprintf("RBACLens PSS-002: container %v must drop ALL capabilities", [c.name])
}

violation contains {"msg": msg} if {
    input.parameters.categories[_] == "capabilities"
    container(c)
    some cap in object.get(c.securityContext.capabilities, "add", [])
    cap in {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE", "SETUID", "SETGID", "NET_RAW", "SYS_MODULE", "SYS_TIME"}
    msg := sprintf("RBACLens WL-010: dangerous capability %v on container %v is not allowed", [cap, c.name])
}

violation contains {"msg": msg} if {
    input.parameters.categories[_] == "readonly-rootfs"
    container(c)
    c.securityContext.readOnlyRootFilesystem != true
    msg := sprintf("RBACLens WL-011: container %v must set readOnlyRootFilesystem: true", [c.name])
}

violation contains {"msg": msg} if {
    input.parameters.categories[_] == "seccomp"
    podspec(s)
    s.securityContext.seccompProfile.type != "RuntimeDefault"
    s.securityContext.seccompProfile.type != "Localhost"
    msg := "RBACLens PSS-001: seccompProfile.type must be RuntimeDefault or Localhost"
}

violation contains {"msg": msg} if {
    input.parameters.categories[_] == "image-latest"
    container(c)
    image_untagged_or_latest(c.image)
    msg := sprintf("RBACLens IMG-001: image %v must use an exact version tag, never :latest and never untagged", [c.image])
}

image_untagged_or_latest(img) if {
    endswith(img, ":latest")
}

image_untagged_or_latest(img) if {
    parts := split(img, "/")
    last := parts[count(parts) - 1]
    not contains(last, ":")
}

violation contains {"msg": msg} if {
    input.parameters.categories[_] == "sa-token"
    podspec(s)
    s.automountServiceAccountToken == true
    msg := "RBACLens WL-009: automountServiceAccountToken must be false"
}
'''

GATEKEEPER_BINDING_REGO = '''package rbaclensbinding

violation contains {"msg": msg} if {
    input.review.object.roleRef.name == "cluster-admin"
    msg := "RBACLens RBAC-001: bindings to the cluster-admin role are not allowed"
}
'''


def build_gatekeeper_bundle(findings):
    """Return a Gatekeeper bundle (YAML text): a ConstraintTemplate +
    Constraint for the workload categories, and — when the scan found
    cluster-admin bindings (or is clean, i.e. baseline) — a second
    template + constraint for RBAC bindings."""
    cats = admission_categories_for(findings)
    docs = [{
        "apiVersion": "templates.gatekeeper.sh/v1",
        "kind": "ConstraintTemplate",
        "metadata": {"name": "rbaclensworkload"},
        "spec": {
            "crd": {"spec": {"names": {"kind": "RBACLensWorkload"},
                             "validation": {"openAPIV3Schema": {
                                 "type": "object",
                                 "properties": {"categories": {
                                     "type": "array",
                                     "items": {"type": "string"}}}}}}},
            "targets": [{"target": "admission.k8s.gatekeeper.sh",
                         "rego": GATEKEEPER_REGO}],
        },
    }, {
        "apiVersion": "constraints.gatekeeper.sh/v1beta1",
        "kind": "RBACLensWorkload",
        "metadata": {"name": "rbaclens-workload"},
        "spec": {
            "match": {"kinds": [{"apiGroups": ["apps", "batch", ""],
                                  "kinds": WORKLOAD_MATCH_KINDS}]},
            "parameters": {"categories": sorted(cats)},
        },
    }]
    if "cluster-admin" in cats:
        docs += [{
            "apiVersion": "templates.gatekeeper.sh/v1",
            "kind": "ConstraintTemplate",
            "metadata": {"name": "rbaclensbinding"},
            "spec": {
                "crd": {"spec": {"names": {"kind": "RBACLensBinding"},
                                 "validation": {"openAPIV3Schema": {
                                     "type": "object"}}}},
                "targets": [{"target": "admission.k8s.gatekeeper.sh",
                             "rego": GATEKEEPER_BINDING_REGO}],
            },
        }, {
            "apiVersion": "constraints.gatekeeper.sh/v1beta1",
            "kind": "RBACLensBinding",
            "metadata": {"name": "rbaclens-binding"},
            "spec": {
                "match": {"kinds": [
                    {"apiGroups": ["rbac.authorization.k8s.io"],
                     "kinds": ["ClusterRoleBinding", "RoleBinding"]}]},
            },
        }]
    return yaml.safe_dump_all(docs, sort_keys=False, allow_unicode=True)


# ---------------------------------------------------------------- --fix-out
DEFAULT_REQUESTS = {"cpu": "100m", "memory": "128Mi"}
DEFAULT_LIMITS = {"cpu": "500m", "memory": "256Mi"}


def _fix_container(container, where, applied):
    """Apply the safe fixes to one container dict. Returns True if
    anything changed."""
    changed = False
    csc = container.setdefault("securityContext", {})
    if csc.get("privileged") is True:
        csc["privileged"] = False
        applied.append("%s: privileged: true -> false" % where)
        changed = True
    if csc.get("allowPrivilegeEscalation") is True:
        csc["allowPrivilegeEscalation"] = False
        applied.append("%s: allowPrivilegeEscalation: true -> false" % where)
        changed = True
    if csc.get("runAsNonRoot") is not True:
        csc["runAsNonRoot"] = True
        applied.append("%s: runAsNonRoot -> true" % where)
        changed = True
    if csc.get("readOnlyRootFilesystem") is not True:
        csc["readOnlyRootFilesystem"] = True
        applied.append("%s: readOnlyRootFilesystem -> true" % where)
        changed = True
    caps = csc.setdefault("capabilities", {})
    drop = caps.setdefault("drop", [])
    if "ALL" not in drop:
        drop.append("ALL")
        applied.append("%s: capabilities.drop += ALL" % where)
        changed = True
    add = caps.get("add") or []
    removed = sorted(set(add) & DANGEROUS_CAPABILITIES)
    if removed:
        caps["add"] = [c for c in add if c not in DANGEROUS_CAPABILITIES]
        applied.append("%s: removed dangerous capabilities %s" % (
            where, removed))
        changed = True
    resources = container.setdefault("resources", {})
    for group, defaults in (("requests", DEFAULT_REQUESTS),
                            ("limits", DEFAULT_LIMITS)):
        grp = resources.setdefault(group, {})
        for key, value in defaults.items():
            if key not in grp:
                grp[key] = value
                applied.append("%s: resources.%s.%s -> %s (default, tune it)"
                               % (where, group, key, value))
                changed = True
    return changed


def fix_manifests(objects, findings):
    """Build fixed copies of the scanned manifests (v1.4).

    Returns (fixed_by_file, applied, manual):
    - fixed_by_file: {relative_path: [fixed docs]} — only files that
      changed (originals are never touched).
    - applied: human-readable lines of what was changed.
    - manual: findings that need a human (hostPath, cluster-admin,
      wildcards, image tags, NetworkPolicy, cloud IAM, CVEs).
    Only safe, mechanical fixes are applied: booleans that lock a pod
    down, drop ALL, and default resource requests/limits (labelled as
    defaults to tune). Anything that changes what the workload can do
    or reach is left for a human.
    """
    by_file = {}
    for obj in objects:
        fname = obj.get("__file__", "")
        if not fname or fname == "live-cluster":
            continue
        doc = copy.deepcopy(obj)
        doc.pop("__file__", None)
        by_file.setdefault(fname, []).append(doc)
    fixed_by_file, applied = {}, []
    for fname, docs in by_file.items():
        changed = False
        for doc in docs:
            if doc.get("kind") not in WORKLOAD_KINDS:
                continue
            spec = pod_spec(doc)
            if not spec:
                continue
            where = obj_id(doc)
            pod_sc = spec.setdefault("securityContext", {})
            for field in ("hostNetwork", "hostPID", "hostIPC"):
                if spec.get(field) is True:
                    spec[field] = False
                    applied.append("%s: %s: true -> false" % (where, field))
                    changed = True
            if spec.get("automountServiceAccountToken") is not False:
                spec["automountServiceAccountToken"] = False
                applied.append("%s: automountServiceAccountToken -> false"
                               % where)
                changed = True
            seccomp = pod_sc.setdefault("seccompProfile", {})
            if seccomp.get("type") not in ("RuntimeDefault", "Localhost"):
                seccomp["type"] = "RuntimeDefault"
                applied.append("%s: seccompProfile.type -> RuntimeDefault"
                               % where)
                changed = True
            if pod_sc.get("runAsNonRoot") is not True:
                pod_sc["runAsNonRoot"] = True
                applied.append("%s: pod runAsNonRoot -> true" % where)
                changed = True
            if "runAsUser" not in pod_sc:
                pod_sc["runAsUser"] = 10001
                applied.append("%s: pod runAsUser -> 10001" % where)
                changed = True
            for container in (spec.get("containers") or []) + \
                    (spec.get("initContainers") or []):
                cwhere = "%s container '%s'" % (
                    where, container.get("name", "?"))
                if _fix_container(container, cwhere, applied):
                    changed = True
        if changed:
            fixed_by_file[fname] = docs
    manual = []
    manual_rules = {"RBAC-001", "RBAC-002", "RBAC-003", "RBAC-004",
                    "RBAC-005", "RBAC-006", "RBAC-007", "RBAC-008",
                    "RBAC-009", "RBAC-010", "RBAC-011", "WL-006",
                    "IMG-001", "IMG-002", "NET-001", "IAM-001", "IAM-002",
                    "IAM-003", "CVE-001"}
    for f in findings:
        if f["rule"] in manual_rules:
            manual.append("[%s] %s — %s (%s)" % (
                f["severity"].upper(), f["rule"], f["title"], f["object"]))
    return fixed_by_file, applied, manual


def write_fix_output(objects, findings, out_dir):
    """Write fixed manifests + FIXES.md into out_dir. Returns the
    (files_written, applied_count, manual_count) tuple."""
    fixed_by_file, applied, manual = fix_manifests(objects, findings)
    os.makedirs(out_dir, exist_ok=True)
    written = 0
    for fname, docs in fixed_by_file.items():
        # Keep the scanned folder's relative layout under out_dir.
        rel = os.path.basename(fname)
        dest = os.path.join(out_dir, rel)
        with open(dest, "w", encoding="utf-8") as fh:
            yaml.safe_dump_all(docs, fh, sort_keys=False,
                               allow_unicode=True)
        written += 1
    lines = ["# RBACLens fixed manifests",
             "",
             "Generated by RBACLens %s from a scan. These are SUGGESTED "
             "fixes — review every change, re-scan the fixed folder with "
             "RBACLens, and only then apply them to a cluster you own or "
             "have written permission to change." % VERSION,
             "",
             "## Applied fixes (%d)" % len(applied)]
    lines += ["- %s" % a for a in applied] or ["- (none — nothing was auto-fixable)"]
    lines += ["", "## Needs a human (%d)" % len(manual),
              "",
              "These findings cannot be fixed mechanically — they change "
              "what the workload can do or reach, or need a version a "
              "tool cannot invent (image tags, cloud roles, CVEs):",
              ""]
    lines += ["- %s" % m for m in manual] or ["- (none)"]
    lines += ["",
              "Note: YAML comments and original formatting are not "
              "preserved in the fixed files (they are re-serialised). "
              "Check the diff before applying.",
              ""]
    with open(os.path.join(out_dir, "FIXES.md"), "w",
              encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return written, len(applied), len(manual)


# ---------------------------------------------------------------- reports
def summary_counts(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def build_text_report(path, inv, findings, score, grade, errors,
                      cve_status=None):
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
    lines.extend(textwrap.wrap(DISCLAIMER, 64))
    lines.append("")
    lines.append("Inventory: %d objects (%d Roles, %d ClusterRoles, "
                 "%d RoleBindings, %d ClusterRoleBindings, %d ServiceAccounts, "
                 "%d workloads, %d NetworkPolicies)" % (
                     c["objects"], c["roles"], c["cluster_roles"],
                     c["role_bindings"], c["cluster_role_bindings"],
                     c["service_accounts"], c["workloads"],
                     c["network_policies"]))
    if c["roles"] + c["cluster_roles"] + c["role_bindings"] \
            + c["cluster_role_bindings"] + c["workloads"] == 0:
        # A folder with objects but nothing auditable must never look
        # like a clean bill of health (v1.4: the false-clean guard).
        lines.append("WARNING: inventory contains no roles, bindings or "
                     "workloads — check the folder is complete; a clean "
                     "score here may mean files are missing, not that "
                     "the cluster is secure.")
    if cve_status is not None:
        lines.append("CVE check (--cve): %s — %s" % (
            cve_status.get("state", "?"), cve_status.get("note", "")))
        for image, rec in (cve_status.get("images") or {}).items():
            if rec.get("status") == "checked":
                lines.append("  - %s: %d CVE(s)%s" % (
                    image, rec.get("cves", 0),
                    (" (%s)" % ", ".join(rec.get("cve_ids") or []))
                    if rec.get("cve_ids") else ""))
            else:
                lines.append("  - %s: %s — %s" % (
                    image, rec.get("status", "?"),
                    rec.get("reason", "")))
    else:
        lines.append("CVE check: not run (use --cve to look images up in "
                     "the NVD vulnerability database)")
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
    lines.append("Lab use only — audit only manifests or clusters you own or "
                 "have written permission to audit.")
    return "\n".join(lines) + "\n"


def build_json_report(path, inv, findings, score, grade, errors,
                      cve_status=None):
    return {
        "tool": "RBACLens",
        "version": VERSION,
        "author": AUTHOR,
        "disclaimer": DISCLAIMER,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "path": path,
        "inventory": inv.counts(),
        "parse_errors": errors,
        "score": score,
        "grade": grade,
        "summary": summary_counts(findings),
        "total_findings": len(findings),
        "cve": cve_status,
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


def print_config(target, args):
    """Gobuster-style config block, like SSTIProbe's do_scan()."""
    if args.quiet:
        return
    header("SCAN")
    info("Target", target)
    info("Output", args.output)
    info("JSON report", args.json or "—")
    info("Min severity", args.min_severity or "all")
    checks = args.check or "all %d" % len(RULES)
    if args.skip_check:
        checks += " (skip %s)" % args.skip_check
    info("Checks", checks)
    info("Fail on", args.fail_on or "critical (default)")
    info("CVE lookup (NVD)", "on (--cve)" if getattr(args, "cve", False)
         else "off")
    info("Admission output", getattr(args, "admission_out", None) or "—")
    info("Gatekeeper output", getattr(args, "gatekeeper_out", None) or "—")
    info("Fixed manifests", getattr(args, "fix_out", None) or "—")
    sep()


def finish_scan(target, inv, findings, errors, args, objects=None,
                cve_status=None):
    """Filters, summary, reports and exit code — shared by file scans
    and live-cluster scans. Returns (exit_code, findings, score, grade).

    Admission policies and fixed manifests are generated from the FULL
    findings, not the filtered display — a --min-severity filter must
    never silently drop a category from the enforcement output."""
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
    if cve_status is not None:
        if cve_status.get("state") == "offline":
            warn("CVE check incomplete — %s" % cve_status.get("note", ""))
        else:
            info("CVE check", cve_status.get("note", ""))

    report = build_text_report(target, inv, shown, score, grade, errors,
                               cve_status=cve_status)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)
    ok("Report saved: %s" % args.output)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(build_json_report(target, inv, shown, score, grade,
                                        errors, cve_status=cve_status),
                      fh, indent=2)
        ok("JSON report saved: %s" % args.json)
    if getattr(args, "admission_out", None):
        with open(args.admission_out, "w", encoding="utf-8") as fh:
            fh.write(build_kyverno_policy(findings))
        ok("Kyverno policy saved: %s" % args.admission_out)
    if getattr(args, "gatekeeper_out", None):
        with open(args.gatekeeper_out, "w", encoding="utf-8") as fh:
            fh.write(build_gatekeeper_bundle(findings))
        ok("Gatekeeper bundle saved: %s" % args.gatekeeper_out)
    if getattr(args, "fix_out", None):
        if objects is None:
            warn("--fix-out needs the scanned objects; skipped")
        else:
            written, applied_n, manual_n = write_fix_output(
                objects, findings, args.fix_out)
            ok("Fixed manifests saved: %s (%d file(s), %d fix(es), "
               "%d need a human)" % (args.fix_out, written, applied_n,
                                     manual_n))
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


def scan_path(path, args):
    """Run a full scan of a manifest file or folder.
    Returns (exit_code, findings, score, grade)."""
    if yaml is None:
        err("PyYAML is not installed. Run: python run.py setup")
        err("  or: pip install pyyaml")
        return 2, [], 0, "F"
    print_config(path, args)
    try:
        objects, errors = collect_manifests(path)
    except ValueError as exc:
        err(str(exc))
        return 2, [], 0, "F"
    if not objects and not errors:
        # v1.4: an empty scan is NOT a clean scan. Reporting 100/A for
        # a folder with nothing in it was the false-clean bug in the
        # v1.3 report — fail loudly instead.
        err("No Kubernetes manifests found in %s — nothing was audited. "
            "Check the path and that the folder actually contains "
            "manifests; no report was written." % path)
        return 2, [], 0, "F"
    inv = Inventory(objects)
    cve_findings, cve_status = [], None
    if getattr(args, "cve", False):
        cve_findings, cve_status = check_cve(inv)
    findings = run_all_checks(inv, cve_findings=cve_findings)
    return finish_scan(path, inv, findings, errors, args, objects=objects,
                       cve_status=cve_status)


def scan_live(args):
    """Run a full scan of a live cluster via kubectl — the same checks,
    the same report, only the source differs. Returns the same tuple
    as scan_path. The report's target is 'live-cluster' (plus namespace
    when one is given); every finding's file is 'live-cluster'."""
    if yaml is None:
        err("PyYAML is not installed. Run: python run.py setup")
        err("  or: pip install pyyaml")
        return 2, [], 0, "F"
    target = "live-cluster"
    if args.namespace:
        target += " (namespace %s)" % args.namespace
    print_config(target, args)
    try:
        objects, errors = collect_live(
            namespace=args.namespace, context=args.context)
    except ValueError as exc:
        err(str(exc))
        return 2, [], 0, "F"
    if not objects and not errors:
        err("No Kubernetes resources found in the live cluster — nothing "
            "was audited. Check the cluster is reachable and the "
            "namespace is right; no report was written.")
        return 2, [], 0, "F"
    inv = Inventory(objects)
    cve_findings, cve_status = [], None
    if getattr(args, "cve", False):
        cve_findings, cve_status = check_cve(inv)
    findings = run_all_checks(inv, cve_findings=cve_findings)
    return finish_scan(target, inv, findings, errors, args, objects=objects,
                       cve_status=cve_status)


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
# Same menu shape as SSTIProbe (GhostTrack / TraceRecon): clear screen,
# banner, numbered options between '═' rule lines, then asks
# "[ ? ] Select option : ". After each option: "Press enter to continue"
# and loop back; Ctrl+C prints "[ ! ] Exit".
MENU_OPTIONS = [
    (1, "Scan a folder of manifests", "scan"),
    (2, "Quick scan: test manifests (bad — planted flaws)", "bad"),
    (3, "Quick scan: test manifests (clean — should pass)", "clean"),
    (4, "Show RBAC inventory of a folder", "inventory"),
    (5, "List all checks", "checks"),
    (6, "Run step tests", "test"),
    (7, "Check setup (doctor)", "doctor"),
    (8, "Scan live cluster (kubectl)", "live"),
    (9, "Enforce: admission policies + fixed manifests for a folder", "enforce"),
    (0, "Exit", None),
]


def ask(prompt, default=""):
    """Ask one [?] question; Enter on its own takes the default."""
    shown = f"{default}" if default else ""
    try:
        value = input(f"{C.CYN}[?]{C.RESET} {prompt} [{shown}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise
    return value or default


def menu_scan(args, default_path, default_output):
    path = ask("ENTER MANIFEST FOLDER OR FILE", default_path)
    if not path:
        path = default_path
    out = ask("ENTER REPORT FILE", default_output)
    args.output = out or default_output
    return scan_path(path, args)


def doctor():
    """Menu option 7: is the setup ready? (SSTIProbe's menu option 5
    checks the lab is reachable; RBACLens checks its own setup.)"""
    header("SETUP CHECK")
    ok("Python %s" % sys.version.split()[0])
    if yaml is not None:
        ok("PyYAML %s" % yaml.__version__)
    else:
        warn("PyYAML is NOT installed — run: python run.py setup")
    base = os.path.dirname(os.path.abspath(__file__))
    bad = os.path.join(base, "test_manifests", "bad")
    clean = os.path.join(base, "test_manifests", "clean")
    if os.path.isdir(bad):
        ok("Test manifests (bad): %s" % bad)
    else:
        warn("Test manifests (bad) missing: %s" % bad)
    if os.path.isdir(clean):
        ok("Test manifests (clean): %s" % clean)
    else:
        warn("Test manifests (clean) missing: %s" % clean)
    # Live-cluster mode (v1.1): kubectl is optional — file scans work
    # without it, so a missing kubectl is a warning, not a failure.
    kubectl = shutil.which("kubectl")
    if kubectl:
        ok("kubectl found: %s" % kubectl)
        try:
            proc = subprocess.run(["kubectl", "cluster-info"],
                                  capture_output=True, text=True, timeout=15)
        except OSError:
            proc = None
        if proc is not None and proc.returncode == 0:
            ok("Cluster reachable (kubectl cluster-info OK) — live mode ready")
        else:
            warn("kubectl found, but no cluster reachable — live mode needs "
                 "a cluster (minikube / kind / kubeconfig); file scans work")
    else:
        warn("kubectl NOT found — live-cluster mode unavailable; "
             "file scans still work")
    # CVE lookup (v1.4): optional, needs network. A failed check here
    # is a warning only — --cve degrades to 'offline, skipped' at
    # scan time and never blocks a file scan.
    try:
        nvd_query_cpe("a", "redis", "redis", "7.0.0", timeout=8)
        ok("NVD API reachable — --cve image lookup will work")
    except ValueError:
        warn("NVD API not reachable — --cve lookups will be skipped "
             "with a note (file scans still work)")
    if yaml is None:
        warn("Doctor: something is missing (see [!] lines above).")
        return 1
    ok("Doctor: all good. Run option 2 to scan the bad manifests.")
    return 0


def show_menu():
    """Clear screen, banner, then the numbered menu."""
    clear()
    banner()
    sep(C.GRN, "═")
    for num, label, _key in MENU_OPTIONS:
        print(f" {C.GRN}[{C.WHT}{num:>2}{C.GRN}]{C.RST} {C.WHT}{label}{C.RST}")
    sep(C.GRN, "═")


def menu(args):
    base = os.path.dirname(os.path.abspath(__file__))
    bad = os.path.join(base, "test_manifests", "bad")
    clean = os.path.join(base, "test_manifests", "clean")
    while True:
        show_menu()
        try:
            choice = input(f"{C.WHT}\n [ ? ] {C.GRN}Select option{C.WHT} : {C.GRN}").strip()
            print(C.RST, end="")
            if choice == "0":
                print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
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
                path = ask("ENTER MANIFEST FOLDER OR FILE", bad)
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
            elif choice == "7":
                doctor()
            elif choice == "8":
                args.namespace = ask("ENTER NAMESPACE (Enter = all namespaces)", "")
                args.context = ask("ENTER KUBECTL CONTEXT (Enter = default)", "")
                args.output = "rbaclens_live_report.txt"
                code, _f, _s, _g = scan_live(args)
                print("Exit code: %d" % code)
            elif choice == "9":
                path = ask("ENTER MANIFEST FOLDER OR FILE", bad)
                args.output = "rbaclens_report.txt"
                args.admission_out = "rbaclens-admission-kyverno.yaml"
                args.gatekeeper_out = "rbaclens-admission-gatekeeper.yaml"
                args.fix_out = "rbaclens-fixed"
                code, _f, _s, _g = scan_path(path or bad, args)
                print("Exit code: %d" % code)
                args.admission_out = None
                args.gatekeeper_out = None
                args.fix_out = None
            else:
                err("Please input a number from the menu (0-9).")
                time.sleep(1)
                continue
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
            return 0
        # GhostTrack pattern: pause, then loop back to the menu.
        try:
            input(f"\n{C.WHT}[ {C.GRN}+ {C.WHT}] {C.GRN}Press enter to continue{C.RST}")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
    return 0


# ---------------------------------------------------------------- CLI
def build_parser():
    p = argparse.ArgumentParser(
        prog="rbaclens",
        description="RBACLens — Kubernetes RBAC and Workload Auditor "
                    "(manifest files, or a live cluster with --live).")
    p.add_argument("path", nargs="?", default=None,
                   help="manifest file or folder to audit")
    p.add_argument("--live", action="store_true",
                   help="scan a live cluster via kubectl instead of files")
    p.add_argument("-n", "--namespace", default=None, metavar="NAME",
                   help="live mode: one namespace only (default: all)")
    p.add_argument("--context", default=None, metavar="NAME",
                   help="live mode: kubectl context (default: current)")
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
    p.add_argument("--cve", action="store_true",
                   help="look container images up in the NVD vulnerability "
                        "database (needs network; offline it is skipped "
                        "with a clear note, never a crash)")
    p.add_argument("--admission-out", default=None, metavar="FILE",
                   help="write a Kyverno ClusterPolicy (Enforce) that "
                        "blocks the flagged patterns")
    p.add_argument("--gatekeeper-out", default=None, metavar="FILE",
                   help="write an OPA Gatekeeper bundle (ConstraintTemplate "
                        "+ Constraints) that blocks the flagged patterns")
    p.add_argument("--fix-out", default=None, metavar="DIR",
                   help="write corrected copies of the manifests (safe "
                        "fixes only) plus FIXES.md into DIR")
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
        try:
            if args.live:
                objects, errors = collect_live(
                    namespace=args.namespace, context=args.context)
            else:
                if not args.path:
                    err("Give a manifest file or folder for --inventory.")
                    return 2
                objects, errors = collect_manifests(args.path)
        except ValueError as exc:
            err(str(exc))
            return 2
        if objects:
            print_inventory(Inventory(objects))
        for e in errors:
            warn("Parse error: %s" % e)
        return 0
    if args.live:
        code, _findings, _score, _grade = scan_live(args)
        return code
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
