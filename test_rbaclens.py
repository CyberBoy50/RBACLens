#!/usr/bin/env python3
"""RBACLens step tests — one test per PDF build-plan step.

Step 1 — parse one manifest (every object prints)
Step 2 — RBAC inventory (check it against the files by hand)
Step 3 — cluster-admin detection (planted binding flagged, least-privilege not)
Step 4 — wildcard detection (planted wildcard flagged, specific rule not)
Step 5 — workload checks (3 planted flaws all reported, clean Deployment passes)
Step 6 — CLI arguments and report (two folders, both reports complete)
Step 7 — full run on a test folder (every planted flaw in the report)
Step 8 — live-cluster mode (v1.1): a fake kubectl prints the bad
manifests as a kind: List dump; collect_live() must find the same
21 objects and 62 findings, and missing/failing kubectl must fail
loudly instead of scanning nothing.
Step 9 — Pod Security Standards (v1.2): PSS-001/002/003 on synthetic
workloads — seccomp missing/wrong type, drop ALL missing, NET_BIND_SERVICE
allowed, no double-count with WL-010.
Step 10 — Zero-limits (v1.4): cloud IAM rules (IRSA / GKE / Azure
annotations, over-broad roles, deprecated pod-identity), image CVE
lookup via NVD (stub fetcher + a best-effort live check), RBAC-010
aggregation expansion, Kyverno + Gatekeeper admission output, --fix-out
remediation, and the empty-folder false-clean guard.

Run:  python run.py test        or        python test_rbaclens.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import rbaclens  # noqa: E402

BAD = os.path.join(HERE, "test_manifests", "bad")
CLEAN = os.path.join(HERE, "test_manifests", "clean")
PASSED = 0


def check(name, condition, detail=""):
    global PASSED
    status = "PASS" if condition else "FAIL"
    print("  [%s] %s %s" % (status, name, detail))
    if not condition:
        raise AssertionError("FAILED: %s %s" % (name, detail))
    PASSED += 1


def scan(path):
    objects, errors = rbaclens.collect_manifests(path)
    assert not errors, "parse errors: %s" % errors
    inv = rbaclens.Inventory(objects)
    return inv, rbaclens.run_all_checks(inv)


def step1():
    print("Step 1 — parse one manifest")
    objects, errors = rbaclens.collect_manifests(
        os.path.join(BAD, "rbac-bad.yaml"))
    check("no parse errors", not errors)
    kinds = sorted({o.get("kind") for o in objects})
    check("every object parsed", len(objects) == 11, "(%d objects)" % len(objects))
    check("kinds seen", kinds == ["ClusterRole", "ClusterRoleBinding",
                                  "Role", "RoleBinding"],
          "(%s)" % ", ".join(kinds))
    for o in objects:
        print("    %s/%s" % (o.get("kind"), rbaclens.obj_name(o)))


def step2():
    print("Step 2 — RBAC inventory")
    inv, _ = scan(BAD)
    c = inv.counts()
    check("roles", c["roles"] == 2, "(%d)" % c["roles"])
    check("cluster_roles", c["cluster_roles"] == 4, "(%d)" % c["cluster_roles"])
    check("role_bindings", c["role_bindings"] == 3, "(%d)" % c["role_bindings"])
    check("cluster_role_bindings", c["cluster_role_bindings"] == 2,
          "(%d)" % c["cluster_role_bindings"])
    check("service_accounts", c["service_accounts"] == 4, "(%d)" % c["service_accounts"])
    check("workloads", c["workloads"] == 6, "(%d)" % c["workloads"])
    check("network_policies", c["network_policies"] == 0, "(%d)" % c["network_policies"])
    # kind: List was flattened (the ipc-pod inside mixed.yaml counts)
    names = {rbaclens.obj_name(o) for o in inv.objects}
    check("List flattened", "ipc-pod" in names)


def step3():
    print("Step 3 — cluster-admin detection")
    inv, findings = scan(BAD)
    ca = [f for f in findings if f["rule"] == "RBAC-001"]
    check("cluster-admin bindings flagged", len(ca) == 2, "(%d)" % len(ca))
    check("subject named (superadmin SA)",
          any("superadmin" in f["evidence"] for f in ca))
    check("subject named (alice)",
          any("alice@example.com" in f["evidence"] for f in ca))
    _inv2, findings2 = scan(CLEAN)
    check("least-privilege binding NOT flagged",
          not [f for f in findings2 if f["rule"] == "RBAC-001"])


def step4():
    print("Step 4 — wildcard detection")
    _inv, findings = scan(BAD)
    wild = {f["rule"] for f in findings if f["rule"].startswith("RBAC-00")
            and f["rule"] in ("RBAC-002", "RBAC-003", "RBAC-004")}
    check("wildcard verbs flagged", "RBAC-002" in wild)
    check("wildcard resources flagged", "RBAC-003" in wild)
    check("wildcard apiGroups flagged", "RBAC-004" in wild)
    _inv2, findings2 = scan(CLEAN)
    check("specific rule NOT flagged",
          not [f for f in findings2 if f["rule"] in
               ("RBAC-002", "RBAC-003", "RBAC-004")])


def step5():
    print("Step 5 — workload checks")
    _inv, findings = scan(BAD)
    wl = {f["rule"] for f in findings if f["rule"].startswith("WL-")}
    for rule in ("WL-001", "WL-003", "WL-004", "WL-006", "WL-007", "WL-008"):
        check("planted flaw %s reported" % rule, rule in wl)
    check("hostPath docker.sock is critical",
          any(f["rule"] == "WL-006" and f["severity"] == "critical"
              for f in findings))
    check("privileged is critical",
          any(f["rule"] == "WL-001" and f["severity"] == "critical"
              for f in findings))
    _inv2, findings2 = scan(CLEAN)
    check("clean Deployment passes (no WL findings)",
          not [f for f in findings2 if f["rule"].startswith("WL-")],
          "(%d)" % len([f for f in findings2 if f["rule"].startswith("WL-")]))
    # PSS on the fixtures: 5 workloads without seccomp, 5 containers
    # without drop ALL, one CHOWN add (PSS-003) — clean passes all three.
    pss = [f for f in findings if f["rule"].startswith("PSS-")]
    check("PSS-001 fires once per workload (5)",
          len([f for f in pss if f["rule"] == "PSS-001"]) == 5,
          "(%d)" % len([f for f in pss if f["rule"] == "PSS-001"]))
    check("PSS-002 fires once per container (5)",
          len([f for f in pss if f["rule"] == "PSS-002"]) == 5,
          "(%d)" % len([f for f in pss if f["rule"] == "PSS-002"]))
    check("PSS-003 fires once (CHOWN)",
          len([f for f in pss if f["rule"] == "PSS-003"]) == 1,
          "(%d)" % len([f for f in pss if f["rule"] == "PSS-003"]))
    check("PSS-003 names CHOWN, not the WL-010 caps",
          any("CHOWN" in f["evidence"] and "SYS_ADMIN" not in f["evidence"]
              for f in pss if f["rule"] == "PSS-003"))
    check("clean workload passes all PSS rules",
          not [f for f in findings2 if f["rule"].startswith("PSS-")])


def step6():
    print("Step 6 — CLI arguments and report")
    py = sys.executable
    for folder, report in ((BAD, "report_bad.txt"), (CLEAN, "report_clean.txt")):
        out = os.path.join(HERE, report)
        proc = subprocess.run(
            [py, os.path.join(HERE, "rbaclens.py"), folder,
             "-o", out, "--json", out.replace(".txt", ".json"), "-q"],
            capture_output=True, text=True)
        check("CLI runs on %s" % folder, proc.returncode in (0, 1, 2),
              "(exit %d)" % proc.returncode)
        check("report exists: %s" % report, os.path.isfile(out))
        text = open(out, encoding="utf-8").read()
        check("report has score", "Score:" in text)
        check("report has findings section", "Findings:" in text)
    bad_text = open(os.path.join(HERE, "report_bad.txt"), encoding="utf-8").read()
    check("bad report lists cluster-admin", "RBAC-001" in bad_text)
    check("bad report carries the disclaimer",
          "DISCLAIMER — AUTHORIZED USE ONLY" in bad_text
          and "PECA 2016" in bad_text)
    import json as _json
    bad_json = _json.load(open(os.path.join(HERE, "report_bad.json"),
                               encoding="utf-8"))
    check("bad JSON report carries the disclaimer field",
          bad_json.get("disclaimer", "").startswith(
              "DISCLAIMER — AUTHORIZED USE ONLY")
          and "PECA 2016" in bad_json.get("disclaimer", ""))
    clean_text = open(os.path.join(HERE, "report_clean.txt"), encoding="utf-8").read()
    check("clean report has no findings", "No findings." in clean_text)


def step7():
    print("Step 7 — full run on a test folder")
    inv, findings = scan(BAD)
    rules = {f["rule"] for f in findings}
    expected = {"RBAC-001", "RBAC-002", "RBAC-003", "RBAC-004", "RBAC-005",
                "RBAC-006", "RBAC-008", "RBAC-009", "RBAC-010", "RBAC-011",
                "WL-001", "WL-002", "WL-003", "WL-004", "WL-005", "WL-006",
                "WL-007", "WL-008", "WL-009", "WL-010", "WL-011",
                "IMG-001", "IMG-002", "NET-001",
                "PSS-001", "PSS-002", "PSS-003",
                "IAM-001", "IAM-002", "IAM-003"}
    missing = expected - rules
    check("every planted flaw in the report", not missing,
          ("(missing: %s)" % ", ".join(sorted(missing))) if missing else
          "(%d findings, %d rules)" % (len(findings), len(rules)))
    counts = rbaclens.summary_counts(findings)
    check("bad folder: 62 findings", len(findings) == 62,
          "(%d)" % len(findings))
    check("bad folder: 8 critical, 23 high, 20 medium, 11 low",
          counts == {"critical": 8, "high": 23, "medium": 20, "low": 11},
          "(%s)" % counts)
    score = rbaclens.score_findings(findings)
    check("score is low for a bad folder", score < 60, "(score %d)" % score)
    check("grade is F", rbaclens.grade_for(score) == "F")
    _inv2, findings2 = scan(CLEAN)
    check("clean folder scores 100", rbaclens.score_findings(findings2) == 100)
    check("clean folder has zero findings", len(findings2) == 0)


def step8():
    print("Step 8 — live-cluster mode (fake kubectl)")
    import yaml
    # Assemble a kind: List dump from the bad manifests, the way
    # `kubectl get ... -o yaml` returns them.
    items = []
    for name in ("rbac-bad.yaml", "workload-bad.yaml", "mixed.yaml",
                 "cloud-bad.yaml"):
        with open(os.path.join(BAD, name), encoding="utf-8") as fh:
            for doc in yaml.safe_load_all(fh):
                if not isinstance(doc, dict):
                    continue
                if doc.get("kind") == "List":
                    items.extend(doc.get("items") or [])
                elif doc.get("kind"):
                    items.append(doc)
    tmpdir = tempfile.mkdtemp(prefix="rbaclens-fake-kubectl-")
    dump = os.path.join(tmpdir, "cluster-dump.yaml")
    with open(dump, "w", encoding="utf-8") as fh:
        yaml.safe_dump({"apiVersion": "v1", "kind": "List", "items": items},
                       fh)
    script = os.path.join(tmpdir, "kubectl")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\ncat %s\n" % dump)
    os.chmod(script, 0o755)
    old_path = os.environ.get("PATH", "")
    try:
        os.environ["PATH"] = tmpdir + os.pathsep + old_path
        objects, errors = rbaclens.collect_live()
        check("fake kubectl returns 21 objects", len(objects) == 21,
              "(%d)" % len(objects))
        check("no parse errors", not errors)
        inv = rbaclens.Inventory(objects)
        findings = rbaclens.run_all_checks(inv)
        check("live scan finds 62 findings", len(findings) == 62,
              "(%d)" % len(findings))
        check("live scan finds the IAM rules",
              {"IAM-001", "IAM-002", "IAM-003"} <=
              {f["rule"] for f in findings})
        check("live mode fetches ReplicaSets (v1.4)",
              "replicasets" in rbaclens.LIVE_RESOURCES)
        check("live scan finds the PSS rules",
              {"PSS-001", "PSS-002", "PSS-003"} <=
              {f["rule"] for f in findings})
        check("live findings tagged live-cluster",
              all(f["file"] == "live-cluster" for f in findings))
        check("live scan finds cluster-admin",
              any(f["rule"] == "RBAC-001" for f in findings))
        check("live score is 0/100",
              rbaclens.score_findings(findings) == 0)
        # kubectl exits 1 -> loud error, not an empty scan.
        with open(script, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\necho 'Unable to connect to the server' >&2\n"
                     "exit 1\n")
        os.chmod(script, 0o755)
        try:
            rbaclens.collect_live()
            check("failing kubectl raises", False)
        except ValueError as exc:
            check("failing kubectl raises", "kubectl failed" in str(exc),
                  "(%s)" % exc)
    finally:
        os.environ["PATH"] = old_path
        shutil.rmtree(tmpdir, ignore_errors=True)
    # No kubectl at all -> loud error.
    empty = tempfile.mkdtemp(prefix="rbaclens-no-kubectl-")
    try:
        os.environ["PATH"] = empty
        try:
            rbaclens.collect_live()
            check("missing kubectl raises", False)
        except ValueError as exc:
            check("missing kubectl raises", "kubectl not found" in str(exc),
                  "(%s)" % exc)
    finally:
        os.environ["PATH"] = old_path
        shutil.rmtree(empty, ignore_errors=True)


def _ctr(name, csc=None):
    """A container with safe defaults, so only the planted PSS flaw fires."""
    base = {"runAsNonRoot": True, "readOnlyRootFilesystem": True,
            "allowPrivilegeEscalation": False}
    base.update(csc or {})
    return {"name": name,
            "image": "nginx:1.27.4@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "securityContext": base,
            "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                          "limits": {"cpu": "500m", "memory": "256Mi"}}}


def _pod(name, pod_sc=None, containers=None):
    """A Pod with safe defaults (no token mount, digest image, limits)."""
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": "default"},
            "spec": {"securityContext": pod_sc or {},
                     "automountServiceAccountToken": False,
                     "containers": containers or [_ctr("main")]},
            "__file__": "synthetic"}


def _pss(obj):
    """PSS findings for one synthetic workload object."""
    inv = rbaclens.Inventory([obj])
    return [f for f in rbaclens.check_workloads(inv)
            if f["rule"].startswith("PSS-")]


def step9():
    print("Step 9 — Pod Security Standards (v1.2)")
    # Bare pod: no seccomp, no drop ALL -> PSS-001 + PSS-002, no PSS-003.
    f = _pss(_pod("bare"))
    check("bare pod: PSS-001 fires",
          any(x["rule"] == "PSS-001" for x in f))
    check("bare pod: PSS-002 fires",
          any(x["rule"] == "PSS-002" for x in f))
    check("bare pod: no PSS-003 (nothing added)",
          not [x for x in f if x["rule"] == "PSS-003"])
    # Fully restricted pod: RuntimeDefault + drop ALL + only NET_BIND_SERVICE.
    ok = _pod("ok", pod_sc={"seccompProfile": {"type": "RuntimeDefault"}},
              containers=[_ctr("main", {"capabilities": {
                  "drop": ["ALL"], "add": ["NET_BIND_SERVICE"]}})])
    check("restricted pod: no PSS findings", not _pss(ok))
    # Wrong seccomp type still fails PSS-001; Localhost passes it.
    check("Unconfined seccomp fails PSS-001",
          any(x["rule"] == "PSS-001" for x in _pss(
              _pod("unconfined",
                   pod_sc={"seccompProfile": {"type": "Unconfined"}}))))
    check("Localhost seccomp passes PSS-001",
          not [x for x in _pss(
              _pod("localhost",
                   pod_sc={"seccompProfile": {"type": "Localhost"}}))
              if x["rule"] == "PSS-001"])
    # SYS_ADMIN is WL-010's — PSS-003 must NOT double-fire it.
    inv = rbaclens.Inventory([_pod(
        "sysadmin",
        containers=[_ctr("main", {"capabilities": {"add": ["SYS_ADMIN"]}})])])
    all_f = rbaclens.check_workloads(inv)
    check("SYS_ADMIN fires WL-010",
          any(x["rule"] == "WL-010" for x in all_f))
    check("SYS_ADMIN does NOT fire PSS-003",
          not [x for x in all_f if x["rule"] == "PSS-003"])
    # CHOWN fires PSS-003; NET_BIND_SERVICE alone does not.
    f = _pss(_pod("chown", containers=[_ctr(
        "main", {"capabilities": {"add": ["CHOWN"]}})]))
    check("CHOWN fires PSS-003",
          len([x for x in f if x["rule"] == "PSS-003"]) == 1)
    check("PSS-003 evidence names CHOWN",
          any("CHOWN" in x["evidence"] for x in f
              if x["rule"] == "PSS-003"))
    f = _pss(_pod("mixed", containers=[_ctr(
        "main", {"capabilities": {"add": ["CHOWN", "NET_BIND_SERVICE"]}})]))
    check("CHOWN + NET_BIND_SERVICE: PSS-003 lists CHOWN only",
          any("['CHOWN']" in x["evidence"]
              for x in f if x["rule"] == "PSS-003"))
    check("NET_BIND_SERVICE alone: no PSS-003",
          not [x for x in _pss(_pod("bind", containers=[_ctr(
              "main", {"capabilities": {"add": ["NET_BIND_SERVICE"]}})]))
              if x["rule"] == "PSS-003"])


def _sa(name, annotations):
    """A ServiceAccount carrying cloud-identity annotations."""
    return {"apiVersion": "v1", "kind": "ServiceAccount",
            "metadata": {"name": name, "namespace": "default",
                         "annotations": annotations},
            "__file__": "synthetic"}


def _iam(obj):
    inv = rbaclens.Inventory([obj] if isinstance(obj, dict) else obj)
    return rbaclens.check_cloud_iam(inv)


def _nvd_vuln(cve_id, score):
    return {"cve": {"id": cve_id,
                    "metrics": {"cvssMetricV31": [
                        {"cvssData": {"baseScore": score}}]}}}


def step10():
    print("Step 10 — Zero-limits (v1.4): IAM, CVE, admission, fix")
    import json as _json
    import yaml as _yaml

    # --- Cloud IAM on the fixtures -------------------------------------
    _inv, findings = scan(BAD)
    iam1 = [f for f in findings if f["rule"] == "IAM-001"]
    check("IAM-001 fires 3 times (IRSA + GKE + pod-identity)",
          len(iam1) == 3, "(%d)" % len(iam1))
    iam2 = [f for f in findings if f["rule"] == "IAM-002"]
    check("IAM-002 fires once, critical, names AdministratorAccess",
          len(iam2) == 1 and iam2[0]["severity"] == "critical"
          and "AdministratorAccess" in iam2[0]["evidence"])
    iam3 = [f for f in findings if f["rule"] == "IAM-003"]
    check("IAM-003 fires once, names the deprecated annotation",
          len(iam3) == 1 and "aadpodidentity" in iam3[0]["evidence"])
    check("GKE identity fires IAM-001 but not IAM-002",
          any("gke-app" in f["object"] for f in iam1)
          and not [f for f in iam2 if "gke-app" in f["object"]])
    _inv2, findings2 = scan(CLEAN)
    check("clean folder: no IAM findings",
          not [f for f in findings2 if f["rule"].startswith("IAM-")])

    # --- Cloud IAM, synthetic ------------------------------------------
    scoped = _sa("scoped", {"eks.amazonaws.com/role-arn":
                            "arn:aws:iam::123456789012:role/app-reader"})
    f = _iam(scoped)
    check("scoped IRSA role: IAM-001 only, no IAM-002",
          any(x["rule"] == "IAM-001" for x in f)
          and not [x for x in f if x["rule"] == "IAM-002"])
    wild = _sa("wild", {"eks.amazonaws.com/role-arn":
                        "arn:aws:iam::123456789012:role/*"})
    f = _iam(wild)
    check("wildcard role ARN fires IAM-002",
          any(x["rule"] == "IAM-002" and "wildcard" in x["evidence"]
              for x in f))
    azure = _sa("az", {"azure.workload.identity/client-id":
                       "11111111-2222-3333-4444-555555555555"})
    f = _iam(azure)
    check("Azure Workload Identity fires IAM-001 only",
          any(x["rule"] == "IAM-001" for x in f)
          and not [x for x in f if x["rule"] in ("IAM-002", "IAM-003")])
    # Pod-template annotation (some setups annotate the pod, not the SA).
    dep = {"apiVersion": "apps/v1", "kind": "Deployment",
           "metadata": {"name": "annotated", "namespace": "default"},
           "spec": {"template": {
               "metadata": {"annotations": {
                   "eks.amazonaws.com/role-arn":
                       "arn:aws:iam::123456789012:role/app-reader"}},
               "spec": {"containers": [{"name": "app", "image": "nginx:1.27.4"}]}}},
           "__file__": "synthetic"}
    f = _iam(dep)
    check("pod-template IRSA annotation fires IAM-001",
          any(x["rule"] == "IAM-001" for x in f))

    # --- CVE lookup, stub fetcher --------------------------------------
    def _pod_with_image(image):
        pod = _pod("cve-test",
                   pod_sc={"seccompProfile": {"type": "RuntimeDefault"}},
                   containers=[_ctr("main", {"capabilities": {
                       "drop": ["ALL"]}})])
        pod["spec"]["containers"][0]["image"] = image
        return pod

    def stub_critical(_part, _vendor, _product, _version):
        return {"vulnerabilities": [_nvd_vuln("CVE-2022-31144", 9.8),
                                    _nvd_vuln("CVE-2022-35951", 5.5)]}

    inv = rbaclens.Inventory([_pod_with_image("redis:7.0.0")])
    f, status = rbaclens.check_cve(inv, fetcher=stub_critical)
    check("CVE-001 fires for a vulnerable image",
          len(f) == 1 and f[0]["rule"] == "CVE-001")
    check("CVE-001 with CVSS 9.8 is critical",
          f[0]["severity"] == "critical")
    check("CVE-001 evidence lists the CVE IDs",
          "CVE-2022-31144" in f[0]["evidence"]
          and "CVE-2022-35951" in f[0]["evidence"])
    check("CVE status records 2 CVEs for the image",
          status["images"]["redis:7.0.0"]["cves"] == 2)

    def stub_medium(_part, _vendor, _product, _version):
        return {"vulnerabilities": [_nvd_vuln("CVE-2021-12345", 5.0)]}

    inv = rbaclens.Inventory([_pod_with_image("redis:7.0.0")])
    f, _s = rbaclens.check_cve(inv, fetcher=stub_medium)
    check("CVE-001 with CVSS 5.0 stays high",
          len(f) == 1 and f[0]["severity"] == "high")

    def stub_clean(_part, _vendor, _product, _version):
        return {"vulnerabilities": []}

    inv = rbaclens.Inventory([_pod_with_image("redis:7.0.0")])
    f, status = rbaclens.check_cve(inv, fetcher=stub_clean)
    check("no CVEs: no finding, image marked checked",
          not f and status["images"]["redis:7.0.0"]["status"] == "checked")

    def stub_down(_part, _vendor, _product, _version):
        raise ValueError("NVD API unreachable: simulated outage")

    inv = rbaclens.Inventory([_pod_with_image("redis:7.0.0")])
    f, status = rbaclens.check_cve(inv, fetcher=stub_down)
    check("NVD down: no findings, no crash, state offline",
          not f and status["state"] == "offline")
    check("NVD down: image marked error, never clean",
          status["images"]["redis:7.0.0"]["status"] == "error")

    def stub_must_not_run(_part, _vendor, _product, _version):
        raise AssertionError("fetcher must not be called for this image")

    inv = rbaclens.Inventory([_pod_with_image("mycorp/custom-app:1.2.3")])
    f, status = rbaclens.check_cve(inv, fetcher=stub_must_not_run)
    check("unmapped image: skipped, fetcher never called",
          not f and status["images"]["mycorp/custom-app:1.2.3"]["status"]
          == "skipped")
    inv = rbaclens.Inventory([_pod_with_image("redis:7")])
    f, status = rbaclens.check_cve(inv, fetcher=stub_must_not_run)
    check("imprecise tag (redis:7): skipped, fetcher never called",
          not f and status["images"]["redis:7"]["status"] == "skipped"
          and "exact version" in status["images"]["redis:7"]["reason"])
    check("version parsing: 1.27.4-alpine -> 1.27.4",
          rbaclens._precise_version("1.27.4-alpine") == "1.27.4")
    check("version parsing: latest/7/3.19 -> None",
          rbaclens._precise_version("latest") is None
          and rbaclens._precise_version("7") is None
          and rbaclens._precise_version("3.19") is None)

    # --- CVE lookup, live NVD (best effort: offline must not fail) -----
    try:
        data = rbaclens.nvd_query_cpe("a", "redis", "redis", "7.0.0",
                                      timeout=15)
        total = data.get("totalResults", 0)
        check("live NVD: redis 7.0.0 returns real CVE data",
              total > 0, "(totalResults=%d)" % total)
    except ValueError as exc:
        print("    (live NVD check skipped — offline: %s)" % exc)
        check("live NVD skipped cleanly while offline", True)

    # --- CVE flag end to end (CLI, clean folder) -----------------------
    py = sys.executable
    out = os.path.join(HERE, "report_cve.txt")
    proc = subprocess.run(
        [py, os.path.join(HERE, "rbaclens.py"), CLEAN, "-o", out,
         "--cve", "-q"],
        capture_output=True, text=True)
    check("CLI --cve runs on the clean folder (exit 0)",
          proc.returncode == 0, "(exit %d)" % proc.returncode)
    cve_text = open(out, encoding="utf-8").read()
    check("CLI --cve report records the CVE check",
          "CVE check (--cve):" in cve_text)
    if os.path.isfile(out):
        os.remove(out)

    # --- RBAC-010 aggregation expansion --------------------------------
    rbac10 = [f for f in findings if f["rule"] == "RBAC-010"]
    check("RBAC-010 names the aggregated role (view-extra)",
          len(rbac10) == 1 and "view-extra" in rbac10[0]["evidence"])
    check("RBAC-010 stays low for a benign aggregate",
          rbac10[0]["severity"] == "low")

    def _cluster_role(name, labels, rules):
        return {"apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {"name": name, "labels": labels},
                "rules": rules, "__file__": "synthetic"}

    agg = _cluster_role("agg", {}, [])
    agg["aggregationRule"] = {"clusterRoleSelectors": [
        {"matchLabels": {"team": "x"}}]}
    wild_role = _cluster_role("wild-x", {"team": "x"},
                              [{"verbs": ["*"], "resources": ["*"],
                                "apiGroups": ["*"]}])
    inv = rbaclens.Inventory([agg, wild_role])
    f = [x for x in rbaclens.check_rbac(inv) if x["rule"] == "RBAC-010"]
    check("aggregated wildcard role escalates RBAC-010 to high",
          len(f) == 1 and f[0]["severity"] == "high"
          and "wild-x" in f[0]["evidence"])
    inv = rbaclens.Inventory([agg])
    f = [x for x in rbaclens.check_rbac(inv) if x["rule"] == "RBAC-010"]
    check("no matching role: RBAC-010 says so, stays low",
          len(f) == 1 and f[0]["severity"] == "low"
          and "no ClusterRole" in f[0]["evidence"])

    # --- Admission output ----------------------------------------------
    kyverno = rbaclens.build_kyverno_policy(findings)
    policy = _yaml.safe_load(kyverno)
    check("Kyverno policy parses, kind ClusterPolicy",
          policy.get("kind") == "ClusterPolicy"
          and policy["metadata"]["name"] == "rbaclens-enforce")
    check("Kyverno policy enforces (blocks, not audits)",
          policy["spec"]["validationFailureAction"] == "Enforce")
    rule_names = {r["name"] for r in policy["spec"]["rules"]}
    check("Kyverno policy blocks privileged containers",
          "block-privileged-containers" in rule_names)
    check("Kyverno policy blocks cluster-admin bindings",
          "block-cluster-admin-bindings" in rule_names)
    check("Kyverno policy covers the flagged categories only",
          "block-hostpath-volumes" in rule_names)
    gatekeeper = rbaclens.build_gatekeeper_bundle(findings)
    docs = list(_yaml.safe_load_all(gatekeeper))
    kinds = {(d.get("kind")) for d in docs}
    check("Gatekeeper bundle has templates + constraints",
          kinds >= {"ConstraintTemplate", "RBACLensWorkload",
                    "RBACLensBinding"})
    check("Gatekeeper Rego blocks privileged containers",
          "privileged" in gatekeeper and "WL-001" in gatekeeper)
    check("Gatekeeper Rego blocks cluster-admin bindings",
          "cluster-admin" in gatekeeper and "RBAC-001" in gatekeeper)
    clean_policy = rbaclens.build_kyverno_policy(findings2)
    clean_names = {r["name"] for r in
                   _yaml.safe_load(clean_policy)["spec"]["rules"]}
    check("clean scan: admission output is the full baseline",
          "block-privileged-containers" in clean_names
          and "block-cluster-admin-bindings" in clean_names)
    cats = rbaclens.admission_categories_for(
        [f for f in findings if f["rule"] == "WL-001"])
    check("one WL-001 finding -> only the privileged category",
          cats == {"privileged"})

    # --- --fix-out ------------------------------------------------------
    objects, _errs = rbaclens.collect_manifests(BAD)
    tmpdir = tempfile.mkdtemp(prefix="rbaclens-fix-")
    try:
        written, applied_n, manual_n = rbaclens.write_fix_output(
            objects, findings, tmpdir)
        check("fix output writes the changed files",
              written >= 1 and os.path.isfile(
                  os.path.join(tmpdir, "workload-bad.yaml")))
        fixes = open(os.path.join(tmpdir, "FIXES.md"),
                     encoding="utf-8").read()
        check("FIXES.md lists manual items (RBAC-001, hostPath)",
              "RBAC-001" in fixes and "WL-006" in fixes)
        check("fix output applied real fixes", applied_n > 10,
              "(%d)" % applied_n)
        fixed_docs = list(_yaml.safe_load_all(
            open(os.path.join(tmpdir, "workload-bad.yaml"),
                 encoding="utf-8")))
        debug = [d for d in fixed_docs
                 if (d.get("metadata") or {}).get("name") == "debug-app"][0]
        spec = debug["spec"]["template"]["spec"]
        ctr = spec["containers"][0]
        check("fixed debug-app: privileged removed",
              ctr["securityContext"]["privileged"] is False)
        check("fixed debug-app: hostNetwork/hostPID removed",
              spec["hostNetwork"] is False and spec["hostPID"] is False)
        check("fixed debug-app: runAsNonRoot + drop ALL + limits",
              ctr["securityContext"]["runAsNonRoot"] is True
              and "ALL" in ctr["securityContext"]["capabilities"]["drop"]
              and ctr["resources"]["limits"]["cpu"] == "500m")
        # Re-scan the fixed file: the mechanical workload flaws are gone,
        # the hostPath (needs a human) is still flagged.
        fixed_inv = rbaclens.Inventory(fixed_docs)
        fixed_wl = {f["rule"] for f in
                    rbaclens.check_workloads(fixed_inv)}
        check("re-scan of fixed file: WL-001/002/003/004/007/008 gone",
              not ({"WL-001", "WL-002", "WL-003", "WL-004", "WL-007",
                    "WL-008"} & fixed_wl))
        check("re-scan of fixed file: hostPath still flagged (manual)",
              "WL-006" in fixed_wl)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    bad_text = open(os.path.join(BAD, "workload-bad.yaml"),
                    encoding="utf-8").read()
    check("original manifests untouched by --fix-out",
          "privileged: true" in bad_text)

    # --- Empty-folder false-clean guard ---------------------------------
    empty = tempfile.mkdtemp(prefix="rbaclens-empty-")
    try:
        proc = subprocess.run(
            [py, os.path.join(HERE, "rbaclens.py"), empty, "-o",
             os.path.join(empty, "r.txt"), "-q"],
            capture_output=True, text=True)
        check("empty folder: exit 2, not a clean 100/A",
              proc.returncode == 2, "(exit %d)" % proc.returncode)
        check("empty folder: no report written",
              not os.path.isfile(os.path.join(empty, "r.txt")))
        fake_inv = rbaclens.Inventory([{
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "cfg", "namespace": "default"},
            "__file__": "synthetic"}])
        text = rbaclens.build_text_report(
            "synthetic", fake_inv, [], 100, "A", [])
        check("objects-but-nothing-auditable: report warns",
              "WARNING: inventory contains no roles" in text)
    finally:
        shutil.rmtree(empty, ignore_errors=True)


def run_all_tests():
    print("RBACLens step tests")
    print("=" * 50)
    for step in (step1, step2, step3, step4, step5, step6, step7, step8, step9,
                 step10):
        step()
        print()
    print("=" * 50)
    print("ALL %d CHECKS PASSED" % PASSED)


if __name__ == "__main__":
    try:
        run_all_tests()
    except AssertionError as exc:
        print()
        print("TESTS FAILED: %s" % exc)
        sys.exit(1)
