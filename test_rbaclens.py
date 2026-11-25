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
16 objects and 46 findings, and missing/failing kubectl must fail
loudly instead of scanning nothing.

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
    check("every object parsed", len(objects) == 10, "(%d objects)" % len(objects))
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
    check("cluster_roles", c["cluster_roles"] == 3, "(%d)" % c["cluster_roles"])
    check("role_bindings", c["role_bindings"] == 3, "(%d)" % c["role_bindings"])
    check("cluster_role_bindings", c["cluster_role_bindings"] == 2,
          "(%d)" % c["cluster_role_bindings"])
    check("service_accounts", c["service_accounts"] == 1, "(%d)" % c["service_accounts"])
    check("workloads", c["workloads"] == 5, "(%d)" % c["workloads"])
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
                "IMG-001", "IMG-002", "NET-001"}
    missing = expected - rules
    check("every planted flaw in the report", not missing,
          ("(missing: %s)" % ", ".join(sorted(missing))) if missing else
          "(%d findings, %d rules)" % (len(findings), len(rules)))
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
    for name in ("rbac-bad.yaml", "workload-bad.yaml", "mixed.yaml"):
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
        check("fake kubectl returns 16 objects", len(objects) == 16,
              "(%d)" % len(objects))
        check("no parse errors", not errors)
        inv = rbaclens.Inventory(objects)
        findings = rbaclens.run_all_checks(inv)
        check("live scan finds 46 findings", len(findings) == 46,
              "(%d)" % len(findings))
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


def run_all_tests():
    print("RBACLens step tests")
    print("=" * 50)
    for step in (step1, step2, step3, step4, step5, step6, step7, step8):
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
