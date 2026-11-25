# RBACLens — Kubernetes RBAC and Workload Auditor

A command-line tool, written in Python, that reads a folder of Kubernetes
YAML manifests and finds the permissions and workload settings attackers
abuse — then grades the whole folder with a score and a letter grade.

**Version:** 1.0
**Author:** CyberBoy50

> Lab use only. Audit only manifests you own or have written permission to
> audit. The tool works on **files only** — it never talks to a live cluster,
> needs no credentials and no network.

## What it finds

| Area | Checks |
|---|---|
| **RBAC** | Cluster-admin bindings (with the subject named), wildcard verbs / resources / API groups, `escalate` / `bind` / `impersonate` verbs, secret readers, pods/exec, anonymous or authenticated users, default ServiceAccount bound, aggregated ClusterRoles, bindings to roles that do not exist |
| **Workloads** | Privileged containers, `allowPrivilegeEscalation`, hostNetwork / hostPID / hostIPC, hostPath volumes (docker.sock and `/` are Critical), run-as-root, missing CPU/memory requests or limits, auto-mounted service-account tokens, dangerous capabilities, writable root filesystem |
| **Images** | `:latest` or untagged images, images not pinned by digest |
| **Network** | Namespaces with workloads but no NetworkPolicy |

25 rules in total — run `python run.py checks` (or `rbaclens.py --list-checks`)
to see them all with their severities.

## How it is better than the famous tools

Research (see `RESEARCH_CLI_TOOLS.md` and `RESEARCH_IMPLEMENTATION.md` —
14 tools read: kubeaudit, KubeLinter, Polaris, kube-bench, Checkov,
Kubescape, kube-score, rbac-tool, Krane, KubeSec, Conftest and more):

- **RBAC checks are on by default.** KubeLinter hides cluster-admin and
  wildcard checks behind opt-in config; kubeaudit and kube-score have none.
- **Files only, no live cluster.** rbac-tool and Krane need a cluster and
  admin read access; RBACLens audits exported YAML anywhere, including CI
  and air-gapped labs.
- **Image digest pinning.** No reviewed tool checks digests; RBACLens does.
- **Score + grade.** Polaris-style 0–100 score and A–F grade, so a folder
  can be gated in CI (`--fail-on critical`).
- **A menu.** Every reviewed tool is CLI-args-only. RBACLens has a numbered
  menu *and* full CLI flags.
- **Easy install.** `python run.py setup` — one command, venv + PyYAML.
  No Go toolchain, no database (Krane needs FalkorDB), no downloads at
  scan time (Kubescape), no Rego to write (Conftest).

## Install

```bash
git clone https://github.com/<you>/RBACLens.git
cd RBACLens
python run.py setup        # first time only — creates venv, installs PyYAML
```

Or without the launcher, if PyYAML is already installed:

```bash
pip install pyyaml
python rbaclens.py --help
```

## Run it

```bash
# Menu (easiest)
python run.py scan                  # no path = menu
python rbaclens.py --menu

# Scan a folder (text report + score)
python run.py scan ./my-manifests
python rbaclens.py ./my-manifests -o report.txt

# Scan one file, with a JSON report for a pipeline
python rbaclens.py ./deploy.yaml -o report.txt --json report.json

# Only the important stuff
python rbaclens.py ./my-manifests --min-severity high -q

# CI gate: fail (exit 2) if anything critical is found
python rbaclens.py ./my-manifests --fail-on critical

# Only some rules, or skip one
python rbaclens.py ./my-manifests --check RBAC-001,WL-001
python rbaclens.py ./my-manifests --skip-check NET-001

# Look at the RBAC inventory before the findings
python rbaclens.py --inventory ./my-manifests
python run.py inventory ./my-manifests
```

Exit codes: `0` clean, `1` findings, `2` critical findings (or `--fail-on` hit).

## Try it on the test manifests

```bash
python run.py scan test_manifests/bad     # 46 findings, score 0/100, grade F
python run.py scan test_manifests/clean   # 0 findings, score 100/100, grade A
python run.py test                        # the 7 build-plan step tests
```

## Scoring

Every finding costs points: Critical −25, High −10, Medium −5, Low −2.
Score starts at 100 and is clamped to 0–100. Grades: A ≥ 90, B ≥ 80,
C ≥ 70, D ≥ 60, F < 60.

## Report

Every scan writes a text report (default `rbaclens_report.txt`) with object
name, severity, evidence and a fix for every finding, plus the score and a
defensive lesson. `--json` writes the same data as JSON for pipelines.

## Files

| File | What it is |
|---|---|
| `rbaclens.py` | The tool — parsing, inventory, checks, scoring, reports, menu |
| `run.py` | Launcher — setup, scan, test, doctor |
| `test_rbaclens.py` | The 7 build-plan step tests (43 checks) |
| `test_manifests/bad/` | Manifests with planted flaws (RBAC + workloads + List) |
| `test_manifests/clean/` | Hardened manifests that must pass with zero findings |
| `requirements.txt` | `pyyaml`, `colorama` |
| `DEMO.md` | Demo and write-up with real run output |
| `STEP_BY_STEP_GUIDE.md` | The 7 build steps, each with its test |
| `RESEARCH.md` / `RESEARCH_CLI_TOOLS.md` / `RESEARCH_IMPLEMENTATION.md` | Research notes on the famous tools |
| `report_bad.txt`, `report_clean.txt` | Sample reports from the test manifests |

## One defensive lesson

**Least privilege in RBAC.** Give every subject only the permissions it
needs, nothing more. A binding to `cluster-admin` hands over the whole
cluster: read every secret, run code in any pod, change RBAC itself. Scope
roles to exact verbs, resources and namespaces instead.
