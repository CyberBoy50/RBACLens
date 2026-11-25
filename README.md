# RBACLens — Kubernetes RBAC and Workload Auditor

A command-line tool, written in Python, that reads a folder of Kubernetes
YAML manifests and finds the permissions and workload settings attackers
abuse — then grades the whole folder with a score and a letter grade.

**Version:** 1.3
**Author:** CyberBoy50

> Lab use only. Audit only manifests or clusters you own or have written
> permission to audit. File scans need no credentials and no network; live
> mode (v1.1) reads your own cluster through kubectl — read-only, nothing
> is written to the cluster.

## Legal — authorized use only

> DISCLAIMER — AUTHORIZED USE ONLY. This tool was built for ethical,
> authorized security testing only. You are using it on your own
> responsibility. The authors are not responsible for how you use it, or
> for anything that happens because of your use. Only test systems, code,
> and data you own or have explicit written permission to test — testing
> anything else may be illegal (for example, PECA 2016 in Pakistan).

## What it finds

| Area | Checks |
|---|---|
| **RBAC** | Cluster-admin bindings (with the subject named), wildcard verbs / resources / API groups, `escalate` / `bind` / `impersonate` verbs, secret readers, pods/exec, anonymous or authenticated users, default ServiceAccount bound, aggregated ClusterRoles, bindings to roles that do not exist |
| **Workloads** | Privileged containers, `allowPrivilegeEscalation`, hostNetwork / hostPID / hostIPC, hostPath volumes (docker.sock and `/` are Critical), run-as-root, missing CPU/memory requests or limits, auto-mounted service-account tokens, dangerous capabilities, writable root filesystem |
| **Images** | `:latest` or untagged images, images not pinned by digest |
| **Network** | Namespaces with workloads but no NetworkPolicy |
| **Pod Security** | Pod Security Standards (restricted profile): seccompProfile, capabilities drop ALL, only NET_BIND_SERVICE may be added |

28 rules in total — run `python run.py checks` (or `rbaclens.py --list-checks`)
to see them all with their severities.

## How it is better than the famous tools

Research (see `RESEARCH_CLI_TOOLS.md` and `RESEARCH_IMPLEMENTATION.md` —
14 tools read: kubeaudit, KubeLinter, Polaris, kube-bench, Checkov,
Kubescape, kube-score, rbac-tool, Krane, KubeSec, Conftest and more):

- **RBAC checks are on by default.** KubeLinter hides cluster-admin and
  wildcard checks behind opt-in config; kubeaudit and kube-score have none.
- **Files first, live cluster too (v1.1).** rbac-tool and Krane need a
  cluster and admin read access; RBACLens audits exported YAML anywhere,
  including CI and air-gapped labs — and with `--live` it audits your own
  cluster through kubectl (read-only `get`), running the exact same 25
  rules on what is actually running.
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
git clone https://github.com/CyberBoy50/RBACLens.git
cd RBACLens
python run.py setup        # first time only — creates venv, installs PyYAML
```

Or without the launcher, if PyYAML is already installed:

```bash
pip install pyyaml
python rbaclens.py --help
```

## Runs on Linux, macOS and Windows

One tool, all three — no separate builds, no Docker, no Go toolchain.
`run.py` picks the right venv Python for your OS automatically
(`venv/bin/python` on Linux/macOS, `venv\Scripts\python.exe` on Windows).
You only need **Python 3.9+** and pip.

| OS | Setup (first time) | Scan |
|---|---|---|
| **Linux** | `python3 run.py setup` | `python3 run.py scan ./my-manifests` |
| **macOS** | `python3 run.py setup` | `python3 run.py scan ./my-manifests` |
| **Windows** | `python run.py setup` | `python run.py scan .\my-manifests` |

One-click, no commands at all:

- **Windows:** double-click `run.bat` — the menu opens.
- **Linux / macOS:** `bash run.sh` — the menu opens.

Same commands, same output, same reports on every OS.

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

## Live cluster mode (v1.1)

The same 28 rules, run against what is actually deployed in your own
cluster — through one read-only `kubectl get`. Nothing is created,
changed or deleted on the cluster.

```bash
python run.py live                        # all namespaces, menu option 8
python run.py live --namespace kube-system
python rbaclens.py --live --context my-cluster -o live_report.txt
python rbaclens.py --live --inventory     # inventory of the live cluster
```

Requirements: `kubectl` on PATH and a working kubeconfig (a local
`minikube` / `kind` cluster is enough to try it). Without a cluster,
`python run.py doctor` says so and file scans still work. To test the
live path without a real cluster, the step tests (step 8) run it against
a fake `kubectl` that prints the bad test manifests — same 16 objects,
same 57 findings.

## Pod Security Standards (v1.2)

Kubernetes ships an official baseline for how locked-down a pod must be:
the Pod Security Standards, levels privileged / baseline / restricted.
The **restricted** profile is the strictest, and most of it is already
covered by the workload rules (privileged WL-001, allowPrivilegeEscalation
WL-002, host namespaces WL-003/004/005, hostPath WL-006, runAsNonRoot
WL-007, readOnlyRootFilesystem WL-011). v1.2 adds the three genuinely
new checks:

- **PSS-001** (Medium) — no `seccompProfile`, or its type is not
  `RuntimeDefault` / `Localhost`. One finding per workload.
- **PSS-002** (High) — the container's `capabilities.drop` does not
  include `ALL`. One finding per container.
- **PSS-003** (High) — the container adds a capability other than
  `NET_BIND_SERVICE`. Capabilities WL-010 already flags (e.g. SYS_ADMIN)
  are never double-counted — PSS-003 fires only for the rest.

The clean test manifests pass all three (seccompProfile RuntimeDefault,
drop ALL, no adds); the bad folder fails them 5 + 5 + 1 times. The same
three rules run in live mode too.

## Try it on the test manifests

```bash
python run.py scan test_manifests/bad     # 57 findings, score 0/100, grade F
python run.py scan test_manifests/clean   # 0 findings, score 100/100, grade A
python run.py test                        # the 8 step tests (incl. live mode)
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
| `run.py` | Launcher — setup, scan, test, doctor (Windows / macOS / Linux) |
| `run.bat` | Windows one-click — opens the menu |
| `run.sh` | Linux / macOS one-click — opens the menu |
| `test_rbaclens.py` | The 9 step tests (71 checks) |
| `test_manifests/bad/` | Manifests with planted flaws (RBAC + workloads + List) |
| `test_manifests/clean/` | Hardened manifests that must pass with zero findings |
| `requirements.txt` | `pyyaml`, `colorama` |
| `DEMO.md` | Demo and write-up with real run output |
| `STEP_BY_STEP_GUIDE.md` | The 7 build steps, each with its test, plus live mode and PSS |
| `RESEARCH.md` / `RESEARCH_CLI_TOOLS.md` / `RESEARCH_IMPLEMENTATION.md` | Research notes on the famous tools |
| `report_bad.txt`, `report_clean.txt` | Sample reports from the test manifests |

## One defensive lesson

**Least privilege in RBAC.** Give every subject only the permissions it
needs, nothing more. A binding to `cluster-admin` hands over the whole
cluster: read every secret, run code in any pod, change RBAC itself. Scope
roles to exact verbs, resources and namespaces instead.
