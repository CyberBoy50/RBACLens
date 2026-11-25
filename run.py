#!/usr/bin/env python3
"""RBACLens launcher — setup, scan, test, doctor.

Usage:
    python run.py setup        # create venv + install dependencies (first time)
    python run.py scan <path>  # audit a manifest file or folder
    python run.py test         # run the 7 build-plan step tests
    python run.py doctor       # check the setup
    python run.py checks       # list all checks
    python run.py inventory <path>  # show the RBAC inventory

Works on Windows (venv\\Scripts\\python.exe), macOS and Linux
(venv/bin/python). Plain `python3 rbaclens.py` also works if PyYAML
is installed.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def venv_python():
    """Path of the venv Python for this OS, or None if no venv yet."""
    if os.name == "nt":
        cand = os.path.join(HERE, "venv", "Scripts", "python.exe")
    else:
        cand = os.path.join(HERE, "venv", "bin", "python")
    return cand if os.path.isfile(cand) else None


def run(cmd, **kw):
    return subprocess.run(cmd, **kw)


def ensure_venv():
    """Create the venv and install requirements if needed. Returns the
    Python executable to use (venv python, or the current one)."""
    vp = venv_python()
    if vp is None:
        print("[*] Creating virtual environment (first time only)...")
        rc = run([sys.executable, "-m", "venv", os.path.join(HERE, "venv")]).returncode
        if rc != 0:
            print("[!] Could not create a venv. Using system Python.")
            return sys.executable
        vp = venv_python()
    req = os.path.join(HERE, "requirements.txt")
    print("[*] Installing dependencies (pyyaml, colorama)...")
    rc = run([vp, "-m", "pip", "install", "-q", "-r", req]).returncode
    if rc != 0:
        print("[!] pip install failed. Try: %s -m pip install -r requirements.txt" % vp)
    return vp


def cmd_setup(_args):
    vp = ensure_venv()
    print("[+] Setup done. Python: %s" % vp)
    print("    Test it: python run.py scan test_manifests/bad")
    return 0


def cmd_scan(args):
    vp = venv_python() or sys.executable
    target = os.path.join(HERE, "rbaclens.py")
    return run([vp, target] + args).returncode


def cmd_test(_args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "test_rbaclens.py")]).returncode


def cmd_doctor(_args):
    print("RBACLens doctor")
    print("-" * 40)
    print("[+] Python %s" % sys.version.split()[0])
    vp = venv_python()
    print("[%s] venv: %s" % ("+" if vp else "!", vp or "not created — run: python run.py setup"))
    try:
        import yaml
        print("[+] PyYAML %s" % yaml.__version__)
    except ImportError:
        print("[!] PyYAML is NOT installed — run: python run.py setup")
    bad = os.path.join(HERE, "test_manifests", "bad")
    clean = os.path.join(HERE, "test_manifests", "clean")
    print("[%s] test manifests (bad): %s" % ("+" if os.path.isdir(bad) else "!", bad))
    print("[%s] test manifests (clean): %s" % ("+" if os.path.isdir(clean) else "!", clean))
    print("-" * 40)
    problems = (vp is None)
    try:
        import yaml  # noqa: F401
    except ImportError:
        problems = True
    if problems:
        print("[!] Doctor: something is missing (see [!] lines above).")
        return 1
    print("[+] Doctor: all good. Run: python run.py scan test_manifests/bad")
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 0
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "setup":
        return cmd_setup(args)
    if cmd == "scan":
        return cmd_scan(args)
    if cmd == "test":
        return cmd_test(args)
    if cmd == "doctor":
        return cmd_doctor(args)
    if cmd == "checks":
        return cmd_scan(["--list-checks"])
    if cmd == "inventory":
        return cmd_scan(["--inventory"] + args)
    print("Unknown command: %s" % cmd)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
