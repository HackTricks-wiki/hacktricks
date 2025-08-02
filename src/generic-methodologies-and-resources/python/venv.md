# venv

{{#include ../../banners/hacktricks-training.md}}

## Quick setup

```bash
# Debian/Ubuntu – install the venv module (one-time)
sudo apt-get install python3-venv

# 1. Create an isolated environment called "pvenv" and ensure the bundled tools are up to date
python3 -m venv --upgrade-deps --prompt pvenv pvenv

# 2. Activate it (POSIX shells)
source pvenv/bin/activate

# 3. Install whatever Python libraries you need – they will be confined to ./pvenv
pip install -r requirements.txt

# 4. Leave the environment
deactivate
```

If you hit the classic *invalid command `bdist_wheel`* error inside a fresh environment just install **wheel**:

```bash
pip install wheel
```

---

## Security considerations for virtual environments

*Isolation is not a sandbox* – code executed inside a `venv` still runs with the *full privileges of the current user*. Do **not** treat a `venv` as a secure sandbox for untrusted code.

1. **Keep core tooling patched**  
   Always create environments with `--upgrade-deps` (Python ≥ 3.9) so that `pip`, `setuptools`, and `wheel` are upgraded at creation time. This prevents you from starting out with versions known to contain high-impact vulnerabilities (e.g. the arbitrary-code-execution bug affecting `pip < 25.0`).  
2. **Avoid `--system-site-packages`**  
   Sharing the global site-packages directory defeats dependency pinning and lets a malicious or outdated global package shadow the versions you expect inside the virtual environment.
3. **Watch for startup file abuse**  
   Python automatically executes `sitecustomize.py`, `usercustomize.py`, and `*.pth` files located inside the environment on every interpreter start-up. Attackers who can write to the venv can plant malicious code here to gain *persistence* — several EDR products detect this technique. 
4. **Symlinks vs copies**  
   When you need extra defense in depth use `--copies` to duplicate the interpreter instead of symlinking it. This avoids surprises if the system-wide binary is replaced.
5. **Reproducibility & integrity**  
   Combine a venv with a *strict* installer workflow: `pip install --require-hashes -r requirements.txt` to enable hash-based verification, then audit the environment with the tools below.

## Auditing the environment for vulnerable packages

The moment you have *any* dependencies installed you should scan the environment for known CVEs.

```bash
# Inside an activated venv
pip install --upgrade pip pip-audit safety

# Audit currently installed packages against the PyPA advisory DB
pip-audit            # or: pip-audit --local  (only packages inside the venv)

# Cross-check using Safety
safety check --full-report
```

`pip-audit` can also fix issues automatically (`--fix`) or export a CycloneDX SBOM for further analysis. 

## Offensive tricks (red-teaming)

* Drop a `.pth` file or a crafted `sitecustomize.py` inside *any* writable virtual-environment path to obtain code execution every time the developer launches Python.
* Replace a legitimate wheel cached under `pvenv/pip-wheel-*.tmp/` during a race condition to exploit the arbitrary code execution bug fixed in `pip 25.0`. 

## Defensive hardening checklist

- Always use `python -m venv --upgrade-deps --prompt <name> <dir>`
- Pin and hash dependencies, commit `requirements.txt` to VCS
- Scan new environments with `pip-audit` (or integrate it in CI)
- Monitor for unexpected file writes to `*/sitecustomize.py`, `*/usercustomize.py`, and `*.pth`
- Prefer `--copies` if you do not trust the system interpreter



## References

- Python documentation – venv module (options `--upgrade-deps`, `--prompt`, etc.). https://docs.python.org/3/library/venv.html
- PyPA `pip-audit` – audit Python environments for vulnerable dependencies. https://github.com/pypa/pip-audit
{{#include ../../banners/hacktricks-training.md}}
