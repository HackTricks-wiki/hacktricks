# Writable System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## परिचय

यदि आप **system-wide `PATH` में किसी directory में लिख सकते हैं** (केवल अपने user `PATH` में नहीं), तो आप system पर **privileges escalate** करने में सक्षम हो सकते हैं।

इसका दुरुपयोग **DLL hijacking** के माध्यम से किया जा सकता है, जब कोई अधिक-privileged service या process ऐसी DLL को load करने का प्रयास करता है जो उसके पहले के search locations में मौजूद नहीं होती और अंततः writable system `PATH` directory में खोजी जाती है।

एक writable Machine `PATH` entry केवल एक **primitive** है, code execution का प्रमाण नहीं। Standard search order का उपयोग करने वाले unpackaged application के लिए, `PATH` तक redirection, API sets, SxS, loaded-module list, KnownDLLs, application और Windows directories, तथा current directory के बाद पहुंचा जाता है। Full path या `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` policy `PATH` को पूरी तरह exclude कर सकती है।<sup>[[4]](#references)</sup>

**DLL hijacking** के बारे में अधिक जानकारी के लिए देखें:

{{#ref}}
./
{{#endref}}

## DLL Hijacking के साथ Privesc

### Missing DLL ढूंढना

सबसे पहले, ऐसे **process की पहचान करें** जो **अधिक privileges** के साथ चल रहा हो और **writable system `PATH` directory से DLL load** करने का प्रयास करता हो।

याद रखें कि यह technique केवल आपके **User PATH** पर नहीं, बल्कि **Machine/System PATH** entry पर निर्भर करती है। इसलिए, Procmon पर समय बिताने से पहले, **Machine PATH** entries को enumerate करना और यह जांचना उपयोगी है कि उनमें से कौन-सी writable हैं:<sup>[[1]](#references)</sup>
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
ACL text भ्रामक हो सकता है, क्योंकि group membership, deny ACEs और inherited permissions परिणाम को प्रभावित करते हैं। अधिकृत test में, create/delete probe **वर्तमान token की effective access** की जाँच करता है (यह intrusive है और alerts उत्पन्न कर सकता है):<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### Target का effective `PATH` confirm करें

Registry से पढ़ा गया Machine `PATH` configuration data है; loader **target process** के environment block का उपयोग करता है। हर process का अपना environment block होता है, और कोई child सामान्यतः अपने parent के environment की copy inherit करता है। इसलिए, लंबे समय से चल रही service पुरानी value बनाए रख सकती है, और custom environment के साथ शुरू की गई service आपके shell में दिखाई देने वाली value से अलग हो सकती है। Target PID द्वारा exact directory के observed Procmon probe को ground truth मानें; lab में `PATH` बदलने के बाद, lookup न होने का निष्कर्ष निकालने से पहले संबंधित process tree को restart करें या reboot करें।<sup>[[5]](#references)</sup>

इन मामलों में समस्या यह है कि वे processes संभवतः पहले से चल रहे होते हैं। उन DLLs की पहचान करने के लिए जिन्हें services load करने का प्रयास करती हैं और load नहीं कर पातीं, Procmon को जितना जल्दी संभव हो launch करें (processes शुरू होने से पहले), फिर:

> [!WARNING]
> Machine `PATH` में user-writable directory जोड़ने से **vulnerable condition बनती है**। ऐसा केवल isolated research VM में करें, ताकि पता लगाया जा सके कि कौन-से privileged processes `PATH` तक पहुंचते हैं; assessed host पर system configuration बदले बिना मौजूदा writable entry को monitor करें।<sup>[[1]](#references)</sup>

- `C:\privesc_hijacking` folder **Create** करें और path `C:\privesc_hijacking` को **System Path env variable** में जोड़ें। आप यह **manually** या **PS** से कर सकते हैं:
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- **`procmon`** लॉन्च करें और **`Options`** --> **`Enable boot logging`** पर जाएँ तथा prompt में **`OK`** दबाएँ।
- फिर **reboot** करें। कंप्यूटर के restart होने पर **`procmon`** जल्द से जल्द events **record** करना शुरू कर देगा।
- **Windows** **start** होने के बाद **`procmon`** फिर से **execute** करें। यह आपको बताएगा कि यह चल रहा था और **पूछेगा कि क्या आप events को store करना चाहते हैं**। **yes** कहें और **events को file में store करें**।
- **file** **generate** होने के **बाद**, खुली हुई **`procmon`** window को **close** करें और **events file** खोलें।
- उन सभी DLLs को खोजने के लिए ये **filters** जोड़ें जिन्हें किसी **process ने writable System Path folder से load करने का प्रयास किया**:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** केवल उन services के लिए आवश्यक है जो इतनी जल्दी start होती हैं कि अन्यथा observe नहीं की जा सकतीं। यदि आप **target service/program को on demand trigger कर सकते हैं** (उदाहरण के लिए, उसके COM interface के साथ interact करके, service को restart करके, या scheduled task को फिर से launch करके), तो आमतौर पर **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, और **`Path begins with <writable_machine_path>`** जैसे filters के साथ normal Procmon capture रखना अधिक तेज होता है।

### छूटे हुए DLLs

इसे एक free **virtual (vmware) Windows 11 machine** में चलाने पर मुझे ये results मिले:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

इस मामले में `.exe` results को ignore करें। Missing-DLL probes इनसे आए थे:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

निम्न example इस article में वर्णित technique का उपयोग करता है, जिसमें [**privilege escalation के लिए `WptsExtensions.dll` का abuse**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) किया गया है।<sup>[[3]](#references)</sup>

### अन्य candidates जिन्हें triage करना उपयोगी है

`WptsExtensions.dll` एक अच्छा example है, लेकिन यह privileged services में दिखाई देने वाला एकमात्र recurring **phantom DLL** नहीं है। Modern hunting rules और public hijack catalogs अभी भी इन जैसे names को track करते हैं:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Client systems पर classic **SYSTEM** candidate। तब उपयोगी जब writable directory **Machine PATH** में हो और service startup के दौरान DLL को probe करे। |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | **server editions** पर interesting, क्योंकि service **SYSTEM** के रूप में run होती है और कुछ builds में **normal user द्वारा on demand trigger की जा सकती है**, जिससे यह केवल reboot वाले cases से बेहतर बनती है। |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | आमतौर पर पहले **`NT AUTHORITY\LOCAL SERVICE`** मिलता है। यह अक्सर पर्याप्त होता है, क्योंकि token में **`SeImpersonatePrivilege`** होता है; इसलिए आप इसे [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) के साथ chain कर सकते हैं। |

इन names को **triage hints** मानें, guaranteed wins नहीं: ये **SKU/build dependent** हैं और Microsoft releases के बीच behavior बदल सकता है। मुख्य बात यह है कि **Machine PATH को traverse करने वाली privileged services में missing DLLs** खोजें, विशेष रूप से तब जब service को **reboot के बिना फिर से trigger किया जा सके**।

### weaponize करने से पहले candidate को validate करें

अपने आप में `NAME NOT FOUND` event पर्याप्त नहीं है। Payload रखने से पहले पूरी chain verify करें:<sup>[[1]](#references)[[4]](#references)</sup>

1. Event अपेक्षित **PID, command line, service account और integrity level** से संबंधित हो, तथा missing path exact writable Machine `PATH` directory हो।
2. उसी DLL basename के लिए कोई earlier directory `SUCCESS` return न करे, और module loaded-module list, KnownDLLs, redirection या SxS manifest द्वारा satisfied न हो।
3. जब कोई low-privileged user intended trigger invoke करे, तब probe repeat हो। केवल boot वाला lookup usable है, लेकिन on-demand lookup की तुलना में operational रूप से काफी खराब है।
4. Payload architecture process से match करे। यदि application बाद में exports resolve करती है, तो legitimate DLL को proxy करें या expected symbols export करें; [Creating and compiling DLLs](README.md#creating-and-compiling-dlls) देखें।
5. पहले एक harmless canary DLL का उपयोग करें, जो PID, identity और timestamp record करे। Procmon में planted path से successful **`Load Image`** आवश्यक मानें, न कि यह assume करें कि पहले हुआ file probe execution का कारण बना।

### Exploitation

**privileges escalate** करने के लिए **`WptsExtensions.dll`** को hijack करें। **path** और **name** ज्ञात होने के बाद malicious DLL generate करें।

आप [**इनमें से किसी भी examples का उपयोग करने का प्रयास कर सकते हैं**](README.md#creating-and-compiling-dlls)। आप ऐसे payloads चला सकते हैं: rev shell प्राप्त करना, user जोड़ना, beacon execute करना...

> [!WARNING]
> ध्यान दें कि **सभी services** **`NT AUTHORITY\SYSTEM`** के रूप में **run नहीं होतीं**। कुछ **`NT AUTHORITY\LOCAL SERVICE`** के रूप में run होती हैं, जिसके पास **कम privileges** होते हैं, इसलिए इनमें से किसी service का abuse करने पर आप नया user create नहीं कर पाएँगे।\
> हालांकि, उस account के पास **`SeImpersonatePrivilege`** user right होता है, इसलिए आप [**privileges escalate करने के लिए Potato suite का उपयोग कर सकते हैं**](../roguepotato-and-printspoofer.md)। इस मामले में, user create करने का प्रयास करने की तुलना में reverse shell बेहतर option है।

**Task Scheduler** service सामान्यतः **`NT AUTHORITY\SYSTEM`** के रूप में run होती है, लेकिन actual deployment verify करें और execution identity का अनुमान केवल service name से न लगाएँ:<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
**malicious Dll generate करने के बाद** (_मेरे मामले में मैंने x64 rev shell का उपयोग किया और मुझे shell वापस मिल गई, लेकिन Defender ने उसे समाप्त कर दिया क्योंकि वह msfvenom से थी_), उसे writable System Path में **WptsExtensions.dll** नाम से save करें और computer को **restart** करें (या service को restart करें अथवा प्रभावित service/program को दोबारा चलाने के लिए जो भी आवश्यक हो, वह करें)।

जब service दोबारा start होगी, तो **DLL load और execute होनी चाहिए** (यह जाँचने के लिए कि **library अपेक्षा के अनुसार load हुई है**, आप **Procmon** वाली trick को फिर से उपयोग कर सकते हैं)।

> [!NOTE]
> Trigger करने से पहले cleanup की योजना बनाएँ। कोई service DLL को mapped रख सकती है और file को तब तक lock कर सकती है, जब तक वह stop न हो जाए; `WptsExtensions.dll` के लिए Task Scheduler को stop करने हेतु elevated rights आवश्यक हैं। इच्छित context प्राप्त करने के बाद, target को सुरक्षित रूप से stop करें, payload हटाएँ और केवल lab के लिए किए गए किसी भी `PATH` change को restore करें।<sup>[[1]](#references)</sup>

### Remediation / detection

हर Machine `PATH` directory से कमजोर write grants हटाएँ और stale entries भी हटाएँ। Developers को trusted libraries को full path से load करना चाहिए या `SetDefaultDllDirectories` / `LoadLibraryEx` search flags के साथ resolution को सीमित करना चाहिए। Defenders, Machine `PATH` में हुए changes को privileged processes द्वारा non-system, user-writable directories से DLLs load करने के साथ correlate कर सकते हैं।<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Windows DLL Hijacking (उम्मीद है) स्पष्ट किया गया](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Persistence या Privilege Escalation के लिए लोड की गई संदिग्ध DLL](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Environment Variables](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
