# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

यदि आप **system-wide `PATH` में किसी directory में write** कर सकते हैं (केवल अपने user `PATH` में नहीं), तो आप system पर **privileges escalate** कर सकते हैं।

इसका दुरुपयोग **DLL hijacking** के माध्यम से किया जा सकता है, जब कोई अधिक-privileged service या process ऐसी DLL load करने का प्रयास करता है जो उसके पहले के search locations में मौजूद नहीं होती और अंततः writable system `PATH` directory में search करता है।

**DLL hijacking** के बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a Missing DLL

सबसे पहले, **ऐसे process की पहचान करें** जो **अधिक privileges** के साथ चल रहा हो और **writable system `PATH` directory से DLL load** करने का प्रयास करता हो।

याद रखें कि यह technique केवल आपके **User PATH** पर नहीं, बल्कि **Machine/System PATH** entry पर निर्भर करती है। इसलिए Procmon पर समय बिताने से पहले, **Machine PATH** entries को enumerate करना और यह जांचना उपयोगी है कि इनमें से कौन-सी writable हैं:<sup>[[1]](#references)</sup>
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
इन मामलों में समस्या यह है कि वे processes संभवतः पहले से ही चल रहे होते हैं। उन DLLs की पहचान करने के लिए जिन्हें services load करने का प्रयास करती हैं और विफल रहती हैं, Procmon को जितना जल्दी संभव हो लॉन्च करें (processes शुरू होने से पहले), फिर:

- **Create** folder `C:\privesc_hijacking` और path `C:\privesc_hijacking` को **System Path env variable** में जोड़ें। आप यह **manually** या **PS** से कर सकते हैं:
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
- **`procmon`** लॉन्च करें और **`Options`** --> **`Enable boot logging`** पर जाएँ, फिर prompt में **`OK`** दबाएँ।
- इसके बाद **reboot** करें। कंप्यूटर restart होने पर **`procmon`** तुरंत events **record** करना शुरू कर देगा।
- **Windows** **start** होने के बाद **`procmon`** फिर से **execute** करें। यह बताएगा कि यह चल रहा था और आपसे पूछेगा कि क्या आप events को किसी file में **store** करना चाहते हैं। **yes** चुनें और **events को file में store** करें।
- **File** **generate** होने के **बाद**, खुली हुई **`procmon`** window को **close** करें और **events file** खोलें।
- Writable System Path folder से **process द्वारा load करने की कोशिश की गई सभी DLLs** खोजने के लिए ये **filters** जोड़ें:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** केवल उन services के लिए आवश्यक है जो इतनी जल्दी start होती हैं कि अन्यथा उन्हें observe करना संभव नहीं होता। यदि आप **target service/program को on demand trigger** कर सकते हैं (उदाहरण के लिए, उसके COM interface के साथ interact करके, service को restart करके, या scheduled task को फिर से launch करके), तो आमतौर पर **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, और **`Path begins with <writable_machine_path>`** जैसे filters के साथ सामान्य Procmon capture रखना अधिक तेज़ होता है।

### छूटी हुई Dlls

एक free **virtual (vmware) Windows 11 machine** में इसे run करने पर मुझे ये results मिले:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

इस मामले में `.exe` results को ignore करें। Missing-DLL probes इनसे आए थे:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

निम्नलिखित example इस article में वर्णित technique का उपयोग करता है, जिसमें [**privilege escalation के लिए `WptsExtensions.dll` का दुरुपयोग**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) किया जाता है।<sup>[[3]](#references)</sup>

### अन्य candidates जिन्हें triage करना उपयोगी है

`WptsExtensions.dll` एक अच्छा example है, लेकिन यह privileged services में दिखाई देने वाला एकमात्र recurring **phantom DLL** नहीं है। Modern hunting rules और public hijack catalogs अभी भी इन जैसे names को track करते हैं:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Client systems पर classic **SYSTEM** candidate। तब उपयोगी है जब writable directory **Machine PATH** में हो और service startup के दौरान DLL को probe करे। |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | **server editions** पर interesting, क्योंकि service **SYSTEM** के रूप में run होती है और कुछ builds में **normal user द्वारा on demand trigger** की जा सकती है, जिससे यह केवल reboot वाले cases से बेहतर बनती है। |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | आमतौर पर पहले **`NT AUTHORITY\LOCAL SERVICE`** प्राप्त होता है। यह अक्सर पर्याप्त होता है, क्योंकि token के पास **`SeImpersonatePrivilege`** होता है; इसलिए इसे [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) के साथ chain कर सकते हैं। |

इन names को guaranteed wins के बजाय **triage hints** मानें: ये **SKU/build dependent** हैं और Microsoft releases के बीच behavior बदल सकता है। मुख्य बात यह है कि privileged services में **Machine PATH को traverse करने वाली missing DLLs** खोजें, खासकर तब जब service को **बिना reboot किए फिर से trigger** किया जा सके।

### Exploitation

**Privileges escalate** करने के लिए **`WptsExtensions.dll`** को hijack करें। **Path** और **name** ज्ञात होने के बाद malicious DLL generate करें।

आप [**इनमें से किसी भी example का उपयोग करने की कोशिश कर सकते हैं**](#creating-and-compiling-dlls)। आप ऐसे payloads run कर सकते हैं: rev shell प्राप्त करना, user जोड़ना, beacon execute करना...

> [!WARNING]
> ध्यान दें कि **सभी services** **`NT AUTHORITY\SYSTEM`** के रूप में **run** नहीं होतीं। कुछ **`NT AUTHORITY\LOCAL SERVICE`** के रूप में run होती हैं, जिसके पास **कम privileges** होते हैं, इसलिए इनमें से किसी service का दुरुपयोग करने पर आप नया user create नहीं कर पाएँगे।\
> हालांकि, इस account के पास **`SeImpersonatePrivilege`** user right होता है, इसलिए आप [**privileges escalate करने के लिए Potato suite**](../roguepotato-and-printspoofer.md) का उपयोग कर सकते हैं। इस मामले में user create करने की कोशिश करने की तुलना में reverse shell बेहतर विकल्प है।

लेखन के समय **Task Scheduler** service **Nt AUTHORITY\SYSTEM** के साथ run होती है।

**Malicious Dll generate** करने के बाद (_मेरे मामले में मैंने x64 rev shell का उपयोग किया और shell वापस मिला, लेकिन defender ने उसे kill कर दिया क्योंकि वह msfvenom से था_), उसे writable System Path में **WptsExtensions.dll** name के साथ save करें और कंप्यूटर को **restart** करें (या service को restart करें अथवा affected service/program को फिर से run करने के लिए जो आवश्यक हो वह करें)।

जब service दोबारा start होगी, तो **dll load और execute होनी चाहिए** (यह check करने के लिए कि **library अपेक्षा के अनुसार load हुई है**, आप **procmon** trick को reuse कर सकते हैं)।

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
