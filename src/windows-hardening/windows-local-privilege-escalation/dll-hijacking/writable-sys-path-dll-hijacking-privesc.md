# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

यदि आपने पाया है कि आप **System Path folder में write** कर सकते हैं (ध्यान दें कि यदि आप User Path folder में write कर सकते हैं, तो यह काम नहीं करेगा), तो संभव है कि आप system में **privileges escalate** कर सकें।

ऐसा करने के लिए आप **Dll Hijacking** का दुरुपयोग कर सकते हैं, जिसमें आप किसी ऐसी **library को hijack** करेंगे जिसे आपसे **अधिक privileges** वाली service या process load कर रही है। चूंकि वह service ऐसी Dll को load कर रही है जो संभवतः पूरे system में मौजूद भी नहीं है, इसलिए वह उसे उस System Path से load करने का प्रयास करेगी जिसमें आप write कर सकते हैं।

**Dll Hijackig क्या है**, इसके बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

सबसे पहले आपको ऐसी **process identify** करनी होगी जो आपसे **अधिक privileges** के साथ चल रही हो और उस System Path से **Dll load** करने का प्रयास कर रही हो जिसमें आप write कर सकते हैं।

याद रखें कि यह technique केवल आपके **User PATH** पर नहीं, बल्कि **Machine/System PATH** entry पर निर्भर करती है। इसलिए Procmon पर समय बिताने से पहले **Machine PATH** entries को enumerate करना और यह जांचना उपयोगी है कि इनमें से कौन-सी writable हैं:<sup>[[1]](#references)</sup>
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
इस मामले में समस्या यह है कि संभवतः वे processes पहले से चल रहे हैं। यह पता लगाने के लिए कि services को कौन-से Dlls नहीं मिल रहे हैं, आपको procmon को जितनी जल्दी हो सके लॉन्च करना होगा (processes लोड होने से पहले)। इसलिए, missing .dlls खोजने के लिए:

- **Create** फ़ोल्डर `C:\privesc_hijacking` बनाएं और path `C:\privesc_hijacking` को **System Path env variable** में जोड़ें। आप यह **manually** या **PS** से कर सकते हैं:
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
- फिर **reboot** करें। कंप्यूटर के restart होने पर **`procmon`** asap events **recording** करना शुरू कर देगा।
- **Windows** के **started** होने के बाद **`procmon`** को फिर से **execute** करें। यह आपको बताएगा कि यह चल रहा था और **पूछेगा कि क्या आप** events को किसी file में **store करना चाहते हैं**। **yes** कहें और **events को file में store करें**।
- **file** **generate** होने के **बाद**, खुली हुई **`procmon`** window को **close** करें और events file को **open** करें।
- ये **filters** add करें और आपको वे सभी Dlls मिल जाएँगी जिन्हें किसी **process ने writable System Path folder** से **load** करने की कोशिश की:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** केवल उन services के लिए आवश्यक है जो इतनी जल्दी start होती हैं कि उन्हें अन्यथा observe नहीं किया जा सकता। यदि आप **target service/program को on demand trigger** कर सकते हैं (उदाहरण के लिए, उसके COM interface के साथ interact करके, service को restart करके, या scheduled task को फिर से launch करके), तो आमतौर पर **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, और **`Path begins with <writable_machine_path>`** जैसे filters के साथ normal Procmon capture रखना अधिक तेज़ होता है।

### छूटी हुई Dlls

इसे एक free **virtual (vmware) Windows 11 machine** में **run** करने पर मुझे ये results मिले:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

इस case में .exe बेकार हैं, इसलिए उन्हें ignore करें। छूटी हुई DLLs इनसे संबंधित थीं:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

यह पता लगाने के बाद, मुझे एक interesting blog post मिला जो यह भी बताता है कि [**privesc के लिए WptsExtensions.dll का abuse कैसे करें**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)। अब हम यही **करने वाले हैं**।<sup>[[3]](#references)</sup>

### आगे triage करने योग्य अन्य candidates

`WptsExtensions.dll` एक अच्छा example है, लेकिन यह एकमात्र recurring **phantom DLL** नहीं है जो privileged services में दिखाई देती है। Modern hunting rules और public hijack catalogs अभी भी इन जैसे names को track करते हैं:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Client systems पर classic **SYSTEM** candidate। तब उपयोगी है जब writable directory **Machine PATH** में हो और service startup के दौरान DLL को probe करे। |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | **server editions** पर interesting है क्योंकि service **SYSTEM** के रूप में run होती है और कुछ builds में इसे **normal user द्वारा on demand trigger किया जा सकता है**, जिससे यह केवल reboot वाले cases से बेहतर बन जाता है। |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | आमतौर पर पहले **`NT AUTHORITY\LOCAL SERVICE`** मिलता है। यह अक्सर पर्याप्त होता है क्योंकि token में **`SeImpersonatePrivilege`** होता है, इसलिए आप इसे [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) के साथ chain कर सकते हैं। |

इन names को guaranteed wins नहीं, बल्कि **triage hints** मानें: ये **SKU/build dependent** हैं और Microsoft releases के बीच behavior बदल सकता है। मुख्य बात यह है कि **Machine PATH को traverse करने वाली privileged services में missing DLLs** खोजें, खासकर तब जब service को **reboot के बिना फिर से trigger** किया जा सके।

### Exploitation

इसलिए **privileges escalate** करने के लिए हम **WptsExtensions.dll** library को hijack करने वाले हैं। **path** और **name** मिलने के बाद हमें केवल **malicious dll generate** करनी है।

आप [**इनमें से किसी भी examples का उपयोग करने की कोशिश कर सकते हैं**](#creating-and-compiling-dlls)। आप ऐसे payloads run कर सकते हैं: rev shell प्राप्त करना, user add करना, beacon execute करना...

> [!WARNING]
> ध्यान दें कि **सभी services** **`NT AUTHORITY\SYSTEM`** के रूप में **run नहीं होतीं**। कुछ **`NT AUTHORITY\LOCAL SERVICE`** के रूप में भी run होती हैं, जिसके पास **कम privileges** होते हैं और आप **उसकी permissions का abuse करके नया user create नहीं कर पाएँगे**।\
> हालांकि, इस user के पास **`seImpersonate`** privilege होता है, इसलिए आप [ **potato suite का उपयोग करके privileges escalate कर सकते हैं**](../roguepotato-and-printspoofer.md)। इसलिए, इस case में user create करने की कोशिश करने के बजाय rev shell एक बेहतर option है।

लेखन के समय **Task Scheduler** service **Nt AUTHORITY\SYSTEM** के साथ run होती है।

**malicious Dll generate** करने के बाद (_मेरे case में मैंने x64 rev shell का उपयोग किया और मुझे shell वापस मिला, लेकिन defender ने उसे kill कर दिया क्योंकि वह msfvenom से आया था_), उसे writable System Path में **WptsExtensions.dll** name के साथ save करें और कंप्यूटर को **restart** करें (या service को restart करें अथवा affected service/program को फिर से run करने के लिए जो भी आवश्यक हो, वह करें)।

जब service फिर से **re-start** होगी, तो **dll load और execute होनी चाहिए** (यह check करने के लिए कि **library expected तरीके से load हुई है**, आप **procmon** trick को फिर से use कर सकते हैं)।

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
