# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## परिचय

अगर आपने पाया कि आप एक **System Path folder** में **write** कर सकते हैं (ध्यान दें कि यह तब काम नहीं करेगा अगर आप केवल एक User Path folder में write कर सकते हैं), तो संभव है कि आप सिस्टम में **privileges escalate** कर सकें।

ऐसा करने के लिए आप एक **Dll Hijacking** का दुरुपयोग कर सकते हैं, जहाँ आप अपनी तुलना में **अधिक privileges** वाले किसी service या process द्वारा **load** की जा रही एक library को **hijack** करेंगे, और क्योंकि वह service एक ऐसी Dll load कर रही है जो शायद पूरे सिस्टम में मौजूद ही नहीं है, वह उसे System Path से load करने की कोशिश करेगी जहाँ आप write कर सकते हैं।

**Dll Hijackig** क्या है, इसके बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
./
{{#endref}}

## Dll Hijacking के साथ Privesc

### Missing Dll ढूंढना

सबसे पहले आपको एक ऐसा **process** पहचानना होगा जो **आपसे अधिक privileges** के साथ चल रहा हो और **System Path** से एक Dll **load** करने की कोशिश कर रहा हो, जहाँ आप write कर सकते हैं।

याद रखें कि यह technique **Machine/System PATH** entry पर निर्भर करती है, सिर्फ आपके **User PATH** पर नहीं। इसलिए, Procmon पर समय खर्च करने से पहले, **Machine PATH** entries को enumerate करना और देखना उपयोगी है कि कौन-सी writable हैं:
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
इस case में problem यह है कि शायद वे processes पहले से ही चल रहे हैं। कौन-सी Dlls missing हैं यह जानने के लिए आपको procmon को जितनी जल्दी हो सके launch करना होगा (processes load होने से पहले)। इसलिए, missing .dlls find करने के लिए यह करें:

- **Create** the folder `C:\privesc_hijacking` और path `C:\privesc_hijacking` को **System Path env variable** में add करें। आप यह **manually** या **PS** के साथ कर सकते हैं:
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
- **`procmon`** लॉन्च करें और **`Options`** --> **`Enable boot logging`** पर जाएँ और प्रॉम्प्ट में **`OK`** दबाएँ।
- फिर, **reboot** करें। जब computer restart होगा, **`procmon`** तुरंत events **record** करना शुरू कर देगा।
- एक बार **Windows** शुरू हो जाए, **`procmon`** को फिर से execute करें, यह बताएगा कि यह चल रहा था और आपसे पूछेगा कि क्या आप events को file में **store** करना चाहते हैं। **yes** कहें और events को file में **store** करें।
- **File** generate होने के **after**, खुले हुए **`procmon`** window को **close** करें और **events file** खोलें।
- ये **filters** जोड़ें और आपको वे सभी Dlls मिल जाएँगी जिन्हें कोई **proccess tried to load** writable System Path folder से:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging is only required for services that start too early** to observe otherwise. If you can **trigger the target service/program on demand** (for example, by interacting with its COM interface, restarting the service, or relaunching a scheduled task), it is usually faster to keep a normal Procmon capture with filters such as **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, and **`Path begins with <writable_machine_path>`**.

### Missed Dlls

इसे एक free **virtual (vmware) Windows 11 machine** पर चलाने पर मुझे ये results मिले:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

इस case में .exe useless हैं, इसलिए उन्हें ignore करें, missed DLLs इनसे थे:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

यह finding करने के बाद, मुझे यह interesting blog post मिला जो यह भी समझाता है कि [**privesc के लिए WptsExtensions.dll को abuse कैसे करें**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)। यही हम **अब करने जा रहे हैं**।

### Other candidates worth triaging

`WptsExtensions.dll` एक अच्छा example है, लेकिन privileged services में दिखने वाली recurring **phantom DLL** केवल यही नहीं है। Modern hunting rules और public hijack catalogs अभी भी ऐसे names track करते हैं जैसे:

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Client systems पर classic **SYSTEM** candidate. तब अच्छा जब writable directory **Machine PATH** में हो और service startup के दौरान DLL probe करे. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | **server editions** पर interesting, क्योंकि service **SYSTEM** के रूप में चलता है और कुछ builds में **normal user द्वारा on demand trigger** किया जा सकता है, जिससे यह reboot-only cases से बेहतर हो जाता है. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | आमतौर पर पहले **`NT AUTHORITY\LOCAL SERVICE`** देता है। यह अक्सर फिर भी पर्याप्त होता है क्योंकि token में **`SeImpersonatePrivilege`** होता है, इसलिए आप इसे [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) के साथ chain कर सकते हैं. |

इन names को **triage hints** की तरह लें, guaranteed wins की तरह नहीं: ये **SKU/build dependent** हैं, और Microsoft releases के बीच behavior बदल सकता है। मुख्य takeaway यह है कि **privileged services में missing DLLs** ढूँढें जो Machine PATH traverse करते हैं, खासकर अगर service को **reboot किए बिना re-trigger** किया जा सकता हो।

### Exploitation

तो, **privileges escalate** करने के लिए हम library **WptsExtensions.dll** को hijack करेंगे। **path** और **name** मिल जाने के बाद हमें बस **malicious dll generate** करनी है।

आप [**इनमें से कोई भी example try कर सकते हैं**](#creating-and-compiling-dlls)। आप ऐसे payloads चला सकते हैं: get a rev shell, add a user, execute a beacon...

> [!WARNING]
> ध्यान दें कि **सभी services** **`NT AUTHORITY\SYSTEM`** के साथ नहीं चलते; कुछ **`NT AUTHORITY\LOCAL SERVICE`** के साथ भी चलते हैं, जिसके पास **कम privileges** होते हैं और आप इसकी permissions abuse करके **new user create नहीं** कर पाएँगे।\
> हालांकि, उस user के पास **`seImpersonate`** privilege होता है, इसलिए आप privileges escalate करने के लिए [**potato suite**](../roguepotato-and-printspoofer.md) का उपयोग कर सकते हैं। इसलिए, इस case में user create करने की कोशिश करने के बजाय rev shell एक बेहतर option है।

लेखन के समय **Task Scheduler** service **Nt AUTHORITY\SYSTEM** के साथ चलती है।

**Malicious Dll generate** करने के बाद (_मेरे case में मैंने x64 rev shell इस्तेमाल किया और मुझे shell वापस मिली, लेकिन defender ने उसे kill कर दिया क्योंकि वह msfvenom से थी_), इसे writable System Path में **WptsExtensions.dll** नाम से save करें और computer को **restart** करें (या service restart करें या affected service/program को फिर से चलाने के लिए जो भी करना पड़े करें)।

जब service फिर से start होगी, तो **dll load और execute** होनी चाहिए (आप **procmon** trick का फिर से उपयोग करके जाँच सकते हैं कि **library expected तरह से load हुई या नहीं**).

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
