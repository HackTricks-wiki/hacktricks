# लिखने योग्य System Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## परिचय

अगर आपने पाया कि आप **System Path फ़ोल्डर में लिख सकते हैं** (ध्यान दें कि यह तब काम नहीं करेगा अगर आप केवल User Path फ़ोल्डर में लिख सकते हैं) तो संभव है कि आप सिस्टम में **अधिकार बढ़ा सकते हैं**।

इसके लिए आप एक **Dll Hijacking** का दुरुपयोग कर सकते हैं जहाँ आप उस सर्विस या प्रोसेस द्वारा लोड हो रहे लाइब्रेरी को **हाइजैक** करने जा रहे हैं जो आपसे **बेहतर privileges** के साथ चल रहा है, और चूँकि वह सर्विस एक ऐसे Dll को लोड कर रही है जो पूरे सिस्टम में शायद मौजूद ही नहीं है, वह इसे उस System Path से लोड करने की कोशिश करेगा जहाँ आप लिख सकते हैं।

Dll Hijackig क्या है इसके बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
./
{{#endref}}

## Dll Hijacking के साथ Privesc

### गायब Dll खोजना

सबसे पहले आपको एक ऐसा **प्रोसेस पहचानना** होगा जो आपके मुकाबले **ज़्यादा privileges** के साथ चल रहा हो और जो उस System Path से **Dll लोड करने** की कोशिश कर रहा हो जिसमें आप लिख सकते हैं।

इस मामलों की दिक्कत यह है कि संभवतः वे प्रोसेस पहले से ही चल रहे होंगे। यह पता लगाने के लिए कि किन Dlls की कमी है, आपको जितनी जल्दी हो सके procmon लॉन्च करना होगा (प्रोसेसेस लोड होने से पहले)। तो, कमी वाले .dlls खोजने के लिए करें:

- **Create** the folder `C:\privesc_hijacking` and add the path `C:\privesc_hijacking` to **System Path env variable**. You can do this **manually** or with **PS**:
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
- Launch **`procmon`** and go to **`Options`** --> **`Enable boot logging`** and press **`OK`** in the prompt.
- फिर, **रीबूट** करें। जब कंप्यूटर पुनः चालू होगा तो **`procmon`** जितनी जल्दी हो सके इवेंट्स रिकॉर्ड करना शुरू कर देगा।
- एक बार **Windows** शुरू हो जाने के बाद फिर से **`procmon`** चलाएँ, यह आपको बताएगा कि यह चल रहा था और यह आपसे पूछेगा कि क्या आप इवेंट्स को किसी फाइल में संग्रहीत करना चाहते हैं। हाँ कहें और इवेंट्स को एक फाइल में स्टोर करें।
- **फाइल** बन जाने के बाद, खुले हुए **`procmon`** विंडो को बंद करें और इवेंट्स फाइल खोलें।
- इन **फिल्टरों** को जोड़ें और आप उन सभी Dlls को पाएँगे जिन्हें कुछ processes ने writable System Path folder से लोड करने की कोशिश की:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Missed Dlls

इसे एक free virtual (vmware) Windows 11 मशीन पर चलाने पर मुझे ये परिणाम मिले:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

इस मामले में .exe बेकार थे इसलिए उन्हें अनदेखा करें, छूटी हुई DLLs निम्न से थीं:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

After finding this, I found this interesting blog post that also explains how to [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Which is what we **are going to do now**.

### Exploitation

तो, privileges escalate करने के लिए हम लाइब्रेरी **WptsExtensions.dll** को hijack करेंगे। Path और नाम मिल जाने पर हमें केवल malicious dll generate करना होगा।

आप [**try to use any of these examples**](#creating-and-compiling-dlls) को आज़मा सकते हैं। आप ऐसे payloads चला सकते हैं: get a rev shell, add a user, execute a beacon...

> [!WARNING]
> ध्यान दें कि **not all the service are run** with **`NT AUTHORITY\SYSTEM`**—कुछ सेवाएँ **`NT AUTHORITY\LOCAL SERVICE`** के साथ भी चलती हैं जिनके पास **कम privileges** होते हैं और आप उन पर निर्भर करते हुए नया user नहीं बना पाएँगे।\
> हालांकि, उस user के पास **`seImpersonate`** privilege होता है, तो आप [ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md) का उपयोग करके privileges escalate कर सकते हैं। इसलिए, इस मामले में rev shell user बनवाने की कोशिश करने से बेहतर विकल्प है।

वर्तमान लेखन के समय **Task Scheduler** सेवा **Nt AUTHORITY\SYSTEM** के साथ चल रही है।

Having **generated the malicious Dll** (_in my case I used x64 rev shell and I got a shell back but defender killed it because it was from msfvenom_), उसको writable System Path में नाम **WptsExtensions.dll** के साथ सेव करें और कंप्यूटर को restart करें (या सेवा को restart करें या प्रभावित service/program को फिर से चलाने के लिए जो भी आवश्यक हो वह करें)।

जब सेवा पुनः चालू होगी, तो **dll लोड और execute होना चाहिए** (आप **`procmon`** trick को दोबारा उपयोग कर के चेक कर सकते हैं कि **library उम्मीद के मुताबिक लोड हुई थी**)। 

{{#include ../../../banners/hacktricks-training.md}}
