# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

यदि आप पाते हैं कि आप **System Path फ़ोल्डर में लिख सकते हैं** (ध्यान दें कि यह तब काम नहीं करेगा जब आप User Path फ़ोल्डर में लिख सकते हैं) तो यह संभव है कि आप **privileges बढ़ा सकते हैं** सिस्टम में।

इसके लिए आप **Dll Hijacking** का दुरुपयोग कर सकते हैं जहाँ आप एक **लाइब्रेरी को हाईजैक करने जा रहे हैं** जिसे एक सेवा या प्रक्रिया द्वारा **आपसे अधिक privileges** के साथ लोड किया जा रहा है, और क्योंकि वह सेवा एक Dll लोड कर रही है जो शायद पूरे सिस्टम में मौजूद नहीं है, यह इसे उस System Path से लोड करने की कोशिश करेगी जहाँ आप लिख सकते हैं।

**Dll Hijacking क्या है** के बारे में अधिक जानकारी के लिए देखें:

{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

आपको सबसे पहले **एक प्रक्रिया की पहचान करनी होगी** जो **आपसे अधिक privileges** के साथ चल रही है और जो **System Path से Dll लोड करने की कोशिश कर रही है** जिसमें आप लिख सकते हैं।

इन मामलों में समस्या यह है कि शायद वे प्रक्रियाएँ पहले से ही चल रही हैं। यह पता लगाने के लिए कि कौन सी Dlls सेवाओं में कमी है, आपको जितनी जल्दी हो सके procmon लॉन्च करना होगा (प्रक्रियाएँ लोड होने से पहले)। इसलिए, कमी वाली .dlls खोजने के लिए करें:

- **Create** करें फ़ोल्डर `C:\privesc_hijacking` और **System Path env variable** में पथ `C:\privesc_hijacking` जोड़ें। आप इसे **manually** या **PS** के साथ कर सकते हैं:
```powershell
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
- **`procmon`** लॉन्च करें और **`Options`** --> **`Enable boot logging`** पर जाएं और प्रॉम्प्ट में **`OK`** दबाएं।
- फिर, **रीबूट** करें। जब कंप्यूटर पुनः चालू होगा, **`procmon`** तुरंत घटनाओं को **रिकॉर्ड** करना शुरू कर देगा।
- एक बार जब **Windows** **शुरू हो जाए, `procmon`** को फिर से चलाएं, यह आपको बताएगा कि यह चल रहा है और **आपसे पूछेगा कि क्या आप घटनाओं को एक फ़ाइल में स्टोर करना चाहते हैं**। **हाँ** कहें और **घटनाओं को एक फ़ाइल में स्टोर करें**।
- **फाइल** **जनरेट** होने के बाद, खुले हुए **`procmon`** विंडो को **बंद** करें और **घटनाओं की फ़ाइल** खोलें।
- ये **फिल्टर** जोड़ें और आप सभी Dlls पाएंगे जो कुछ **प्रोसेस ने** writable System Path फ़ोल्डर से **लोड करने की कोशिश की**:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### छूटे हुए Dlls

एक मुफ्त **वर्चुअल (vmware) Windows 11 मशीन** में इसे चलाने पर मुझे ये परिणाम मिले:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

इस मामले में .exe बेकार हैं इसलिए उन्हें अनदेखा करें, छूटे हुए DLLs थे:

| सेवा                             | Dll                | CMD लाइन                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| टास्क शेड्यूलर (Schedule)      | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| डायग्नोस्टिक पॉलिसी सेवा (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

यह खोजने के बाद, मैंने एक दिलचस्प ब्लॉग पोस्ट पाया जो यह भी बताता है कि कैसे [**WptsExtensions.dll का दुरुपयोग करें privesc के लिए**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)। जो हम **अब करने जा रहे हैं**।

### शोषण

तो, **privileges को बढ़ाने** के लिए हम लाइब्रेरी **WptsExtensions.dll** को हाईजैक करने जा रहे हैं। **पथ** और **नाम** होने के साथ, हमें बस **दुष्ट dll** **जनरेट** करने की आवश्यकता है।

आप [**इन उदाहरणों में से किसी का उपयोग करने की कोशिश कर सकते हैं**](./#creating-and-compiling-dlls)। आप payloads चला सकते हैं जैसे: एक rev shell प्राप्त करें, एक उपयोगकर्ता जोड़ें, एक beacon निष्पादित करें...

> [!WARNING]
> ध्यान दें कि **सभी सेवाएं** **`NT AUTHORITY\SYSTEM`** के साथ **नहीं चलतीं**, कुछ **`NT AUTHORITY\LOCAL SERVICE`** के साथ भी चलती हैं, जिसमें **कम विशेषाधिकार** होते हैं और आप **नया उपयोगकर्ता बनाने में असमर्थ होंगे** इसके अनुमतियों का दुरुपयोग करें।\
> हालाँकि, उस उपयोगकर्ता के पास **`seImpersonate`** विशेषाधिकार है, इसलिए आप [**potato suite का उपयोग करके विशेषाधिकार बढ़ा सकते हैं**](../roguepotato-and-printspoofer.md)। इसलिए, इस मामले में एक rev shell एक उपयोगकर्ता बनाने की कोशिश करने से बेहतर विकल्प है।

लेखन के समय **टास्क शेड्यूलर** सेवा **Nt AUTHORITY\SYSTEM** के साथ चल रही है।

**दुष्ट Dll** (_मेरे मामले में मैंने x64 rev shell का उपयोग किया और मुझे एक shell वापस मिला लेकिन डिफेंडर ने इसे मार दिया क्योंकि यह msfvenom से था_) को writable System Path में **WptsExtensions.dll** नाम से सहेजें और कंप्यूटर को **रीस्टार्ट** करें (या सेवा को पुनः प्रारंभ करें या प्रभावित सेवा/प्रोग्राम को फिर से चलाने के लिए जो भी करना हो करें)।

जब सेवा पुनः प्रारंभ होती है, तो **dll को लोड और निष्पादित किया जाना चाहिए** (आप **procmon** ट्रिक का **पुनः उपयोग** कर सकते हैं यह जांचने के लिए कि **लाइब्रेरी अपेक्षित रूप से लोड हुई थी**)। 

{{#include ../../../banners/hacktricks-training.md}}
