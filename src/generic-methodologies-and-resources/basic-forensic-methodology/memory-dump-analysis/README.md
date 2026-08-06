# Memory dump analysis

{{#include ../../../banners/hacktricks-training.md}}

## शुरू करें

pcap के अंदर **malware** को **search** करना शुरू करें। [**Malware Analysis**](../malware-analysis.md) में बताए गए **tools** का उपयोग करें।

## [Volatility](volatility-cheatsheet.md)

**Volatility मेमोरी dump analysis के लिए मुख्य open-source framework है**। यह Python tool external sources या VMware VMs से प्राप्त dumps का analysis करता है और dump के OS profile के आधार पर processes और passwords जैसी information की पहचान करता है। यह plugins के साथ extensible है, जिससे forensic investigations के लिए यह काफी versatile बन जाता है।

[**यहाँ cheatsheet देखें**](volatility-cheatsheet.md)

## Mini dump crash report

जब dump छोटा हो (सिर्फ कुछ KB, या शायद कुछ MB), तो यह संभवतः memory dump नहीं, बल्कि mini dump crash report होता है।

![Volatility - Mini dump crash report: जब dump छोटा हो (सिर्फ कुछ KB, या शायद कुछ MB), तो यह संभवतः memory dump नहीं, बल्कि mini dump crash report होता है](<../../../images/image (532).png>)

यदि Visual Studio install है, तो आप इस file को open करके process name, architecture, exception info और execute हो रहे modules जैसी basic information प्राप्त कर सकते हैं:

![Volatility - Mini dump crash report: यदि Visual Studio install है, तो आप इसे open करके process name, architecture, exception info और... जैसी basic information प्राप्त कर सकते हैं](<../../../images/image (263).png>)

आप exception को load करके decompiled instructions भी देख सकते हैं।

![Volatility - Mini dump crash report: आप exception को load करके decompiled instructions भी देख सकते हैं](<../../../images/image (142).png>)

![Volatility - Mini dump crash report: आप exception को load करके decompiled instructions भी देख सकते हैं](<../../../images/image (610).png>)

फिर भी, dump का गहराई से analysis करने के लिए Visual Studio सबसे अच्छा tool नहीं है।

आपको इसे **IDA** या **Radare** का उपयोग करके **depth** में inspection के लिए **open** करना चाहिए।

{{#include ../../../banners/hacktricks-training.md}}
