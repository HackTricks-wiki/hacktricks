# Memory dump analysis

{{#include ../../../banners/hacktricks-training.md}}

## प्रारंभ

pcap के अंदर **malware** को **search** करना शुरू करें। [**Malware Analysis**](../malware-analysis.md) में बताए गए **tools** का उपयोग करें।

## [Volatility](volatility-cheatsheet.md)

**Volatility memory dump analysis के लिए एक open-source framework है**। यह Python tool external sources या VMware VMs से प्राप्त dumps का analysis करता है और dump के OS profile के आधार पर processes और passwords जैसी जानकारी पहचानता है। यह plugins के साथ extensible है, जिससे forensic investigations के लिए यह अत्यंत versatile बन जाता है।<sup>[[1]](#references)[[2]](#references)</sup>

[**cheatsheet यहां देखें**](volatility-cheatsheet.md)

## Mini dump crash report

जब dump छोटा हो (सिर्फ कुछ KB, शायद कुछ MB), तो यह full memory dump के बजाय mini dump crash report हो सकता है।<sup>[[3]](#references)</sup>

![Volatility - Mini dump crash report: एक छोटी dump file जिसे Mini DuMP crash report के रूप में पहचाना गया है](<../../../images/image (532).png>)

यदि Visual Studio installed है, तो आप इस file को खोलकर process name, architecture, exception details और loaded modules जैसी basic information देख सकते हैं:<sup>[[4]](#references)</sup>

![Volatility - Mini dump crash report: यदि Visual Studio installed है, तो आप इस file को खोलकर process name, architecture, exception info और अन्य basic information देख सकते हैं](<../../../images/image (263).png>)

आप exception का inspection भी कर सकते हैं और module का disassembly देख सकते हैं।<sup>[[4]](#references)</sup>

![Visual Studio minidump Actions panel जिसमें natively debug करने और symbol paths set करने के options हैं](<../../../images/image (142).png>)

![Visual Studio disassembly जिसमें minidump exception से instructions दिखाई गई हैं](<../../../images/image (610).png>)

हालांकि, dump का in-depth analysis करने के लिए Visual Studio सबसे अच्छा tool नहीं है।

आपको इसे **IDA** या **Radare** का उपयोग करके **in-depth inspection** के लिए **open** करना चाहिए।

## References

- [1] [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [2] [Volatility Usage](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Minidump Files](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Visual Studio debugger में dump files का उपयोग](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
