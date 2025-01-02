# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/image (48).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) का उपयोग करें ताकि आप दुनिया के **सबसे उन्नत** सामुदायिक उपकरणों द्वारा संचालित **कार्यप्रवाहों** को आसानी से बना और **स्वचालित** कर सकें।\
आज ही एक्सेस प्राप्त करें:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## वे कैसे काम करते हैं

यह प्रक्रिया नीचे दिए गए चरणों में स्पष्ट की गई है, जो दिखाती है कि सेवा बाइनरी को SMB के माध्यम से लक्षित मशीन पर दूरस्थ निष्पादन प्राप्त करने के लिए कैसे हेरफेर किया जाता है:

1. **ADMIN$ शेयर पर SMB के माध्यम से एक सेवा बाइनरी की कॉपी** की जाती है।
2. **दूरस्थ मशीन पर एक सेवा का निर्माण** बाइनरी की ओर इशारा करके किया जाता है।
3. सेवा **दूरस्थ रूप से शुरू की जाती है**।
4. बाहर निकलने पर, सेवा **रुकी जाती है, और बाइनरी को हटा दिया जाता है**।

### **PsExec को मैन्युअल रूप से निष्पादित करने की प्रक्रिया**

मान लेते हैं कि एक निष्पादन योग्य पेलोड है (जो msfvenom के साथ बनाया गया है और एंटीवायरस पहचान से बचने के लिए Veil का उपयोग करके छिपाया गया है), जिसका नाम 'met8888.exe' है, जो एक मीटरप्रीटर रिवर्स_http पेलोड का प्रतिनिधित्व करता है, निम्नलिखित चरण उठाए जाते हैं:

- **बाइनरी की कॉपी करना**: निष्पादन योग्य को एक कमांड प्रॉम्प्ट से ADMIN$ शेयर में कॉपी किया जाता है, हालांकि इसे फ़ाइल सिस्टम पर कहीं भी रखा जा सकता है ताकि यह छिपा रहे।

- **एक सेवा बनाना**: Windows `sc` कमांड का उपयोग करते हुए, जो दूरस्थ रूप से Windows सेवाओं को क्वेरी, बनाने और हटाने की अनुमति देता है, "meterpreter" नामक एक सेवा बनाई जाती है जो अपलोड की गई बाइनरी की ओर इशारा करती है।

- **सेवा शुरू करना**: अंतिम चरण में सेवा को शुरू करना शामिल है, जो संभवतः "टाइम-आउट" त्रुटि का परिणाम देगा क्योंकि बाइनरी एक वास्तविक सेवा बाइनरी नहीं है और अपेक्षित प्रतिक्रिया कोड लौटाने में विफल रहती है। यह त्रुटि महत्वहीन है क्योंकि प्राथमिक लक्ष्य बाइनरी का निष्पादन है।

Metasploit श्रोता का अवलोकन करने पर पता चलेगा कि सत्र सफलतापूर्वक आरंभ किया गया है।

[`sc` कमांड के बारे में अधिक जानें](https://technet.microsoft.com/en-us/library/bb490995.aspx)।

विस्तृत चरणों के लिए देखें: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**आप Windows Sysinternals बाइनरी PsExec.exe का भी उपयोग कर सकते हैं:**

![](<../../images/image (165).png>)

आप [**SharpLateral**](https://github.com/mertdas/SharpLateral) का भी उपयोग कर सकते हैं:
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
<figure><img src="/images/image (48).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) का उपयोग करें ताकि आप दुनिया के **सबसे उन्नत** सामुदायिक उपकरणों द्वारा संचालित **कार्यप्रवाहों** को आसानी से बना और **स्वचालित** कर सकें।\
आज ही एक्सेस प्राप्त करें:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{{#include ../../banners/hacktricks-training.md}}
