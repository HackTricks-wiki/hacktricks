# Windows Credentials Protections

## Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) प्रोटोकॉल, जो Windows XP के साथ पेश किया गया था, HTTP प्रोटोकॉल के माध्यम से प्रमाणीकरण के लिए डिज़ाइन किया गया है और **Windows XP से Windows 8.0 और Windows Server 2003 से Windows Server 2012 तक डिफ़ॉल्ट रूप से सक्षम है**। यह डिफ़ॉल्ट सेटिंग **LSASS में स्पष्ट-टेक्स्ट पासवर्ड भंडारण** का परिणाम देती है। एक हमलावर Mimikatz का उपयोग करके **इन क्रेडेंशियल्स को निकाल सकता है**:
```bash
sekurlsa::wdigest
```
इस फ़ीचर को **चालू या बंद करने के लिए**, _**UseLogonCredential**_ और _**Negotiate**_ रजिस्ट्री कुंजियाँ _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ के भीतर "1" पर सेट की जानी चाहिए। यदि ये कुंजियाँ **गायब हैं या "0" पर सेट हैं**, तो WDigest **अक्षम** है:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP & PPL protected processes)

**Protected Process (PP)** और **Protected Process Light (PPL)** **Windows kernel-level protections** हैं जो संवेदनशील प्रक्रियाओं जैसे **LSASS** तक अनधिकृत पहुंच को रोकने के लिए डिज़ाइन की गई हैं। **Windows Vista** में पेश किया गया, **PP model** मूल रूप से **DRM** प्रवर्तन के लिए बनाया गया था और केवल **विशेष मीडिया प्रमाणपत्र** के साथ हस्ताक्षरित बाइनरी को सुरक्षित करने की अनुमति दी गई थी। एक प्रक्रिया जिसे **PP** के रूप में चिह्नित किया गया है, केवल अन्य प्रक्रियाओं द्वारा पहुंची जा सकती है जो **भी PP** हैं और जिनका **समान या उच्च सुरक्षा स्तर** है, और तब भी, **केवल सीमित पहुंच अधिकारों** के साथ जब तक विशेष रूप से अनुमति न दी जाए।

**PPL**, जो **Windows 8.1** में पेश किया गया, PP का एक अधिक लचीला संस्करण है। यह **"सुरक्षा स्तरों"** को पेश करके **व्यापक उपयोग के मामलों** (जैसे, LSASS, Defender) की अनुमति देता है जो **डिजिटल सिग्नेचर के EKU (Enhanced Key Usage)** क्षेत्र पर आधारित हैं। सुरक्षा स्तर `EPROCESS.Protection` क्षेत्र में संग्रहीत होता है, जो एक `PS_PROTECTION` संरचना है जिसमें:
- **Type** (`Protected` या `ProtectedLight`)
- **Signer** (जैसे, `WinTcb`, `Lsa`, `Antimalware`, आदि)

यह संरचना एक एकल बाइट में पैक की गई है और **कौन किससे पहुंच सकता है** यह निर्धारित करती है:
- **उच्च साइनर मान निम्न को एक्सेस कर सकते हैं**
- **PPLs PP को एक्सेस नहीं कर सकते**
- **असुरक्षित प्रक्रियाएं किसी भी PPL/PP को एक्सेस नहीं कर सकतीं**

### What you need to know from an offensive perspective

- जब **LSASS PPL के रूप में चलता है**, इसे सामान्य प्रशासनिक संदर्भ से `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` का उपयोग करके खोलने के प्रयास **`0x5 (Access Denied)`** के साथ विफल होते हैं, भले ही `SeDebugPrivilege` सक्षम हो।
- आप **LSASS सुरक्षा स्तर** की जांच कर सकते हैं जैसे कि Process Hacker का उपयोग करके या प्रोग्रामेटिक रूप से `EPROCESS.Protection` मान को पढ़कर।
- LSASS आमतौर पर `PsProtectedSignerLsa-Light` (`0x41`) होगा, जिसे **केवल उच्च-स्तरीय साइनर** के साथ हस्ताक्षरित प्रक्रियाओं द्वारा एक्सेस किया जा सकता है, जैसे `WinTcb` (`0x61` या `0x62`)।
- PPL एक **Userland-only restriction** है; **kernel-level code इसे पूरी तरह से बायपास कर सकता है**।
- LSASS का PPL होना **क्रेडेंशियल डंपिंग को रोकता नहीं है यदि आप कर्नेल शेलकोड निष्पादित कर सकते हैं** या **उचित पहुंच के साथ उच्च-विशिष्ट प्रक्रिया का लाभ उठा सकते हैं**।
- **PPL सेट करना या हटाना** रिबूट या **Secure Boot/UEFI सेटिंग्स** की आवश्यकता होती है, जो रजिस्ट्री परिवर्तनों को उलटने के बाद भी PPL सेटिंग को बनाए रख सकती हैं।

**Bypass PPL protections options:**

यदि आप PPL के बावजूद LSASS को डंप करना चाहते हैं, तो आपके पास 3 मुख्य विकल्प हैं:
1. **एक साइन किए गए कर्नेल ड्राइवर (जैसे, Mimikatz + mimidrv.sys)** का उपयोग करें ताकि **LSASS के सुरक्षा ध्वज को हटा सकें**:

![](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** का उपयोग करें ताकि कस्टम कर्नेल कोड चलाया जा सके और सुरक्षा को अक्षम किया जा सके। **PPLKiller**, **gdrv-loader**, या **kdmapper** जैसे उपकरण इसे संभव बनाते हैं।
3. **किसी अन्य प्रक्रिया से एक मौजूदा LSASS हैंडल चुराएं** जो इसे खोले हुए है (जैसे, एक AV प्रक्रिया), फिर इसे **अपनी प्रक्रिया में डुप्लिकेट करें**। यह `pypykatz live lsa --method handledup` तकनीक का आधार है।
4. **कुछ विशेषाधिकार प्राप्त प्रक्रिया का दुरुपयोग करें** जो आपको इसके पते की जगह में या किसी अन्य विशेषाधिकार प्राप्त प्रक्रिया के अंदर मनमाना कोड लोड करने की अनुमति देगा, प्रभावी रूप से PPL प्रतिबंधों को बायपास करना। आप इसका एक उदाहरण [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) या [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump) में देख सकते हैं।

**LSASS के लिए LSA सुरक्षा (PPL/PP) की वर्तमान स्थिति की जांच करें**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
जब आप **`mimikatz privilege::debug sekurlsa::logonpasswords`** चलाते हैं, तो यह शायद `0x00000005` त्रुटि कोड के साथ विफल हो जाएगा।

- इस बारे में अधिक जानकारी के लिए देखें [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)

## Credential Guard

**Credential Guard**, जो कि **Windows 10 (Enterprise और Education संस्करण)** के लिए विशेष है, मशीन क्रेडेंशियल्स की सुरक्षा को **Virtual Secure Mode (VSM)** और **Virtualization Based Security (VBS)** का उपयोग करके बढ़ाता है। यह CPU वर्चुअलाइजेशन एक्सटेंशन का लाभ उठाता है ताकि मुख्य ऑपरेटिंग सिस्टम की पहुंच से दूर एक सुरक्षित मेमोरी स्थान में प्रमुख प्रक्रियाओं को अलग किया जा सके। यह अलगाव सुनिश्चित करता है कि यहां तक कि कर्नेल भी VSM में मेमोरी तक पहुंच नहीं सकता, प्रभावी रूप से **pass-the-hash** जैसे हमलों से क्रेडेंशियल्स की सुरक्षा करता है। **Local Security Authority (LSA)** इस सुरक्षित वातावरण में एक ट्रस्टलेट के रूप में कार्य करता है, जबकि मुख्य OS में **LSASS** प्रक्रिया केवल VSM के LSA के साथ संवाद करने के रूप में कार्य करती है।

डिफ़ॉल्ट रूप से, **Credential Guard** सक्रिय नहीं है और इसे एक संगठन के भीतर मैन्युअल रूप से सक्रिय करने की आवश्यकता होती है। यह **Mimikatz** जैसे उपकरणों के खिलाफ सुरक्षा बढ़ाने के लिए महत्वपूर्ण है, जो क्रेडेंशियल्स को निकालने की अपनी क्षमता में बाधित होते हैं। हालाँकि, कस्टम **Security Support Providers (SSP)** को जोड़कर कमजोरियों का लाभ उठाया जा सकता है ताकि लॉगिन प्रयासों के दौरान क्रेडेंशियल्स को स्पष्ट पाठ में कैप्चर किया जा सके।

**Credential Guard** की सक्रियण स्थिति की पुष्टि करने के लिए, _**LsaCfgFlags**_ रजिस्ट्री कुंजी _**HKLM\System\CurrentControlSet\Control\LSA**_ के तहत जांची जा सकती है। "**1**" का मान **UEFI लॉक** के साथ सक्रियण को दर्शाता है, "**2**" बिना लॉक के, और "**0**" यह दर्शाता है कि यह सक्षम नहीं है। यह रजिस्ट्री जांच, जबकि एक मजबूत संकेतक है, Credential Guard को सक्षम करने के लिए एकमात्र कदम नहीं है। इस सुविधा को सक्षम करने के लिए विस्तृत मार्गदर्शन और एक PowerShell स्क्रिप्ट ऑनलाइन उपलब्ध है।
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Windows 10 में **Credential Guard** को सक्षम करने और **Windows 11 Enterprise और Education (संस्करण 22H2)** के संगत सिस्टम में इसके स्वचालित सक्रियण के लिए व्यापक समझ और निर्देशों के लिए [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage) पर जाएं।

क्रेडेंशियल कैप्चर के लिए कस्टम SSPs को लागू करने पर अधिक विवरण [इस गाइड](../active-directory-methodology/custom-ssp.md) में प्रदान किए गए हैं।

## RDP RestrictedAdmin Mode

**Windows 8.1 और Windows Server 2012 R2** ने कई नए सुरक्षा फीचर्स पेश किए, जिनमें _**RDP के लिए Restricted Admin mode**_ शामिल है। इस मोड को [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) हमलों से संबंधित जोखिमों को कम करने के लिए सुरक्षा बढ़ाने के लिए डिज़ाइन किया गया था।

परंपरागत रूप से, जब आप RDP के माध्यम से एक दूरस्थ कंप्यूटर से कनेक्ट करते हैं, तो आपकी क्रेडेंशियल्स लक्ष्य मशीन पर संग्रहीत होती हैं। यह एक महत्वपूर्ण सुरक्षा जोखिम प्रस्तुत करता है, विशेष रूप से जब उच्च विशेषाधिकार वाले खातों का उपयोग किया जाता है। हालाँकि, _**Restricted Admin mode**_ के परिचय के साथ, यह जोखिम काफी हद तक कम हो गया है।

**mstsc.exe /RestrictedAdmin** कमांड का उपयोग करके RDP कनेक्शन शुरू करते समय, दूरस्थ कंप्यूटर पर आपकी क्रेडेंशियल्स को संग्रहीत किए बिना प्रमाणीकरण किया जाता है। यह दृष्टिकोण सुनिश्चित करता है कि, यदि किसी मैलवेयर संक्रमण या यदि एक दुर्भावनापूर्ण उपयोगकर्ता दूरस्थ सर्वर तक पहुँच प्राप्त करता है, तो आपकी क्रेडेंशियल्स से समझौता नहीं किया जाएगा, क्योंकि वे सर्वर पर संग्रहीत नहीं हैं।

यह ध्यान रखना महत्वपूर्ण है कि **Restricted Admin mode** में, RDP सत्र से नेटवर्क संसाधनों तक पहुँचने के प्रयास आपकी व्यक्तिगत क्रेडेंशियल्स का उपयोग नहीं करेंगे; इसके बजाय, **मशीन की पहचान** का उपयोग किया जाता है।

यह फीचर दूरस्थ डेस्कटॉप कनेक्शनों को सुरक्षित करने और सुरक्षा उल्लंघन की स्थिति में संवेदनशील जानकारी को उजागर होने से बचाने में एक महत्वपूर्ण कदम है।

![](../../images/RAM.png)

अधिक विस्तृत जानकारी के लिए [इस संसाधन](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/) पर जाएं।

## Cached Credentials

Windows **डोमेन क्रेडेंशियल्स** को **Local Security Authority (LSA)** के माध्यम से सुरक्षित करता है, जो **Kerberos** और **NTLM** जैसे सुरक्षा प्रोटोकॉल के साथ लॉगिन प्रक्रियाओं का समर्थन करता है। Windows की एक प्रमुख विशेषता यह है कि यह **अंतिम दस डोमेन लॉगिन** को कैश करने की क्षमता रखता है ताकि उपयोगकर्ता तब भी अपने कंप्यूटर तक पहुँच सकें जब **डोमेन कंट्रोलर ऑफ़लाइन** हो—यह लैपटॉप उपयोगकर्ताओं के लिए एक वरदान है जो अक्सर अपनी कंपनी के नेटवर्क से दूर होते हैं।

कैश किए गए लॉगिन की संख्या को एक विशिष्ट **रजिस्ट्री कुंजी या समूह नीति** के माध्यम से समायोजित किया जा सकता है। इस सेटिंग को देखने या बदलने के लिए, निम्नलिखित कमांड का उपयोग किया जाता है:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
इन कैश किए गए क्रेडेंशियल्स तक पहुंच को कड़ी निगरानी में रखा गया है, केवल **SYSTEM** खाता ही उन्हें देखने के लिए आवश्यक अनुमतियों के साथ है। जिन्हें इस जानकारी तक पहुंचने की आवश्यकता है, उन्हें SYSTEM उपयोगकर्ता विशेषाधिकारों के साथ ऐसा करना होगा। क्रेडेंशियल्स यहाँ संग्रहीत हैं: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** का उपयोग इन कैश किए गए क्रेडेंशियल्स को निकालने के लिए `lsadump::cache` कमांड का उपयोग किया जा सकता है।

अधिक जानकारी के लिए, मूल [source](http://juggernaut.wikidot.com/cached-credentials) व्यापक जानकारी प्रदान करता है।

## Protected Users

**Protected Users group** में सदस्यता उपयोगकर्ताओं के लिए कई सुरक्षा सुधार लाती है, जो क्रेडेंशियल चोरी और दुरुपयोग के खिलाफ उच्च स्तर की सुरक्षा सुनिश्चित करती है:

- **Credential Delegation (CredSSP)**: भले ही **Allow delegating default credentials** के लिए Group Policy सेटिंग सक्षम हो, Protected Users के स्पष्ट पाठ क्रेडेंशियल्स को कैश नहीं किया जाएगा।
- **Windows Digest**: **Windows 8.1 और Windows Server 2012 R2** से शुरू होकर, सिस्टम Protected Users के स्पष्ट पाठ क्रेडेंशियल्स को कैश नहीं करेगा, चाहे Windows Digest स्थिति कुछ भी हो।
- **NTLM**: सिस्टम Protected Users के स्पष्ट पाठ क्रेडेंशियल्स या NT एक-तरफा कार्यों (NTOWF) को कैश नहीं करेगा।
- **Kerberos**: Protected Users के लिए, Kerberos प्रमाणीकरण **DES** या **RC4 keys** उत्पन्न नहीं करेगा, न ही यह स्पष्ट पाठ क्रेडेंशियल्स या प्रारंभिक Ticket-Granting Ticket (TGT) अधिग्रहण के बाद दीर्घकालिक कुंजियों को कैश करेगा।
- **Offline Sign-In**: Protected Users के लिए साइन-इन या अनलॉक पर कोई कैश किया गया वेरिफायर नहीं बनाया जाएगा, जिसका अर्थ है कि इन खातों के लिए ऑफ़लाइन साइन-इन समर्थित नहीं है।

ये सुरक्षा उपाय तब सक्रिय होते हैं जब एक उपयोगकर्ता, जो **Protected Users group** का सदस्य है, डिवाइस में साइन इन करता है। यह सुनिश्चित करता है कि विभिन्न क्रेडेंशियल समझौता करने के तरीकों के खिलाफ सुरक्षा के लिए महत्वपूर्ण सुरक्षा उपाय मौजूद हैं।

अधिक विस्तृत जानकारी के लिए, आधिकारिक [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) देखें।

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

{{#include ../../banners/hacktricks-training.md}}
