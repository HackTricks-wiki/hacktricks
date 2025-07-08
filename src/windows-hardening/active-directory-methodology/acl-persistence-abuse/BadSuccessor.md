# Active Directory ACLs/ACEs का दुरुपयोग

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

Delegated Managed Service Accounts (**dMSAs**) एक नया AD प्रिंसिपल प्रकार है जिसे **Windows Server 2025** के साथ पेश किया गया है। इन्हें पुराने सेवा खातों को बदलने के लिए डिज़ाइन किया गया है, जिससे एक-क्लिक “माइग्रेशन” संभव हो जाता है जो स्वचालित रूप से पुराने खाते के Service Principal Names (SPNs), समूह सदस्यता, प्रतिनिधित्व सेटिंग्स, और यहां तक कि क्रिप्टोग्राफिक कुंजियों को नए dMSA में कॉपी करता है, जिससे अनुप्रयोगों को एक सहज परिवर्तन मिलता है और Kerberoasting के जोखिम को समाप्त करता है।

Akamai के शोधकर्ताओं ने पाया कि एकल विशेषता — **`msDS‑ManagedAccountPrecededByLink`** — KDC को बताती है कि एक dMSA किस पुराने खाते का “उत्तराधिकारी” है। यदि एक हमलावर उस विशेषता को लिख सकता है (और **`msDS‑DelegatedMSAState` → 2** को टॉगल कर सकता है), तो KDC खुशी-खुशी एक PAC बनाएगा जो **चुने गए पीड़ित के हर SID को विरासत में लेता है**, प्रभावी रूप से dMSA को किसी भी उपयोगकर्ता, जिसमें Domain Admins भी शामिल हैं, का अनुकरण करने की अनुमति देता है।

## dMSA वास्तव में क्या है?

* **gMSA** तकनीक के शीर्ष पर बनाया गया लेकिन नए AD वर्ग **`msDS‑DelegatedManagedServiceAccount`** के रूप में संग्रहीत।
* **ऑप्ट-इन माइग्रेशन** का समर्थन करता है: `Start‑ADServiceAccountMigration` कॉल करने से dMSA को पुराने खाते से जोड़ा जाता है, पुराने खाते को `msDS‑GroupMSAMembership` पर लिखने की अनुमति मिलती है, और `msDS‑DelegatedMSAState` = 1 को पलटा जाता है।
* `Complete‑ADServiceAccountMigration` के बाद, अधिसूचित खाता अक्षम हो जाता है और dMSA पूरी तरह से कार्यात्मक हो जाता है; कोई भी होस्ट जो पहले पुराने खाते का उपयोग करता था, स्वचालित रूप से dMSA का पासवर्ड खींचने के लिए अधिकृत होता है।
* प्रमाणीकरण के दौरान, KDC एक **KERB‑SUPERSEDED‑BY‑USER** संकेत डालता है ताकि Windows 11/24H2 क्लाइंट स्वचालित रूप से dMSA के साथ पुनः प्रयास करें।

## हमले की आवश्यकताएँ
1. **कम से कम एक Windows Server 2025 DC** ताकि dMSA LDAP वर्ग और KDC लॉजिक मौजूद हो।
2. **किसी OU पर कोई वस्तु-निर्माण या विशेषता-लेखन अधिकार** (कोई भी OU) – जैसे `Create msDS‑DelegatedManagedServiceAccount` या बस **Create All Child Objects**। Akamai ने पाया कि 91% वास्तविक दुनिया के टेनेंट ऐसे “सौम्य” OU अनुमतियाँ गैर-प्रशासकों को प्रदान करते हैं।
3. किसी भी डोमेन-जोड़े गए होस्ट से टूलिंग (PowerShell/Rubeus) चलाने की क्षमता ताकि Kerberos टिकटों का अनुरोध किया जा सके।
*पीड़ित उपयोगकर्ता पर कोई नियंत्रण आवश्यक नहीं है; हमला कभी भी लक्षित खाते को सीधे छूता नहीं है।*

## चरण-दर-चरण: BadSuccessor*विशेषाधिकार वृद्धि

1. **एक dMSA खोजें या बनाएं जिसे आप नियंत्रित करते हैं**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

क्योंकि आपने उस OU के अंदर वस्तु बनाई है जिसमें आप लिख सकते हैं, आप स्वचालित रूप से इसके सभी विशेषताओं के मालिक हैं।

2. **दो LDAP लेखनों में “पूर्ण माइग्रेशन” का अनुकरण करें**:
- किसी भी पीड़ित का `msDS‑ManagedAccountPrecededByLink = DN` सेट करें (जैसे `CN=Administrator,CN=Users,DC=lab,DC=local`)।
- `msDS‑DelegatedMSAState = 2` सेट करें (माइग्रेशन-पूर्ण)।

**Set‑ADComputer, ldapmodify**, या यहां तक कि **ADSI Edit** जैसे उपकरण काम करते हैं; कोई डोमेन-प्रशासक अधिकार आवश्यक नहीं हैं।

3. **dMSA के लिए एक TGT का अनुरोध करें** — Rubeus `/dmsa` ध्वज का समर्थन करता है:

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

वापस किया गया PAC अब SID 500 (Administrator) के साथ-साथ Domain Admins/Enterprise Admins समूहों को शामिल करता है।

## सभी उपयोगकर्ताओं के पासवर्ड इकट्ठा करें

वैध माइग्रेशनों के दौरान KDC को नए dMSA को **पुराने खाते को जारी किए गए टिकटों को डिक्रिप्ट** करने की अनुमति देनी चाहिए। लाइव सत्रों को तोड़ने से बचने के लिए, यह वर्तमान-कुंजियों और पिछले-कुंजियों को एक नए ASN.1 ब्लॉब में रखता है जिसे **`KERB‑DMSA‑KEY‑PACKAGE`** कहा जाता है।

क्योंकि हमारी नकली माइग्रेशन यह दावा करती है कि dMSA पीड़ित का उत्तराधिकारी है, KDC निष्ठापूर्वक पीड़ित की RC4-HMAC कुंजी को **previous-keys** सूची में कॉपी करता है – भले ही dMSA की कभी कोई “पिछली” पासवर्ड न हो। वह RC4 कुंजी बिना नमकीन की होती है, इसलिए यह प्रभावी रूप से पीड़ित का NT हैश है, हमलावर को **ऑफलाइन क्रैकिंग या “पास-थी-हैश”** क्षमता देती है।

इसलिए, हजारों उपयोगकर्ताओं को सामूहिक रूप से लिंक करना एक हमलावर को “स्केल पर” हैश डंप करने की अनुमति देता है, **BadSuccessor को विशेषाधिकार वृद्धि और क्रेडेंशियल समझौता प्राइमिटिव दोनों में बदल देता है**।

## उपकरण

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## संदर्भ

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

{{#include ../../../banners/hacktricks-training.md}}
