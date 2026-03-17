# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT जिसका उपयोग **किसी भी सेवा में किसी भी उपयोगकर्ता के रूप में पहुँच** के लिए किया जा सकता है। A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. क्योंकि domain controllers उन TGTs को ट्रैक नहीं करते जो उन्होंने वैध रूप से जारी किए हैं, वे उन TGTs को स्वीकार कर लेते हैं जो अपने ही krbtgt hash से encrypt किए गए होते हैं।

There are two common techniques to detect the use of golden tickets:

- उन TGS-REQs की जांच करें जिनका कोई संबंधित AS-REQ नहीं होता।
- उन TGTs की तलाश करें जिनमें अजीब मान होते हैं, जैसे Mimikatz का डिफ़ॉल्ट 10-year lifetime।

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. यह प्राप्त किया जाता है द्वारा **requesting** एक **TGT**, उसे domain के krbtgt hash के साथ **decrypting** करना, टिकट के वांछित fields को **modifying** करना, और फिर उसे **re-encrypting** करना। यह एक golden ticket की ऊपर बताई गई दो कमियों को दूर कर देता है क्योंकि:

- TGS-REQs के साथ पहले एक AS-REQ होगा।
- TGT को एक DC द्वारा जारी किया गया था, जिसका मतलब यह है कि इसमें domain की Kerberos policy से संबंधित सभी सही विवरण होंगे। भले ही इन्हें golden ticket में सटीक रूप से forge किया जा सकता है, यह अधिक जटिल है और गलतियों के लिए खुला रहता है।

### Requirements & workflow

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash ताकि TGT को decrypt और re-sign किया जा सके।
- **Legitimate TGT blob**: `/tgtdeleg`, `asktgt`, `s4u` के साथ प्राप्त किया गया, या memory से tickets export करके।
- **Context data**: target user RID, group RIDs/SIDs, और (वैकल्पिक रूप से) LDAP-derived PAC attributes।
- **Service keys** (only if you plan to re-cut service tickets): impersonate करने के लिए service SPN की AES key।

1. किसी भी नियंत्रित user के लिए AS-REQ के माध्यम से एक TGT प्राप्त करें (Rubeus `/tgtdeleg` सुविधाजनक है क्योंकि यह क्लाइंट को credentials के बिना Kerberos GSS-API dance करने के लिए मजबूर करता है)।
2. लौटे हुए TGT को krbtgt key के साथ decrypt करें, PAC attributes (user, groups, logon info, SIDs, device claims, आदि) को patch/संशोधित करें।
3. उसी krbtgt key के साथ टिकट को re-encrypt/sign करें और इसे वर्तमान logon session में inject करें (`kerberos::ptt`, `Rubeus.exe ptt`, ...)।
4. वैकल्पिक रूप से, वायर पर stealthy बने रहने के लिए वैध TGT blob और target service key प्रदान करके प्रक्रिया को service ticket पर दोहराएँ।

### Updated Rubeus tradecraft (2024+)

हाल के कार्यों में Huntress ने Rubeus के अंदर `diamond` action को आधुनिक बनाया है, `/ldap` और `/opsec` improvements को पोर्ट करके जो पहले केवल golden/silver tickets के लिए मौजूद थे। `/ldap` अब वास्तविक PAC context LDAP क्वेरी करके **और** SYSVOL को mount करके account/group attributes तथा Kerberos/password policy (उदा., `GptTmpl.inf`) निकालता है, जबकि `/opsec` AS-REQ/AS-REP flow को Windows से match करने के लिए two-step preauth exchange करता है और AES-only + realistic KDCOptions को लागू करता है। इससे obvious indicators जैसे missing PAC fields या policy-mismatched lifetimes काफी कम हो जाते हैं।
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (वैकल्पिक `/ldapuser` & `/ldappassword` के साथ) लक्षित उपयोगकर्ता के PAC नीति डेटा को मिरर करने के लिए AD और SYSVOL को क्वेरी करता है।
- `/opsec` Windows जैसी AS-REQ retry लागू करता है, शोर करने वाले फ्लैग्स को शून्य कर देता है और AES256 पर टिके रहता है।
- `/tgtdeleg` पीड़ित के cleartext password या NTLM/AES key को छुए बिना भी एक decryptable TGT लौटाता है।

### Service-ticket recutting

उसी Rubeus रिफ्रेश ने TGS blobs पर diamond technique लागू करने की क्षमता जोड़ दी। `diamond` को **base64-encoded TGT** (जो `asktgt`, `/tgtdeleg`, या पहले से फोर्ज किए गए TGT से हो सकती है), **service SPN**, और **service AES key** देकर, आप KDC को छुए बिना वास्तविक दिखने वाले service tickets बना सकते हैं — प्रभावी रूप से एक अधिक stealthy silver ticket।
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
यह वर्कफ़्लो उस स्थिति में आदर्श है जब आपके पास पहले से किसी service account key का नियंत्रण हो (उदा., `lsadump::lsa /inject` या `secretsdump.py` से dump की हुई) और आप बिना कोई नया AS/TGS ट्रैफ़िक जारी किए, AD नीति, समयसीमाएँ, और PAC डेटा से पूरी तरह मेल खाता हुआ एक एकल TGS बनाना चाहते हैं।

### Sapphire-style PAC swaps (2025)

एक नया मोड़ जिसे कभी-कभी **sapphire ticket** कहा जाता है, Diamond के "real TGT" बेस को **S4U2self+U2U** के साथ मिलाकर एक privileged PAC चोरी करने और उसे अपने ही TGT में डालने का तरीका है। अतिरिक्त SIDs बनाने के बजाय, आप एक high-privilege user के लिए U2U S4U2self टिकट का अनुरोध करते हैं जहाँ `sname` low-priv requester को टार्गेट करता है; KRB_TGS_REQ requester's TGT को `additional-tickets` में ले जाता है और `ENC-TKT-IN-SKEY` सेट करता है, जिससे service ticket उस user की key से decrypt हो सकती है। फिर आप privileged PAC निकालते हैं और उसे अपने वैध TGT में splice करके krbtgt key से पुनः साइन करते हैं।

Impacket का `ticketer.py` अब `-impersonate` + `-request` (live KDC exchange) के माध्यम से sapphire सपोर्ट के साथ आता है:
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` एक username या SID स्वीकार करता है; `-request` टिकट्स को decrypt/patch करने के लिए live user creds के साथ krbtgt key material (AES/NTLM) की आवश्यकता होती है।

Key OPSEC tells when using this variant:

- TGS-REQ में `ENC-TKT-IN-SKEY` और `additional-tickets` (पीड़ित TGT) शामिल होगा — सामान्य ट्रैफ़िक में दुर्लभ।
- `sname` अक्सर requesting user के बराबर होता है (self-service access) और Event ID 4769 में caller और target एक ही SPN/user के रूप में दिखते हैं।
- उसी client computer के साथ 4768/4769 जोड़े की एंट्रीज़ की उम्मीद करें लेकिन विभिन्न CNAMES (low-priv requester बनाम privileged PAC owner)।

### OPSEC & detection notes

- पारंपरिक hunter heuristics (TGS बिना AS, दशक-भर की lifetimes) golden tickets पर अभी भी लागू होते हैं, पर diamond tickets तब मुख्य रूप से सामने आते हैं जब **PAC content या group mapping असंभव सा दिखता है**। हर PAC field (logon hours, user profile paths, device IDs) भरें ताकि automated comparisons तुरंत नकली को फ्लैग न कर दें।
- **Groups/RIDs को ओवरसबसक्राइब न करें**। अगर आपको केवल `512` (Domain Admins) और `519` (Enterprise Admins) की ज़रूरत है, तो वहीं रोक दें और सुनिश्चित करें कि target account वैध रूप से AD में कहीं और उन groups का हिस्सा दिखता है। अत्याधिक `ExtraSids` संदिग्ध होता है।
- Sapphire-style swaps U2U fingerprints छोड़ते हैं: `ENC-TKT-IN-SKEY` + `additional-tickets` साथ में ऐसा `sname` जो 4769 में किसी user (अक्सर requester) की ओर इशारा करता है, और नकली टिकट से निकला follow-up 4624 logon। केवल no-AS-REQ gaps देखने के बजाय उन fields को correlate करें।
- Microsoft ने CVE-2026-20833 के कारण **RC4 service ticket issuance** को चरणबद्ध रूप से बंद करना शुरू किया; KDC पर AES-only etypes लागू करना domain को मजबूत करने के साथ ही diamond/sapphire tooling के अनुरूप भी है (/opsec पहले से AES मजबूर करता है)। नकली PACs में RC4 मिलाना धीरे-धीरे और अधिक अलग दिखेगा।
- Splunk का Security Content project diamond tickets के लिए attack-range telemetry और ऐसी detections वितरित करता है जैसे *Windows Domain Admin Impersonation Indicator*, जो असामान्य Event ID 4768/4769/4624 sequences और PAC group परिवर्तनों को correlate करता है। उस dataset को replay (या ऊपर दिए गए commands से अपना डेटा बनाकर) करना SOC कवरेज (T1558.001) को validate करने में मदद करता है और साथ ही आपको ठोस alert logic देता है जिसे आप टालने के लिए उपयोग कर सकते हैं।

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
