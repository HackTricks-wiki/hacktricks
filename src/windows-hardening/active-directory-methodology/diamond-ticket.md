# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, diamond ticket एक TGT होता है जिसका उपयोग **किसी भी user के रूप में किसी भी service को access करने** के लिए किया जा सकता है। golden ticket पूरी तरह offline forge किया जाता है, उस domain के krbtgt hash से encrypted होता है, और फिर उपयोग के लिए logon session में pass किया जाता है। क्योंकि domain controllers उन TGTs को track नहीं करते जिन्हें उन्होंने वैध रूप से issue किया है, वे अपने krbtgt hash से encrypted TGTs को आसानी से accept कर लेते हैं।<sup>[[1]](#references)</sup>

golden tickets के उपयोग का पता लगाने के लिए दो सामान्य techniques हैं:

- ऐसे TGS-REQs खोजें जिनके अनुरूप कोई AS-REQ न हो।
- ऐसे TGTs खोजें जिनमें असामान्य values हों, जैसे Mimikatz का default 10-year lifetime।

एक **diamond ticket** **DC द्वारा issue किए गए legitimate TGT के fields को modify करके** बनाया जाता है। इसके लिए **TGT को request** किया जाता है, उसे domain के krbtgt hash से **decrypt** किया जाता है, ticket के आवश्यक fields को **modify** किया जाता है, और फिर उसे **re-encrypt** किया जाता है। इससे golden ticket की ऊपर बताई गई दोनों कमियां दूर हो जाती हैं, क्योंकि:<sup>[[1]](#references)</sup>

- TGS-REQs से पहले संबंधित AS-REQ मौजूद होगा।
- TGT को DC ने issue किया था, इसलिए उसमें domain की Kerberos policy के सभी सही details होंगे। हालांकि golden ticket में इन्हें सटीक रूप से forge किया जा सकता है, लेकिन यह अधिक complex और mistakes की संभावना वाला होता है।

### Requirements और workflow

- **Cryptographic material**: TGT को decrypt और re-sign करने के लिए krbtgt AES256 key (preferred) या NTLM hash।
- **Legitimate TGT blob**: `/tgtdeleg`, `asktgt`, `s4u` से प्राप्त किया गया, या memory से tickets export करके प्राप्त किया गया।
- **Context data**: target user RID, group RIDs/SIDs, और (वैकल्पिक रूप से) LDAP-derived PAC attributes।
- **Service keys** (केवल तब, जब आप service tickets को दोबारा बनाने की योजना रखते हों): impersonate की जाने वाली service SPN की AES key।

1. AS-REQ के माध्यम से किसी controlled user के लिए TGT प्राप्त करें (`Rubeus /tgtdeleg` सुविधाजनक है क्योंकि यह client को credentials के बिना Kerberos GSS-API dance करने के लिए मजबूर करता है)।
2. लौटाए गए TGT को krbtgt key से decrypt करें और PAC attributes (user, groups, logon info, SIDs, device claims आदि) को patch करें।
3. उसी krbtgt key से ticket को re-encrypt/sign करें और उसे current logon session में inject करें (`kerberos::ptt`, `Rubeus.exe ptt`...)।
4. वैकल्पिक रूप से, valid TGT blob और target service key देकर service ticket पर भी यही process दोहराएं, ताकि wire पर stealthy बने रहें।

### Updated Rubeus tradecraft (2024+)

Huntress के हालिया work ने Rubeus के अंदर `diamond` action को modernize किया है। इसमें `/ldap` और `/opsec` के वे improvements port किए गए हैं जो पहले केवल golden/silver tickets के लिए उपलब्ध थे। `/ldap` अब LDAP को query करके real PAC context प्राप्त करता है और account/group attributes के साथ Kerberos/password policy (जैसे `GptTmpl.inf`) निकालने के लिए SYSVOL को mount करता है, जबकि `/opsec` two-step preauth exchange करके और केवल AES + realistic KDCOptions enforce करके AS-REQ/AS-REP flow को Windows के अनुरूप बनाता है। इससे missing PAC fields या policy-mismatched lifetimes जैसे स्पष्ट indicators काफी कम हो जाते हैं।<sup>[[3]](#references)</sup>
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
- `/ldap` (वैकल्पिक `/ldapuser` और `/ldappassword` के साथ) target user के PAC policy data को mirror करने के लिए AD और SYSVOL को query करता है।
- `/opsec` Windows-जैसे AS-REQ retry को force करता है, noisy flags को zero करता है और केवल AES256 पर टिकता है।
- `/tgtdeleg` victim के cleartext password या NTLM/AES key को छुए बिना भी decryptable TGT लौटाता है।

### Service-ticket recutting

उसी Rubeus refresh में TGS blobs पर diamond technique लागू करने की क्षमता भी जोड़ी गई। `diamond` को **base64-encoded TGT** (`asktgt`, `/tgtdeleg`, या पहले से forged TGT से), **service SPN**, और **service AES key** देकर, आप KDC को छुए बिना realistic service tickets mint कर सकते हैं—effectively एक अधिक stealthy silver ticket।<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
यह workflow तब आदर्श है जब आपके पास पहले से किसी service account की key हो (जैसे `lsadump::lsa /inject` या `secretsdump.py` से dumped) और आप कोई नया AS/TGS traffic भेजे बिना ऐसा one-off TGS बनाना चाहते हों, जो AD policy, timelines और PAC data से पूरी तरह मेल खाता हो।<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

एक नया तरीका, जिसे कभी-कभी **sapphire ticket** कहा जाता है, Diamond के "real TGT" base को **S4U2self+U2U** के साथ मिलाकर किसी privileged PAC को चुराता है और उसे आपके अपने TGT में डालता है। अतिरिक्त SIDs गढ़ने के बजाय, आप किसी high-privilege user के लिए U2U S4U2self ticket request करते हैं, जिसमें `sname` low-priv requester को target करता है; KRB_TGS_REQ में requester का TGT `additional-tickets` में शामिल होता है और `ENC-TKT-IN-SKEY` सेट होता है, जिससे service ticket को उस user की key से decrypt किया जा सकता है। इसके बाद आप privileged PAC extract करके, krbtgt key से दोबारा sign करने से पहले, उसे अपने legitimate TGT में splice कर देते हैं।<sup>[[2]](#references)[[5]](#references)</sup>

Impacket के `ticketer.py` में अब `-impersonate` + `-request` के माध्यम से sapphire support उपलब्ध है (live KDC exchange):<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` username या SID स्वीकार करता है; `-request` को tickets को decrypt/patch करने के लिए live user creds और krbtgt key material (AES/NTLM) दोनों की आवश्यकता होती है।

इस variant का उपयोग करते समय मुख्य OPSEC संकेत:<sup>[[5]](#references)</sup>

- TGS-REQ में `ENC-TKT-IN-SKEY` और `additional-tickets` (victim TGT) होंगे — जो सामान्य traffic में दुर्लभ है।
- `sname` अक्सर requesting user के बराबर होता है (self-service access), और Event ID 4769 caller और target को समान SPN/user के रूप में दिखाता है।
- समान client computer लेकिन अलग CNAMES (low-priv requester बनाम privileged PAC owner) वाली paired 4768/4769 entries की अपेक्षा करें।

### OPSEC और detection notes

- Traditional hunter heuristics (AS के बिना TGS, दशक-लंबी lifetimes) golden tickets पर अभी भी लागू होते हैं, लेकिन diamond tickets मुख्यतः तब सामने आते हैं जब **PAC content या group mapping असंभव दिखाई देती है**। PAC के हर field (logon hours, user profile paths, device IDs) को populate करें, ताकि automated comparisons forgery को तुरंत flag न करें।<sup>[[3]](#references)</sup>
- **Groups/RIDs को आवश्यकता से अधिक न जोड़ें**। यदि आपको केवल `512` (Domain Admins) और `519` (Enterprise Admins) चाहिए, तो वहीं रुकें और सुनिश्चित करें कि target account AD में अन्य स्थानों पर plausibly इन groups का सदस्य हो। अत्यधिक `ExtraSids` स्पष्ट संकेत है।
- Sapphire-style swaps U2U fingerprints छोड़ते हैं: `ENC-TKT-IN-SKEY` + `additional-tickets`, साथ में 4769 में ऐसा `sname` जो किसी user (अक्सर requester) की ओर point करता है, और forged ticket से होने वाला follow-up 4624 logon। केवल no-AS-REQ gaps खोजने के बजाय इन fields को correlate करें।<sup>[[5]](#references)</sup>
- Microsoft ने CVE-2026-20833 के कारण **RC4 service ticket issuance** को चरणबद्ध तरीके से समाप्त करना शुरू कर दिया है; KDC पर AES-only etypes लागू करने से domain harden होता है और diamond/sapphire tooling के अनुरूप भी रहता है (`/opsec` पहले से AES को force करता है)। Forged PACs में RC4 मिलाना आगे चलकर अधिक स्पष्ट रूप से दिखाई देगा।<sup>[[6]](#references)</sup>
- Splunk का Security Content project diamond tickets के लिए attack-range telemetry और *Windows Domain Admin Impersonation Indicator* जैसी detections वितरित करता है, जो असामान्य Event ID 4768/4769/4624 sequences और PAC group changes को correlate करती हैं। उस dataset को replay करना (या ऊपर दिए commands से अपना dataset generate करना) T1558.001 के लिए SOC coverage validate करने में मदद करता है, साथ ही आपको evade करने योग्य concrete alert logic भी देता है।<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
