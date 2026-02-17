# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket को पूरी तरह से ऑफ़लाइन फ़ोर्ज किया जाता है, उस डोमेन के krbtgt hash से एन्क्रिप्ट किया जाता है, और फिर उपयोग हेतु एक लॉगऑन सत्र में डाला जाता है। क्योंकि domain controllers उन TGTs को ट्रैक नहीं करते जिन्हें उन्होंने वैध रूप से जारी किया है, वे उन TGTs को खुशी-खुशी स्वीकार कर लेते हैं जो उनके अपने krbtgt hash से एन्क्रिप्ट किए गए होते हैं।

There are two common techniques to detect the use of golden tickets:

- Look for TGS-REQs that have no corresponding AS-REQ.
- Look for TGTs that have silly values, such as Mimikatz's default 10-year lifetime.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. यह TGT प्राप्त करके, उसे डोमेन के krbtgt key से डिक्रिप्ट करके, टिकट के इच्छित फ़ील्ड्स को मॉडिफ़ाई करके और फिर उसे फिर से एन्क्रिप्ट/साइन करके हासिल किया जाता है। इससे golden ticket के उन दो उल्लेखित कमियों पर पार पाया जाता है क्योंकि:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. हालाँकि इन्हें golden ticket में सटीक रूप से फोर्ज किया जा सकता है, वह अधिक जटिल है और त्रुटियों के लिए खुला रहता है।

### Requirements & workflow

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Obtain a TGT for any controlled user via AS-REQ (Rubeus `/tgtdeleg` is convenient because it coerces the client to perform the Kerberos GSS-API dance without credentials).
2. Decrypt the returned TGT with the krbtgt key, patch PAC attributes (user, groups, logon info, SIDs, device claims, etc.).
3. Re-encrypt/sign the ticket with the same krbtgt key and inject it into the current logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionally, repeat the process over a service ticket by supplying a valid TGT blob plus the target service key to stay stealthy on the wire.

### Updated Rubeus tradecraft (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` अब AD से सीधे सटीक PAC attributes ऑटो-भरेगा (user profile, logon hours, sidHistory, domain policies), जबकि `/opsec` AS-REQ/AS-REP फ्लो को Windows क्लाइंट से अलग न करने योग्य बनाता है — यह two-step pre-auth sequence को पूरा करता है और केवल AES-आधारित crypto को लागू करता है। इससे स्पष्ट संकेतक जैसे blank device IDs या अवास्तविक validity windows नाटकीय रूप से कम हो जाते हैं।
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) AD और SYSVOL को क्वेरी करके लक्ष्य उपयोगकर्ता के PAC नीति डेटा की नकल करता है।
- `/opsec` Windows-जैसी AS-REQ retry को मजबूर करता है, शोर करने वाले फ़्लैग्स को शून्य कर देता है और AES256 पर टिके रहता है।
- `/tgtdeleg` पीड़ित के cleartext password या NTLM/AES key को छुए बिना भी एक decryptable TGT लौटाता है।

### सर्विस-टिकट रीकटिंग

इसी Rubeus refresh ने diamond technique को TGS blobs पर लागू करने की क्षमता भी जोड़ दी। `diamond` को **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), the **service SPN**, और the **service AES key** देकर, आप KDC को छुए बिना वास्तविक-सी दिखने वाले service tickets मिंट कर सकते हैं — प्रभावतः एक stealthier silver ticket।
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
This workflow आदर्श है जब आप पहले से ही किसी service account key को नियंत्रित करते हैं (उदा., `lsadump::lsa /inject` या `secretsdump.py` से dump किया हुआ) और बिना किसी नए AS/TGS ट्रैफ़िक को जारी किए AD policy, timelines, और PAC data से पूरी तरह मेल खाता हुआ एक बार का TGS काटना चाहते हैं।

### Sapphire-style PAC swaps (2025)

A newer twist sometimes called a **sapphire ticket** combines Diamond's "real TGT" base with **S4U2self+U2U** to steal a privileged PAC and drop it into your own TGT. अतिरिक्त SIDs बनाने की बजाय, आप किसी high-privilege user के लिए U2U S4U2self टिकट का अनुरोध करते हैं, उस PAC को निकालते हैं, और उसे अपने legitimate TGT में splice करके krbtgt key से पुनः साइन कर देते हैं। क्योंकि U2U `ENC-TKT-IN-SKEY` सेट करता है, परिणामी वायर फ़्लो एक वैध user-to-user एक्सचेंज जैसा दिखता है।

Minimal Linux-side reproduction with Impacket's patched `ticketer.py` (adds sapphire support):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — सामान्य ट्रैफ़िक में दुर्लभ।
- `sname` अक्सर अनुरोध करने वाले उपयोगकर्ता के समान होता है (self-service access) और Event ID 4769 कॉलर और लक्ष्य को एक ही SPN/user के रूप में दिखाता है।
- एक ही क्लाइंट कंप्यूटर के साथ जोड़ीदार 4768/4769 एंट्रीज़ की उम्मीद रखें, लेकिन अलग CNAMES (कम-विशेषाधिकार अनुरोधकर्ता बनाम उच्च-विशेषाधिकार PAC मालिक)।

### OPSEC & detection notes

- पारंपरिक hunter heuristics (TGS without AS, decade-long lifetimes) अभी भी golden tickets पर लागू होते हैं, लेकिन diamond tickets मुख्यतः तब उभरते हैं जब **PAC content or group mapping असंभव दिखता है**। हर PAC फ़ील्ड भरें (logon hours, user profile paths, device IDs) ताकि automated comparisons तुरंत फोर्जरी को फ़्लैग न करें।
- **Do not oversubscribe groups/RIDs**. यदि आपको केवल `512` (Domain Admins) और `519` (Enterprise Admins) की आवश्यकता है, तो वहीं रोकें और सुनिश्चित करें कि target account AD में कहीं और उन समूहों का यथार्थसंगत सदस्य दिखता हो। अत्यधिक `ExtraSids` एक संकेत है।
- Sapphire-style swaps U2U fingerprints छोड़ते हैं: `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` in 4769, और एक फॉलो-अप 4624 लॉगऑन जो फोर्ज्ड टिकट से सोर्स्ड होता है। केवल no-AS-REQ गैप्स देखने के बजाय उन फ़ील्ड्स को कोरिलेट करें।
- Microsoft ने CVE-2026-20833 के कारण **RC4 service ticket issuance** को चरणबद्ध रूप से हटाना शुरू कर दिया है; KDC पर केवल AES-etypes लागू करने से domain मजबूत होता है और diamond/sapphire tooling के अनुरूप होता है (/opsec पहले से AES लागू करता है)। फोर्ज किए गए PACs में RC4 मिलाना धीरे-धीरे और अधिक ध्यान खींचेगा।
- Splunk's Security Content project diamond tickets के लिए attack-range telemetry और *Windows Domain Admin Impersonation Indicator* जैसे detections वितरित करता है, जो असामान्य Event ID 4768/4769/4624 अनुक्रम और PAC group परिवर्तनों को कोरिलेट करता है। उस dataset को दोबारा चलाना (या ऊपर दिए गए commands से अपना बनाना) SOC कवरेज के लिए T1558.001 को वैलिडेट करने में मदद करता है, साथ ही आपको concrete alert logic देता है जिसे आप टालने के तरीके समझ सकते हैं।

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
