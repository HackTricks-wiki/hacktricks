# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**golden ticket** की तरह, diamond ticket एक TGT है जिसे किसी भी उपयोगकर्ता के रूप में किसी भी सेवा तक पहुँचने के लिए इस्तेमाल किया जा सकता है। A golden ticket पूरी तरह से ऑफ़लाइन फ़ोर्ज किया जाता है, उस डोमेन के krbtgt hash से एन्क्रिप्ट किया जाता है, और फिर उपयोग के लिए एक logon session में डाल दिया जाता है। क्योंकि डोमेन नियंत्रक उन TGTs को ट्रैक नहीं करते जो उन्होंने वैध रूप से जारी किए हैं, वे खुशी-खुशी उन TGTs को स्वीकार कर लेते हैं जो उनके अपने krbtgt hash से एन्क्रिप्ट किए गए हों।

golden tickets के उपयोग का पता लगाने के दो सामान्य तरीके हैं:

- ऐसे TGS-REQs खोजें जिनके कोई संबंधित AS-REQ नहीं हैं।
- ऐसे TGTs देखें जिनके मान अतार्किक हों, जैसे Mimikatz का डिफ़ॉल्ट 10-year lifetime।

diamond ticket वैध TGT के फील्ड्स को संशोधित करके बनता है जिसे किसी DC ने जारी किया था। यह प्रक्रिया इस तरह होती है: एक TGT request करना, उसे डोमेन के krbtgt key से decrypt करना, टिकट के इच्छित फील्ड्स को modify करना, और फिर उसे re-encrypt करना। यह golden ticket की ऊपर बताई गई दोनों कमियों को दूर कर देता है क्योंकि:

- TGS-REQs के पहले एक AS-REQ मौजूद होगा।
- TGT एक DC द्वारा जारी किया गया था, जिसका मतलब है कि इसमें domain की Kerberos policy से संबंधित सभी सही विवरण होंगे। हालांकि इन्हें golden ticket में सटीक रूप से फ़ोर्ज किया जा सकता है, पर वह अधिक जटिल है और त्रुटियों के प्रति अधिक संवेदनशील है।

### आवश्यकताएँ और कार्यप्रवाह

- **Cryptographic material**: krbtgt AES256 key (preferred) या NTLM hash ताकि TGT को decrypt और re-sign किया जा सके।
- **Legitimate TGT blob**: `/tgtdeleg`, `asktgt`, `s4u` के माध्यम से प्राप्त किया गया, या memory से tickets export करके।
- **Context data**: target user RID, group RIDs/SIDs, और (वैकल्पिक रूप से) LDAP-प्राप्त PAC attributes।
- **Service keys** (केवल यदि आप service tickets को फिर से बनाने का प्लान कर रहे हैं): impersonate किए जाने वाले service SPN की AES key।

1. किसी भी नियंत्रित उपयोगकर्ता के लिए AS-REQ के माध्यम से TGT प्राप्त करें (Rubeus `/tgtdeleg` सुविधाजनक है क्योंकि यह client को बिना credentials के Kerberos GSS-API dance करने के लिए मजबूर करता है)।
2. लौटे हुए TGT को krbtgt key से decrypt करें, PAC attributes (user, groups, logon info, SIDs, device claims, आदि) को patch/समायोजित करें।
3. वही krbtgt key उपयोग करके टिकट को फिर से re-encrypt/sign करें और इसे current logon session में inject करें (`kerberos::ptt`, `Rubeus.exe ptt`...)।
4. वैकल्पिक रूप से, stealthy रहने के लिए प्रक्रिया को service ticket पर दोहराएँ — वैध TGT blob और target service key प्रदान करके।

### Updated Rubeus tradecraft (2024+)

Huntress द्वारा हाल के काम ने Rubeus के अंदर `diamond` action को आधुनिक बनाया है, `/ldap` और `/opsec` सुधारों को पोर्ट करके जो पहले केवल golden/silver tickets के लिए मौजूद थे। `/ldap` अब सीधे AD से सटीक PAC attributes auto-populate करता है (user profile, logon hours, sidHistory, domain policies), जबकि `/opsec` AS-REQ/AS-REP फ्लो को एक Windows client से अलग न दिखने वाला बनाता है — यह two-step pre-auth sequence को निभाकर और AES-only crypto को लागू करके करता है। इससे blank device IDs या unrealistically लंबी validity windows जैसे स्पष्ट संकेत काफी हद तक कम हो जाते हैं।
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (वैकल्पिक `/ldapuser` & `/ldappassword` के साथ) AD और SYSVOL को क्वेरी करके target user के PAC policy data की नकल करता है।
- `/opsec` Windows जैसी AS-REQ retry को बाध्य करता है, noisy flags को शून्य करता है और AES256 पर टिके रहता है।
- `/tgtdeleg` cleartext password या पीड़ित के NTLM/AES key को छुए बिना भी एक decryptable TGT लौटाता है।

### सर्विस-टिकट रीकटिंग

उसी Rubeus refresh ने diamond technique को TGS blobs पर लागू करने की क्षमता जोड़ दी। `diamond` को **base64-encoded TGT** (जो `asktgt`, `/tgtdeleg`, या पहले से बने TGT में से हो), **service SPN**, और **service AES key** देने पर, आप KDC को छुए बिना वास्तविक-समान service tickets बना सकते हैं — प्रभावी रूप से एक अधिक छिपा हुआ silver ticket।
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
This workflow is ideal when you already control a service account key (e.g., dumped with `lsadump::lsa /inject` or `secretsdump.py`) and want to cut a one-off TGS that perfectly matches AD policy, timelines, and PAC data without issuing any new AS/TGS traffic.

### OPSEC & detection notes

- पारंपरिक hunter heuristics (TGS without AS, decade-long lifetimes) अभी भी golden tickets पर लागू होते हैं, लेकिन diamond tickets मुख्यतः तब सामने आते हैं जब **PAC content या group mapping असंभव दिखे**। प्रत्येक PAC फ़ील्ड (logon hours, user profile paths, device IDs) भरें ताकि automated comparisons तुरंत फोर्जरी को फ़्लैग न करें।
- **Do not oversubscribe groups/RIDs**. यदि आपको केवल `512` (Domain Admins) और `519` (Enterprise Admins) ही चाहिए, तो वहीं रोकें और सुनिश्चित करें कि target account अन्यत्र AD में संभावित रूप से उन समूहों का सदस्य दिखता हो। अत्यधिक `ExtraSids` एक संकेत है।
- Splunk's Security Content project diamond tickets के लिए attack-range telemetry और *Windows Domain Admin Impersonation Indicator* जैसे detections वितरित करता है, जो असामान्य Event ID 4768/4769/4624 सिक्वेंस और PAC group परिवर्तनों को correlate करता है। उस dataset को replay करना (या ऊपर दिए गए कमांड्स से अपना खुद का जनरेट करना) SOC कवरेज को validate करने में मदद करता है और आपको ऐसी concrete alert logic देता है जिसे evade किया जा सके (T1558.001 के लिए)।

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
