# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- TGS-REQs जो किसी corresponding AS-REQ के बिना हों, की तलाशी लें।
- ऐसे TGTs खोजें जिनकी मान्यताएँ अजीब हों, जैसे Mimikatz का default 10-year lifetime।

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### आवश्यकताएँ और कार्यप्रवाह

- Cryptographic material: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- Legitimate TGT blob: `/tgtdeleg`, `asktgt`, `s4u` के साथ प्राप्त किया गया या memory से tickets export करके।
- Context data: लक्ष्य उपयोगकर्ता का RID, group RIDs/SIDs, और (वैकल्पिक रूप से) LDAP-derived PAC attributes।
- Service keys (only if you plan to re-cut service tickets): impersonate किए जाने वाले service SPN का AES key।

1. किसी भी नियंत्रित उपयोगकर्ता के लिए AS-REQ के जरिये TGT प्राप्त करें (Rubeus `/tgtdeleg` सुविधाजनक है क्योंकि यह क्लाइंट को Kerberos GSS-API dance बिना प्रमाण-पत्रों के करने के लिए बाध्य करता है)।
2. लौटे हुए TGT को krbtgt key से decrypt करें, PAC attributes (user, groups, logon info, SIDs, device claims, आदि) patch करें।
3. उसी krbtgt key से ticket को re-encrypt/sign करें और उसे current logon session में inject करें (`kerberos::ptt`, `Rubeus.exe ptt`...)।
4. वैकल्पिक रूप से, stealthy रहने के लिए प्रक्रिया को service ticket पर दोहराएँ — वैध TGT blob और target service key प्रदान करके नेटवर्क पर ट्रैफ़िक में छुपा रहें।

### Updated Rubeus tradecraft (2024+)

Recent work by Huntress ने Rubeus के अंदर `diamond` action को modernize किया है, `/ldap` और `/opsec` improvements को पोर्ट करके जो पहले केवल golden/silver tickets के लिए मौजूद थे। `/ldap` अब सीधे AD से सही PAC attributes को auto-populate करता है (user profile, logon hours, sidHistory, domain policies), जबकि `/opsec` AS-REQ/AS-REP flow को एक Windows client से indistinguishable बनाता है — यह two-step pre-auth sequence करता है और AES-only crypto को enforce करता है। इससे ऐसे स्पष्ट संकेतक जैसे blank device IDs या unrealistic validity windows काफी कम हो जाते हैं।
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) AD और SYSVOL को क्वेरी करता है ताकि लक्षित उपयोगकर्ता के PAC policy data का mirror बनाया जा सके।
- `/opsec` Windows-like AS-REQ retry को मजबूर करता है, noisy flags को शून्य करता है और AES256 पर टिके रहता है।
- `/tgtdeleg` आपसे victim का cleartext password या NTLM/AES key छूने से रोकता है, फिर भी decryptable TGT लौटाता है।

### Service-ticket recutting

The same Rubeus refresh added the ability to apply the diamond technique to TGS blobs. By feeding `diamond` a **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), the **service SPN**, and the **service AES key**, you can mint realistic service tickets without touching the KDC—effectively a more stealthy silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
This workflow is ideal when you already control a service account key (e.g., dumped with `lsadump::lsa /inject` or `secretsdump.py`) and want to cut a one-off TGS that perfectly matches AD policy, timelines, and PAC data without issuing any new AS/TGS traffic.

### OPSEC & डिटेक्शन नोट्स

- The traditional hunter heuristics (TGS without AS, decade-long lifetimes) still apply to golden tickets, but diamond tickets mainly surface when the **PAC content or group mapping looks impossible**. Populate every PAC field (logon hours, user profile paths, device IDs) so automated comparisons do not immediately flag the forgery.
- **Do not oversubscribe groups/RIDs**. If you only need `512` (Domain Admins) and `519` (Enterprise Admins), stop there and make sure the target account plausibly belongs to those groups elsewhere in AD. Excessive `ExtraSids` is a giveaway.
- Splunk's Security Content project distributes attack-range telemetry for diamond tickets plus detections such as *Windows Domain Admin Impersonation Indicator*, which correlates unusual Event ID 4768/4769/4624 sequences and PAC group changes. Replaying that dataset (or generating your own with the commands above) helps validate SOC coverage for T1558.001 while giving you concrete alert logic to evade.

## संदर्भ

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
