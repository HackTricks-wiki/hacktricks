# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

Kuna mbinu mbili za kawaida za kugundua matumizi ya golden tickets:

- Tafuta TGS-REQs ambazo hazina AS-REQ zinazolingana.
- Tafuta TGTs ambazo zina thamani zisizo za kawaida, kama vile Mimikatz's default 10-year lifetime.

A diamond ticket is made by modifying the fields of a legitimate TGT that was issued by a DC. This is achieved by requesting a TGT, decrypting it with the domain's krbtgt hash, modifying the desired fields of the ticket, then re-encrypting it. This overcomes the two aforementioned shortcomings of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### Requirements & workflow

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Pata TGT kwa mtumiaji yeyote unaodhibitiwa kupitia AS-REQ (Rubeus `/tgtdeleg` ni rahisi kwa sababu inalazimisha client kufanya mchakato wa Kerberos GSS-API bila cheti).
2. Decrypt TGT iliyorejeshwa kwa kutumia krbtgt key, rekebisha sifa za PAC (user, groups, logon info, SIDs, device claims, n.k.).
3. Re-encrypt/sign tiketi kwa kutumia krbtgt key ileile na uingize katika session ya sasa ya logon (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Hiari, rudia mchakato kwa tiketi ya huduma kwa kutoa blob halali ya TGT pamoja na service key lengwa ili kubaki kimyakimya kwenye mtandao.

### Updated Rubeus tradecraft (2024+)

Kazi ya hivi karibuni ya Huntress iliboresha kitendo cha `diamond` ndani ya Rubeus kwa kuleta maboresho ya `/ldap` na `/opsec` ambayo awali yalikuwepo tu kwa golden/silver tickets. `/ldap` sasa hujaza moja kwa moja sifa sahihi za PAC kutoka AD (profile ya mtumiaji, logon hours, sidHistory, sera za domain), wakati `/opsec` hufanya mtiririko wa AS-REQ/AS-REP usiotambulika kutoka kwa client ya Windows kwa kutekeleza mlolongo wa pre-auth wa hatua mbili na kufuata kripto ya AES pekee. Hii inapunguza kwa kiasi kikubwa viashiria vinavyoonekana kama vitambulisho vya kifaa vilivyokuwa tupu au nyuso za uhalali zisizo za kweli.
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) hufanya uchunguzi kwenye AD na SYSVOL ili kuiga data ya sera za PAC za mtumiaji lengwa.
- `/opsec` inalazimisha retry ya AS-REQ inayofanana na Windows, ikifanya bendera zenye kelele kuwa sifuri na kutumia AES256 pekee.
- `/tgtdeleg` haigusi nenosiri kwa maandishi wazi wala ufunguo wa NTLM/AES wa mwathiriwa, huku ikirudisha TGT inayoweza kufumbuliwa.

### Urekebishaji wa service-ticket

Toleo hilo la Rubeus liliongeza uwezo wa kutumia diamond technique kwa blobs za TGS. Kwa kumlisha `diamond` **base64-encoded TGT** (kutoka kwa `asktgt`, `/tgtdeleg`, au TGT iliyotengenezwa hapo awali), **service SPN**, na **service AES key**, unaweza kuunda service tickets zinazofanana na halisi bila kugusa KDC—kwa ufanisi silver ticket iliyofichika zaidi.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Muundo huu wa kazi ni bora wakati tayari unasimamia funguo ya akaunti ya huduma (kwa mfano, zilivunwa kwa `lsadump::lsa /inject` au `secretsdump.py`) na unataka kukata TGS la mara moja ambalo linaendana kikamilifu na sera za AD, ratiba, na data ya PAC bila kutoa trafiki mpya ya AS/TGS.

### OPSEC & detection notes

- The traditional hunter heuristics (TGS without AS, decade-long lifetimes) bado zinatumika kwa golden tickets, lakini diamond tickets hasa hujitokeza wakati **PAC content or group mapping looks impossible**. Jaza kila field ya PAC (logon hours, user profile paths, device IDs) ili ulinganishaji wa automatiska usitambulishe udanganyifu mara moja.
- **Do not oversubscribe groups/RIDs**. Ikiwa unahitaji tu `512` (Domain Admins) na `519` (Enterprise Admins), acha hapo na hakikisha akaunti lengwa inafaa kuwa sehemu ya vikundi hivyo mahali pengine ndani ya AD. Excessive `ExtraSids` ni ishara ya udanganyifu.
- Splunk's Security Content project inasambaza attack-range telemetry kwa ajili ya diamond tickets pamoja na utambuzi kama *Windows Domain Admin Impersonation Indicator*, ambao unaunganisha mfululizo usio wa kawaida wa Event ID 4768/4769/4624 na mabadiliko ya group za PAC. Kurudia dataset hiyo (au kuunda yako mwenyewe kwa kutumia amri zilizo hapo juu) husaidia kuthibitisha ufunikaji wa SOC kwa T1558.001 huku ikikupa mantiki halisi ya onyo ya kuepuka.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
