# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, diamond ticket ni TGT ambayo inaweza kutumika **kupata huduma yoyote kama mtumiaji yeyote**. A golden ticket hutengenezwa kabisa nje ya mtandao, imetiwa viwango kwa krbtgt hash ya domain hiyo, kisha ipelekwe ndani ya kikao cha kuingia ili itumike. Kwa sababu domain controllers hawafuati TGTs ambazo walizitoa kwa njia halali, watakubali kwa furaha TGT zilizoambatishwa kwa krbtgt hash yao wenyewe.

Kuna mbinu mbili za kawaida za kugundua matumizi ya golden tickets:

- Tafuta TGS-REQs ambazo hazina AS-REQ zinazolingana.
- Tafuta TGTs ambazo zina maadili yasiyo ya kawaida, kama vile muda wa maisha wa chaguo-msingi wa Mimikatz wa miaka 10.

A **diamond ticket** inatengenezwa kwa **kubadilisha mashamba ya TGT halali ambayo ilitolewa na DC**. Hii inafikiwa kwa **kuomba** TGT, **kui-decrypt** kwa kutumia krbtgt hash ya domain, **kurekebisha** mashamba yanayohitajika ya tiketi, kisha **kuiencrypt tena**. Hii **inaondoa mapungufu hayo mawili** ya golden ticket kwa sababu:

- TGS-REQs zitakuwa na AS-REQ iliyotangulia.
- TGT ilitolewa na DC, ambayo inamaanisha itakuwa na maelezo yote sahihi kutoka kwa sera ya Kerberos ya domain. Ingawa haya yanaweza kuigizwa kwa usahihi kwenye golden ticket, ni ngumu zaidi na yanaweza kusababisha makosa.

### Mahitaji & mtiririko

- **Vifaa vya kriptografia**: krbtgt AES256 key (inayopendekezwa) au NTLM hash kwa kusudi la ku-decrypt na kusaini tena TGT.
- **Blob halali ya TGT**: inapatikana kwa kutumia `/tgtdeleg`, `asktgt`, `s4u`, au kwa ku-export tickets kutoka kumbukumbu.
- **Taarifa za muktadha**: target user RID, group RIDs/SIDs, na (hiari) LDAP-derived PAC attributes.
- **Vifunguo vya huduma** (tu ikiwa unakusudia kuchora tena service tickets): AES key ya service SPN itakayofanyiwa kuiga.

1. Pata TGT kwa mtumiaji yeyote unaodhibitiwa kupitia AS-REQ (Rubeus `/tgtdeleg` ni rahisi kwa sababu inalazimisha client kufanya Kerberos GSS-API dance bila kredensiali).
2. Decrypt TGT iliyorejeshwa kwa kutumia krbtgt key, rekebisha PAC attributes (user, groups, logon info, SIDs, device claims, n.k.).
3. Re-encrypt/saini tena tiketi kwa kutumia krbtgt key ile ile na iingize ndani ya kikao cha kuingia kilichopo (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Hiari, rudia mchakato kwa service ticket kwa kutoa blob halali ya TGT pamoja na funguo ya huduma lengwa ili kubaki kimya kwenye mtandao.

### Updated Rubeus tradecraft (2024+)

Kazi ya hivi karibuni ya Huntress imesasisha kitendo cha `diamond` ndani ya Rubeus kwa kuhamisha maboresho ya `/ldap` na `/opsec` ambayo hapo awali yalikuwepo tu kwa golden/silver tickets. `/ldap` sasa inajaza moja kwa moja sifa sahihi za PAC kutoka AD (user profile, logon hours, sidHistory, domain policies), wakati `/opsec` inafanya mtiririko wa AS-REQ/AS-REP usiyotambulika kutoka kwa mteja wa Windows kwa kufanya mfululizo wa pre-auth wa hatua mbili na kulazimisha kripto ya AES pekee. Hii inapunguza kwa kiasi kikubwa viashiria vinavyoeleweka kama vile device IDs zilizo wazi au dirisha la uhalali lisilo la kawaida.
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
- `/ldap` (kwa hiari pamoja na `/ldapuser` & `/ldappassword`) huita AD na SYSVOL ili kunakili data za sera za PAC za mtumiaji lengwa.
- `/opsec` inalazimisha jaribio la AS-REQ linalofanana na Windows, ikiweka bendera zinazosababisha kelele kwa sifuri na kubaki kwa AES256.
- `/tgtdeleg` huzuia kugusa cleartext password au NTLM/AES key ya mwathiriwa, huku ikirudisha TGT inayoweza kufunguliwa.

### Service-ticket recutting

Urekebishaji ule ule wa Rubeus uliongeza uwezo wa kutumia diamond technique kwa TGS blobs. Kwa kumlisha `diamond` **base64-encoded TGT** (kutoka kwa `asktgt`, `/tgtdeleg`, au TGT iliyotengenezwa hapo awali), **service SPN**, na **service AES key**, unaweza kutengeneza tiketi za huduma za kuonekana halisi bila kugusa KDC—kwa ufanisi silver ticket isiyoonekana zaidi.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Mtiririko huu wa kazi ni mzuri wakati tayari unadhibiti funguo ya akaunti ya huduma (mf., dumped with `lsadump::lsa /inject` or `secretsdump.py`) na unataka kukata TGS moja-mara inayolingana kikamilifu na sera za AD, ratiba, na data ya PAC bila kutoa traffic mpya ya AS/TGS.

### OPSEC & vidokezo vya utambuzi

- Kanuni za jadi za hunter heuristics (TGS without AS, decade-long lifetimes) bado zinatumika kwa golden tickets, lakini diamond tickets kwa kawaida huibuka hasa wakati **maudhui ya PAC au ramani ya vikundi inaonekana haiwezekani**. Jaza kila uwanja wa PAC (logon hours, user profile paths, device IDs) ili ulinganifu wa kiotomatiki usitoke haraka na kuibua uundaji.
- **Usizidishe vikundi/RIDs**. Ikiwa unahitaji tu `512` (Domain Admins) na `519` (Enterprise Admins), simama hapo na hakikisha akaunti lengwa inaonekana kwa mantiki kuwa mwanachama wa vikundi hivyo mahali pengine ndani ya AD. Excessive `ExtraSids` ni ishara.
- Mradi wa Splunk Security Content unasambaza telemetry ya attack-range kwa diamond tickets pamoja na detections kama *Windows Domain Admin Impersonation Indicator*, ambayo inahusisha mfululizo usio wa kawaida wa Event ID 4768/4769/4624 na mabadiliko ya vikundi vya PAC. Kucheza dataset hiyo tena (au kuunda yako mwenyewe kwa kutumia amri zilizo hapo juu) husaidia kuthibitisha ufunikaji wa SOC kwa T1558.001 na kukupa mantiki thabiti za onyo za kuepuka.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
