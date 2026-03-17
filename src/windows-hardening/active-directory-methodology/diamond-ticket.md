# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Kama golden ticket**, diamond ticket ni TGT ambayo inaweza kutumika **kupata huduma yoyote kama mtumiaji yeyote**. Golden ticket imepandikizwa kabisa offline, imefichwa kwa krbtgt hash ya domain hiyo, kisha imeingizwa kwenye kikao cha kuingia (logon session) kwa matumizi. Kwa sababu domain controllers hawafuatilii TGTs ambazo zilitolewa kwa njia halali, watakubali kwa urahisi TGTs zilizofichwa kwa krbtgt hash yao wenyewe.

Kuna mbinu mbili za kawaida za kugundua matumizi ya golden tickets:

- Tafuta TGS-REQs ambazo hazina AS-REQ inayolingana.
- Tafuta TGTs ambazo zina thamani zisizo za kawaida, kama vile lifetime ya miaka 10 ya default ya Mimikatz.

A **diamond ticket** inatengenezwa kwa **kubadilisha maeneo ya TGT halali iliyotolewa na DC**. Huu unafikiwa kwa **kuita** TGT, **kuifungua** kwa krbtgt hash ya domain, **kubadilisha** mashamba yaliyohitajika ya tiketi, kisha **kuifunga tena**. Hii **inaondoa hasara mbili zilizotajwa** za golden ticket kwa sababu:

- TGS-REQs zitatokea ikiwa na AS-REQ iliyotangulia.
- TGT ilitolewa na DC ambayo inamaanisha itakuwa na maelezo yote sahihi kutoka kwa sera ya Kerberos ya domain. Ingawa haya yanaweza kuundwa kwa usahihi kwenye golden ticket, ni ngumu zaidi na wazi kwa makosa.

### Requirements & workflow

- **Cryptographic material**: krbtgt AES256 key (inadhibitiwa) au NTLM hash ili kufungua na kusaini tena TGT.
- **Legitimate TGT blob**: inapatikana kwa kutumia `/tgtdeleg`, `asktgt`, `s4u`, au kwa kusafirisha tiketi kutoka kwenye memory.
- **Context data**: target user RID, group RIDs/SIDs, na (hiari) LDAP-derived PAC attributes.
- **Service keys** (tu kama unapanga kukata tena service tickets): AES key ya service SPN itakayodaiwa.

1. Pata TGT kwa mtumiaji yoyote unaodhibitiwa kupitia AS-REQ (Rubeus `/tgtdeleg` ni rahisi kwa sababu inalazimisha client kufanya Kerberos GSS-API dance bila credentials).
2. Fungua TGT iliyorejeshwa kwa krbtgt key, rekebisha PAC attributes (mtumiaji, vikundi, taarifa za logon, SIDs, dai za kifaa, n.k.).
3. Funga/saini tena tiketi kwa krbtgt key ile ile na uingize kwenye kikao cha sasa cha logon (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Hiari, rudia mchakato kwa service ticket kwa kutoa TGT blob halali pamoja na service key ya lengo ili kubaki stealthy kwenye wire.

### Updated Rubeus tradecraft (2024+)

Kazi ya hivi karibuni ya Huntress iliboresha action ya `diamond` ndani ya Rubeus kwa kuleta maboresho ya `/ldap` na `/opsec` ambayo hapo awali yalikuwepo tu kwa golden/silver tickets. `/ldap` sasa huvuta muktadha halisi wa PAC kwa kuuliza LDAP **na** kuunganisha SYSVOL ili kutoa sifa za account/group pamoja na sera ya Kerberos/password (mfano, `GptTmpl.inf`), wakati `/opsec` inafanya mtiririko wa AS-REQ/AS-REP ulingane na Windows kwa kufanya mazungumzo ya preauth ya hatua mbili na kulazimisha AES-only + realistic KDCOptions. Hii inapunguza kwa kiasi kikubwa viashiria vinavyoonekana kama utelezaji wa mashamba ya PAC au lifetimes zisizolingana na sera.
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
- `/ldap` (kwa hiari `/ldapuser` & `/ldappassword`) huwauliza AD na SYSVOL ili kuiga data za sera za PAC za mtumiaji lengwa.
- `/opsec` inalazimisha jaribio jipya la AS-REQ lenye tabia za Windows, ikifuta bendera zenye kelele na kubaki kutumia AES256.
- `/tgtdeleg` inakuweka mbali na cleartext password au NTLM/AES key ya mwathiriwa, huku ikirudisha TGT inayoweza kufunguliwa.

### Kukata upya service-ticket

Marekebisho yale yale ya Rubeus yaliongeza uwezo wa kutumia diamond technique kwenye TGS blobs. Kwa kumpa `diamond` **base64-encoded TGT** (kutokana na `asktgt`, `/tgtdeleg`, au TGT iliyotengenezwa hapo awali), **service SPN**, na **service AES key**, unaweza kutengeneza service tickets zinazofanana na halisi bila kugusa KDC—kwa ufanisi silver ticket iliyofichika zaidi.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
This workflow is ideal when you already control a service account key (e.g., dumped with `lsadump::lsa /inject` or `secretsdump.py`) and want to cut a one-off TGS that perfectly matches AD policy, timelines, and PAC data without issuing any new AS/TGS traffic.

### Sapphire-style PAC swaps (2025)

Mbinu mpya inayojulikana kama **sapphire ticket** inaunganisha msingi wa "real TGT" wa Diamond na **S4U2self+U2U** ili kuiba PAC yenye ruhusa ya juu na kuiweka ndani ya TGT yako mwenyewe. Badala ya kubuni SIDs za ziada, unahitaji tiketi ya U2U S4U2self kwa mtumiaji mwenye ruhusa ya juu ambapo `sname` inalenga muombaji mwenye ruhusa za chini; KRB_TGS_REQ inabeba TGT ya muombaji katika `additional-tickets` na inaweka `ENC-TKT-IN-SKEY`, kuruhusu service ticket kufunguliwa kwa kutumia ufunguo wa mtumiaji huyo. Kisha unatolea PAC yenye ruhusa ya juu na kuichanganya ndani ya TGT yako halali kabla ya kusaini tena kwa ufunguo wa krbtgt.

Impacket's `ticketer.py` now ships sapphire support via `-impersonate` + `-request` (live KDC exchange):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` inapokea username au SID; `-request` inahitaji live user creds pamoja na krbtgt key material (AES/NTLM) ili ku-decrypt/patch tickets.

Key OPSEC inavyoonyesha unapotumia aina hii:

- TGS-REQ itabeba `ENC-TKT-IN-SKEY` na `additional-tickets` (the victim TGT) — nadra kwenye trafiki ya kawaida.
- `sname` mara nyingi ni sawa na mtumiaji anayeomba (self-service access) na Event ID 4769 inaonyesha mwito na lengo ni SPN/mtumiaji yuleyule.
- Tegemea jozi za 4768/4769 zenye kompyuta ya mteja ile ile lakini CNAMES tofauti (muombaji mwenye haki ndogo vs. mmiliki wa PAC mwenye kipaumbele).

### OPSEC & detection notes

- Kanuni za jadi za hunter heuristics (TGS bila AS, decade-long lifetimes) bado zinatumika kwa golden tickets, lakini diamond tickets huvuka hasa pale **maudhui ya PAC au group mapping inapoonekana haiwezekani**. Jaza kila uwanja wa PAC (logon hours, user profile paths, device IDs) ili kulinganisha kwa automatiki zisibaini forgeries mara moja.
- **Usisajili vikundi/RIDs kupita kiasi**. Ikiwa unahitaji tu `512` (Domain Admins) na `519` (Enterprise Admins), simama hapo na hakikisha akaunti lengwa inaonekana kuwa mwanachama wa vikundi hivyo mahali pengine ndani ya AD. Excessive `ExtraSids` ni ishara.
- Sapphire-style swaps huacha alama za U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` pamoja na `sname` inayomwonyesha mtumiaji (mara nyingi muombaji) katika 4769, na logon ya 4624 inayofuata iliyotokana na ticket bandia. Fananisha mashamba hayo badala ya kutafuta tu mapengo ya no-AS-REQ.
- Microsoft imeanza kuondoa hatua kwa hatua **RC4 service ticket issuance** kwa sababu ya CVE-2026-20833; kulazimisha AES-only etypes kwenye KDC kunatia nguvu domain na kunalingana na zana za diamond/sapphire (/opsec tayari inalazimisha AES). Kuchanganya RC4 ndani ya PACs bandia kutatoa dalili zaidi.
- Mradi wa Splunk's Security Content unasambaza telemetry ya attack-range kwa diamond tickets pamoja na detections kama *Windows Domain Admin Impersonation Indicator*, ambayo inafananisha mfululizo usio wa kawaida wa Event ID 4768/4769/4624 na mabadiliko ya vikundi vya PAC. Kuchezesha dataset hiyo tena (au kuunda yako kwa amri zilizo hapo juu) husaidia kuthibitisha coverage ya SOC kwa T1558.001 wakati ikikupa mantiki halisi ya onyo ya kuepuka.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
