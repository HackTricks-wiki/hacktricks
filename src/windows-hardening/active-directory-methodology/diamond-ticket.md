# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. 

A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Tafuta TGS-REQs ambazo hazina AS-REQ inayolingana.
- Tafuta TGTs ambazo zina thamani zisizo za kawaida, kama vile muda wa chaguo-msingi wa miaka 10 wa Mimikatz.

A diamond ticket is made by modifying the fields of a legitimate TGT that was issued by a DC. This is achieved by requesting a TGT, decrypting it with the domain's krbtgt hash, modifying the desired fields of the ticket, then re-encrypting it. This overcomes the two aforementioned shortcomings of a golden ticket because:

- TGS-REQs zitatokea na AS-REQ iliyotangulia.
- The TGT ilitolewa na DC, ambayo inamaanisha itakuwa na taarifa zote sahihi kutoka kwa sera ya Kerberos ya domain. Ingawa hizi zinaweza kutengenezwa kwa usahihi katika golden ticket, ni ngumu zaidi na zinafungua nafasi ya makosa.

### Requirements & workflow

- Vifaa vya kriptografia: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- Legitimate TGT blob: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- Data za muktadha: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- Service keys (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Pata TGT ya mtumiaji yeyote unaodhibitiwa kupitia AS-REQ (Rubeus `/tgtdeleg` ni rahisi kwa sababu inalazimisha mteja kufanya Kerberos GSS-API dance bila credentials).
2. Decrypt TGT iliyorejeshwa kwa kutumia krbtgt key ya domain, rekebisha sifa za PAC (user, groups, logon info, SIDs, device claims, n.k.).
3. Re-encrypt/saini tiketi tena kwa krbtgt key ile ile na uingize kwenye kikao cha sasa cha kuingia (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Hiari, rudia mchakato kwa service ticket kwa kutoa valid TGT blob pamoja na service key lengwa ili kubaki stealthy kwenye wire.

### Updated Rubeus tradecraft (2024+)

Work mpya ya Huntress imesasisha kitendo cha `diamond` ndani ya Rubeus kwa kuhamisha maboresho ya `/ldap` na `/opsec` ambayo awali yalikuwepo tu kwa golden/silver tickets. `/ldap` sasa inajaza moja kwa moja sifa sahihi za PAC kutoka AD (user profile, logon hours, sidHistory, domain policies), wakati `/opsec` inafanya mtiririko wa AS-REQ/AS-REP usitofautiane na mteja wa Windows kwa kufanya mfululizo wa pre-auth wa hatua mbili na kuzuia crypto isipokuwa AES pekee. Hii inapunguza kwa kiasi kikubwa viashiria vinavyoonekana kama device IDs tupu au madurisho ya uhalali yasiyokuwa na ukweli.
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) hufanya maombi kwa AD na SYSVOL ili kuiga data ya sera ya PAC ya mtumiaji lengwa.
- `/opsec` inalazimisha jaribio la AS-REQ lenye mtindo wa Windows, ikifuta noisy flags na kubaki kwenye AES256.
- `/tgtdeleg` inakuweka mbali na cleartext password au NTLM/AES key ya mwathiriwa huku ikirudisha decryptable TGT.

### Kukata upya tiketi ya huduma

Sasisho ile ile ya Rubeus iliongeza uwezo wa kutumia diamond technique kwa TGS blobs. Kwa kumpa `diamond` **base64-encoded TGT** (kutoka kwa `asktgt`, `/tgtdeleg`, au TGT iliyotengenezwa kabla), **service SPN**, na **service AES key**, unaweza kutengeneza service tickets za kuonekana halisi bila kugusa KDC—kwa ufanisi silver ticket isiyogunduka zaidi.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Mfumo huu wa kazi ni mzuri wakati tayari unadhibiti ufunguo wa akaunti ya huduma (kwa mfano, uliotolewa kwa `lsadump::lsa /inject` au `secretsdump.py`) na unataka kutengeneza TGS ya mara moja inayolingana kabisa na sera za AD, ratiba, na data ya PAC bila kutoa trafiki mpya ya AS/TGS.

### Sapphire-style PAC swaps (2025)

Mguso mpya wa mbinu, mara nyingine huitwa **sapphire ticket**, unaunganisha msingi wa "real TGT" wa Diamond na **S4U2self+U2U** ili kuiba PAC yenye cheo na kuiweka ndani ya TGT yako mwenyewe. Badala ya kuunda SIDs za ziada, unaomba tiketi ya U2U S4U2self kwa mtumiaji mwenye vibali vya juu, unachukua PAC hiyo, na kuiweka ndani ya TGT yako halali kabla ya kusaini tena kwa krbtgt key. Kwa sababu U2U inaweka `ENC-TKT-IN-SKEY`, mtiririko wa waya unaotokea unaonekana kama ubadilishanaji halali kati ya watumiaji.

Uigaji mdogo upande wa Linux na Impacket iliyorekebishwa `ticketer.py` (inaongeza msaada wa sapphire):
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

- TGS-REQ itaabeba `ENC-TKT-IN-SKEY` na `additional-tickets` (TGT ya mwathiriwa) — nadra katika trafiki ya kawaida.
- `sname` mara nyingi ni sawa na mtumiaji aliyemtaka (self-service access) na Event ID 4769 inaonyesha mdai na lengo kuwa SPN/mtumiaji mmoja.
- Tegemea rekodi za 4768/4769 zilizounganishwa na kompyuta ya mteja ile ile lakini CNAMES tofauti (muombaji mwenye ruhusa ndogo vs. mmiliki wa PAC mwenye ruhusa).

### Vidokezo vya OPSEC & utambuzi

- Mbinu za jadi za hunter heuristics (TGS without AS, decade-long lifetimes) bado zinatumika kwa golden tickets, lakini diamond tickets kawaida huibuka wakati **maudhui ya PAC au upangaji wa vikundi unaonekana kuwa hauwezekani**. Jaza kila uwanja wa PAC (logon hours, user profile paths, device IDs) ili kulinganisha kwa otomatiki kusiibambike udanganyifu mara moja.
- **Usizidi kujiandikisha vikundi/RIDs**. Ikiwa unahitaji tu `512` (Domain Admins) na `519` (Enterprise Admins), simama hapo na hakikisha akaunti lengwa inaonekana kuwa mwanachama wa vikundi hivyo mahali pengine ndani ya AD. Kuwa na `ExtraSids` nyingi ni ishara.
- Sapphire-style swaps huacha alama za vidole za U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` katika 4769, na kuingia kwa 4624 kilichofuata kikiwa kimeanzishwa na tiketi iliyodanganywa. Linganisha mashamba hayo badala ya kutafuta tu mapengo ya no-AS-REQ.
- Microsoft imeanza kuondoa hatua kwa hatua **RC4 service ticket issuance** kwa sababu ya CVE-2026-20833; kulazimisha AES-only etypes kwenye KDC kunaimarisha domain na kunaendana na zana za diamond/sapphire (/opsec tayari inalazimisha AES). Kuchanganya RC4 ndani ya PAC zilizodanganywa kutakuwa wazi zaidi kwa kadiri.
- Splunk's Security Content project unasambaza attack-range telemetry kwa diamond tickets pamoja na utambuzi kama *Windows Domain Admin Impersonation Indicator*, ambayo inaunganisha mfuatano usio wa kawaida wa Event ID 4768/4769/4624 na mabadiliko ya vikundi vya PAC. Kuchezeshwa dataset hiyo (au kuzalisha yako mwenyewe kwa amri zilizotajwa hapo juu) husaidia kuthibitisha ufunikaji wa SOC kwa T1558.001 huku ikikupa mantiki ya onyo halisi ya kuepuka.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
