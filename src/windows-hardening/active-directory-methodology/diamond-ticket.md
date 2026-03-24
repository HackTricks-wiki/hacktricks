# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT wat gebruik kan word om **toegang tot enige diens as enige gebruiker te kry**. A golden ticket word volledig offline vervals, met die krbtgt-hash van daardie domein geïnkripteer, en dan in 'n aanmeldessie ingevoeg vir gebruik. Omdat domeincontrollers nie TGTs wat hulle wettiglik uitgereik het opspoor nie, sal hulle sonder probleem TGTs aanvaar wat met hul eie krbtgt-hash geïnkripteer is.

Daar is twee algemene tegnieke om die gebruik van golden tickets te ontdek:

- Soek na TGS-REQs wat geen ooreenstemmende AS-REQ het nie.
- Soek na TGTs met onrealistiese waardes, soos Mimikatz se standaard 10-jaar leeftyd.

A diamond ticket word gemaak deur die velde van 'n wettige TGT wat deur 'n DC uitgereik is, te wysig. Dit word bereik deur 'n TGT te versoek, dit met die domein se krbtgt-hash te ontsleutel, die verlangde velde van die ticket te wysig, en dit dan weer te enkripteer. Dit oorkom die twee voorafgenoemde tekortkominge van 'n golden ticket omdat:

- TGS-REQs sal 'n voorafgaande AS-REQ hê.
- Die TGT is deur 'n DC uitgereik, wat beteken dit sal al die korrekte besonderhede volgens die domein se Kerberos-beleid hê. Alhoewel hierdie inligting akkuraat in 'n golden ticket vervals kan word, is dit meer kompleks en vatbaar vir foute.

### Vereistes & workflow

- Cryptographic material: die krbtgt AES256 sleutel (verkieslik) of NTLM-hash om die TGT te ontsleutel en weer te teken.
- Legitimate TGT blob: verkrygbaar met `/tgtdeleg`, `asktgt`, `s4u`, of deur tickets uit geheue te exporteer.
- Context data: die teikengebruiker se RID, groep RIDs/SIDs, en (opsioneel) LDAP-afgeleide PAC-attribuutte.
- Service keys (slegs as jy beplan om service tickets weer te sny): AES-sleutel van die diens se SPN wat nageboots gaan word.

1. Verkry 'n TGT vir enige beheerbare gebruiker via AS-REQ (Rubeus `/tgtdeleg` is gerieflik omdat dit die kliënt dwing om die Kerberos GSS-API-dans sonder geloofsbriewe uit te voer).
2. Ontsleutel die teruggegewe TGT met die krbtgt sleutel, pas PAC-attribuutte aan (gebruiker, groepe, aanmeldinligting, SIDs, toestel-eise, ens.).
3. Her-enkripteer/teken die ticket met dieselfde krbtgt-sleutel en injekteer dit in die huidige aanmeldessie (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opsioneel, herhaal die proses oor 'n service ticket deur 'n geldige TGT blob plus die teiken diens sleutel te voorsien om stil in die netwerkverkeer te bly.

### Bygewerkte Rubeus tradecraft (2024+)

Onlangse werk deur Huntress het die `diamond`-aksie binne Rubeus gemoderniseer deur die `/ldap` en `/opsec` verbeterings te poort wat voorheen slegs vir golden/silver tickets bestaan het. `/ldap` haal nou werklike PAC-konteks deur LDAP te bevraagteken **en** SYSVOL te mount om rekening/groep-attribuutte plus Kerberos/wagwoordbeleid te onttrek (bv., `GptTmpl.inf`), terwyl `/opsec` die AS-REQ/AS-REP-vloei laat ooreenstem met Windows deur die twee-stap preauth-uitruil uit te voer en AES-only + realistiese KDCOptions af te dwing. Dit verminder dramaties duidelike aanwysers soos ontbrekende PAC-velde of lewensduur wat nie met die beleid ooreenstem nie.
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) vra AD en SYSVOL om die geteikende gebruiker se PAC-beleidsdata te weerspieël.
- `/opsec` dwing 'n Windows-agtige AS-REQ-herhaling af, stel luidrugtige vlae op nul en bly by AES256.
- `/tgtdeleg` hou jou hande weg van die cleartext password of die NTLM/AES key van die slagoffer, terwyl dit steeds 'n decryptable TGT teruggee.

### Service-ticket hervervaardiging

Die selfde Rubeus-refresh het die vermoë bygevoeg om die diamond technique op TGS blobs toe te pas. Deur aan `diamond` 'n **base64-encoded TGT** (van `asktgt`, `/tgtdeleg`, of 'n voorheen vervalste TGT), die **service SPN**, en die **service AES key** te voorsien, kan jy realistiese service tickets skep sonder om die KDC aan te raak — effektief 'n meer stealthy silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
This workflow is ideaal wanneer jy reeds beheer oor 'n service account key het (bv. gedump met `lsadump::lsa /inject` of `secretsdump.py`) en 'n eenmalige TGS wil sny wat perfek pas by AD-beleid, tydlyne, en PAC-data sonder om enige nuwe AS/TGS-verkeer uit te stuur.

### Sapphire-style PAC swaps (2025)

A newer twist sometimes called a **sapphire ticket** combines Diamond's "real TGT" base with **S4U2self+U2U** to steal a privileged PAC and drop it into your own TGT. In plaas van om ekstra SIDs te bedink, versoek jy 'n U2U S4U2self ticket vir 'n gebruiker met hoë privilegies waar die `sname` die lae-privilegie versoeker teiken; die KRB_TGS_REQ dra die versoeker se TGT in `additional-tickets` en stel `ENC-TKT-IN-SKEY`, wat toelaat dat die service ticket met daardie gebruiker se sleutel ontsleuteld word. Jy onttrek dan die bevoorregte PAC en heg dit in jou regmatige TGT in voordat jy dit weer onderteken met die krbtgt sleutel.

Impacket's `ticketer.py` now ships sapphire support via `-impersonate` + `-request` (live KDC exchange):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` aanvaar 'n gebruikersnaam of SID; `-request` vereis live user creds plus krbtgt key material (AES/NTLM) om tickets te ontsleutel/patch.

Key OPSEC-aanwysers wanneer hierdie variant gebruik word:

- TGS-REQ sal `ENC-TKT-IN-SKEY` en `additional-tickets` (die slagoffer TGT) dra — skaars in normale verkeer.
- `sname` is dikwels gelyk aan die versoekende gebruiker (self-service access) en Event ID 4769 wys die beller en teiken as dieselfde SPN/gebruiker.
- Verwag gepaarde 4768/4769 inskrywings met dieselfde kliëntrekenaar maar verskillende CNAMES (low-priv requester vs. privileged PAC owner).

### OPSEC & opsporingsnotas

- Die tradisionele hunter heuristieke (TGS without AS, decade-long lifetimes) geld steeds vir golden tickets, maar diamond tickets kom hoofsaaklik na vore wanneer die **PAC-inhoud of group mapping lyk onmoontlik**. Vul elke PAC-veld (logon hours, user profile paths, device IDs) sodat geautomatiseerde vergelykings nie dadelik die vervalsing flag nie.
- **Moet nie oversubscribe groups/RIDs nie**. As jy net `512` (Domain Admins) en `519` (Enterprise Admins) nodig het, hou dit daar en maak seker die teikenrekening behoort plausibel aan daardie groepe elders in AD. Oormatige `ExtraSids` is 'n duidelike aanwijser.
- Sapphire-style swaps laat U2U fingerprints agter: `ENC-TKT-IN-SKEY` + `additional-tickets` plus 'n `sname` wat na 'n gebruiker wys (dikwels die versoeker) in 4769, en 'n opvolg 4624 aanmelding wat uit die vervalste ticket afkomstig is. Korrelleer daardie velde in plaas daarvan om slegs na no-AS-REQ gaps te kyk.
- Microsoft het begin om **RC4 service ticket issuance** uit te faseer weens CVE-2026-20833; die afdwing van AES-only etypes op die KDC verhard die domein en stem ooreen met diamond/sapphire tooling (/opsec dwing reeds AES af). Om RC4 in vervalste PACs te meng sal toenemend uitstaan.
- Splunk's Security Content project versprei attack-range telemetry vir diamond tickets plus detections soos *Windows Domain Admin Impersonation Indicator*, wat ongewoon Event ID 4768/4769/4624 reekse en PAC group changes korreleer. Herlaai daardie dataset (of genereer jou eie met die opdragte hierbo) help om SOC-dekking vir T1558.001 te valideer terwyl dit jou konkrete alert logic gee om te ontduik.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
