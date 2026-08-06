# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Soos 'n golden ticket** is 'n diamond ticket 'n TGT wat gebruik kan word om **toegang tot enige diens as enige gebruiker te verkry**. 'n Golden ticket word volledig offline vervals, met die krbtgt-hash van daardie domein geënkripteer, en dan in 'n logonsessie ingespuit vir gebruik. Omdat domeinbeheerders nie die TGTs naspoor wat dit (of hulle) wettiglik uitgereik het nie, sal hulle TGTs wat met hul eie krbtgt-hash geënkripteer is, geredelik aanvaar.<sup>[[1]](#references)</sup>

Daar is twee algemene tegnieke om die gebruik van golden tickets op te spoor:

- Soek na TGS-REQs wat geen ooreenstemmende AS-REQ het nie.
- Soek na TGTs wat onrealistiese waardes het, soos Mimikatz se verstek-leeftyd van 10 jaar.

'n **Diamond ticket** word geskep deur **die velde van 'n wettige TGT wat deur 'n DC uitgereik is, te wysig**. Dit word bereik deur 'n **TGT aan te vra**, dit met die domein se krbtgt-hash te **dekripteer**, die verlangde velde van die ticket te **wysig**, en dit dan weer te **enkripteer**. Dit **oorkom die twee bogenoemde tekortkominge** van 'n golden ticket omdat:<sup>[[1]](#references)</sup>

- TGS-REQs sal deur 'n voorafgaande AS-REQ voorafgegaan word.
- Die TGT is deur 'n DC uitgereik, wat beteken dat dit al die korrekte besonderhede uit die domein se Kerberos-policy sal bevat. Hoewel hierdie besonderhede akkuraat in 'n golden ticket vervals kan word, is dit meer kompleks en vatbaar vir foute.

### Vereistes & workflow

- **Kriptografiese materiaal**: die krbtgt AES256-sleutel (verkieslik) of NTLM-hash om die TGT te dekripteer en te heronderteken.
- **Wettige TGT-blob**: verkry met `/tgtdeleg`, `asktgt`, `s4u`, of deur tickets uit die memory te exporteer.
- **Konteksdata**: die teikengebruiker se RID, groep-RIDs/SIDs, en (opsioneel) LDAP-afgeleide PAC-attribuutdata.
- **Dienssleutels** (slegs indien jy beplan om diens-tickets te herskep): AES-sleutel van die diens-SPN wat nageboots moet word.

1. Verkry 'n TGT vir enige beheerde gebruiker via AS-REQ (`/tgtdeleg` in Rubeus is gerieflik omdat dit die client dwing om die Kerberos GSS-API-dans sonder credentials uit te voer).
2. Dekripteer die teruggestuurde TGT met die krbtgt-sleutel, en patch die PAC-attribuutdata (gebruiker, groepe, logon-inligting, SIDs, device claims, ens.).
3. Enkripteer/onderteken die ticket weer met dieselfde krbtgt-sleutel en inject dit in die huidige logonsessie (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Herhaal die proses opsioneel met 'n diens-ticket deur 'n geldige TGT-blob plus die teikendiens se sleutel te verskaf om stealthy op die wire te bly.

### Updated Rubeus tradecraft (2024+)

Onlangse werk deur Huntress het die `diamond`-aksie binne Rubeus gemoderniseer deur die `/ldap`- en `/opsec`-verbeterings te port wat voorheen slegs vir golden/silver tickets bestaan het. `/ldap` haal nou werklike PAC-konteks op deur LDAP te query **en** SYSVOL te mount om rekening-/groep-attribuutdata plus Kerberos-/password-policy te onttrek (byvoorbeeld `GptTmpl.inf`), terwyl `/opsec` die AS-REQ/AS-REP-vloei met Windows laat ooreenstem deur die twee-stap preauth-uitruiling uit te voer en slegs AES plus realistiese KDCOptions af te dwing. Dit verminder ooglopende indicators, soos ontbrekende PAC-velde of policy-wanpassende leeftye, dramaties.<sup>[[3]](#references)</sup>
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
- `/ldap` (met opsionele `/ldapuser` & `/ldappassword`) raadpleeg AD en SYSVOL om die teiken-gebruiker se PAC policy data te weerspieël.
- `/opsec` dwing 'n Windows-agtige AS-REQ-herpoging af, stel raserige flags op nul en hou by AES256.
- `/tgtdeleg` hou jou weg van die slagoffer se cleartext password of NTLM/AES key, terwyl dit steeds 'n dekripteerbare TGT terugstuur.

### Service-ticket hersnyding

Diezelfde Rubeus-opdatering het die vermoë bygevoeg om die diamond technique op TGS blobs toe te pas. Deur `diamond` 'n **base64-encoded TGT** (van `asktgt`, `/tgtdeleg`, of 'n voorheen forged TGT), die **service SPN**, en die **service AES key** te gee, kan jy realistiese service tickets skep sonder om aan die KDC te raak—effektief 'n meer diskrete silver ticket.<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Hierdie workflow is ideaal wanneer jy reeds 'n service account key beheer (bv. gedump met `lsadump::lsa /inject` of `secretsdump.py`) en 'n eenmalige TGS wil skep wat perfek by AD-beleid, tydlyne en PAC-data pas sonder om enige nuwe AS/TGS-verkeer uit te reik.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

'n Nuwer variasie, wat soms 'n **sapphire ticket** genoem word, kombineer Diamond se "real TGT"-basis met **S4U2self+U2U** om 'n bevoorregte PAC te steel en dit in jou eie TGT te plaas. In plaas daarvan om ekstra SIDs uit te dink, versoek jy 'n U2U S4U2self-ticket vir 'n gebruiker met hoë bevoorregting, waar die `sname` op die gebruiker wat die versoek rig, gerig is; die KRB_TGS_REQ bevat die versoeker se TGT in `additional-tickets` en stel `ENC-TKT-IN-SKEY`, waardeur die service ticket met daardie gebruiker se sleutel gedekripteer kan word. Jy onttrek dan die bevoorregte PAC en voeg dit in jou wettige TGT in voordat jy dit weer met die krbtgt-sleutel onderteken.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket se `ticketer.py` sluit nou sapphire-ondersteuning in via `-impersonate` + `-request` (live KDC-uitruil):<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` aanvaar ’n gebruikersnaam of SID; `-request` vereis lewendige gebruiker-credentials plus krbtgt-sleutelmateriale (AES/NTLM) om tickets te dekripteer/patch.

Belangrike OPSEC-aanwysers wanneer hierdie variant gebruik word:<sup>[[5]](#references)</sup>

- TGS-REQ sal `ENC-TKT-IN-SKEY` en `additional-tickets` (die slagoffer se TGT) bevat — skaars in normale verkeer.
- `sname` is dikwels gelyk aan die versoekende gebruiker (selfdiens-toegang), en Event ID 4769 toon die oproeper en teiken as dieselfde SPN/gebruiker.
- Verwag gepaarde 4768/4769-inskrywings met dieselfde kliëntrekenaar, maar verskillende CNAMES (laeprivilegie-versoeker teenoor bevoorregte PAC-eienaar).

### OPSEC & opsporingsnotas

- Die tradisionele hunter-heuristieke (TGS sonder AS, dekadelange leeftye) geld steeds vir golden tickets, maar diamond tickets kom hoofsaaklik na vore wanneer die **PAC-inhoud of groepkartering onmoontlik lyk**. Vul elke PAC-veld in (aanmeldingstye, gebruikerprofielpaaie, toestel-ID's) sodat outomatiese vergelykings nie die vervalsing onmiddellik vlag nie.<sup>[[3]](#references)</sup>
- **Moenie te veel groups/RIDs toewys nie**. As jy slegs `512` (Domain Admins) en `519` (Enterprise Admins) nodig het, stop daar en maak seker die teikenrekening behoort elders in AD geloofwaardig aan hierdie groups. Oormatige `ExtraSids` is ’n weggee-teken.
- Sapphire-style swaps laat U2U-vingerafdrukke: `ENC-TKT-IN-SKEY` + `additional-tickets`, plus ’n `sname` wat na ’n gebruiker wys (dikwels die versoeker) in 4769, en ’n daaropvolgende 4624-aanmelding wat uit die forged ticket afkomstig is. Korrelleer daardie velde eerder as om slegs na gapings sonder AS-REQ te soek.<sup>[[5]](#references)</sup>
- Microsoft het begin om **RC4 service ticket issuance** uit te faseer weens CVE-2026-20833; die afdwing van AES-only etypes op die KDC verhard die domein en pas ook by diamond/sapphire tooling (/opsec forseer reeds AES). Die vermenging van RC4 in forged PACs sal toenemend uitstaan.<sup>[[6]](#references)</sup>
- Splunk se Security Content-projek versprei attack-range-telemetrie vir diamond tickets, plus detections soos *Windows Domain Admin Impersonation Indicator*, wat ongewone Event ID 4768/4769/4624-volgordes en PAC-groepveranderings korreleer. Deur daardie dataset te herspeel (of jou eie een met die opdragte hierbo te genereer), kan jy SOC-dekking vir T1558.001 valideer terwyl jy konkrete alert-logika kry om te ontduik.<sup>[[4]](#references)</sup>

## Verwysings

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
