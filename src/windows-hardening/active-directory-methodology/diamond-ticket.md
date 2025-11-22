# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, 'n diamond ticket is 'n TGT wat gebruik kan word om **enige diens as enige gebruiker te benader**. A golden ticket word heeltemal offline vervals, versleutel met die krbtgt-hash van daardie domein, en dan in 'n aanmeldsessie ingevoeg vir gebruik. Omdat domain controllers nie TGTs wat hulle wettiglik uitgereik het opspoor nie, sal hulle maklik TGTs aanvaar wat met hul eie krbtgt-hash versleutel is.

Daar is twee algemene tegnieke om die gebruik van golden tickets te ontduik:

- Kyk vir TGS-REQs wat geen ooreenstemmende AS-REQ het nie.
- Kyk vir TGTs met absurde waardes, soos Mimikatz se standaard 10‑jaar leeftyd.

A **diamond ticket** word gemaak deur **die velde van 'n wettige TGT wat deur 'n DC uitgereik is, te wysig**. Dit word bereik deur 'n **TGT** aan te **vra**, dit te **dekripteer** met die domein se krbtgt-hash, die verlangde velde van die kaartjie te **wysig**, en dan weer te **her-enkripteer**. Dit **oorkom die twee reeds genoemde tekortkominge** van 'n golden ticket omdat:

- TGS-REQs sal 'n voorafgaande AS-REQ hê.
- Die TGT is deur 'n DC uitgereik, wat beteken dit sal al die korrekte besonderhede uit die domein se Kerberos-beleid hê. Alhoewel hierdie in 'n golden ticket akkuraat vervals kan word, is dit meer kompleks en vatbaar vir foute.

### Requirements & workflow

- **Cryptographic material**: die krbtgt AES256-sleutel (verkieslik) of NTLM-hash om die TGT te dekripteer en weer te onderteken.
- **Legitimate TGT blob**: verkry met `/tgtdeleg`, `asktgt`, `s4u`, of deur tickets uit geheue te eksporteer.
- **Context data**: die teiken gebruiker se RID, groep RIDs/SIDs, en (opsioneel) LDAP-afgeleide PAC-attribuutte.
- **Service keys** (slegs as jy beplan om service tickets te herknip): AES-sleutel van die diens SPN wat nageboots gaan word.

1. Verkry 'n TGT vir enige beheerste gebruiker via AS-REQ (Rubeus `/tgtdeleg` is handig omdat dit die kliënt dwing om die Kerberos GSS-API-dans sonder credentials uit te voer).
2. Dekripteer die teruggegewe TGT met die krbtgt-sleutel, pas PAC-attribuutte aan (user, groups, logon info, SIDs, device claims, ens.).
3. Her-enkripteer/onderteken die kaartjie met dieselfde krbtgt-sleutel en injekteer dit in die huidige aanmeldsessie (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opsioneel, herhaal die proses oor 'n service ticket deur 'n geldige TGT-blob plus die teiken diens-sleutel te voorsien om onopvallend op die netwerk te bly.

### Updated Rubeus tradecraft (2024+)

Onlangs het werk deur Huntress die `diamond`-aksie binne Rubeus gemoderniseer deur die `/ldap`- en `/opsec`-verbeterings oor te dra wat voorheen slegs vir golden/silver tickets bestaan het. `/ldap` vul nou outomaties akkurate PAC-attribuutte regstreeks uit AD in (user profile, logon hours, sidHistory, domain policies), terwyl `/opsec` die AS-REQ/AS-REP-vloei ononderskeibaar van 'n Windows-kliënt maak deur die twee-stap pre-auth volgorde uit te voer en slegs AES-kripto af te dwing. Dit verminder dramaties duidelike aanduiders soos leë device IDs of onrealistiese geldigheidsvensters.
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) vra AD en SYSVOL om die teiken-gebruiker se PAC-beleiddata te spieël.
- `/opsec` dwing 'n Windows-agtige AS-REQ-herhaling af, maak lawaaierige vlae nul en hou by AES256.
- `/tgtdeleg` hou jou hande van die cleartext-wagwoord of NTLM/AES-sleutel van die slagoffer af terwyl dit steeds 'n ontsleutelbare TGT teruggee.

### Hersnying van service-tickets

Dieselfde Rubeus-opdatering het die vermoë bygevoeg om die diamond technique op TGS-blobs toe te pas. Deur `diamond` 'n **base64-encoded TGT** (van `asktgt`, `/tgtdeleg`, of 'n voorheen vervalste TGT), die **service SPN**, en die **service AES key** te voorsien, kan jy realistiese service tickets skep sonder om die KDC aan te raak—effektief 'n meer gesluierde silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Hierdie workflow is ideaal wanneer jy reeds beheer oor `service account key` het (bv. gedump met `lsadump::lsa /inject` of `secretsdump.py`) en ’n eenmalige TGS wil sny wat perfek by AD-beleid, tydlyne, en PAC-data pas sonder om enige nuwe AS/TGS-verkeer uit te stuur.

### OPSEC & opsporingsnotas

- Die tradisionele hunter-heuristieke (TGS sonder AS, dekade-lange lewensduurte) is steeds van toepassing op golden tickets, maar diamond tickets verskyn hoofsaaklik wanneer die **PAC-inhoud of groepstoewysing onmoontlik lyk**. Vul elke PAC-veld (logon hours, user profile paths, device IDs) sodat geoutomatiseerde vergelykings die vervalsing nie onmiddellik aandui nie.
- **Do not oversubscribe groups/RIDs**. As jy slegs `512` (Domain Admins) en `519` (Enterprise Admins) nodig het, hou daarby en maak seker die teikenrekening behoort waarskynlik tot daardie groepe elders in AD. Oormatige `ExtraSids` is ’n weggee.
- Splunk's Security Content project versprei attack-range telemetry vir diamond tickets plus detections soos *Windows Domain Admin Impersonation Indicator*, wat ongewone Event ID 4768/4769/4624-reekse en PAC-groepveranderinge korreleer. Her-afspeel van daardie dataset (of die generering van jou eie met die opdragte hierbo) help om SOC-dekking vir T1558.001 te valideer en voorsien konkrete waarskuwingslogika wat jy kan gebruik om ontduiking te toets.

## Verwysings

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
