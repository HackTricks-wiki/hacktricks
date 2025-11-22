# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Soek na TGS-REQs wat geen ooreenstemmende AS-REQ het nie.
- Soek na TGTs wat onrealistiese waardes het, soos Mimikatz's verstek 10-jaar geldigheid.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### Vereistes & werkvloe

- **Kriptografiese materiaal**: die krbtgt AES256 key (preferred) of NTLM hash om die TGT te ontsluit en weer te onderteken.
- **Legitieme TGT-blob**: verkry met `/tgtdeleg`, `asktgt`, `s4u`, of deur tickets uit geheue te exporteer.
- **Konteksdata**: die teiken gebruiker se RID, groep RIDs/SIDs, en (opsioneel) LDAP-afgeleide PAC-attribuutte.
- **Dienssleutels** (slegs as jy beplan om service tickets weer te sny): AES key van die service SPN wat geïmpersonifieer gaan word.

1. Verkry 'n TGT vir enige beheerlike gebruiker via AS-REQ (Rubeus `/tgtdeleg` is gerieflik omdat dit die kliënt dwing om die Kerberos GSS-API dance sonder credentials uit te voer).
2. Ontsleutel die teruggegewe TGT met die krbtgt key, pas PAC-attribuutte aan (gebruiker, groepe, aanmeldinligting, SIDs, toestel-eise, ens.).
3. Her-enkripteer/onderteken die ticket met dieselfde krbtgt key en injekteer dit in die huidige aanmeldessie (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opsioneel, herhaal die proses oor 'n service ticket deur 'n geldige TGT-blob plus die teiken diens sleutel te voorsien om op die netwerk stealt te bly.

### Updated Rubeus tradecraft (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now auto-populates accurate PAC attributes straight from AD (user profile, logon hours, sidHistory, domain policies), while `/opsec` makes the AS-REQ/AS-REP flow indistinguishable from a Windows client by performing the two-step pre-auth sequence and enforcing AES-only crypto. This dramatically reduces obvious indicators such as blank device IDs or unrealistic validity windows.
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
- `/ldap` (met opsioneel `/ldapuser` & `/ldappassword`) vra AD en SYSVOL om die teiken gebruiker se PAC-beleidsdata te weerspieël.
- `/opsec` dwing 'n Windows-agtige AS-REQ-hersoek af, stel lawaaierige flags na nul en hou by AES256.
- `/tgtdeleg` hou jou hande van die wagwoord in duidelike teks of die NTLM/AES-sleutel van die slagoffer af, terwyl dit steeds 'n ontsleutelbare TGT teruggee.

### Herverwerking van service-tickets

Dieselfde Rubeus-opdatering het die vermoë bygevoeg om die diamond-tegniek op TGS-blobs toe te pas. Deur aan `diamond` 'n **base64-encoded TGT** (van `asktgt`, `/tgtdeleg`, of 'n vooraf vervalste TGT), die **service SPN**, en die **service AES key** te voorsien, kan jy realistiese service tickets skep sonder om die KDC aan te raak — effektief 'n meer onopvallende silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Hierdie werkstroom is ideaal wanneer jy reeds 'n service account key beheer (bv. gedump met `lsadump::lsa /inject` of `secretsdump.py`) en 'n eenmalige TGS wil sny wat perfek pas by AD-beleid, tydlyne, en PAC-data sonder om enige nuwe AS/TGS-verkeer uit te reik.

### OPSEC & opsporingsnotas

- Die tradisionele hunter heuristieke (TGS sonder AS, dekadelange leeftye) is steeds van toepassing op golden tickets, maar diamond tickets kom veral na vore wanneer die **PAC-inhoud of group mapping onmoontlik lyk**. Vul elke PAC-veld (logon hours, user profile paths, device IDs) sodat geoutomatiseerde vergelykings nie onmiddellik die vervalsing vlag nie.
- **Moet nie groepe/RIDs oor-inskryf nie**. As jy net `512` (Domain Admins) en `519` (Enterprise Admins) nodig het, hou daarby en maak seker dat die teikenrekening waarskynlik aan daardie groepe elders in AD behoort. Oormatige `ExtraSids` is 'n weggee-teken.
- Splunk se Security Content-projek versprei attack-range telemetry vir diamond tickets sowel as detecties soos *Windows Domain Admin Impersonation Indicator*, wat vreemde Event ID 4768/4769/4624-reekse en PAC-groepveranderinge korreleer. Om daardie dataset te herhaal (of jou eie te genereer met die opdragte hierbo) help om SOC-dekking vir T1558.001 te valideer en gee jou konkrete waarskuwingslogika om te ontduik.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
