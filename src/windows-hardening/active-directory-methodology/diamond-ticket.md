# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

Postoje dve uobičajene metode za detekciju upotrebe golden tickets:

- Potražite TGS-REQs koji nemaju odgovarajući AS-REQ.
- Potražite TGT-ove sa neprirodnim vrednostima, npr. Mimikatz podrazumevano trajanje od 10 godina.

A **diamond ticket** se pravi tako što se **menjaju polja legitimnog TGT-a koji je izdao DC**. Ovo se postiže tako što se **zahteva** **TGT**, **dešifruje** on sa krbtgt hešom domena, **izmenjuju** željena polja tiketa, i zatim se **ponovo šifruje**. Ovo **prevazilazi dve prethodno pomenute mane** golden ticket-a jer:

- TGS-REQs će imati prethodni AS-REQ.
- TGT je izdao DC, što znači da će imati sve ispravne detalje iz domain-ove Kerberos politike. Iako se to može tačno falsifikovati u golden ticket-u, to je složenije i podložnije greškama.

### Zahtevi i tok rada

- **Kriptografski materijal**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitiman TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Kontekstualni podaci**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Nabavite TGT za bilo kog kontrolisanog user-a putem AS-REQ (Rubeus `/tgtdeleg` je zgodan jer prisiljava klijenta da izvede Kerberos GSS-API dance bez kredencijala).
2. Dešifrujte vraćeni TGT krbtgt ključem, izmenite PAC atribute (user, groups, logon info, SIDs, device claims, itd.).
3. Ponovo šifrujte/potpišite tiket istim krbtgt ključem i ubacite ga u trenutnu logon sesiju (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalno, ponovite proces nad service ticket-om tako što ćete dostaviti validan TGT blob plus ciljni service key da biste ostali neprimetni na mreži.

### Ažurirane Rubeus tehnike (2024+)

Nedavni rad Huntress-a modernizovao je `diamond` action unutar Rubeus-a tako što je preneo `/ldap` i `/opsec` poboljšanja koja su ranije postojala samo za golden/silver tickets. `/ldap` sada automatski popunjava tačne PAC atribute direktno iz AD (user profile, logon hours, sidHistory, domain policies), dok `/opsec` čini AS-REQ/AS-REP tok neodvojivim od Windows klijenta tako što izvodi dvoetapnu pre-auth sekvencu i forsira AES-only crypto. Ovo dramatično smanjuje očigledne indikatore kao što su prazni device ID-ovi ili nerealni periodi validnosti.
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
- `/ldap` (sa opcionim `/ldapuser` & `/ldappassword`) vrši upite prema AD i SYSVOL kako bi preslikao PAC policy podatke ciljanog korisnika.
- `/opsec` primorava Windows-like AS-REQ retry, nulira noisy flags i koristi AES256.

### Service-ticket recutting

Isto Rubeus refresh dodao je mogućnost primene diamond technique na TGS blobs. Dajući `diamond` a **base64-encoded TGT** (iz `asktgt`, `/tgtdeleg`, ili prethodno forged TGT), **service SPN**, i **service AES key**, možete izraditi realistične service tickets bez diranja KDC-a — efektivno diskretniji silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ovaj radni tok je idealan kada već kontrolišete ključ servisnog naloga (npr. iskopan pomoću `lsadump::lsa /inject` ili `secretsdump.py`) i želite da izradite jednokratni TGS koji savršeno odgovara AD politici, vremenskim okvirima i PAC podacima bez slanja novog AS/TGS saobraćaja.

### OPSEC i napomene o detekciji

- Klasične hunter heuristike (TGS bez AS, trajanja merena decenijom) i dalje važe za golden tickets, ali diamond tickets se uglavnom pokažu kada sadržaj PAC-a ili mapiranje grupa izgleda nemoguće. Popunite svako PAC polje (logon hours, user profile paths, device IDs) tako da automatska poređenja odmah ne označe falsifikat.
- **Ne pretjerujte sa grupama/RID-ovima**. Ako su vam dovoljni samo `512` (Domain Admins) i `519` (Enterprise Admins), stanite tu i uverite se da ciljnom nalogu verovatno pripadaju te grupe i na drugim mestima u AD. Prekomerni `ExtraSids` otkriva prevaru.
- Splunk's Security Content project distribuira attack-range telemetriju za diamond tickets kao i detekcije poput *Windows Domain Admin Impersonation Indicator*, koja korelira neuobičajene sekvence Event ID 4768/4769/4624 i promene PAC grupa. Reprodukcija tog skupa podataka (ili generisanje sopstvenog pomoću komandi iznad) pomaže da se potvrdi SOC pokrivenost za T1558.001, istovremeno dajući konkretnu logiku alarma koju možete ispitati/izbeći.

## Reference

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
