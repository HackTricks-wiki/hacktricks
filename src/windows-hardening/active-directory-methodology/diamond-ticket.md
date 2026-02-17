# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, diamond ticket je TGT koji se može koristiti za **pristup bilo kojoj usluzi kao bilo koji korisnik**. A golden ticket se potpuno forguje offline, šifruje sa krbtgt hešem tog domena, i potom ubacuje u sesiju prijavljivanja za upotrebu. Pošto kontroleri domena ne prate TGT-ove koje su legitimno izdale, rado će prihvatiti TGT-ove koji su šifrovani njegovim sopstvenim krbtgt hešem.

Postoje dve uobičajene tehnike za otkrivanje upotrebe golden tickets:

- Tražite TGS-REQs koji nemaju odgovarajući AS-REQ.
- Tražite TGTs koji imaju besmislene vrednosti, kao što je Mimikatz-ov podrazumevani rok trajanja od 10 godina.

A diamond ticket se pravi tako što se modifikuju polja legitimnog TGT-a koji je izdao DC. Ovo se postiže tako što se zatraži TGT, dešifruje sa krbtgt hešem domena, izmeni željena polja tiketa, a zatim ponovo šifruje/potpiše. Ovo prevazilazi dve prethodno pomenute mane golden ticket-a zato što:

- TGS-REQs će imati prethodni AS-REQ.
- TGT je izdao DC što znači da će imati sve tačne detalje iz Kerberos politike domena. Iako se ovi podaci mogu precizno forgovati u golden ticket-u, to je složenije i podložno greškama.

### Zahtevi i tok rada

- **Cryptographic material**: krbtgt AES256 ključ (poželjno) ili NTLM hash za dekriptovanje i ponovni potpis TGT-a.
- **Legitimate TGT blob**: dobijen pomoću `/tgtdeleg`, `asktgt`, `s4u`, ili izvozom tiketa iz memorije.
- **Context data**: ciljni korisnički RID, group RIDs/SIDs, i (opciono) LDAP-izvedeni PAC atributi.
- **Service keys** (samo ako planirate ponovo da izrežete service tickets): AES ključ servisa SPN-a koji će biti impersoniran.

1. Nabavite TGT za bilo kog kontrolisanog korisnika putem AS-REQ (Rubeus `/tgtdeleg` je zgodan jer naterava klijenta da izvrši Kerberos GSS-API razmenu bez kredencijala).
2. Dešifrujte vraćeni TGT krbtgt ključem, ispravite PAC atribute (user, groups, logon info, SIDs, device claims, itd.).
3. Ponovo šifrujte/potpišite tiket istim krbtgt ključem i injektujte ga u trenutnu sesiju prijavljivanja (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalno, ponovite proces nad service ticket-om tako što ćete obezbediti validan TGT blob plus ciljni service ključ kako biste ostali stealth na mreži.

### Ažurirane Rubeus taktike (2024+)

Nedavni rad Huntress-a modernizovao je `diamond` akciju unutar Rubeus-a portovanjem `/ldap` i `/opsec` poboljšanja koja su ranije postojala samo za golden/silver tickets. `/ldap` sada automatski popunjava tačne PAC atribute direktno iz AD (user profile, logon hours, sidHistory, domain policies), dok `/opsec` čini AS-REQ/AS-REP tok neprepoznatljivim od Windows klijenta izvršavanjem dvo-stepene pre-auth sekvence i forsiranjem AES-only crypto. Ovo dramatično smanjuje očigledne indikatore kao što su prazni device ID-jevi ili nerealni vremenski prozori validnosti.
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
- `/ldap` (sa opcionim `/ldapuser` & `/ldappassword`) upituje AD i SYSVOL da preslika PAC policy podatke ciljanog korisnika.
- `/opsec` forsira Windows-like AS-REQ retry, resetuje noisy flags i pridržava se AES256.
- `/tgtdeleg` drži tvoje ruke podalje od cleartext password ili NTLM/AES ključa žrtve, dok i dalje vraća decryptable TGT.

### Ponovno kreiranje servisnih tiketa

Isti Rubeus refresh je dodao mogućnost primene diamond technique na TGS blobs. Davanjem `diamond` **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), **service SPN**, i **service AES key**, možete napraviti realistične service tickets bez diranja KDC—efektivno prikriveniji silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ovaj tok rada je idealan kada već kontrolišete ključ servisnog naloga (npr. dumped with `lsadump::lsa /inject` ili `secretsdump.py`) i želite da isečete jednokratni TGS koji savršeno odgovara AD policy, timelines i PAC podacima bez slanja novog AS/TGS saobraćaja.

### Sapphire-style PAC swaps (2025)

A newer twist sometimes called a **sapphire ticket** kombinuje Diamond-ovu bazu "real TGT" sa **S4U2self+U2U** da ukrade privilegovani PAC i ubaci ga u sopstveni TGT. Umesto izmišljanja dodatnih SIDs, tražite U2U S4U2self ticket za korisnika sa visokim privilegijama, ekstrahujete taj PAC i ušijete ga u vaš legitimni TGT pre ponovnog potpisivanja sa krbtgt key. Pošto U2U postavlja `ENC-TKT-IN-SKEY`, rezultujući wire flow izgleda kao legitimna razmena korisnik-prema-korisniku.

Minimalna reprodukcija na Linux strani sa Impacket's patched `ticketer.py` (adds sapphire support):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Ključni OPSEC indikatori pri korišćenju ove varijante:

- TGS-REQ će nositi `ENC-TKT-IN-SKEY` i `additional-tickets` (žrtvin TGT) — retko u normalnom saobraćaju.
- `sname` često odgovara korisniku koji zahteva (pristup sopstvenom nalogu) i Event ID 4769 prikazuje pozivaoca i cilj kao isti SPN/korisnik.
- Očekujte uparene unose 4768/4769 sa istim klijentskim računarom ali različitim CNAMES (zahtevač niskih privilegija nasuprot vlasnika privilegovanog PAC-a).

### OPSEC i napomene za detekciju

- Tradicionalne hunter heuristike (TGS without AS, decade-long lifetimes) i dalje važe za golden tickets, ali diamond tickets se uglavnom pojavljuju kada **sadržaj PAC-a ili mapiranje grupa deluje nemoguće**. Popunite svako polje PAC-a (logon hours, user profile paths, device IDs) tako da automatska poređenja ne označe odmah falsifikat.
- **Ne prekomerno dodeljujte grupe/RID-ove**. Ako su vam potrebni samo `512` (Domain Admins) i `519` (Enterprise Admins), stanite tu i postarajte se da ciljni nalog verodostojno pripada tim grupama negde u AD. Pretjerano `ExtraSids` odaje.
- Sapphire-style zamene ostavljaju U2U otiske: `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` u 4769, kao i naknadni 4624 logon koji potiče iz falsifikovanog ticketa. Korelacijom povežite ta polja umesto da tražite samo praznine bez AS-REQ.
- Microsoft je počeo fazno ukidanje **RC4 service ticket issuance** zbog CVE-2026-20833; forsiranje isključivo AES etypes na KDC-u dodatno ojačava domen i usklađuje se sa diamond/sapphire tooling (/opsec već forsira AES). Umešavanje RC4 u falsifikovane PAC-e će se sve više isticati.
- Projekat Splunk Security Content distribuira attack-range telemetriju za diamond tickets i detekcije poput *Windows Domain Admin Impersonation Indicator*, koja koreliše neuobičajene sekvence Event ID 4768/4769/4624 i promene PAC grupa. Reprodukovanje tog dataset-a (ili generisanje sopstvenog pomoću komandi iznad) pomaže da se validira SOC pokrivenost za T1558.001 i daje vam konkretnu logiku alarma koju treba zaobići.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
