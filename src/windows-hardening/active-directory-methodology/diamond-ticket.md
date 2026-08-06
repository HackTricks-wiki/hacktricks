# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Kao golden ticket**, diamond ticket je TGT koji se može koristiti za **pristup bilo kom servisu kao bilo koji korisnik**. Golden ticket se u potpunosti kreira offline, šifruje se hash-om krbtgt naloga tog domena, a zatim se prosleđuje logon sesiji radi korišćenja. Pošto domain controllers ne prate TGT-ove koje su legitimno izdali, spremno će prihvatiti TGT-ove šifrovane sopstvenim krbtgt hash-om.<sup>[[1]](#references)</sup>

Postoje dve uobičajene tehnike za otkrivanje korišćenja golden tickets:

- Potražite TGS-REQ zahteve koji nemaju odgovarajući AS-REQ.
- Potražite TGT-ove koji imaju besmislene vrednosti, kao što je podrazumevano trajanje od 10 godina u Mimikatz-u.

**Diamond ticket** se kreira **izmenom polja legitimnog TGT-a koji je izdao DC**. To se postiže tako što se **zatraži** **TGT**, **dešifruje** se pomoću krbtgt hash-a domena, **izmene** se željena polja ticketa, a zatim se ticket **ponovo šifruje**. Ovo **prevazilazi dva prethodno navedena nedostatka** golden ticket-a zato što:<sup>[[1]](#references)</sup>

- TGS-REQ zahtevi će imati prethodni AS-REQ.
- TGT je izdao DC, što znači da će sadržati sve ispravne detalje iz Kerberos policy-ja domena. Iako se oni mogu precizno falsifikovati u golden ticket-u, to je složenije i podložnije greškama.

### Zahtevi i workflow

- **Kriptografski materijal**: krbtgt AES256 ključ (preporučeno) ili NTLM hash, potreban za dešifrovanje i ponovno potpisivanje TGT-a.
- **Legitimni TGT blob**: dobija se pomoću `/tgtdeleg`, `asktgt`, `s4u` ili izvozom ticketa iz memorije.
- **Kontekstualni podaci**: RID ciljnog korisnika, grupni RID-ovi/SID-ovi i, opciono, PAC atributi izvedeni iz LDAP-a.
- **Service keys** (samo ako planirate da ponovo kreirate service tickets): AES ključ service SPN-a koji treba impersonate-ovati.

1. Dobavite TGT za bilo kog kontrolisanog korisnika putem AS-REQ-a (`/tgtdeleg` u Rubeus-u je praktičan jer primorava klijenta da obavi Kerberos GSS-API razmenu bez credentials-a).
2. Dešifrujte dobijeni TGT pomoću krbtgt ključa, a zatim izmenite PAC atribute (korisnik, grupe, informacije o logovanju, SID-ovi, device claims itd.).
3. Ponovo šifrujte/potpišite ticket istim krbtgt ključem i ubacite ga u trenutnu logon sesiju (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opciono, ponovite proces nad service ticket-om tako što ćete proslediti validan TGT blob i ključ ciljnog servisa kako biste ostali stealthy na mreži.

### Ažurirani Rubeus tradecraft (2024+)

Nedavni rad kompanije Huntress modernizovao je `diamond` akciju unutar Rubeus-a prenošenjem poboljšanja `/ldap` i `/opsec`, koja su prethodno postojala samo za golden/silver tickets. `/ldap` sada preuzima stvarni PAC kontekst upitom LDAP-a **i** montiranjem SYSVOL-a radi izdvajanja atributa naloga/grupa, kao i Kerberos/password policy-ja (npr. `GptTmpl.inf`), dok `/opsec` usklađuje AS-REQ/AS-REP tok sa Windows-om obavljanjem preauth razmene u dva koraka i nametanjem samo AES-a + realističnih KDCOptions vrednosti. Ovo značajno smanjuje očigledne indikatore, kao što su nedostajuća PAC polja ili trajanja neusklađena sa policy-jem.<sup>[[3]](#references)</sup>
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
- `/ldap` (uz opcione `/ldapuser` i `/ldappassword`) ispituje AD i SYSVOL kako bi preslikao podatke o PAC pravilima ciljnog korisnika.
- `/opsec` forsira Windows-like AS-REQ retry, postavlja bučne flagove na nulu i koristi isključivo AES256.
- `/tgtdeleg` ne zahteva cleartext password niti NTLM/AES key žrtve, a ipak vraća TGT koji se može dešifrovati.

### Ponovno krojenje service-ticket-a

Isto Rubeus osvežavanje dodalo je mogućnost primene diamond tehnike na TGS blobs. Prosleđivanjem alatu `diamond` **base64-encoded TGT-a** (iz `asktgt`, `/tgtdeleg` ili prethodno forged TGT-a), **service SPN-a** i **service AES key-a**, možete kreirati realistične service tickets bez komunikacije sa KDC-om — praktično diskretniji silver ticket.<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ovaj workflow je idealan kada već kontrolišete ključ service account-a (npr. izvučen pomoću `lsadump::lsa /inject` ili `secretsdump.py`) i želite da izdате jednokratni TGS koji se savršeno podudara sa AD policy-jem, vremenskim okvirima i PAC podacima, bez slanja novog AS/TGS saobraćaja.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Noviji pristup, koji se ponekad naziva **sapphire ticket**, kombinuje Diamond-ovu osnovu „real TGT“ sa **S4U2self+U2U** kako bi se ukrao privilegovani PAC i ubacio u sopstveni TGT. Umesto izmišljanja dodatnih SID-ova, šaljete zahtev za U2U S4U2self ticket za korisnika sa visokim privilegijama, pri čemu `sname` cilja requester-a sa niskim privilegijama; KRB_TGS_REQ prenosi TGT requester-a u `additional-tickets` i postavlja `ENC-TKT-IN-SKEY`, što omogućava dešifrovanje service ticket-a pomoću ključa tog korisnika. Zatim izvlačite privilegovani PAC i ubacujete ga u svoj legitimni TGT pre ponovnog potpisivanja pomoću krbtgt ključa.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket-ov `ticketer.py` sada podržava sapphire putem opcija `-impersonate` + `-request` (live KDC exchange):<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` prihvata username ili SID; `-request` zahteva aktivne korisničke credse, kao i ključni materijal za krbtgt (AES/NTLM) radi dešifrovanja/izmene ticket-a.

Ključni OPSEC indikatori prilikom korišćenja ove varijante:<sup>[[5]](#references)</sup>

- TGS-REQ će sadržati `ENC-TKT-IN-SKEY` i `additional-tickets` (victim TGT) — što je retko u normalnom saobraćaju.
- `sname` je često jednak korisniku koji šalje zahtev (self-service access), a Event ID 4769 prikazuje caller i target kao isti SPN/user.
- Očekujte uparene 4768/4769 zapise sa istim klijentskim računarom, ali različitim CNAME vrednostima (low-priv requester naspram privilegovanog PAC owner-a).

### OPSEC i napomene o detekciji

- Tradicionalne hunter heuristike (TGS bez AS-a, životni vekovi od više decenija) i dalje važe za golden tickets, ali diamond tickets uglavnom postaju uočljivi kada **PAC sadržaj ili mapiranje grupa deluju nemoguće**. Popunite svako PAC polje (sati prijavljivanja, putanje korisničkih profila, ID-jevi uređaja) kako automatizovana poređenja ne bi odmah označila forgery.<sup>[[3]](#references)</sup>
- **Nemojte preterivati sa grupama/RID-ovima**. Ako su vam potrebni samo `512` (Domain Admins) i `519` (Enterprise Admins), zaustavite se tu i proverite da ciljni account na drugim mestima u AD-u verovatno pripada tim grupama. Prekomeran broj `ExtraSids` predstavlja očigledan indikator.
- Sapphire-style swaps ostavljaju U2U fingerprint-e: `ENC-TKT-IN-SKEY` + `additional-tickets`, kao i `sname` koji u 4769 pokazuje na user-a (često requestera), uz naknadni 4624 logon zasnovan na forged ticket-u. Korelišite ta polja umesto da tražite samo praznine bez AS-REQ-a.<sup>[[5]](#references)</sup>
- Microsoft je počeo postepeno da ukida **RC4 izdavanje service ticket-a** zbog CVE-2026-20833; nametanje AES-only etypes na KDC-u istovremeno ojačava domain i usklađuje ga sa diamond/sapphire tooling-om (/opsec već forsira AES). Mešanje RC4 u forged PAC-ove će sve više biti uočljivo.<sup>[[6]](#references)</sup>
- Splunk Security Content projekat distribuira attack-range telemetriju za diamond tickets, zajedno sa detekcijama kao što je *Windows Domain Admin Impersonation Indicator*, koja koreliše neuobičajene sekvence Event ID 4768/4769/4624 i promene PAC grupa. Reprodukovanje tog dataset-a (ili generisanje sopstvenog pomoću navedenih komandi) pomaže u proveri SOC coverage-a za T1558.001, uz pružanje konkretne alert logike koju treba zaobići.<sup>[[4]](#references)</sup>

## Reference

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
