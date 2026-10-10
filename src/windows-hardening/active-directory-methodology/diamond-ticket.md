# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Poput golden ticket-a**, diamond ticket je TGT koji se može koristiti za **pristup bilo kojoj usluzi kao bilo koji korisnik**. Golden ticket se falsifikuje potpuno offline, šifruje se krbtgt hash-om tog domena, a zatim prosleđuje u prijavnu sesiju radi upotrebe. Pošto kontroleri domena ne prate koje su TGT-ove legitimno izdali, rado će prihvatiti TGT-ove šifrovane sopstvenim krbtgt hash-om.<sup>[[1]](#references)</sup>

Postoje dve uobičajene tehnike za otkrivanje upotrebe golden ticket-a:

- Potražite TGS-REQ zahteve bez odgovarajućeg AS-REQ zahteva.
- Potražite TGT-ove sa neobičnim vrednostima, kao što je Mimikatz-ovo podrazumevano trajanje od 10 godina.

**Diamond ticket** se pravi **izmenom polja u legitimnom TGT-u koji je izdao DC**. To se postiže tako što se **zatraži** **TGT**, **dešifruje** pomoću krbtgt hash-a domena, **izmenе** željena polja u ticket-u, a zatim se ticket **ponovo šifruje**. Time se **prevazilaze dva prethodno navedena nedostatka** golden ticket-a, jer:<sup>[[1]](#references)</sup>

- TGS-REQ zahtevima prethodi AS-REQ zahtev.
- TGT je izdao DC, što znači da sadrži sve ispravne detalje iz Kerberos smernica domena. Iako se ti detalji mogu precizno falsifikovati u golden ticket-u, to je složenije i podložnije greškama.

### Zahtevi i tok rada

- **Kriptografski materijal**: krbtgt AES256 ključ (poželjno) ili NTLM hash, potreban za dešifrovanje i ponovno potpisivanje TGT-a.
- **Legitiman TGT blob**: pribavljen pomoću `/tgtdeleg`, `asktgt`, `s4u` ili izvozom ticket-a iz memorije.
- **Kontekstualni podaci**: RID ciljnog korisnika, RID-ovi/SID-ovi grupa i (opciono) PAC atributi dobijeni preko LDAP-a.
- **Service keys** (samo ako planirate da ponovo izdate service ticket-e): AES ključ service SPN-a za koji želite da se predstavljate.

1. Pribavite TGT za bilo kog korisnika pod svojom kontrolom putem AS-REQ zahteva (Rubeus `/tgtdeleg` je praktičan jer primorava klijenta da obavi Kerberos GSS-API razmenu bez akreditiva).
2. Dešifrujte vraćeni TGT pomoću krbtgt ključa i izmenite PAC atribute (korisnik, grupe, podaci za prijavu, SID-ovi, device claims itd.).
3. Ponovo šifrujte/potpišite ticket istim krbtgt ključem i ubacite ga u trenutnu prijavnu sesiju (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opciono, ponovite postupak za service ticket tako što ćete proslediti važeći TGT blob i ciljni service key, kako biste ostali neprimetni na mreži.

### Ažurirani Rubeus tradecraft (2024+)

Nedavni rad Huntress-a modernizovao je akciju `diamond` u Rubeus-u, prenošenjem poboljšanja `/ldap` i `/opsec`, koja su ranije postojala samo za golden/silver ticket-e. `/ldap` sada pribavlja stvarni PAC kontekst postavljanjem LDAP upita **i** montiranjem SYSVOL-a radi izdvajanja atributa naloga/grupa i Kerberos/password smernica (npr. `GptTmpl.inf`), dok `/opsec` usklađuje tok AS-REQ/AS-REP sa Windows-om tako što obavlja dvofaznu preauth razmenu i nameće samo AES i realistične KDCOptions vrednosti. Time se značajno smanjuju očigledni indikatori, kao što su nedostajuća PAC polja ili trajanja koja nisu usklađena sa smernicama.<sup>[[3]](#references)</sup>

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

- `/ldap` (sa opcionim argumentima `/ldapuser` i `/ldappassword`) upućuje upite ka AD-u i SYSVOL-u kako bi preslikao podatke o PAC smernicama ciljnog korisnika.
- `/opsec` forsira ponovni pokušaj AS-REQ-a nalik Windowsu, nulira upadljive zastavice i koristi samo AES256.
- `/tgtdeleg` omogućava da ne dolazite u kontakt sa lozinkom u čistom tekstu niti sa NTLM/AES ključem žrtve, a da pritom i dalje dobijete TGT koji može da se dešifruje.

### Ponovno kreiranje servisne karte

Isto osvežavanje Rubeus-a donelo je mogućnost primene diamond tehnike na TGS blobove. Ako alatu `diamond` prosledite **TGT kodiran u base64 formatu** (iz `asktgt`, `/tgtdeleg` ili prethodno falsifikovanog TGT-a), **SPN servisa** i **AES ključ servisa**, možete da kreirate uverljive servisne karte bez kontakta sa KDC-om — praktično, prikriveniju silver ticket.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

This workflow je idealan kada već kontrolišeš ključ servisnog naloga (npr. izvučen pomoću `lsadump::lsa /inject` ili `secretsdump.py`) i želiš da napraviš jednokratni TGS koji savršeno odgovara AD pravilima, vremenskim okvirima i PAC podacima, bez slanja bilo kakvog novog AS/TGS saobraćaja.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Novija varijanta, ponekad nazvana **sapphire ticket**, kombinuje osnovu „pravog TGT-a“ iz Diamond-a sa **S4U2self+U2U** kako bi ukrala privilegovani PAC i ubacila ga u sopstveni TGT. Umesto da izmišlja dodatne SID-ove, tražiš U2U S4U2self ticket za korisnika sa visokim privilegijama, pri čemu `sname` cilja podnosioca zahteva sa niskim privilegijama; KRB_TGS_REQ sadrži TGT podnosioca zahteva u `additional-tickets` i postavlja `ENC-TKT-IN-SKEY`, što omogućava dešifrovanje service ticket-a ključem tog korisnika. Zatim izdvajaš privilegovani PAC i umećeš ga u svoj legitimni TGT pre ponovnog potpisivanja ključem krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket-ov `ticketer.py` sada podržava sapphire pomoću opcija `-impersonate` + `-request` (razmena uživo sa KDC-om):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` prihvata korisničko ime ili SID; `-request` zahteva važeće korisničke akreditive i materijal ključa krbtgt (AES/NTLM) za dešifrovanje/izmenu tiketa.

Ključni OPSEC pokazatelji pri korišćenju ove varijante:<sup>[[5]](#references)</sup>

- TGS-REQ će sadržati `ENC-TKT-IN-SKEY` i `additional-tickets` (TGT žrtve) — što je retko u uobičajenom saobraćaju.
- `sname` je često jednak korisniku koji podnosi zahtev (samouslužni pristup), a Event ID 4769 prikazuje pozivaoca i cilj kao isti SPN/korisnika.
- Očekujte uparene unose 4768/4769 sa istim klijentskim računarom, ali različitim CNAMES (korisnik sa niskim privilegijama koji podnosi zahtev naspram privilegovanog vlasnika PAC-a).

### OPSEC i napomene o detekciji

- Tradicionalne heuristike za lov na pretnje (TGS bez AS-a, vekovi trajanja od deset godina) i dalje važe za golden tickets, ali diamond tickets se uglavnom otkrivaju kada **sadržaj PAC-a ili mapiranje grupa deluju nemoguće**. Popunite svako polje PAC-a (radno vreme za prijavu, putanje korisničkog profila, ID-jevi uređaja) kako bi automatizovana poređenja odmah otkrila falsifikat.<sup>[[3]](#references)</sup>
- **Nemojte preterivati sa grupama/RID-ovima**. Ako su vam potrebni samo `512` (Domain Admins) i `519` (Enterprise Admins), ograničite se na njih i proverite da li ciljnom nalogu uverljivo pripadaju te grupe na drugim mestima u AD-u. Prevelik broj `ExtraSids` odaje falsifikat.
- Zamene u stilu Sapphire ostavljaju U2U tragove: `ENC-TKT-IN-SKEY` + `additional-tickets`, uz `sname` koji u 4769 upućuje na korisnika (često podnosioca zahteva), kao i naknadnu prijavu 4624 koja potiče od falsifikovanog tiketa. Korelišite ta polja umesto da tražite samo praznine bez AS-REQ-a.<sup>[[5]](#references)</sup>
- Microsoft je počeo da postepeno ukida **izdavanje servisnih tiketa RC4** zbog CVE-2026-20833; nametanje samo AES etypes na KDC-u istovremeno jača domen i usklađuje ga sa diamond/sapphire alatima (/opsec već nameće AES). Uključivanje RC4 u falsifikovane PAC-ove će se sve lakše uočavati.<sup>[[6]](#references)</sup>
- Splunk Security Content project distribuira attack-range telemetriju za diamond tickets, kao i detekcije poput *Windows Domain Admin Impersonation Indicator*, koja koreliše neuobičajene sekvence Event ID 4768/4769/4624 i promene grupa u PAC-u. Ponovna reprodukcija tog skupa podataka (ili generisanje sopstvenog pomoću gornjih komandi) pomaže u proveri pokrivenosti SOC-a za T1558.001, a istovremeno vam pruža konkretnu logiku upozorenja koju možete izbeći.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Dragoceno kamenje: nova generacija Kerberos napada (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Volimo da se igramo tiketima (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Prepravljanje Kerberos Diamond Ticket-a (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – podaci o Diamond Ticket napadu i detekcije (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Senovita strana dragulja: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Nametanje RC4 za servisne tikete za CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
