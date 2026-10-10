# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Poput golden ticket-a**, diamond ticket je TGT koji se može koristiti za **pristup bilo kojoj usluzi kao bilo koji korisnik**. Golden ticket se u potpunosti falsifikuje van mreže, šifruje se kriptografskim sažetkom krbtgt-a tog domena, a zatim se prosleđuje sesiji prijave radi upotrebe. Pošto kontroleri domena ne prate koje su TGT-ove legitimno izdali, bez problema će prihvatati TGT-ove šifrovane sopstvenim kriptografskim sažetkom krbtgt-a.<sup>[[1]](#references)</sup>

Postoje dve uobičajene tehnike za otkrivanje upotrebe golden ticket-a:

- Potražite TGS-REQ zahteve bez odgovarajućeg AS-REQ zahteva.
- Potražite TGT-ove sa besmislenim vrednostima, kao što je Mimikatz-ovo podrazumevano trajanje od 10 godina.

**Diamond ticket** se pravi **izmenom polja legitimnog TGT-a koji je izdao DC**. To se postiže tako što se **zatraži** **TGT**, **dešifruje** kriptografskim sažetkom krbtgt-a domena, **izmene** željena polja tiketa, a zatim **ponovo šifruje**. Time se **prevazilaze dva prethodno navedena nedostatka** golden ticket-a jer:<sup>[[1]](#references)</sup>

- TGS-REQ zahtevima prethodiće AS-REQ zahtev.
- TGT je izdao DC, što znači da će sadržati sve ispravne detalje iz Kerberos smernica domena. Iako se oni mogu tačno falsifikovati u golden ticket-u, to je složenije i podložnije greškama.

### Zahtevi i tok rada

- **Kriptografski materijal**: AES256 ključ krbtgt-a (poželjno) ili NTLM hash, potreban za dešifrovanje i ponovno potpisivanje TGT-a.
- **Legitiman TGT blob**: dobijen pomoću `/tgtdeleg`, `asktgt`, `s4u` ili izvozom tiketa iz memorije.
- **Kontekstualni podaci**: RID ciljnog korisnika, RID-ovi/SID-ovi grupa i (opciono) PAC atributi dobijeni preko LDAP-a.
- **Ključevi usluga** (samo ako planirate da ponovo izdate servisne tikete): AES ključ SPN-a usluge čiji identitet želite da lažno predstavite.

1. Dobavite TGT za bilo kog kontrolisanog korisnika putem AS-REQ zahteva (Rubeus `/tgtdeleg` je zgodan jer primorava klijenta da obavi Kerberos GSS-API razmenu bez akreditiva).
2. Dešifrujte dobijeni TGT ključem krbtgt-a i izmenite PAC atribute (korisnika, grupe, informacije o prijavi, SID-ove, zahteve uređaja itd.).
3. Ponovo šifrujte/potpišite tiket istim ključem krbtgt-a i ubacite ga u trenutnu sesiju prijave (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opciono, ponovite postupak nad servisnim tiketom tako što ćete navesti važeći TGT blob i ključ ciljne usluge kako biste ostali neupadljivi na mreži.

### Izmenjene Rubeus tehnike (2024+)

Nedavni rad kompanije Huntress modernizovao je akciju `diamond` u okviru Rubeus-a tako što je uneo poboljšanja `/ldap` i `/opsec`, koja su ranije postojala samo za golden/silver ticket-e. `/ldap` sada pribavlja stvarni PAC kontekst upitima ka LDAP-u **i** montiranjem SYSVOL-a radi izdvajanja atributa naloga/grupa i Kerberos/smernica za lozinke (npr. `GptTmpl.inf`), dok `/opsec` usklađuje tok AS-REQ/AS-REP zahteva sa Windows-om tako što obavlja dvofaznu razmenu preautentifikacije i nameće isključivo AES i realistične KDCOptions. Time se znatno smanjuju očigledni indikatori, kao što su nedostajuća PAC polja ili trajanja koja nisu usklađena sa smernicama.<sup>[[3]](#references)</sup>

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

- `/ldap` (uz opcione `/ldapuser` i `/ldappassword`) upituje AD i SYSVOL kako bi preslikao podatke o PAC pravilima ciljnog korisnika.
- `/opsec` forsira ponovni AS-REQ pokušaj nalik Windows-u, poništava upadljive zastavice i koristi isključivo AES256.
- `/tgtdeleg` omogućava da ne pristupate lozinki u čistom tekstu niti NTLM/AES ključu žrtve, a da pritom i dalje dobijete TGT koji se može dešifrovati.

### Ponovno sastavljanje servisne karte

Isto osvežavanje Rubeus-a dodalo je mogućnost primene diamond tehnike na TGS blob-ove. Prosleđivanjem `diamond`-u **TGT-a kodiranog u base64** (iz `asktgt`, `/tgtdeleg` ili prethodno falsifikovanog TGT-a), **service SPN-a** i **AES ključa servisa**, možete da izdate realistične servisne karte bez komunikacije sa KDC-om — što je, u suštini, prikrivenija silver ticket tehnika.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Ovaj workflow je idealan kada već kontrolišete ključ servisnog naloga (npr. izvučen pomoću `lsadump::lsa /inject` ili `secretsdump.py`) i želite da napravite jednokratni TGS koji se savršeno poklapa sa AD pravilima, vremenskim okvirima i PAC podacima, bez slanja ikakvog novog AS/TGS saobraćaja.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Noviji pristup, koji se ponekad naziva **sapphire ticket**, kombinuje osnovu Diamond-a, odnosno „pravog TGT-a“, sa **S4U2self+U2U** kako bi se ukrao privilegovani PAC i ubacio u sopstveni TGT. Umesto izmišljanja dodatnih SID-ova, zatražite U2U S4U2self ticket za korisnika sa visokim privilegijama, pri čemu `sname` cilja podnosioca zahteva sa niskim privilegijama; KRB_TGS_REQ sadrži TGT podnosioca zahteva u `additional-tickets` i postavlja `ENC-TKT-IN-SKEY`, što omogućava dešifrovanje service ticket-a ključem tog korisnika. Zatim izdvojite privilegovani PAC i umetnite ga u svoj legitimni TGT pre nego što ga ponovo potpišete krbtgt ključem.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket-ov `ticketer.py` sada uključuje podršku za sapphire putem opcija `-impersonate` + `-request` (razmena sa aktivnim KDC-om):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` prihvata korisničko ime ili SID; `-request` zahteva aktivne korisničke akreditive i krbtgt ključni materijal (AES/NTLM) za dešifrovanje/izmenu ticket-a.

Ključni OPSEC pokazatelji pri korišćenju ove varijante:<sup>[[5]](#references)</sup>

- TGS-REQ će sadržati `ENC-TKT-IN-SKEY` i `additional-tickets` (victim TGT) — retkost u uobičajenom saobraćaju.
- `sname` je često jednak korisniku koji podnosi zahtev (samoposlužni pristup), a Event ID 4769 prikazuje istog pozivaoca i cilj kao SPN/korisnika.
- Očekujte uparene unose 4768/4769 sa istim klijentskim računarom, ali različitim CNAMES (podnosilac zahteva sa niskim privilegijama naspram privilegovanog vlasnika PAC-a).

### OPSEC i napomene o detekciji

- Tradicionalne heuristike za lov (TGS bez AS, životni vek od deset godina) i dalje važe za golden tickets, ali diamond tickets uglavnom dolaze do izražaja kada **sadržaj PAC-a ili mapiranje grupa deluju nemoguće**. Popunite svako PAC polje (radno vreme za prijavu, putanje korisničkih profila, ID-jeve uređaja) kako automatizovana poređenja ne bi odmah označila falsifikat.<sup>[[3]](#references)</sup>
- **Nemojte preterivati s grupama/RID-ovima**. Ako su vam potrebni samo `512` (Domain Admins) i `519` (Enterprise Admins), stanite tu i uverite se da nalog verovatno pripada tim grupama i na drugim mestima u AD-u. Prekomeran broj `ExtraSids` je očigledan znak.
- Zamene u Sapphire stilu ostavljaju U2U tragove: `ENC-TKT-IN-SKEY` + `additional-tickets`, kao i `sname` koji upućuje na korisnika (često podnosioca zahteva) u 4769, uz naknadnu prijavu 4624 koja potiče od falsifikovanog ticket-a. Povežite ta polja umesto da tražite samo praznine bez AS-REQ-a.<sup>[[5]](#references)</sup>
- Microsoft je počeo postepeno da ukida **izdavanje servisnih ticket-a pomoću RC4** zbog CVE-2026-20833; nametanje samo AES etype-ova na KDC-u istovremeno ojačava domen i usklađeno je s diamond/sapphire alatima (/opsec već nameće AES). Upotreba RC4 u falsifikovanim PAC-ovima sve će više upadati u oči.<sup>[[6]](#references)</sup>
- Splunk Security Content projekat distribuira telemetriju iz attack-range okruženja za diamond tickets, kao i detekcije poput *Windows Domain Admin Impersonation Indicator*, koja povezuje neuobičajene nizove događaja Event ID 4768/4769/4624 i promene grupa u PAC-u. Ponovno puštanje tog skupa podataka (ili generisanje sopstvenog pomoću gorenavedenih komandi) pomaže u proveri SOC pokrivenosti za T1558.001, uz pružanje konkretne logike upozorenja koju možete izbeći.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Dragoceno drago kamenje: Nova generacija Kerberos napada (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: Volimo da se igramo ticketima (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Ponovno oblikovanje Kerberos Diamond Ticket-a (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Podaci o napadima Diamond Ticket i detekcije (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Сеновита страна драгуља: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Nametanje RC4 за сервисне ticket-е за CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
