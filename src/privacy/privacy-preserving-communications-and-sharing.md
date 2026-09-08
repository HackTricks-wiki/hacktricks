# Komunikacije i deljenje uz očuvanje privatnosti

{{#include ../banners/hacktricks-training.md}}

End-to-end encryption štiti sadržaj. Ona automatski ne skriva nalog, broj telefona, graf kontakata, IP adresu, push token, preview notifikacija, vreme, metapodatke datoteka niti ponašanje primaoca. Izaberite alat prema metapodacima koje uklanja i posmatračima koje uvodi.

## Poređenje modela komunikacije

| Alat/model | Korisno svojstvo | Preostali posmatrači i ograničenja |
|---|---|---|
| Signal | Zreo E2EE; usernames mogu započeti kontakt bez deljenja broja; sealed sender smanjuje servisne metapodatke | Broj telefona je potreban za registraciju; servis, push provider, kontakti i endpoints zadržavaju određena opažanja |
| SimpleX | Nema globalni user identifier; queues po kontaktu; opcioni Tor transport | Relay timing/transport, push service, invitations i endpoints; noviji/manji ekosistem |
| Briar | Direktna sinhronizacija; Tor online; Bluetooth/Wi-Fi offline; nema centralnog message store-a | Kontakti i endpoints; lokalni radio-posmatrači; fokusiran na Android; obe strane moraju biti dostupne ili se mora koristiti Mailbox |
| OnionShare | Direktan file/receive/chat/site preko privremene onion usluge; nema storage provider-a | Računar pošiljaoca je servis; bearer link omogućava pristup; timing i endpoints ostaju |
| `age` encrypted file | Jednostavna enkripcija ključem primaoca nezavisna od transporta | Transport vidi pošiljaoca/primaoca/timing/veličinu; filenames/archive metapodaci i endpoints ostaju |
| Običan email + TLS | Enkripcija kanala između servera | Oba mail provider-a obično mogu čitati sadržaj i zadržavaju routing/account metapodatke |

## Signal: privatni kontakt bez otkrivanja broja

Signal usernames mogu započeti chat bez otkrivanja broja telefona korisnika novom kontaktu, ali broj telefona i dalje ostaje potreban za registraciju.<sup>[[1]](#references)</sup> Sealed sender je postepena zaštita metapodataka, a ne zaštita od svake IP/timing korelacije.<sup>[[2]](#references)</sup>

### Radni tok

1. Instalirajte Signal iz zvanične app store/projektne distribucije i prvo ažurirajte OS.
2. Registrujte se brojem koji imate zakonsko pravo da koristite. Nemojte koristiti iznajmljene SMS aktivacije, broj druge osobe niti provider nalog pribavljen lažnim identitetom.
3. U **Settings → Privacy → Phone Number** podesite ko može videti broj i ko može pronaći nalog pomoću broja, u skladu sa threat modelom.
4. Kreirajte username za pronalaženje novih kontakata. Podelite njegov tačan link/QR preko već autentifikovanog kanala; usernames se mogu menjati i nisu ime profila.
5. Onemogućite upload/permissions za kontakte ako pogodnost nije vredna povezivanja i ručno dodajte kontakte tamo gde platforma to podržava.
6. Otvorite detalje kontakta i uporedite safety number/QR preko drugog kanala ili uživo pre slanja osetljivog sadržaja.
7. Proverite linked devices, registration lock/PIN, notification previews, screen security, call relaying, podrazumevane disappearing-message postavke i ponašanje backup-a.
8. Pošaljite neosetljivu testnu poruku i uputite poziv. Na obe strane proverite tragove na lock-screen-u, desktop-u, wearable uređajima i cloud-notification sistemu.
9. Promenu safety number-a ili neočekivani linked device tretirajte kao događaj za istragu, a ne kao upozorenje koje treba automatski odbaciti.

Nemojte mešati pseudonimnu profilnu fotografiju, bio, članstvo u grupama ili raspored sa identifikujućim Signal kontekstom.

## SimpleX: connections po kontaktu bez globalnog identifikatora

SimpleX usmerava poruke kroz unidirectional queues i ne dodeljuje network-wide user identifier. Njegova sopstvena politika i dalje dokumentuje transport sessions, privremene server podatke, kompromise push-notification sistema i odgovornost endpoint-a.<sup>[[3]](#references)</sup>

### Radni tok

1. Preuzmite održavan client sa zvaničnog projekta/store-a i proverite izdavača. Koristite namenski OS/app profil kada identiteti ne smeju da se mešaju.
2. Kreirajte **lokalni** profil sa display name-om i slikom specifičnim za kontekst. Brisanje aplikacije bez backup-a može dovesti do gubitka profila i connections.
3. Pri prvom pokretanju namerno izaberite notification mode. Instant mobile push može izložiti dodatne metapodatke Apple/Google infrastrukturi.
4. Kreirajte jednokratni invitation link za jedan kontakt. Prenesite ga preko autentifikovanog kanala; svako ko dobije aktivnu invitation može pokušati da je iskoristi.
5. Nakon povezivanja otvorite detalje kontakta i uporedite security code uživo ili preko nezavisnog verifikovanog kanala.<sup>[[4]](#references)</sup>
6. Koristite incognito per-group profil tamo gde je podržan, umesto recikliranja istog profila kroz nepovezane grupe.
7. Konfigurišite client-ov podržani Tor transport ako lokalna mreža/server ne treba da vidi direktni IP. Potvrdite konekciju nakon promene; nemojte forsirati nepodržani system proxy.
8. Proverite delivery receipts, link previews, calls, automatic downloads i database export/backup. Svaka od ovih funkcija menja metapodatke ili izloženost endpoint-a.
9. Testirajte recovery na rezervnom izolovanom uređaju bez pokretanja dupliciranog live profile state-a; projekat upozorava da istovremene kopije mogu poremetiti conversations.

Globalni identifier ne sprečava kontakt da identifikuje korisnika kroz sadržaj, ponovno korišćenje profila, isporuku invitation-a, timing ili social graph.

## Briar: direktno slanje poruka otporno na prekide

Briar direktno sinhronizuje uređaje, preko Tor-a kada su online i preko Bluetooth/Wi-Fi-ja tokom lokalnih prekida. Zvanični threat model pretpostavlja samo ograničeno protivničko praćenje short-range radio komunikacije, pa lokalna wireless komunikacija nije nevidljiva.<sup>[[5]](#references)</sup>

### Radni tok

1. Instalirajte iz zvanične Briar distribucije i proverite izvor paketa. Koristite podržani Android uređaj sa aktuelnim security update-ima.
2. Kreirajte lokalni nalog sa jedinstvenim context nickname-om i snažnom lozinkom. Ne postoji password-reset putanja; proverite da se unlock secret može obnoviti.
3. Dodajte kontakte licem u lice skeniranjem QR kodova jedni drugih kada je moguće. Ovo autentifikuje kontakt i izbegava slanje linka kroz korelabilan kanal.
4. U connectivity settings uključite samo potrebne transport-e: Tor/Internet, Wi-Fi i/ili Bluetooth. Isključite lokalne radio uređaje kada nisu potrebni.
5. Za asinhronu isporuku procenite Briar Mailbox na namenskom uređaju koji je stalno napajan; inventarišite ga i fizički zaštitite kao message server.
6. Pošaljite bezopasnu testnu poruku dok je Internet dostupan, a zatim testirajte planirani outage path sa onemogućenim Internetom na lokaciji za koju vlasnik daje ovlašćenje.
7. Proverite Android backups, notification previews, screenshots i exportovan sadržaj. Lokalna encrypted storage je izložena kada je endpoint otključan ili kompromitovan.
8. Uklonite izgubljene kontakte/uređaje i ugasite ceo kontekst ako su fizičko posedovanje ili password naloga kompromitovani.

## OnionShare: direktan privremeni transfer

OnionShare pokreće onion servis na računaru pošiljaoca/primaoca; datoteke se ne upload-uju kod storage provider-a, a saobraćaj je end-to-end enkriptovan unutar Tor-a.<sup>[[6]](#references)</sup> Kompletan onion URL je bearer capability i mora biti zaštićen.

### GUI file-sharing workflow

1. Instalirajte OnionShare iz njegove zvanične potpisane distribucije i Tor Browser na strani primaoca.
2. Stavite **sanitized copies** datoteka u namenski staging directory. Nemojte usmeravati OnionShare na lični home directory.
3. Otvorite **Share Files**, dodajte samo staged files, ostavite uključenu zaštitu private key/access i zadržite uključenu opciju **Stop sharing after files have been sent** za jednog primaoca.
4. Pokrenite sharing i pošaljite kompletan onion URL preko već autentifikovanog E2EE kanala. Nemojte ga nalepiti u email, issue trackers ili javne chatove.
5. Primalac otvara URL u Tor Browser-u, sa pošiljaocem proverava očekivane filenames/size i preuzima datoteke.
6. Obe strane upoređuju prethodno dogovoreni ili zasebno dostavljeni SHA-256 digest radi integriteta kada je sama datoteka security boundary.
7. Potvrdite da je OnionShare zaustavljen nakon preuzimanja; u suprotnom ga ručno zaustavite i zatvorite aplikaciju.
8. Obrišite staged copy u skladu sa retention policy-jem i proverite OnionShare history/log settings zbog nenamernog otkrivanja filename-a.

### CLI workflow

Zvanični CLI prihvata datoteke kao positional arguments i zaustavlja se nakon podrazumevanog jednog završenog share-a. Na host-u sa instaliranim zvaničnim CLI/Tor-om:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Bezbedno dostavite dobijeni puni URL. Nemojte dodavati `--public`, `--no-autostop-sharing`, opširno beleženje imena datoteka ili persistence, osim ako model pretnji izričito zahteva tako nastalu izloženost.<sup>[[7]](#references)</sup>

Primljene dokumente tretirajte kao zlonamerne. Otvarajte ih u privremenom VM-u/Dangerzone-style renderer-u, a ne na hostu koji sadrži identitet.

## Nezavisno šifrovanje datoteke pomoću `age`

Šifrovanje nezavisno od transporta korisno je kada storage/email provajder može da vidi objekat. Ono ne skriva pošiljaoca, primaoca, veličinu, vreme slanja niti ime datoteke, osim ako se ti podaci zasebno ne obrade.

### Podešavanje primaoca
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Potvrdite autentičnost javnog stringa primaoca putem drugog kanala. Pošiljalac zatim pokreće:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Primalac dešifruje u novu putanju:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
Zvanični CLI upozorava da `-o` prepisuje postojeći izlaz, zato koristite novi direktorijum i proverite digest/sadržaj pre nego što ga premestite.<sup>[[8]](#references)</sup> Nikada ne šaljite datoteku identiteta zajedno sa ciphertextom.

## Reproduktivni pipeline za sanitizaciju datoteka

Uklanjanje metapodataka zavisi od formata. Sačuvajte šifrovani original kada su autentičnost, forenzika ili lanac čuvanja važni; radite na kopiji.

### JPEG primer
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
Ovo prati bezbednije smernice ExifTool-a za JPEG: slepo uklanjanje svake oznake može ukloniti i informacije o boji.<sup>[[9]](#references)</sup> Zatim vizuelno pregledajte piksele da biste uočili lica, odraze, ekrane, orijentire i jedinstvene obrasce oštećenja/šuma.

### Office/PDF workflow

1. Čuvajte izvornik koji je moguće uređivati, šifrovan i van mreže u odnosu na kontekst objavljivanja.
2. U aplikaciji za izradu uklonite komentare, praćene izmene, skrivene slajdove/listove, ugrađene datoteke, lične template-e i svojstva dokumenta.
3. Izvezite novi PDF iz posebnog čistog profila; nemojte ga „štampati“ na cloud printer.
4. Pregledajte ga pomoću alata koji razumeju format, kao i privremenog vizuelnog renderer-a:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Pretražite renderovani izlaz u potrazi za imenima, putanjama, email adresama i tekstom revizije. Rasterizacija može ukloniti aktivne strukture, ali narušava pristupačnost/pretragu i ne uklanja vidljivi sadržaj niti stil pisanja.
6. Izračunajte hash konačnog artefakta i prenesite **samo** tu kopiju kroz publication compartment.

## Privacy Pass: anonimna autorizacija za dizajnere servisa

Privacy Pass razdvaja **izdavanje** tokena od njihove **iskorišćenosti**. Origin može saznati da klijent poseduje token odobren od issuer-a, a da ne sazna konkretnu interakciju klijenta prilikom izdavanja. Ponovna upotreba tokena, jedinstveni metadata podaci, vremensko podudaranje ili koluzija mogu ponovo uvesti mogućnost povezivanja.<sup>[[10]](#references)</sup>

Bezbedan obrazac implementacije:

1. Definišite tvrdnju koju token dokazuje (na primer, podobnost za rate-limit), a ne skrivenu globalnu identifikaciju.
2. Koristite standardizovanu arhitekturu i protokole za izdavanje; nemojte implementirati blind-signature cryptography od nule.
3. Razdvojite administraciju issuer/attester-a i origin-a kada to zahtevano svojstvo nalaže.
4. Svedite javne/private token metadata podatke na minimum i obezbedite da anonymity set-ovi budu dovoljno veliki.
5. Izdajte batch-eve pre upotrebe, kada je to podržano, kako se vreme izdavanja ne bi trivijalno poklapalo sa vremenom iskorišćenosti.
6. Iskoristite svaki token jednom, validirajte challenge vezan za origin i obrišite stanje tokena kojima je istekao rok.
7. Sprečite da cookies, IP logging i application accounts neprimetno ponište svojstvo privatnosti tokena.
8. Testirajte da li issuer i origin logovi mogu povezati kontrolisani događaj izdavanja i iskorišćenosti pomoću vremenskog podudaranja, metadata podataka ili jedinstvenih grešaka.

Privacy Pass je funkcija aplikacije, a ne nešto što korisnik može naknadno dodati proizvoljnom nalogu.

## Communications verification checklist

- [ ] Kontakt/pozivnica/ključ je nezavisno autentifikovan.
- [ ] Izloženost phone number-a, username-a, profila, grupe i upload-a kontakata je razjašnjena.
- [ ] Direktni IP, relay, Tor, push-provider i local-radio posmatrači su navedeni.
- [ ] Notification previews, wearables, povezani desktop računari i backups su testirani.
- [ ] Fajlovi su sanitizovani, po potrebi enkriptovani i otvoreni u disposable context-u.
- [ ] Recovery funkcioniše bez povezivanja nepovezanih identiteta.
- [ ] Za logove, istoriju i privremene share servise postoji pravilo za gašenje/čuvanje.

## References

- [1] [Signal — Privatnost phone number-a i usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Privacy Policy i uslovi korišćenja](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Vodič za privatnost i bezbednost](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Kako funkcioniše](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Dizajn bezbednosti](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Napredna upotreba i CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — zvanični CLI i upotreba](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — Bezbedno uklanjanje metadata podataka](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy Pass arhitektura](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}
