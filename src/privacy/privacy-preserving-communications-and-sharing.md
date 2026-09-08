# Komunikacije i deljenje uz očuvanje privatnosti

End-to-end encryption štiti sadržaj. Ne skriva automatski nalog, broj telefona, graf kontakata, IP adresu, push token, pregled obaveštenja, vreme, metadata datoteka niti ponašanje primaoca. Izaberite alat prema metadata podacima koje uklanja i posmatračima koje uvodi.

## Poređenje modela komunikacije

| Alat/model | Korisna osobina | Preostali posmatrači i ograničenja |
|---|---|---|
| Signal | Zreo E2EE; usernames mogu započeti kontakt bez deljenja broja; sealed sender smanjuje service metadata | Broj telefona je potreban za registraciju; service, push provider, kontakti i endpoints zadržavaju određena opažanja |
| SimpleX | Nema globalni user identifier; queues po kontaktu; opcioni Tor transport | Relay timing/transport, push service, invitations i endpoints; noviji/manji ekosistem |
| Briar | Direktna sinhronizacija; Tor online; Bluetooth/Wi-Fi offline; nema centralni message store | Kontakti i endpoints; lokalni radio posmatrači; fokusiran na Android; obe strane moraju biti dostupne ili koristiti Mailbox |
| OnionShare | Direktan file/receive/chat/site preko privremenog onion service-a; nema storage provider | Računar pošiljaoca je service; bearer link saznaje pristup; timing i endpoints ostaju |
| `age` encrypted file | Jednostavno šifrovanje recipient key-em, nezavisno od transporta | Transport vidi pošiljaoca/primaoca/timing/veličinu; filenames/archive metadata i endpoints ostaju |
| Običan email + TLS | Šifrovanje kanala između servera | Oba mail provider-a obično mogu čitati sadržaj i zadržavati routing/account metadata |

## Signal: privatni kontakt bez otkrivanja broja

Signal usernames mogu započeti chat bez otkrivanja korisnikovog broja telefona novom kontaktu, ali je broj telefona i dalje potreban za registraciju.<sup>[[1]](#references)</sup> Sealed sender je postepena zaštita metadata podataka, a ne zaštita od svake korelacije IP adrese i vremena.<sup>[[2]](#references)</sup>

### Workflow

1. Instalirajte Signal iz zvanične app store/project lokacije i najpre ažurirajte OS.
2. Registrujte se brojem koji imate zakonsko pravo da koristite. Nemojte koristiti iznajmljene SMS activations, broj druge osobe niti provider account pribavljen lažnim identitetom.
3. U **Settings → Privacy → Phone Number** podesite ko može videti broj i ko može pronaći nalog prema broju, u skladu sa threat model-om.
4. Kreirajte username za otkrivanje novih kontakata. Njegov tačan link/QR podelite preko već authenticated channel-a; usernames mogu da se promene i nisu profile name.
5. Isključite upload/permissions za kontakte ako pogodnost nije vredna povezivanja i dodajte kontakte ručno tamo gde platforma to podržava.
6. Otvorite detalje kontakta i uporedite safety number/QR preko drugog channel-a ili uživo pre slanja osetljivog sadržaja.
7. Pregledajte linked devices, registration lock/PIN, notification previews, screen security, call relaying, podrazumevana podešavanja disappearing messages i ponašanje backup-a.
8. Pošaljite testnu poruku i pozovite kontakt bez osetljivog sadržaja. Pregledajte lock-screen, desktop, wearable i cloud-notification tragove na obe strane.
9. Promenjeni safety number ili neočekivani linked device tretirajte kao događaj za istragu, a ne kao upozorenje koje treba automatski odbaciti.

Nemojte mešati pseudonimnu profilnu fotografiju, bio, članstvo u grupama ili raspored sa identifikujućim Signal context-om.

## SimpleX: connections po kontaktu bez globalnog identifikatora

SimpleX usmerava poruke kroz unidirectional queues i ne dodeljuje network-wide user identifier. Njegova sopstvena policy i dalje dokumentuje transport sessions, privremene server podatke, kompromise push notifications i odgovornost endpoint-a.<sup>[[3]](#references)</sup>

### Workflow

1. Preuzmite održavan client sa zvaničnog projekta/store lokacije i proverite publisher-a. Koristite namenski OS/app profile kada identiteti ne smeju da se mešaju.
2. Kreirajte **local** profile sa display name-om i slikom specifičnim za context. Brisanje aplikacije bez backup-a može dovesti do gubitka profile-a i connections.
3. Pri prvom pokretanju pažljivo izaberite notification mode. Instant mobile push može otkriti dodatne metadata podatke Apple/Google infrastructure.
4. Kreirajte one-time invitation link za jedan kontakt. Prenesite ga preko authenticated channel-a; svako ko dođe do aktivne invitation može pokušati da je iskoristi.
5. Nakon povezivanja otvorite detalje kontakta i uporedite security code uživo ili preko nezavisnog verified channel-a.<sup>[[4]](#references)</sup>
6. Koristite incognito per-group profile tamo gde je podržan, umesto recikliranja istog profile-a kroz nepovezane grupe.
7. Konfigurišite client-ov podržani Tor transport ako lokalna mreža/server ne treba da vidi direktan IP. Potvrdite konekciju nakon promene; nemojte forsirati nepodržani system proxy.
8. Pregledajte delivery receipts, link previews, calls, automatic downloads i database export/backup. Svaka od ovih opcija menja metadata ili izloženost endpoint-a.
9. Testirajte recovery na rezervnom izolovanom uređaju bez pokretanja dupliciranog live profile state-a; projekat upozorava da concurrent copies mogu poremetiti conversations.

Nepostojanje globalnog identifikatora ne sprečava kontakt da identifikuje korisnika kroz sadržaj, ponovno korišćenje profile-a, dostavljanje invitation, timing ili social graph.

## Briar: direktno slanje poruka otporno na prekide

Briar direktno sinhronizuje uređaje, preko Tor-a kada su online i preko Bluetooth/Wi-Fi-ja tokom lokalnih prekida. Zvanični threat model pretpostavlja samo ograničeno adversarial monitoring kratkodometnog radija, pa lokalni wireless nije nevidljiv.<sup>[[5]](#references)</sup>

### Workflow

1. Instalirajte iz zvanične Briar distribucije i proverite izvor package-a. Koristite podržani Android uređaj sa aktuelnim security updates.
2. Kreirajte lokalni account sa jedinstvenim context nickname-om i snažnom lozinkom. Ne postoji password-reset path; proverite da li je unlock secret moguće povratiti.
3. Dodajte kontakte licem u lice skeniranjem QR kodova jedni drugima, kada je moguće. Ovo authenticates kontakt i izbegava slanje linka kroz channel koji može biti korelisan.
4. U connectivity settings uključite samo potrebne transport-e: Tor/Internet, Wi-Fi i/ili Bluetooth. Isključite lokalne radio uređaje kada nisu potrebni.
5. Za asinhrono dostavljanje procenite Briar Mailbox na namenskom uređaju koji je stalno napajan; popišite ga i fizički zaštitite kao message server.
6. Pošaljite bezopasan test dok je Internet dostupan, a zatim testirajte planirani outage path sa isključenim Internetom na lokaciji za koju imate ovlašćenje vlasnika.
7. Pregledajte Android backups, notification previews, screenshots i exported content. Lokalno encrypted storage je izloženo kada je endpoint unlocked/compromised.
8. Uklonite izgubljene kontakte/uređaje i ugasite ceo context ako su fizičko posedovanje ili account password kompromitovani.

## OnionShare: direktan privremeni transfer

OnionShare pokreće onion service na računaru pošiljaoca/primaoca; datoteke se ne upload-uju kod storage provider-a, a saobraćaj je end-to-end encrypted unutar Tor-a.<sup>[[6]](#references)</sup> Kompletan onion URL je bearer capability i mora biti zaštićen.

### GUI file-sharing workflow

1. Instalirajte OnionShare iz njegove zvanične signed distribucije i Tor Browser na strani primaoca.
2. Stavite **sanitized copies** datoteka u namenski staging directory. Nemojte usmeravati OnionShare na lični home directory.
3. Otvorite **Share Files**, dodajte samo staged files, ostavite uključenu private key/access zaštitu i za jednog primaoca ostavite uključenu opciju **Stop sharing after files have been sent**.
4. Pokrenite deljenje i pošaljite kompletan onion URL preko već authenticated E2EE channel-a. Nemojte ga lepiti u email, issue trackere ili javne chat-ove.
5. Primalac otvara URL u Tor Browser-u, proverava očekivane filenames/veličinu sa pošiljaocem i preuzima datoteke.
6. Obe strane upoređuju unapred dogovoreni ili odvojeno dostavljeni SHA-256 digest radi integriteta kada je sama datoteka security boundary.
7. Potvrdite da je OnionShare zaustavljen nakon preuzimanja; u suprotnom ga ručno zaustavite i zatvorite aplikaciju.
8. Obrišite staged copy prema retention policy-ju i pregledajte OnionShare history/log settings radi nenamernog otkrivanja filename-a.

### CLI workflow

Zvanični CLI prihvata datoteke kao positional arguments i zaustavlja se nakon podrazumevanog jednog završenog deljenja. Na host-u sa instaliranim official CLI/Tor-om:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Bezbedno dostavite dobijeni puni URL. Nemojte dodavati `--public`, `--no-autostop-sharing`, detaljno beleženje imena datoteka ili persistence, osim ako model pretnji izričito zahteva takvu izloženost.<sup>[[7]](#references)</sup>

Primljene dokumente tretirajte kao zlonamerne. Otvarajte ih u disposable VM/Dangerzone-style renderer-u, a ne na hostu koji sadrži identitet.

## Nezavisno šifrovanje datoteke pomoću `age`

Encryption nezavisan od transporta je koristan kada storage/email provider može da vidi objekat. On ne skriva pošiljaoca, primaoca, veličinu, vreme slanja niti naziv datoteke, osim ako se tim elementima ne upravlja odvojeno.

### Podešavanje primaoca
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Potvrdite autentičnost javnog stringa primaoca putem drugog kanala. Pošiljalac zatim izvršava:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Primalac dešifruje u novu putanju:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
Zvanični CLI upozorava da `-o` prepisuje postojeći izlaz, zato koristite novi direktorijum i proverite digest/sadržaj pre nego što ga premestite.<sup>[[8]](#references)</sup> Nikada ne šaljite fajl identiteta zajedno sa šifratom.

## Ponovljivi pipeline za sanitizaciju fajlova

Uklanjanje metapodataka zavisi od formata. Sačuvajte original u šifrovanom obliku kada su autentičnost, forenzika ili lanac čuvanja dokaza važni; radite na kopiji.

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
Ovo prati ExifTool-ove bezbednije smernice za JPEG: slepo uklanjanje svake oznake može ukloniti i informacije o boji.<sup>[[9]](#references)</sup> Zatim vizuelno pregledajte piksele u potrazi za licima, odrazima, ekranima, orijentirima i jedinstvenim obrascima oštećenja/šuma.

### Office/PDF tok rada

1. Čuvajte original koji se može uređivati, šifrovan i van mreže u odnosu na kontekst objavljivanja.
2. U aplikaciji za izradu uklonite komentare, praćene izmene, skrivene slajdove/listove, ugrađene datoteke, lične šablone i svojstva dokumenta.
3. Izvezite novi PDF iz posebnog čistog profila; nemojte „štampati“ na cloud štampač.
4. Pregledajte ga alatima koji prepoznaju format, kao i privremenim vizuelnim rendererom:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Pretražite renderovani izlaz u potrazi za imenima, putanjama, email adresama i tekstom revizije. Rasterizacija može ukloniti aktivne strukture, ali narušava pristupačnost/pretragu i ne uklanja vidljivi sadržaj niti stil pisanja.
6. Izračunajte hash finalnog artefakta i prenesite **samo tu kopiju** kroz publication compartment.

## Privacy Pass: anonimna autorizacija za dizajnere servisa

Privacy Pass razdvaja **izdavanje** tokena od njihove **iskorišćavanja**. Origin može saznati da klijent poseduje token odobren od issuer-a, a da ne sazna konkretnu interakciju klijenta prilikom izdavanja. Ponovna upotreba tokena, jedinstveni metadata podaci, vremenska korelacija ili saradnja mogu ponovo uvesti mogućnost povezivanja.<sup>[[10]](#references)</sup>

Bezbedan obrazac implementacije:

1. Definišite iskaz koji token dokazuje (na primer, podobnost za rate-limit), a ne skrivenu globalnu identifikaciju.
2. Koristite standardizovanu arhitekturu i protokole izdavanja; nemojte sami implementirati blind-signature kriptografiju.
3. Razdvojite administraciju issuer/attester-a i origin-a kada to zahteva željeno svojstvo.
4. Smanjite količinu javnih/privatnih token metadata podataka i obezbedite dovoljno velike skupove anonimnosti.
5. Izdajte batch-eve pre upotrebe gde je to podržano, kako vreme izdavanja ne bi trivijalno odgovaralo vremenu iskorišćavanja.
6. Iskoristite svaki token jednom, proverite challenge vezan za origin i obrišite stanje tokena kojima je istekao rok.
7. Sprečite da cookies, IP logging i application accounts neprimetno ponište svojstvo privatnosti tokena.
8. Testirajte da li issuer i origin logovi mogu da povežu kontrolisani događaj izdavanja i iskorišćavanja koristeći vreme, metadata podatke ili jedinstvene greške.

Privacy Pass je funkcija aplikacije, a ne nešto što korisnik može naknadno dodati proizvoljnom nalogu.

## Kontrolna lista za verifikaciju komunikacije

- [ ] Kontakt/pozivnica/ključ su nezavisno autentifikovani.
- [ ] Izloženost broja telefona, korisničkog imena, profila, grupe i otpremanja kontakata je razjašnjena.
- [ ] Direktni IP, relay, Tor, push-provider i posmatrači lokalnog radija su navedeni.
- [ ] Pregledi obaveštenja, nosivi uređaji, povezani desktop računari i backup-i su testirani.
- [ ] Fajlovi su sanitizovani, po potrebi enkriptovani i otvoreni u disposable kontekstu.
- [ ] Oporavak funkcioniše bez povezivanja nepovezanih identiteta.
- [ ] Za logove, istoriju i privremene share servise postoji pravilo za gašenje/zadržavanje.

## References

- [1] [Signal — Privatnost broja telefona i korisnička imena](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Politika privatnosti i uslovi korišćenja](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Vodič za privatnost i bezbednost](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Kako funkcioniše](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Dizajn bezbednosti](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Napredna upotreba i CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — zvanični CLI i upotreba](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — Bezbedno uklanjanje metadata podataka](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Arhitektura Privacy Pass-a](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
