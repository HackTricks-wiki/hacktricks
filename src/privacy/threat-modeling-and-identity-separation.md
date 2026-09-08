# Modeliranje pretnji i odvajanje identiteta

{{#include ../banners/hacktricks-training.md}}

Najčešći uzrok gubitka anonimnosti nije neispravna kriptografija. To je **povezivanje**: jedan identifikator, obrazac vremena, uređaj, nalog, plaćanje, datoteka ili ljudska navika povezuje dva konteksta koji su trebalo da ostanu odvojeni.

## Napravite model pretnji po privatnost

EFF-ov plan bezbednosti sa šest pitanja predstavlja dobru osnovu: šta mora biti zaštićeno, od koga, kakav je uticaj i verovatnoća neuspeha, koliko je truda dostupno i koji saveznici mogu pomoći.<sup>[[1]](#references)</sup> Učinite ga operativnim pomoću male tabele:

| Sredstvo/radnja | Posmatrač | Vidljivi podaci | Putanja korelacije | Kontrola | Preostali rizik |
|---|---|---|---|---|---|
| Istraživanje klijenta | ISP | Metapodaci odredišta/vremena | Evidencija kućnog pretplatnika | Tor Browser | Korišćenje Tor-a je vidljivo; end-to-end korelacija |
| Pseudonimni nalog | Platforma | IP, browser, podaci za oporavak | Ponovo korišćen telefon/email/fotografija | Namenjeni kontekst i alias | Korelacija pisanja/društvenog grafa |
| Online kupovina | Trgovac | Nalog, dostava, tokenizovana kartica | Adresa i istorija naloga | Kupovina bez naloga, minimalna polja, virtuelna kartica | Izdavalac i prevoznik zadržavaju evidenciju |
| Red-team saobraćaj | Meta/klijent | Izvorni IP i ponašanje | Evidencije provajdera/angažmana | Namenjeni autorizovani izlaz | Namerno pripisiv pod eskalacijom |

Pregledajte tabelu svaki put kada se promene lokacija, provajder, uređaj, sagovornik ili posledice.

## Nacrtajte graf povezanosti

Tretirajte svaki identitet kao zaseban čvor. Dodajte ivicu za svaki zajednički atribut:

- email ili adresa za oporavak;
- broj telefona ili otpremanje imenika kontakata;
- korisničko ime, avatar, fotografija, biografija ili stil pisanja/koda;
- lozinka, nalog za sinhronizaciju passkey-ja ili bezbednosno pitanje;
- uređaj, advertising ID, browser profil, cookies, fontovi ili ekstenzije;
- IP adresa, vremenska zona, jezik, raspored ili istovremeni online status;
- bankovna kartica, exchange nalog, klaster novčanika, adresa za dostavu ili program lojalnosti;
- polja autora dokumenta, EXIF lokacija, oznake štampača ili vlasnik cloud-share-a;
- kolega, članstvo u grupama i društveni graf.

Ivica nije automatski fatalna, ali pokazuje koji posmatrač može uspostaviti vezu. EFF posebno upozorava da brojevi telefona, email adrese i ponovo korišćene fotografije mogu povezati profile.<sup>[[2]](#references)</sup>

## Napravite compartment korak po korak

1. **Imenujte kontekst i zabranjene veze.** Primer: `client-red-2026`, uz zabranu korišćenja ličnog emaila, kućnih browser profila, ličnih načina plaćanja i nepovezanih klijenata.
2. **Izaberite granicu izolacije.** Po rastućoj snazi: zaseban browser profil → zaseban OS nalog → zaseban VM/qube → namenski uređaj. Zaseban tab ili privatni prozor nisu bezbednosna granica.
3. **Kreirajte sveže identifikatore unutar te granice.** Koristite email/alias specifičan za kontekst, korisničko ime, lozinku, password-manager vault ili collection i authentication keys. Nemojte dodavati lični kanal za oporavak ako je nepovezivost sa provajderom važna.
4. **Izaberite jednu mrežnu politiku.** Odlučite da li kontekst uvek koristi client VPN, engagement VPS, pouzdani VPN ili Tor. Gde je moguće, primenite fail-closed rutiranje.
5. **Izaberite politiku plaćanja.** Način plaćanja mora odgovarati modelu posmatrača; virtuelna kartica može sakriti PAN od trgovca, ali i dalje identifikuje korisnika izdavaocu.
6. **Postavite pravila prenosa podataka.** Dajte prednost usko ograničenim, namernim prenosima. Clipboard, deljene fascikle, USB uređaje, cloud sync, štampače i screenshots tretirajte kao moguće mostove.
7. **Zabeležite datume kreiranja i uklanjanja.** Definišite koji dokazi moraju biti zadržani zbog ugovora/poreza/usaglašenosti, a koji privremeni podaci treba da isteknu.
8. **Testirajte veze pre korišćenja.** Pregledajte podešavanja naloga, polja za oporavak, javni profil, IP/DNS, stanje browsera, metapodatke datoteka i kontrolne table provajdera.

{% hint style="warning" %}
Nemojte izmišljati podatke o identitetu tamo gde servis ili zakon zahtevaju tačnu identifikaciju. Privacy compartment služi minimizaciji i odvajanju podataka, a ne prevari identiteta ili zaobilaženju customer due diligence postupka.
{% endhint %}

## Osnovna konfiguracija krajnje tačke i naloga

- Koristite podržan hardver i bez odlaganja instalirajte OS, browser, wallet i firmware updates.
- Omogućite enkripciju uređaja i koristite jaku šifru uređaja. Enkripcija podataka u mirovanju pomaže kada je isključen uređaj izgubljen ili zaplenjen, ali ne i dok malware ili otključana sesija mogu da čitaju podatke.<sup>[[3]](#references)</sup>
- Koristite jedinstvene, nasumično generisane lozinke u password manageru.
- Dajte prednost authentication metodama otpornim na phishing, kao što su WebAuthn/passkeys ili hardware security keys, tamo gde model pretnji dozvoljava njihov model oporavka/sinhronizacije. NIST navodi da ručno uneti OTP-ovi nisu otporni na phishing jer ih impostor može proslediti.<sup>[[4]](#references)</sup>
- Čuvajte recovery codes offline i odvojeno od krajnje tačke. Proverite da li sinhronizovani passkey nalog povezuje identitete koji treba da ostanu odvojeni.
- Onemogućite nepotrebne dozvole za lokaciju, kontakte, mikrofon, kameru, Bluetooth, advertising ID i rad u pozadini.
- Nemojte mešati lični cloud sync, browser sync, password-manager naloge ili app stores sa kontekstom koji zahteva visoku odvojenost.

## Privatnost browsera

Browser fingerprinting koristi vidljivu konfiguraciju, uređaj, okruženje i ponašanje za identifikaciju ili korelaciju korisnika. Brisanje cookies-a ili promena IP adresa ne uklanja ga pouzdano, a W3C smatra da je potpuno tehničko uklanjanje pomoću široko primenjenih sredstava malo verovatno.<sup>[[5]](#references)</sup>

Za uobičajenu privatnost:

1. Koristite održavan browser sa HTTPS-only režimom i snažnom zaštitom od praćenja.
2. Blokirajte praćenje trećih strana i koristite partitioning stanja gde je podržan.
3. Koristite odvojene browser profile za zaista odvojene kontekste.
4. Onemogućite nepotrebne dozvole i brišite podatke sa sajtova prema definisanom rasporedu.
5. Izbegavajte prijavljivanje na naloge bogate identitetskim podacima tokom nepovezanog osetljivog istraživanja.

Za web anonimnost koristite **Tor Browser u standardnoj konfiguraciji**. Nemojte prosleđivati normalan browser kroz Tor: Tor Project upozorava da obični browseri mogu otkrivati podatke kroz DNS/WebRTC, trajno stanje, fontove, plugins i razlike u fingerprintu.<sup>[[6]](#references)</sup> Izbegavajte dodatne ekstenzije, neuobičajene veličine prozora, prilagođene fontove i podešavanja zbog kojih se browser izdvaja.<sup>[[7]](#references)</sup>

## Komunikacije i metapodaci

Metapodaci obuhvataju pošiljaoca, primaoca, vreme, lokaciju i drugi kontekst čak i kada je sadržaj poruke enkriptovan.<sup>[[8]](#references)</sup>

- Dajte prednost end-to-end-encrypted alatima sa minimalizovanim metapodacima na serveru i otvorenim protokolima/klijentima gde je to praktično.
- Osetljive kontakte proverite nezavisnim kanalom ili lično. Signal safety numbers su namenjeni ovoj proveri.<sup>[[9]](#references)</sup>
- Signal usernames mogu započeti kontakt bez deljenja broja telefona, ali je broj telefona i dalje potreban za registraciju; pažljivo podesite vidljivost/dostupnost broja telefona za pronalaženje.<sup>[[9]](#references)</sup>
- Poruke koje nestaju smanjuju broj zadržanih kopija; primaoci i dalje mogu fotografisati, kopirati, proslediti ili arhivirati sadržaj.
- Email obično otkriva routing metapodatke. Čak ni privacy-focused provajderi ne mogu učiniti poruku end-to-end enkriptovanom kada druga strana koristi običan email, osim ako obe strane koriste kompatibilan E2EE metod. Proton, na primer, navodi da se za običnu poštu ka drugim provajderima koristi TLS i da ona ostaje čitljiva prijemnom provajderu.<sup>[[10]](#references)</sup>
- Koristite odvojene address books i nemojte otpremati lične kontakte na pseudonimni nalog.

## Datoteke, fotografije i autorstvo

Tails upozorava da fotografije mogu sadržati podatke o kameri i lokaciji, a kancelarijski dokumenti mogu sadržati polja autora i vremena kreiranja.<sup>[[11]](#references)</sup>

Pre deljenja:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Zatim ponovo otvorite očišćenu kopiju u izolovanom vieweru i proverite:

- svojstva dokumenta, komentare, praćene izmene, skrivene sheetove/slajdove, thumbnailove i priloge;
- EXIF/XMP/IPTC, GPS, vremenske oznake, nazive uređaja/softvera i jedinstvene ID-jeve;
- vidljive odraze, orijentire, sadržaj ekrana, glasove, lica i zvukove iz pozadine;
- naziv fajla, putanje unutar arhive, vlasnika cloud-share-a, sertifikat za potpisivanje i istoriju revizija.

Sanitizacija može oštetiti dokaze ili autentičnost. Sačuvajte šifrovani original kada su lanac čuvanja ili kasnija verifikacija važni. Stilometrija i coding style takođe mogu povezati autora; uklanjanje metapodataka ne menja ljudski stil.

## Uobičajeni obrasci grešaka

- Prijavljivanje na lični nalog preko „anonimne“ veze.
- Ponovno korišćenje recovery telefona, avatara, korisničkog imena, javnog ključa, walleta ili adrese za donacije.
- Istovremeno upravljanje dvema identitetima iz korelisanih konteksta.
- Kopiranje teksta/fajlova kroz lični cloud clipboard ili deljeni folder.
- Instaliranje prepoznatljivih Tor Browser ekstenzija ili menjanje velikog broja podrazumevanih podešavanja.
- Verovanje tvrdnji o „no logs“ bez razumevanja toga šta se loguje, koliko dugo i od strane kojih podizvođača.
- Pretpostavljanje da je sekundarni telefon anoniman dok putuje zajedno sa ličnim telefonom. EFF navodi da se lokacija mobilnih uređaja i zajedničko kretanje mogu koristiti za korelaciju uređaja.<sup>[[3]](#references)</sup>
- Tretiranje enkripcije kao brisanja; endpointi i primaoci mogu zadržati plaintext.

## Kontrolna lista za verifikaciju

- [ ] Kontekst nema ličnu recovery adresu, telefon, sync nalog ili ponovo korišćene medije, osim ako je to namerno prihvaćeno.
- [ ] Predviđena mrežna putanja je aktivna i u slučaju greške bezbedno se prekida.
- [ ] Vremenska zona, locale, ekstenzije i dozvole browsera/uređaja usklađeni su sa planom.
- [ ] Nijedan lični nalog nije otvoren u compartmentu.
- [ ] Fajlovi su pregledani i sanitizovani; originalima se rukuje odvojeno.
- [ ] Kontakti su autentifikovani kroz drugi kanal.
- [ ] Metapodaci vidljivi provideru i period zadržavanja su razumljivi.
- [ ] Procedure za teardown, zadržavanje dokaza i oporavak naloga su dokumentovane.

## References

- [1] [EFF Surveillance Self-Defense — Vaš bezbednosni plan](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Zaštita na društvenim mrežama](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Prisustvovanje protestu](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Autentifikacija i upravljanje authenticatorima](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Ublažavanje browser fingerprintinga u web specifikacijama](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Korišćenje Tora sa drugim browserima](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugins i add-ons u Tor Browseru](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Zašto su komunikacioni metapodaci važni](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Privatnost broja telefona i korisnička imena: detaljniji pregled](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Šta je šifrovano unutar Proton Mail-a?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Upozorenja: Tails je bezbedan, ali nije magičan](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
