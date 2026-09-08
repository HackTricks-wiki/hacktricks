# Modeliranje pretnji i razdvajanje identiteta

Najčešći neuspeh anonimnosti nije pokvarena kriptografija. To je **povezivanje**: jedan identifikator, obrazac vremena, uređaj, nalog, plaćanje, datoteka ili ljudska navika povezuje dva konteksta koji su trebalo da ostanu odvojeni.

## Napravite model pretnji privatnosti

EFF-ov plan bezbednosti sa šest pitanja predstavlja dobru osnovu: šta mora biti zaštićeno, od koga, kakav je uticaj i verovatnoća neuspeha, koliko truda je dostupno i koji saveznici mogu pomoći.<sup>[[1]](#references)</sup> Učinite ga operativnim pomoću male tabele:

| Sredstvo/radnja | Posmatrač | Uočljivi podaci | Način korelacije | Kontrola | Preostali rizik |
|---|---|---|---|---|---|
| Istraživanje klijenta | ISP | Odredišni/vremenski metapodaci | Evidencija kućnog pretplatnika | Tor Browser | Upotreba Tor-a je vidljiva; end-to-end korelacija |
| Pseudonimni nalog | Platforma | IP, browser, podaci za oporavak | Ponovo korišćen telefon/email/fotografija | Namenski kontekst i alias | Korelacija pisanja/društvenog grafa |
| Online kupovina | Trgovac | Nalog, dostava, tokenizovana kartica | Adresa i istorija naloga | Kupovina bez naloga, minimalna polja, virtuelna kartica | Izdavalac i prevoznik zadržavaju evidenciju |
| Red-team saobraćaj | Meta/klijent | Izvorni IP i ponašanje | Evidencija provajdera/angažmana | Namenski autorizovani izlaz | Namerno pripisiv u slučaju eskalacije |

Pregledajte tabelu svaki put kada se promene lokacija, provajder, uređaj, druga strana ili posledice.

## Nacrtajte graf povezanosti

Tretirajte svaki identitet kao zaseban čvor. Dodajte ivicu za svaki zajednički atribut:

- email ili adresa za oporavak;
- broj telefona ili otpremanje adresara;
- korisničko ime, avatar, fotografija, biografija ili stil pisanja/koda;
- lozinka, nalog za passkey-sync ili bezbednosno pitanje za oporavak;
- uređaj, advertising ID, browser profil, cookies, fontovi ili ekstenzije;
- IP adresa, vremenska zona, jezik, raspored ili istovremeni online status;
- bankovna kartica, exchange nalog, wallet klaster, adresa za dostavu ili loyalty program;
- polja autora dokumenta, EXIF lokacija, oznake štampača ili vlasnik cloud-share-a;
- kolega, članstvo u grupi i društveni graf.

Ivica nije automatski fatalna, ali pokazuje koji posmatrač može uspostaviti vezu. EFF posebno upozorava da brojevi telefona, email adrese i ponovo korišćene fotografije mogu povezati profile.<sup>[[2]](#references)</sup>

## Napravite compartment korak po korak

1. **Imenujte kontekst i zabranjene veze.** Primer: `client-red-2026`, sa zabranom korišćenja ličnog emaila, kućnih browser profila, ličnih metoda plaćanja i nepovezanih klijenata.
2. **Izaberite granicu izolacije.** Po rastućoj jačini: zaseban browser profil → zaseban OS nalog → zaseban VM/qube → namenski uređaj. Zaseban tab ili private window nisu bezbednosna granica.
3. **Napravite sveže identifikatore unutar te granice.** Koristite email/alias specifičan za kontekst, korisničko ime, password-manager vault ili kolekciju i autentikacione ključeve. Nemojte dodavati lični kanal za oporavak ako je neophodno da se ne možete povezati sa provajderom.
4. **Izaberite jednu mrežnu politiku.** Odlučite da li će kontekst uvek koristiti client VPN, engagement VPS, pouzdani VPN ili Tor. Gde je moguće, primenite fail-closed rutiranje.
5. **Izaberite politiku plaćanja.** Metod plaćanja mora odgovarati modelu posmatrača; virtuelna kartica može sakriti PAN od trgovca, ali i dalje identifikuje korisnika izdavaocu.
6. **Postavite pravila prenosa podataka.** Dajte prednost usko ograničenim, namernim prenosima. Tretirajte clipboard, deljene fascikle, USB uređaje, cloud sync, štampače i screenshots kao moguće mostove.
7. **Zabeležite datume kreiranja i uklanjanja.** Definišite koje dokaze treba zadržati zbog ugovora/poreza/usaglašenosti, a koji privremeni podaci treba da isteknu.
8. **Testirajte veze pre upotrebe.** Pregledajte podešavanja naloga, polja za oporavak, javni profil, IP/DNS, stanje browsera, metapodatke datoteka i kontrolne table provajdera.

{% hint style="warning" %}
Nemojte izmišljati podatke o identitetu tamo gde servis ili zakon zahtevaju tačnu identifikaciju. Privacy compartment služi minimizaciji i razdvajanju podataka, a ne prevari identiteta ili zaobilaženju provere klijenta.
{% endhint %}

## Osnovna podešavanja endpointa i naloga

- Koristite podržan hardver i pravovremeno instalirajte OS, browser, wallet i firmware ažuriranja.
- Omogućite šifrovanje uređaja i koristite snažnu šifru uređaja. Šifrovanje podataka u mirovanju pomaže kada se isključen uređaj izgubi ili zapleni, ali ne i dok malware ili otključana sesija mogu da čitaju podatke.<sup>[[3]](#references)</sup>
- Koristite jedinstvene, nasumično generisane lozinke u password manageru.
- Dajte prednost autentikaciji otpornoj na phishing, kao što su WebAuthn/passkeys ili hardverski security keys, tamo gde model pretnji dozvoljava njihov model oporavka/sinhronizacije. NIST navodi da ručno uneti OTP-ovi nisu otporni na phishing jer ih impostor može proslediti.<sup>[[4]](#references)</sup>
- Čuvajte kodove za oporavak offline i odvojeno od endpointa. Proverite da li synced passkey nalog povezuje identitete koji treba da ostanu odvojeni.
- Isključite nepotrebne dozvole za lokaciju, kontakte, mikrofon, kameru, Bluetooth, advertising ID i pozadinski rad.
- Nemojte mešati lični cloud sync, browser sync, password-manager naloge ili app stores sa kontekstom koji zahteva visoku izolaciju.

## Privatnost browsera

Browser fingerprinting koristi uočljivu konfiguraciju, uređaj, okruženje i ponašanje za identifikaciju ili korelaciju korisnika. Brisanje cookies-a ili promena IP adresa ne sprečavaju ga pouzdano, a W3C smatra da je potpuno tehničko uklanjanje pomoću široko primenjenih sredstava malo verovatno.<sup>[[5]](#references)</sup>

Za uobičajenu privatnost:

1. Koristite održavan browser sa HTTPS-only režimom i snažnom zaštitom od praćenja.
2. Blokirajte third-party tracking i particionišite stanje gde je podržano.
3. Koristite zasebne browser profile za zaista odvojene kontekste.
4. Isključite nepotrebne dozvole i brišite podatke sajtova prema definisanom rasporedu.
5. Izbegavajte prijavljivanje na naloge bogate identitetskim podacima dok obavljate nepovezano osetljivo istraživanje.

Za web anonimnost koristite **Tor Browser u standardnoj konfiguraciji**. Nemojte usmeravati normalan browser kroz Tor: Tor Project upozorava da obični browseri mogu odavati podatke preko DNS/WebRTC-a, trajnog stanja, fontova, plug-inova i razlika u fingerprintu.<sup>[[6]](#references)</sup> Izbegavajte dodatne ekstenzije, neuobičajene veličine prozora, prilagođene fontove i preference zbog kojih se browser izdvaja.<sup>[[7]](#references)</sup>

## Komunikacije i metapodaci

Metapodaci obuhvataju pošiljaoca, primaoca, vreme, lokaciju i drugi kontekst, čak i kada je sadržaj poruke šifrovan.<sup>[[8]](#references)</sup>

- Dajte prednost end-to-end-encrypted alatima sa smanjenim server-side metapodacima i otvorenim protokolima/klijentima gde je to praktično.
- Osetljive kontakte proverite pomoću nezavisnog kanala ili lično. Signal safety numbers su namenjeni ovoj proveri.<sup>[[9]](#references)</sup>
- Signal usernames mogu započeti kontakt bez deljenja broja telefona, ali je broj telefona i dalje potreban za registraciju; pažljivo podesite vidljivost/dostupnost broja telefona.<sup>[[9]](#references)</sup>
- Disappearing messages smanjuju broj sačuvanih kopija; primaoci i dalje mogu fotografisati, kopirati, proslediti ili arhivirati sadržaj.
- Email obično otkriva routing metadata. Čak ni privacy-focused provajderi ne mogu učiniti poruku end-to-end encrypted kada druga strana koristi običan email, osim ako obe strane koriste kompatibilan E2EE metod. Proton, na primer, dokumentuje da se za običnu poštu ka drugim provajderima koristi TLS i da ona ostaje čitljiva provajderu primaoca.<sup>[[10]](#references)</sup>
- Koristite odvojene adresare i nemojte otpremati lične kontakte na pseudonimni nalog.

## Datoteke, fotografije i autorstvo

Tails upozorava da fotografije mogu sadržati podatke o kameri i lokaciji, a kancelarijski dokumenti mogu sadržati polja autora i vremena kreiranja.<sup>[[11]](#references)</sup>

Pre deljenja:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Zatim ponovo otvorite očišćenu kopiju u izolovanom pregledniku i proverite:

- svojstva dokumenta, komentare, praćene izmene, skrivene listove/slajdove, sličice i priloge;
- EXIF/XMP/IPTC, GPS, vremenske oznake, nazive uređaja/softvera i jedinstvene ID-jeve;
- vidljive odraze, orijentire, sadržaj ekrana, glasove, lica i pozadinske zvukove;
- naziv datoteke, putanje u arhivi, vlasnika cloud-share resursa, sertifikat za potpisivanje i istoriju revizija.

Sanitizacija može oštetiti dokaze ili autentičnost. Sačuvajte šifrovani original kada su lanac čuvanja dokaza ili kasnija verifikacija važni. Stylometry i stil kodiranja takođe mogu povezati autora; uklanjanje metapodataka ne menja ljudski stil.

## Uobičajeni obrasci grešaka

- Prijavljivanje na lični nalog putem „anonimne“ veze.
- Ponovno korišćenje telefona za oporavak naloga, avatara, korisničkog imena, javnog ključa, novčanika ili adrese za donacije.
- Istovremeno upravljanje dvema identitetima iz korelisanih konteksta.
- Kopiranje teksta/datoteka putem ličnog cloud clipboard-a ili deljene fascikle.
- Instaliranje prepoznatljivih Tor Browser ekstenzija ili menjanje velikog broja podrazumevanih postavki.
- Verovanje tvrdnji o „bez logova“ bez razumevanja šta se beleži, koliko dugo i od strane kojih podizvođača.
- Pretpostavljanje da je sekundarni telefon anoniman dok putuje zajedno sa ličnim telefonom. EFF napominje da lokacija mobilnog uređaja i zajedničko kretanje mogu povezati uređaje.<sup>[[3]](#references)</sup>
- Tretiranje enkripcije kao brisanja; endpoint-i i primaoci mogu zadržati plaintext.

## Kontrolna lista za verifikaciju

- [ ] Kontekst nema ličnu adresu za oporavak, telefon, sync nalog ili ponovo korišćene medije, osim ako je to namerno prihvaćeno.
- [ ] Predviđena mrežna putanja je aktivna i bezbedno se prekida pri grešci.
- [ ] Vremenska zona, lokalizacija, ekstenzije i dozvole browsera/uređaja odgovaraju planu.
- [ ] Nijedan lični nalog nije otvoren u compartment-u.
- [ ] Datoteke su pregledane i sanitizovane; originalima se rukuje odvojeno.
- [ ] Kontakti su autentifikovani putem drugog kanala.
- [ ] Metapodaci vidljivi provajderu i period zadržavanja su razumljivi.
- [ ] Procedure za teardown, zadržavanje dokaza i oporavak naloga su dokumentovane.

## References

- [1] [EFF Surveillance Self-Defense — Vaš bezbednosni plan](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Zaštita na društvenim mrežama](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Prisustvovanje protestu](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Upravljanje autentifikacijom i autentifikatorima](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Ublažavanje browser fingerprinting-a u web specifikacijama](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Korišćenje Tor-a sa drugim browserima](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugin-i i dodaci u Tor Browser-u](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Zašto su metapodaci komunikacije važni](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Privatnost telefonskog broja i korisnička imena: detaljniji pregled](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Šta je šifrovano unutar Proton Mail-a?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Upozorenja: Tails je bezbedan, ali nije magičan](https://tails.net/doc/about/warnings/index.en.html)
