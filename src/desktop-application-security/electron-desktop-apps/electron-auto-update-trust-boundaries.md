# Granice poverenja pri automatskom ažuriranju Electron aplikacija

{{#include ../../banners/hacktricks-training.md}}

## Površina napada automatskog ažuriranja Electron aplikacija

Tretirajte program za ažuriranje kao granicu za daljinsko izvršavanje koda: on preuzima izvršni sadržaj, odlučuje da li je taj sadržaj noviji i pouzdan, smešta ga lokalno i predaje instalateru. Pregledajte ceo graf poverenja — indeks izdanja, metapodatke za svaku verziju, artefakt, odvojene potpise, ugrađeni ključ za verifikaciju, keš, privremenu putanju i instalater — a ne samo to da li je konačni `.app` potpisan.<sup>[[1]](#references)[[2]](#references)</sup>

### Testovi visokog prioriteta

- **Rollback/replay:** ponovo pustite raniji, važeći manifest i njegov i dalje potpisani artefakt. Potpis potvrđuje autentičnost svog sadržaja, ali ne garantuje svežinu; klijent mora da odbije verzije ispod trajno sačuvane monotone granice, osim ako autentifikovana politika oporavka izričito ne dozvoljava vraćanje na stariju verziju.<sup>[[2]](#references)</sup>
- **Zamena metapodataka/artefakta:** nezavisno izmenite verziju, URL, očekivani hash, artefakt i odvojeni potpis. Pokušajte i da kombinujete važeći par artefakta i potpisa iz jednog izdanja sa metapodacima drugog izdanja. Ako metapodaci izdanja nisu potpisani, TLS ili potpisana izvršna datoteka ne sprečavaju kompromitovani izvor/CDN da promeni logiku izbora.<sup>[[1]](#references)[[2]](#references)</sup>
- **Zabuna oko potpisanog kanala:** poslužite legitimno potpisanu alpha, beta, development ili debug verziju preko produkcionog feeda. Ponovna upotreba istog ključa i politike u različitim okruženjima omogućava artefaktu da prođe proveru koja se oslanja samo na potpisnika; identitet/kanal produkcionog okruženja mora biti deo autentifikovane politike ili mora da se koristi zaseban koren poverenja.<sup>[[2]](#references)</sup>
- **TOCTOU privremene datoteke:** utvrdite da li se pri verifikaciji otvara putanja, a zatim se pri instalaciji ista putanja ponovo otvara. Ako lokalni napadač može da preimenuje, zameni ili preusmeri privremeno smešteni objekat između tih operacija, instalater može da obradi bajtove koji nikada nisu verifikovani. Privremeni direktorijum sa dozvolama `0700` ograničava pristup, ali ne čini te dve operacije atomskim.<sup>[[2]](#references)</sup>

Statička i runtime trijaža mogu brzo da otkriju ove granice.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

Tokom ovlašćenog testa presretnite proveru ažuriranja, sačuvajte svaku primljenu poruku i menjajte po jedno polje. Zatim proverite vlasništvo i dozvole staging direktorijuma i pratite otvaranje datoteka od preuzimanja do instalacije. Na macOS-u nastavite sa [testiranjem granice poverenja instalatora](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md) ako tok dođe do privilegovanog pomoćnog programa, a razmotrite [slabosti potpisivanja koda](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md) umesto da „potpisano” smatrate potpunom proverom identiteta.<sup>[[2]](#references)</sup>

### Očekivano povezivanje i smernice

Odbranjiv dizajn autentifikuje i metapodatke za izbor i bajtove artefakta. Referentni dizajn SafeUpdater prikazuje ugrađeni javni ključ Ed25519, potpisane manifeste i artefakte, potpisanu poruku izvedenu iz `SHA-256(file)` i verzije, kao i SHA-512 sažetak artefakta sačuvan u potpisanim metapodacima; izričito je naveden kao istraživački primer, a ne kao paket spreman za produkciju.<sup>[[1]](#references)[[2]](#references)</sup>

Proverite da li cilj obezbeđuje i sledeća svojstva.<sup>[[1]](#references)[[2]](#references)</sup>

- koristi nedvosmislen potpisani prikaz koji povezuje sažetak artefakta sa njegovom kanonskom verzijom i okruženjem izdanja;
- podrazumevano onemogućava vraćanje na stariju verziju i sprovodi minimalnu prihvaćenu verziju za ovlašćeno vraćanje;
- razdvaja produkciju od neprodukcije pomoću različitih ključeva/kanala ili autentifikovanih podataka o smernicama za izdanja; i
- instalira već verifikovanu otvorenu datoteku (ili ekvivalentni nepromenljivi rukovalac/objekat) umesto da ponovo razrešava istu putanju.

## References

- [1] [Referentna implementacija Doyensec ElectronSafeUpdater](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater: Projektovanje bezbednog mehanizma za automatsko ažuriranje Electron aplikacija](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
