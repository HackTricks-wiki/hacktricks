# macOS Serial Number

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Nemojte pretpostaviti da svaki Mac ima serijski broj od 12 znakova koji se može dekodirati. Apple-ov stariji format sadržao je informacije o proizvodnji i konfiguraciji, ali je Apple počeo da uvodi nasumične serijske brojeve u nove proizvode 2021. godine. Nasumični format ne otkriva detalje o proizvodnji ili konfiguraciji.<sup>[[1]](#references)</sup>

### Nasleđeni format od 12 znakova

Za mnoge uređaje proizvedene od 2010. godine do prelaska na nasumični format, format od 12 znakova i dalje može pružiti korisne inventarske podatke:<sup>[[3]](#references)</sup>

- Znakovi 1–3 identifikuju lokaciju proizvodnje.
- Znakovi 4–5 kodiraju polovinu godine i nedelju proizvodnje.
- Znakovi 6–8 razlikuju uređaje proizvedene na istoj lokaciji i u isto vreme.
- Znakovi 9–12 identifikuju kod modela ili konfiguracije.

Na primer, `C02L13ECF8J2` prati ovu nasleđenu strukturu. Mapiranja fabrika koja održava zajednica uključuju prefikse kao što su `FC`, `F`, `XA`, `XB`, `QP` i `G8` za lokacije u Sjedinjenim Državama; `RN` za Meksiko; `CK` za Cork; `VM` za Foxconn lokaciju u Češkoj Republici; `SG` ili `E` za Singapur; `MB` za Maleziju; `PT` ili `CY` za Koreju; i `EE`, `QT` ili `UV` za Tajvan. Brojni prefiksi — uključujući `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3` i `C7` — povezivani su sa kineskim fabrikama; `RM` je povezivan sa obnovljenim uređajima.<sup>[[3]](#references)</sup>

Kodovi datuma četvrtog znaka kreću se od `C` (prva polovina 2010. godine) do `Z` (druga polovina 2019. godine), nakon čega se sekvenca ponovo koristi. Kod petog znaka, cifre `1`–`9` predstavljaju nedelje 1–9, dok slova `C`–`Y`, izuzimajući samoglasnike i `S`, predstavljaju nedelje 10–27; dodajte 26 kada četvrti znak označava drugu polovinu godine.<sup>[[3]](#references)</sup>

Ova mapiranja su korisna za trijažu nasleđenih uređaja, ali nisu autoritativan dokaz porekla, starosti ili autentičnosti. Potvrdite rezultat pomoću Apple-ovih inventarskih podataka.

Za pouzdanu identifikaciju, preuzmite serijski broj sa uređaja i koristite Apple-ovu proveru pokrića ili tehničkih specifikacija, umesto pokušaja da zaključite model na osnovu pozicija znakova.<sup>[[2]](#references)</sup>

### Preuzimanje serijskog broja

Grafički interfejs ga prikazuje u odeljku **Apple menu > About This Mac**.<sup>[[2]](#references)</sup> Iz shell-a, bilo koja od sledećih komandi očitava serijski broj platforme:
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
Tretirajte serijski broj kao identifikator, a ne kao autentifikator: potvrdite uređaj kroz odgovarajući Apple ili MDM inventarski tok pre donošenja odluka o upisu ili vlasništvu.

## References

- [1] [MacRumors - Apple započinje prelazak na nasumične serijske brojeve](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Pronađite naziv modela i serijski broj svog Mac računara](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Dekodirajte značenje Apple serijskog broja](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
