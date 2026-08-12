# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garažna vrata

Daljinski upravljači za garažna vrata koriste nekoliko regionalnih i proizvodno specifičnih Sub-GHz opsega. Frekvencije kao što su 300, 310, 315, 390 i 433.92 MHz se često sreću, ali ne postoji univerzalni opseg garažnih vrata „300–190 MHz“. Pre odašiljanja identifikujte oznaku ciljnog uređaja, regulatorni region i uočeni signal.<sup>[[1]](#references)</sup>

## Vrata automobila

Mnogi ključevi sa daljinskim upravljačem koriste **315 MHz ili 433.92 MHz**, pri čemu regionalna pravila i dizajn vozila utiču na izbor. Sama frekvencija ne znači da 433 MHz ima veći domet od 315 MHz: snaga odašiljanja, efikasnost antene, modulacija, osetljivost prijemnika, prostiranje signala i lokalni propisi takođe imaju uticaj. U Evropi se najčešće koristi 433.92 MHz, dok je 315 MHz uobičajen u Severnoj Americi i Japanu.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

U prikazanom sistemu sa fiksnim kodom, slanje svakog koda jednom umesto pet puta smanjuje procenjeno vreme na šest minuta:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Uklanjanje čekanja od 2 ms između signala smanjuje trajanje ovog primera na približno tri minuta.

Korišćenjem De Bruijn sequence za preklapanje kandidatskih bitovskih nizova, prikazani napad se smanjuje na približno osam sekundi kada prijemnik prihvata neprekidni niz bez obaveznog preambule ili resetovanja okvira.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implementira ovaj napad protiv kompatibilnih sistema sa fiksnim kodom.<sup>[[5]](#references)</sup>

Zahtevanje **preambule će onemogućiti** optimizaciju **De Bruijn Sequence**, a **rolling codes će sprečiti ovaj napad** (pod pretpostavkom da je kod dovoljno dug da ne može da se izvrši bruteforce).

## Sub-GHz Attack

Za napad na ove signale pomoću Flipper Zero proverite:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Zaštita pomoću Rolling Codes

Automatski otvarači garažnih vrata obično koriste bežični daljinski upravljač za otvaranje i zatvaranje garažnih vrata. Daljinski upravljač **šalje radiofrekventni (RF) signal** otvaraču garažnih vrata, koji aktivira motor za otvaranje ili zatvaranje vrata.

Moguće je da neko upotrebi uređaj poznat kao code grabber za presretanje RF signala i njegovo snimanje za kasniju upotrebu. Ovo je poznato kao **replay attack**. Da bi sprečili ovu vrstu napada, mnogi moderni otvarači garažnih vrata koriste sigurniji metod šifrovanja poznat kao sistem **rolling code**.

**RF signal se obično prenosi pomoću rolling code-a**, što znači da se kod menja pri svakoj upotrebi. Zbog toga je **teško** da neko **presretne** signal i **upotrebi** ga za sticanje **neovlašćenog** pristupa garaži.

U sistemu sa rolling code-om, daljinski upravljač i otvarač garažnih vrata imaju **zajednički algoritam** koji **generiše novi kod** svaki put kada se daljinski upravljač upotrebi. Otvarač garažnih vrata će odgovoriti samo na **ispravan kod**, zbog čega je nekome mnogo teže da stekne neovlašćen pristup garaži samo snimanjem koda.

### **Missing Link Attack**

U osnovi, osluškujete pritisak na dugme i **snimate signal dok se daljinski upravljač nalazi van dometa** uređaja (na primer automobila ili garaže). Zatim se približite uređaju i **upotrebite snimljeni kod da ga otvorite**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> Namerno RF ometanje je nezakonito u mnogim jurisdikcijama i može poremetiti sisteme važne za bezbednost. Testove ometanja izvršavajte samo u oklopljenoj, ovlašćenoj laboratoriji i u skladu sa primenljivim radio-propisima.<sup>[[6]](#references)</sup>

Napadač bi mogao da **ometa signal u blizini vozila ili prijemnika** tako da prijemnik ne može da dekodira kod, da zasebno snimi blokirani prenos, prekine ometanje i zatim ponovo emituje snimljeni kod.<sup>[[2]](#references)</sup>

Žrtva će u nekom trenutku upotrebiti **ključeve da zaključa automobil**, ali će napad već imati **snimljeno dovoljno kodova za „zatvaranje vrata“** koji bi se, nadamo se, mogli ponovo poslati za otvaranje vrata (**možda će biti potrebna promena frekvencije**, jer neki automobili koriste iste kodove za otvaranje i zatvaranje, ali osluškuju obe komande na različitim frekvencijama).

> [!WARNING]
> **Jamming funkcioniše**, ali je uočljiv jer bi **osoba koja zaključava automobil jednostavno proverila vrata** kako bi se uverila da su zaključana i primetila da je automobil otključan. Pored toga, ako bi bila upoznata sa ovakvim napadima, mogla bi da primeti da vrata nisu proizvela zvuk zaključavanja ili da se svetla automobila nisu uključila kada je pritisnuto dugme „lock“.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Ovo je **diskretnija jamming tehnika**. Napadač će ometati signal, tako da pokušaj žrtve da zaključa vrata neće uspeti, ali će napadač **snimiti ovaj kod**. Zatim će žrtva **ponovo pokušati da zaključa automobil** pritiskom na dugme, a automobil će **snimiti ovaj drugi kod**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Neposredno nakon toga, **napadač može poslati prvi kod** i **automobil će se zaključati** (žrtva će misliti da ga je zaključao drugi pritisak). Zatim će napadač moći da **pošalje drugi ukradeni kod kako bi otvorio** automobil (pod pretpostavkom da se kod za **„zatvaranje automobila“ može upotrebiti i za njegovo otvaranje**). Možda će biti potrebna promena frekvencije (jer neki automobili koriste iste kodove za otvaranje i zatvaranje, ali osluškuju obe komande na različitim frekvencijama).

Jedna RollJam implementacija koristi širinu opsega prijemnika: jammer emituje dovoljno blizu noseće frekvencije daljinskog upravljača da desenzitivizuje širi prijemnik vozila, dok uži prijemnik napadača ostaje podešen na frekvenciju daljinskog upravljača i i dalje može da snima signal. Tačan pomak i širina opsega zavise od ciljnog hardvera.<sup>[[2]](#references)</sup>

> [!WARNING]
> Druge implementacije opisane u specifikacijama pokazuju da je **rolling code samo deo** ukupnog poslatog koda. Na primer, poslati kod je **24-bitni ključ**, gde je prvih **12 bitova rolling code**, drugih **8 bitova je komanda** (kao što su zaključavanje ili otključavanje), a poslednja 4 bita su **checksum**. Vozila koja implementiraju ovaj tip takođe su prirodno podložna napadu, jer napadač samo treba da zameni segment rolling code-a kako bi mogao da **upotrebi bilo koji rolling code na obe frekvencije**.

> [!CAUTION]
> Imajte na umu da će, ako žrtva pošalje treći kod dok napadač šalje prvi, prvi i drugi kod biti poništeni.

### Alarm Sounding Jamming Attack

Tokom testiranja aftermarket sistema sa rolling code-om instaliranog u automobilu, **slanje istog koda dva puta** odmah je **aktiviralo alarm** i imobilajzer, pružajući jedinstvenu priliku za **denial of service**. Ironično, način za **isključivanje alarma** i imobilajzera bio je **pritiskanje** **daljinskog upravljača**, što je napadaču omogućilo da **neprekidno izvodi DoS attack**. Ovaj napad se može kombinovati i sa **prethodnim kako bi se pribavilo više kodova**, jer bi žrtva želela da što pre zaustavi napad.<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero dokumentacija - regionalne Sub-GHz frekvencije](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Zaobilaženje Rolling Code sistema - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Vozite kao da ste ga hakovali (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Kako hakovati automobil - RollJam rekonstrukcija pomoću YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Izvorni kod OpenSesame](https://github.com/samyk/opensesame)
- [6] [FCC Enforcement Advisory - sprovođenje zabrane jammer-a](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
