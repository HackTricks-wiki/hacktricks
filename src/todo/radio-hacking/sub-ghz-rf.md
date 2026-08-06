# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

Uređaji za otvaranje garažnih vrata obično rade na frekvencijama u opsegu od 300 do 190 MHz, pri čemu su najčešće frekvencije 300 MHz, 310 MHz, 315 MHz i 390 MHz. Ovaj frekvencijski opseg se često koristi za uređaje za otvaranje garažnih vrata zato što je manje zagušen od drugih frekvencijskih opsega i manje je verovatno da će doći do interference sa drugim uređajima.

## Car Doors

Većina daljinskih upravljača za automobile radi na **315 MHz ili 433 MHz**. To su obe radio-frekvencije i koriste se u različitim primenama. Glavna razlika između ove dve frekvencije jeste to što 433 MHz ima veći domet od 315 MHz. To znači da je 433 MHz pogodniji za primene koje zahtevaju veći domet, kao što je daljinsko otključavanje bez ključa.\
U Evropi se često koristi 433.92MHz, dok se u SAD i Japanu koristi 315MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Ako se umesto slanja svakog koda 5 puta (šalje se na ovaj način da bi se osiguralo da ga prijemnik primi) svaki kod pošalje samo jednom, vreme se smanjuje na 6 minuta:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

a ako **uklonite period čekanja od 2 ms** između signala, možete **smanjiti vreme na 3 minuta.**

Pored toga, korišćenjem De Bruijn Sequence (načina da se smanji broj bitova potrebnih za slanje svih potencijalnih binarnih brojeva radi bruteforce-a), ovo **vreme se smanjuje na samo 8 sekundi**:<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Primer ovog napada implementiran je na adresi [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Zahtev za **preamble-om sprečiće De Bruijn Sequence** optimizaciju, a **rolling codes će sprečiti ovaj napad** (pod pretpostavkom da je code dovoljno dug da ne može da se izvrši bruteforce).

## Sub-GHz Attack

Za napad na ove signale pomoću Flipper Zero proverite:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatski uređaji za otvaranje garažnih vrata obično koriste bežični daljinski upravljač za otvaranje i zatvaranje garažnih vrata. Daljinski upravljač **šalje radio-frekvencijski (RF) signal** uređaju za otvaranje garažnih vrata, koji aktivira motor za otvaranje ili zatvaranje vrata.

Moguće je da neko upotrebi uređaj poznat kao code grabber za presretanje RF signala i njegovo snimanje za kasniju upotrebu. Ovo je poznato kao **replay attack**. Da bi sprečili ovu vrstu napada, mnogi moderni uređaji za otvaranje garažnih vrata koriste bezbedniji metod enkripcije poznat kao sistem **rolling code**.

**RF signal se obično prenosi pomoću rolling code-a**, što znači da se code menja pri svakoj upotrebi. Zbog toga je nekome **teško** da **presretne** signal i **upotrebi** ga za sticanje **neovlašćenog** pristupa garaži.

U sistemu rolling code, daljinski upravljač i uređaj za otvaranje garažnih vrata imaju **zajednički algoritam** koji **generiše novi code** svaki put kada se daljinski upravljač upotrebi. Uređaj za otvaranje garažnih vrata reagovaće samo na **ispravan code**, zbog čega je nekome mnogo teže da stekne neovlašćen pristup garaži jednostavnim snimanjem koda.

### **Missing Link Attack**

U osnovi, slušate pritisak na dugme i **snimate signal dok je daljinski upravljač van dometa** uređaja (na primer automobila ili garaže). Zatim se približite uređaju i **upotrebite snimljeni code da ga otvorite**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Napadač može da **ometa signal u blizini vozila ili prijemnika**, tako da **prijemnik zapravo ne može da „čuje“ code**, a kada se to dogodi, jednostavno možete **snimiti i ponovo emitovati** code nakon prestanka ometanja.<sup>[[2]](#references)</sup>

Žrtva će u nekom trenutku upotrebiti **ključeve da zaključa automobil**, ali će napad već **snimiti dovoljno code-ova za „zatvaranje vrata“** koji bi, nadamo se, mogli ponovo da se emituju radi otvaranja vrata (možda će biti potrebna **promena frekvencije**, jer postoje automobili koji koriste iste code-ove za otvaranje i zatvaranje, ali osluškuju obe komande na različitim frekvencijama).

> [!WARNING]
> **Jamming funkcioniše**, ali je primetan: ako osoba koja zaključava automobil jednostavno proveri vrata da bi se uverila da su zaključana, primetila bi da je automobil otključan. Pored toga, ako je upoznata sa ovakvim napadima, mogla bi čak da primeti da se vrata nikada nisu zaključala — jer se nije čuo **zvuk** zaključavanja ili zato što se **svetla** automobila nisu uključila kada je pritisnuto dugme za zaključavanje.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Ovo je prikrivenija **Jamming tehnika**. Napadač će ometati signal, tako da pokušaj žrtve da zaključa vrata neće uspeti, ali će napadač **snimiti ovaj code**. Zatim će žrtva **ponovo pokušati da zaključa automobil** pritiskom na dugme, a automobil će **snimiti ovaj drugi code**.<sup>[[2]](#references)[[4]](#references)</sup>\
Neposredno nakon toga, **napadač može poslati prvi code** i **automobil će se zaključati** (žrtva će misliti da ga je zaključao drugi pritisak). Zatim će napadač moći da **pošalje drugi ukradeni code kako bi otvorio** automobil (pod pretpostavkom da se **code za „zatvaranje automobila“ može koristiti i za njegovo otvaranje**). Možda će biti potrebna promena frekvencije (jer postoje automobili koji koriste iste code-ove za otvaranje i zatvaranje, ali osluškuju obe komande na različitim frekvencijama).

Napadač može da **ometa prijemnik automobila, ali ne i svoj prijemnik**, zato što, ako prijemnik automobila osluškuje, na primer, širokopojasni opseg od 1MHz, napadač neće **ometati** tačnu frekvenciju koju koristi daljinski upravljač, već **blisku frekvenciju u tom spektru**, dok će **prijemnik napadača osluškivati uži opseg** u kojem može da čuje signal daljinskog upravljača **bez signala ometanja**.

> [!WARNING]
> Druge implementacije navedene u specifikacijama pokazuju da je **rolling code samo deo** ukupnog poslatog koda. Na primer, poslati code je **24-bitni ključ**, gde je prvih **12 bitova rolling code**, drugih **8 bitova predstavlja komandu** (kao što su zaključavanje ili otključavanje), a poslednja 4 bita predstavljaju **checksum**. Vozila koja implementiraju ovaj tip takođe su prirodno ranjiva, jer napadač samo treba da zameni segment rolling code-a kako bi mogao da **upotrebi bilo koji rolling code na obe frekvencije**.

> [!CAUTION]
> Imajte na umu da će, ako žrtva pošalje treći code dok napadač šalje prvi, prvi i drugi code biti poništeni.

### Alarm Sounding Jamming Attack

Prilikom testiranja aftermarket rolling code sistema instaliranog u automobilu, **slanje istog koda dva puta** odmah je **aktiviralo alarm** i imobilajzer, što pruža jedinstvenu mogućnost za **denial of service**. Ironično, način za **isključivanje alarma** i imobilajzera bio je **pritiskanje** **daljinskog upravljača**, što napadaču omogućava da **neprekidno izvršava DoS attack**. Ovaj napad se može kombinovati i sa **prethodnim kako bi se dobilo više code-ova**, jer bi žrtva želela da što pre zaustavi napad.<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
