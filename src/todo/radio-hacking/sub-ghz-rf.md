# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garažna vrata

Otvarači garažnih vrata obično rade na frekvencijama u opsegu od 190 do 300 MHz, pri čemu su najčešće frekvencije 300 MHz, 310 MHz, 315 MHz i 390 MHz. Ovaj frekvencijski opseg se često koristi za otvarače garažnih vrata zato što je manje zauzet od drugih frekvencijskih opsega i zato što je manja verovatnoća smetnji od drugih uređaja.

## Vrata automobila

Većina daljinskih upravljača za automobile radi na **315 MHz ili 433 MHz**. Ovo su radio-frekvencije i koriste se u različitim primenama. Glavna razlika između ove dve frekvencije jeste to što 433 MHz ima veći domet od 315 MHz. To znači da je 433 MHz pogodniji za primene koje zahtevaju veći domet, kao što je daljinsko otključavanje bez ključa.\
U Evropi se često koristi 433.92 MHz, a u SAD i Japanu 315 MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Ako se, umesto slanja svakog koda 5 puta (šalje se toliko puta kako bi se osiguralo da ga prijemnik primi), svaki kod pošalje samo jednom, vreme se smanjuje na 6 minuta:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

a ako **uklonite period čekanja od 2 ms** između signala, možete **smanjiti vreme na 3 minuta.**

Pored toga, korišćenjem De Bruijn Sequence (načina da se smanji broj bitova potrebnih za slanje svih potencijalnih binarnih brojeva pri brute-force napadu), ovo **vreme se smanjuje na samo 8 sekundi**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Primer ovog napada implementiran je u [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)<sup>[[3]](#references)</sup>

Zahtev za **preambulom sprečiće optimizaciju pomoću De Bruijn Sequence**, a **rolling codes će sprečiti ovaj napad** (pod pretpostavkom da je kod dovoljno dug da ne može da se izvrši brute-force napad).

## Sub-GHz Attack

Za napad na ove signale pomoću uređaja Flipper Zero pogledajte:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatski otvarači garažnih vrata obično koriste bežični daljinski upravljač za otvaranje i zatvaranje garažnih vrata. Daljinski upravljač **šalje radio-frekvencijski (RF) signal** otvaraču garažnih vrata, koji aktivira motor za otvaranje ili zatvaranje vrata.

Moguće je da neko upotrebi uređaj poznat kao code grabber za presretanje RF signala i njegovo snimanje za kasniju upotrebu. Ovo je poznato kao **replay attack**. Kako bi sprečili ovu vrstu napada, mnogi moderni otvarači garažnih vrata koriste bezbedniji metod enkripcije poznat kao sistem **rolling code**.

**RF signal se obično prenosi pomoću rolling code-a**, što znači da se kod menja pri svakoj upotrebi. Zbog toga je **teško** nekome da **presretne** signal i **upotrebi** ga za sticanje **neovlašćenog** pristupa garaži.

U sistemu rolling code, daljinski upravljač i otvarač garažnih vrata imaju **zajednički algoritam** koji **generiše novi kod** svaki put kada se daljinski upravljač upotrebi. Otvarač garažnih vrata reagovaće samo na **ispravan kod**, zbog čega je nekome mnogo teže da stekne neovlašćeni pristup garaži samo snimanjem koda.

### **Missing Link Attack**

U osnovi, osluškujete pritisak na dugme i **hvatate signal dok se daljinski upravljač nalazi van dometa** uređaja (na primer automobila ili garaže). Zatim se približite uređaju i **upotrebite uhvaćeni kod za njegovo otvaranje**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Napadač može da **ometa signal u blizini vozila ili prijemnika**, tako da **prijemnik zapravo ne može da „čuje“ kod**, a kada do toga dođe, napadač može jednostavno da **uhvati i ponovo pošalje** kod nakon što prestane sa ometanjem.

Žrtva će u nekom trenutku upotrebiti **ključeve da zaključa automobil**, ali će napadač do tada **snimiti dovoljno kodova za „zatvaranje vrata“** koji bi, nadamo se, mogli ponovo da se pošalju radi otvaranja vrata (možda će biti potrebna **promena frekvencije**, jer postoje automobili koji koriste iste kodove za otvaranje i zatvaranje, ali osluškuju obe komande na različitim frekvencijama).

> [!WARNING]
> **Ometanje funkcioniše**, ali je primetno: ako osoba koja zaključava automobil jednostavno proveri vrata kako bi se uverila da su zaključana, primetiće da je automobil otključan. Pored toga, ako je upoznata sa ovakvim napadima, mogla bi da primeti da se vrata nikada nisu čula kako se zaključavaju ili da **svetla automobila** nikada nisu trepnula kada je pritisnula dugme za zaključavanje.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Ovo je **diskretnija tehnika ometanja**. Napadač će ometati signal, pa pokušaj žrtve da zaključa vrata neće uspeti, ali će napadač **snimiti ovaj kod**. Zatim će žrtva **ponovo pokušati da zaključa automobil** pritiskom na dugme, a automobil će **snimiti ovaj drugi kod**.\
Napadač tada može odmah da pošalje prvi kod i **automobil će se zaključati** (žrtva će misliti da ga je zaključao drugi pritisak). Nakon toga, napadač će moći da **pošalje drugi ukradeni kod i otključa** automobil (pod pretpostavkom da se kod za **„zatvaranje automobila“ može upotrebiti i za njegovo otvaranje**). Možda će biti potrebna promena frekvencije (jer postoje automobili koji koriste iste kodove za otvaranje i zatvaranje, ali osluškuju obe komande na različitim frekvencijama).<sup>[[3]](#references)[[2]](#references)</sup>

Napadač može da **ometa prijemnik automobila, a ne svoj prijemnik**, jer, ako prijemnik automobila osluškuje, na primer, širokopojasni opseg od 1 MHz, napadač neće **ometati** tačnu frekvenciju koju koristi daljinski upravljač, već **frekvenciju blisku njoj u tom spektru**, dok će **prijemnik napadača osluškivati uži opseg** u kojem može da čuje signal daljinskog upravljača **bez signala ometanja**.

> [!WARNING]
> Druge implementacije navedene u specifikacijama pokazuju da je **rolling code samo deo** ukupnog poslatog koda. Na primer, poslati kod može biti **24-bitni ključ**, pri čemu je prvih **12 bitova rolling code**, sledećih **8 bitova komanda** (kao što su zaključavanje ili otključavanje), a poslednja 4 bita su **checksum**. Vozila koja implementiraju ovaj tip takođe su prirodno ranjiva, jer napadač samo treba da zameni segment rolling code-a kako bi mogao da **upotrebi bilo koji rolling code na obe frekvencije**.

> [!CAUTION]
> Imajte na umu da će, ako žrtva pošalje treći kod dok napadač šalje prvi, prvi i drugi kod biti poništeni.

### Alarm Sounding Jamming Attack

Prilikom testiranja aftermarket rolling code sistema instaliranog u automobilu, **slanje istog koda dva puta** odmah je **aktiviralo alarm** i imobilajzer, pružajući jedinstvenu mogućnost za **denial of service**. Ironično, način za **isključivanje alarma** i imobilajzera bio je **pritiskanje** dugmeta na **daljinskom upravljaču**, što napadaču pruža mogućnost da **neprekidno izvršava DoS napad**. Ovaj napad se može kombinovati i sa **prethodnim kako bi se dobilo više kodova**, jer će žrtva želeti da što pre zaustavi napad.<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Drive It Like You Hacked It (DEF CON 23) - OpenSesame / RollJam](https://samy.pl/defcon2015/)
- [4] [How to hack a car (RollJam recreation)](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
