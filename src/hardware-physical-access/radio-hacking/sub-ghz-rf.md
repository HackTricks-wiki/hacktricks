# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garažna vrata

Daljinski upravljači za garažna vrata koriste različite raspodele sub-GHz frekvencija, specifične za region i proizvod. Mogu se sresti frekvencije kao što su 300, 310, 315, 390 i 433.92 MHz, ali ne postoji univerzalni opseg za garažna vrata „300–190 MHz“. Pre emitovanja utvrdite šta piše na oznaci ciljnog uređaja, koji regulatorni region važi i kakav je signal zabeležen.<sup>[[1]](#references)</sup>

## Vrata automobila

Mnogi daljinski upravljači za automobile koriste **315 MHz ili 433.92 MHz**, pri čemu na izbor utiču regionalna pravila i dizajn vozila. Sama frekvencija ne znači da signal od 433 MHz ima veći domet od signala od 315 MHz: važni su i snaga predajnika, efikasnost antene, modulacija, osetljivost prijemnika, prostiranje signala i lokalni propisi. U Evropi se često koristi 433.92 MHz, dok je 315 MHz uobičajen u Severnoj Americi i Japanu.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

U prikazanom sistemu sa fiksnim kodom, slanjem svakog koda jednom umesto pet puta procenjeno vreme se smanjuje na šest minuta:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Uklanjanjem pauze od 2 ms između signala, ovaj primer se skraćuje na približno tri minuta.

Korišćenjem De Bruijn sekvence za preklapanje nizova kandidatnih bitova, prikazani napad se skraćuje na približno osam sekundi, pod uslovom da prijemnik prihvata neprekidnu sekvencu bez obavezne preambule ili resetovanja frejma.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implementira ovaj napad na kompatibilne sisteme sa fiksnim kodom.<sup>[[5]](#references)</sup>

Obavezna **preambula onemogućava** optimizaciju De Bruijn sekvencom, a **rolling codes sprečavaju ovaj napad** (pod pretpostavkom da je kod dovoljno dug da ne može da se probije brute-force napadom).

## Sub-GHz Attack

Da biste napali ove signale pomoću Flipper Zero, pogledajte:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Zaštita pomoću Rolling Codes

Automatski otvarači garažnih vrata obično koriste bežični daljinski upravljač za otvaranje i zatvaranje garažnih vrata. Daljinski upravljač **šalje radiofrekventni (RF) signal** otvaraču garažnih vrata, koji aktivira motor za otvaranje ili zatvaranje vrata.

Neko može da upotrebi uređaj poznat kao code grabber za presretanje RF signala i njegovo snimanje za kasniju upotrebu. To se naziva **replay attack**. Da bi sprečili ovu vrstu napada, mnogi savremeni otvarači garažnih vrata koriste bezbedniji metod šifrovanja poznat kao sistem **rolling code**.

**RF signal se obično prenosi pomoću rolling code-a**, što znači da se kod menja pri svakoj upotrebi. Zbog toga je **teško** nekome da **presretne** signal i **upotrebi** ga za sticanje **neovlašćenog** pristupa garaži.

U sistemu rolling code, daljinski upravljač i otvarač garažnih vrata koriste **zajednički algoritam** koji **generiše novi kod** pri svakoj upotrebi daljinskog upravljača. Otvarač garažnih vrata reaguje samo na **ispravan kod**, zbog čega je znatno teže steći neovlašćen pristup garaži samo snimanjem koda.

### **Missing Link Attack**

U suštini, osluškujete pritisak na dugme i **snimate signal dok je daljinski upravljač van dometa uređaja** (na primer, automobila ili garažnih vrata). Zatim se približite uređaju i **upotrebite snimljeni kod da biste ga otvorili**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> Namerno ometanje RF signala je nezakonito u mnogim jurisdikcijama i može da poremeti sisteme važne za bezbednost. Testiranje ometanja obavljajte samo u zaštićenoj, ovlašćenoj laboratoriji i u skladu sa važećim radio-propisima.<sup>[[6]](#references)</sup>

Napadač može da **ometa signal u blizini vozila ili prijemnika**, tako da prijemnik ne može da dekodira kod, da zasebno snimi blokirani prenos, prekine ometanje i zatim ponovo emituje snimljeni kod.<sup>[[2]](#references)</sup>

Žrtva će u nekom trenutku **upotrebiti ključeve da zaključa automobil**, ali napad će do tada **snimiti dovoljno kodova za „zatvaranje vrata“** koji bi, nadamo se, mogli ponovo da se emituju radi otključavanja vrata (možda će biti potrebna **promena frekvencije**, jer neki automobili koriste iste kodove za otključavanje i zaključavanje, ali osluškuju obe komande na različitim frekvencijama).

> [!WARNING]
> **Ometanje funkcioniše**, ali se može primetiti: ako **osoba koja zaključava automobil jednostavno proveri vrata** da bi se uverila da su zaključana, primetiće da je automobil otključan. Osim toga, ako zna za ovakve napade, mogla bi da primeti da vrata nisu proizvela **zvuk** zaključavanja ili da **svetla** automobila nisu zatreperila kada je pritisnula dugme „zaključaj“.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Ovo je **prikrivenija tehnika jamming-a**. Napadač ometa signal, pa kada žrtva pokuša da zaključa vrata, to neće uspeti, ali napadač će **snimiti ovaj kod**. Zatim će žrtva **ponovo pokušati da zaključa automobil** pritiskom na dugme, a automobil će **snimiti ovaj drugi kod**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Odmah zatim, **napadač može da pošalje prvi kod** i **automobil će se zaključati** (žrtva će misliti da ga je zaključao drugim pritiskom). Zatim će napadač moći da **pošalje drugi ukradeni kod da bi otključao** automobil (pod pretpostavkom da se kod za **„zaključavanje automobila“ može koristiti i za njegovo otključavanje**). Možda će biti potrebna promena frekvencije (jer neki automobili koriste iste kodove za otključavanje i zaključavanje, ali osluškuju obe komande na različitim frekvencijama).

Jedna implementacija RollJam-a koristi širinu frekventnog opsega prijemnika: ometač emituje dovoljno blizu noseće frekvencije daljinskog upravljača da zasiti širi prijemnik vozila, dok uži prijemnik napadača ostaje podešen na daljinski upravljač i može da ga snima. Tačan pomak i širina opsega zavise od ciljnog hardvera.<sup>[[2]](#references)</sup>

> [!WARNING]
> Druge implementacije opisane u specifikacijama pokazuju da je **rolling code samo jedan deo** ukupnog poslatog koda. Na primer, poslati kod je **24-bitni ključ**, gde je prvih **12 bitova rolling code**, sledećih **8 komanda** (na primer, zaključavanje ili otključavanje), a poslednja 4 su **checksum**. Vozila koja koriste ovaj tip sistema takođe su ranjiva, jer napadač samo treba da zameni segment rolling code-a da bi mogao da **upotrebi bilo koji rolling code na obe frekvencije**.

> [!CAUTION]
> Imajte na umu da ako žrtva pošalje treći kod dok napadač šalje prvi, prvi i drugi kod biće poništeni.

### Alarm Sounding Jamming Attack

Tokom testiranja sistema rolling code sa dodatnom opremom, ugrađenog u automobil, **slanje istog koda dva puta** odmah je **aktiviralo alarm** i imobilajzer, što je omogućilo jedinstven vid **denial of service** napada. Ironično, načinom **isključivanja alarma** i imobilajzera bilo je da se pritisne **daljinski upravljač**, čime je napadaču omogućeno da **neprekidno izvodi DoS attack**. Ovaj napad se može i kombinovati sa **prethodnim kako bi se dobilo više kodova**, jer bi žrtva želela da što pre zaustavi napad.<sup>[[2]](#references)</sup>

## References

- [1] [Dokumentacija za Flipper Zero — regionalne Sub-GHz frekvencije](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Zaobilaženje sistema Rolling Code — Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar — DEF CON 23: Vozi kao da si ga hakovao (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Kako hakovati automobil — rekonstrukcija RollJam napada pomoću YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Izvorni kod za OpenSesame](https://github.com/samyk/opensesame)
- [6] [FCC — obaveštenje o sprovođenju propisa: suzbijanje upotrebe ometača](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
