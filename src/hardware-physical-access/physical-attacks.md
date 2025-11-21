# Fizički napadi

{{#include ../banners/hacktricks-training.md}}

## Oporavak lozinke BIOS-a i sigurnost sistema

**Resetovanje BIOS-a** može se postići na više načina. Većina matičnih ploča sadrži **bateriju** koja, kada se ukloni na oko **30 minuta**, resetuje podešavanja BIOS-a, uključujući lozinku. Alternativno, **jumper na matičnoj ploči** može se podesiti da resetuje ova podešavanja povezivanjem određenih pinova.

U situacijama kada hardverske izmene nisu moguće ili praktične, **softverski alati** nude rešenje. Pokretanje sistema sa **Live CD/USB** distribucijama kao što je **Kali Linux** omogućava pristup alatima kao što su **_killCmos_** i **_CmosPWD_**, koji mogu pomoći u oporavku lozinke BIOS-a.

U slučajevima kada je lozinka za BIOS nepoznata, njeno pogrešno unošenje **tri puta** obično rezultira kodom greške. Ovaj kod se može iskoristiti na sajtovima kao što je [https://bios-pw.org](https://bios-pw.org) da bi se potencijalno dobila upotrebljiva lozinka.

### UEFI sigurnost

Za moderne sisteme koji koriste **UEFI** umesto tradicionalnog BIOS-a, alat **chipsec** se može koristiti za analizu i modifikaciju UEFI podešavanja, uključujući onemogućavanje **Secure Boot**. Ovo se može postići sledećom komandom:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM zadržava podatke kratko nakon isključenja napajanja, obično za **1 do 2 minuta**. Ova postojanost može se produžiti do **10 minuta** nanošenjem hladnih supstanci, kao što je tečni azot. Tokom tog produženog perioda može se napraviti **memory dump** pomoću alata kao što su **dd.exe** i **volatility** za analizu.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** je alat napravljen za **physical memory manipulation** preko DMA, kompatibilan sa interfejsima kao što su **FireWire** i **Thunderbolt**. Omogućava zaobilaženje procedura logovanja tako što patchuje memoriju da prihvati bilo koju lozinku. Međutim, neefikasan je protiv sistema **Windows 10**.

---

## Live CD/USB for System Access

Zamena sistemskih binarnih fajlova kao što su **_sethc.exe_** ili **_Utilman.exe_** kopijom **_cmd.exe_** može obezbediti command prompt sa sistemskim privilegijama. Alati poput **chntpw** mogu se koristiti za uređivanje **SAM** fajla Windows instalacije, što omogućava promenu lozinke.

**Kon-Boot** je alat koji olakšava prijavljivanje u Windows sisteme bez poznavanja lozinke tako što privremeno menja Windows kernel ili UEFI. Više informacija može se naći na [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: Pristup BIOS podešavanjima.
- **F8**: Ulazak u Recovery mode.
- Pritiskanje **Shift** nakon Windows banera može zaobići autologon.

### BAD USB Devices

Uređaji poput **Rubber Ducky** i **Teensyduino** služe kao platforme za kreiranje **bad USB** uređaja, sposobnih da izvrše unapred definisane payload-e kada se povežu na ciljnu mašinu.

### Volume Shadow Copy

Administrator privileges omogućavaju kreiranje kopija osetljivih fajlova, uključujući **SAM** fajl, preko PowerShell-a.

---

## Bypassing BitLocker Encryption

BitLocker enkripciju je potencijalno moguće zaobići ako se **recovery password** nalazi u memory dump fajlu (**MEMORY.DMP**). Alati kao **Elcomsoft Forensic Disk Decryptor** ili **Passware Kit Forensic** mogu se koristiti za tu svrhu.

---

## Social Engineering for Recovery Key Addition

Novi BitLocker recovery key može se dodati pomoću taktika socijalnog inženjeringa, ubeđivanjem korisnika da izvrši komandu koja dodaje novi recovery key sastavljen od nula, čime se pojednostavljuje proces dešifrovanja.

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

Mnogi moderni laptopovi i desktop računari malog formata uključuju **chassis-intrusion switch** koji nadgleda Embedded Controller (EC) i BIOS/UEFI firmware. Dok je primarna svrha prekidača da podigne alarm kada se uređaj otvori, proizvođači ponekad implementiraju nedokumentovani recovery shortcut koji se aktivira kada se prekidač preklopi u specifičnom obrascu.

### How the Attack Works

1. Prekidač je povezan na **GPIO interrupt** na EC-u.
2. Firmware koji radi na EC prati **timing i broj pritisaka**.
3. Kada se prepozna hard-kodirani obrazac, EC poziva *mainboard-reset* rutinu koja **briše sadržaj NVRAM/CMOS** sistema.
4. Pri narednom bootu, BIOS učitava podrazumevane vrednosti – **supervisor password, Secure Boot keys i sva prilagođena podešavanja se brišu**.

> Nakon što je Secure Boot onemogućen i firmware password uklonjen, napadač može jednostavno boot-ovati bilo koji eksterni OS image i dobiti neograničen pristup internim diskovima.

### Real-World Example – Framework 13 Laptop

Recovery shortcut za Framework 13 (11th/12th/13th-gen) je:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Nakon desetog ciklusa EC postavlja zastavicu koja naređuje BIOS-u da obriše NVRAM pri sledećem ponovnom pokretanju. Cela procedura traje ~40 s i zahteva **samo odvijač**.

### Generički postupak eksploatacije

1. Uključite uređaj ili izvedite suspend-resume tako da EC radi.
2. Skinite donji poklopac da otkrijete intrusion/maintenance switch.
3. Reproducirajte specifični za proizvođača obrazac prebacivanja (proverite dokumentaciju, forume ili reverse-engineer-ujte EC firmware).
4. Ponovo sastavite i reboot-ujte – zaštite firmvera bi trebalo da budu onemogućene.
5. Boot-ujte sa live USB (npr. Kali Linux) i obavite uobičajene post-exploitation aktivnosti (credential dumping, data exfiltration, implantacija malicioznih EFI binarnih datoteka, itd.).

### Detekcija & ublažavanje

* Evidentirajte chassis-intrusion događaje u OS management konzoli i povežite ih sa neočekivanim BIOS resetima.
* Koristite **tamper-evident pečate** na šrafovima/poklopcima da detektujete otvaranje.
* Držite uređaje u **fizički kontrolisanim zonama**; pretpostavite da fizički pristup znači potpuni kompromis.
* Gde je moguće, onemogućite vendor “maintenance switch reset” feature ili zahtevajte dodatnu kriptografsku autorizaciju za NVRAM reset.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Karakteristike senzora
- Uobičajeni “wave-to-exit” senzori sparuju near-IR LED emitter sa TV-remote stilom receiver modula koji prijavljuje logic high tek nakon što vidi više pulsa (~4–10) ispravnog carrier-a (≈30 kHz).
- Plastični poklopac onemogućava emitteru i receiveru da gledaju direktno jedno u drugo, pa kontroler pretpostavlja da validirani carrier dolazi iz obližnjeg reflektovanja i aktivira relej koji otvara mehanizam za otvaranje vrata (door strike).
- Kada kontroler veruje da je cilj prisutan, često menja outbound modulation envelope, ali receiver nastavlja da prihvata bilo koji burst koji se poklapa sa filtriranim carrier-om.

### Tok napada
1. **Zabeležite profil emisije** – priključite logic analyser na pinove kontrolera da snimite i pre-detection i post-detection talasne oblike koji pokreću internu IR LED.
2. **Reprodukujte samo “post-detection” talasni oblik** – uklonite/ignorišite fabrički emitter i upravljajte eksternom IR LED-om sa unapred trigger-ovanim pattern-om od samog početka. Pošto receiver obraća pažnju samo na broj pulsa/frekvenciju, tretira spoofed carrier kao stvarnu refleksiju i aktivira relay liniju.
3. **Kontrolišite prenos** – emitujte carrier u podešenim burst-evima (npr. desetine milisekundi on, slično off) da dostavite minimalan broj pulsa bez saturacije AGC-a prijemnika ili logike za upravljanje interferencijama. Kontinuirana emisija brzo desenzitizuje senzor i sprečava aktiviranje releja.

### Reflektivna injekcija na velikim daljinama
- Zamenom bench LED-a sa visokosnažnom IR diodom, MOSFET driver-om i fokusirajućom optikom omogućava se pouzdano okidanje sa ~6 m udaljenosti.
- Napadaču nije potreban direktan line-of-sight sa receiver otvorom; usmeravanje snopa ka unutrašnjim zidovima, policama ili okvirima vrata vidljivim kroz staklo omogućava da reflektovana energija uđe u ~30° vidno polje i oponaša kratkoročni talas rukom.
- Pošto receiver-i očekuju samo slabe refleksije, znatno snažniji eksterni snop može se odbiti od više površina i i dalje ostati iznad praga detekcije.

### Weaponizovana baterijska lampa za napad
- Ugradnja driver-a unutar komercijalne baterijske lampe skriva alat na vidnom mestu. Zamenite vidljivu LED za visokosnažnu IR LED usklađenu sa opsegom receiver-a, dodajte ATtiny412 (ili sličan) da generiše ≈30 kHz burst-ove, i koristite MOSFET da potroši struju LED-a.
- Teleskopska zoom sočiva zaoštrava snop radi dometa/preciznosti, dok vibracioni motor pod kontrolom MCU daje hapticku potvrdu da je modulacija aktivna bez emitovanja vidljive svetlosti.
- Ciklusiranje kroz nekoliko sačuvanih modulation pattern-a (neznatno različite carrier frekvencije i envelope) povećava kompatibilnost između rebrendiranih porodica senzora, omogućavajući operatoru da pretražuje reflektujuće površine dok relej ne klikne i vrata ne otvore.

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)

{{#include ../banners/hacktricks-training.md}}
