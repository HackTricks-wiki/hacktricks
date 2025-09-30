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


Firmware to podstawowe oprogramowanie, które umożliwia urządzeniom prawidłowe działanie poprzez zarządzanie i ułatwianie komunikacji między komponentami hardware a oprogramowaniem, z którego korzystają użytkownicy. Jest przechowywane w pamięci stałej, co zapewnia urządzeniu dostęp do kluczowych instrukcji od momentu włączenia, prowadząc do uruchomienia systemu operacyjnego. Analiza i ewentualna modyfikacja firmware'u to krytyczny krok w identyfikowaniu luk bezpieczeństwa.

## **Zbieranie informacji**

**Zbieranie informacji** to istotny początkowy etap zrozumienia składu urządzenia i technologii, których używa. Proces ten obejmuje gromadzenie danych o:

- architekturze CPU i systemie operacyjnym, na którym działa
- szczegółach bootloadera
- układzie hardware i datasheetach
- metrykach codebase i lokalizacjach źródeł
- zewnętrznych bibliotekach i typach licencji
- historiach aktualizacji i certyfikacjach regulacyjnych
- diagramach architektury i przepływów
- ocenach bezpieczeństwa i zidentyfikowanych podatnościach

Do tego celu narzędzia **OSINT** są nieocenione, podobnie jak analiza dostępnych komponentów open-source zarówno ręcznie, jak i automatycznie. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują darmową analizę statyczną, którą można wykorzystać do znalezienia potencjalnych problemów.

## **Pozyskiwanie firmware'u**

Pozyskanie firmware'u można realizować na różne sposoby, z różnym stopniem trudności:

- **Bezpośrednio** od źródła (deweloperzy, producenci)
- **Budując** go z dostarczonych instrukcji
- **Pobierając** ze stron wsparcia producenta
- Wykorzystując zapytania **Google dork** do znajdywania hostowanych plików firmware
- Dostęp do **cloud storage** bezpośrednio, za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytywanie **updates** metodami man-in-the-middle
- **Extracting** z urządzenia przez połączenia takie jak **UART**, **JTAG**, lub **PICit**
- **Sniffing** zapytań o aktualizacje w komunikacji urządzenia
- Identyfikacja i użycie **hardcoded update endpoints**
- **Dumping** z bootloadera lub przez sieć
- **Usunięcie i odczyt** pamięci masowej (storage chip), gdy wszystkie inne metody zawiodą, przy użyciu odpowiednich narzędzi hardware

## Analiza firmware

Teraz, gdy **masz firmware**, musisz wydobyć z niego informacje, aby wiedzieć, jak go traktować. Różne narzędzia, których możesz użyć do tego:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli nie znajdziesz wiele przy pomocy tych narzędzi, sprawdź **entropy** obrazu za pomocą `binwalk -E <bin>` — jeśli entropy jest niskie, to prawdopodobnie nie jest zaszyfrowany. Jeśli entropy jest wysokie, najprawdopodobniej jest zaszyfrowany (lub w jakiś sposób skompresowany).

Ponadto możesz użyć tych narzędzi do wyodrębnienia **plików osadzonych wewnątrz firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Pozyskiwanie systemu plików

Dzięki wcześniejszym wspomnianym narzędziom, takim jak `binwalk -ev <bin>`, powinieneś być w stanie **wyodrębnić system plików**.\
Binwalk zwykle wyodrębnia go wewnątrz **folderu nazwanego według typu systemu plików**, który zazwyczaj jest jednym z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie znajdzie magic byte systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk, aby **znaleźć offset systemu plików i wyodrębnić (carve) skompresowany system plików** z binarki oraz **ręcznie wyodrębnić** system plików zgodnie z jego typem, korzystając z poniższych kroków.
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
Alternatywnie można uruchomić także następujące polecenie.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Dla squashfs (użytego w przykładzie powyżej)

`$ unsquashfs dir.squashfs`

Pliki będą znajdować się później w katalogu "`squashfs-root`".

- Dla archiwów CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza Firmware

Po uzyskaniu firmware ważne jest jego rozebranie, aby zrozumieć strukturę i potencjalne podatności. Proces ten polega na użyciu różnych narzędzi do analizy i wyodrębniania cennych danych z obrazu firmware.

### Narzędzia do analizy wstępnej

Poniżej podano zestaw poleceń do wstępnej inspekcji pliku binarnego (nazywanego `<bin>`). Polecenia te pomagają w identyfikacji typów plików, wydobywaniu ciągów, analizie danych binarnych oraz zrozumieniu informacji o partycjach i systemach plików:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić stan szyfrowania obrazu, sprawdza się **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, podczas gdy wysoka entropia może wskazywać na możliwe szyfrowanie lub kompresję.

Dla wyodrębniania **osadzonych plików** zalecane są narzędzia i zasoby takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Używając `binwalk -ev <bin>`, zwykle można wyodrębnić system plików, często do katalogu nazwanego według typu systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpoznaje typu systemu plików z powodu brakujących magicznych bajtów, konieczne jest ręczne wyodrębnienie. Obejmuje to użycie `binwalk` do znalezienia offsetu systemu plików, a następnie polecenia `dd` do wydzielenia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), używane są różne polecenia do ręcznego rozpakowania zawartości.

### Filesystem Analysis

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie błędów bezpieczeństwa. Zwraca się uwagę na niebezpieczne demony sieciowe, zakodowane na stałe poświadczenia, API endpoints, funkcje serwera aktualizacji, niekompilowany kod, skrypty startowe oraz skompilowane binaria do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** pod kątem poświadczeń użytkowników
- certyfikaty SSL i klucze w **etc/ssl**
- pliki konfiguracyjne i skrypty pod kątem potencjalnych podatności
- osadzone binaria do dalszej analizy
- typowe web serwery i binaria urządzeń IoT

Kilka narzędzi pomaga w wykrywaniu poufnych informacji i podatności w systemie plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) oraz [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania wrażliwych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) oraz [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Security Checks on Compiled Binaries

Zarówno kod źródłowy, jak i skompilowane binaria znalezione w systemie plików muszą być sprawdzone pod kątem podatności. Narzędzia takie jak **checksec.sh** dla binariów Unix i **PESecurity** dla binariów Windows pomagają zidentyfikować niechronione binaria, które mogą być wykorzystane.

## Emulating Firmware for Dynamic Analysis

Proces emulacji firmware umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Podejście to może napotkać problemy związane ze sprzętem lub zależnościami architektury, ale przeniesienie root filesystemu lub konkretnych binariów na urządzenie o zgodnej architekturze i kolejności bajtów (np. Raspberry Pi) lub na gotową maszynę wirtualną może ułatwić dalsze testy.

### Emulating Individual Binaries

Do badania pojedynczych programów kluczowe jest określenie kolejności bajtów (endianness) oraz architektury CPU programu.

#### Example with MIPS Architecture

To emulate a MIPS architecture binary, one can use the command:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia emulacyjne:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Dla MIPS (big-endian) używa się `qemu-mips`, a dla binariów little-endian wyborem będzie `qemu-mipsel`.

#### Emulacja architektury ARM

Dla binariów ARM proces jest podobny — do emulacji używa się `qemu-arm`.

### Pełna emulacja systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają pełną emulację firmware, automatyzując proces i wspierając analizę dynamiczną.

## Analiza dynamiczna w praktyce

Na tym etapie do analizy wykorzystuje się środowisko urządzenia rzeczywistego lub emulowanego. Ważne jest utrzymanie dostępu do shell do OS i filesystem. Emulacja może nie odzwierciedlać dokładnie interakcji z hardware, co może wymagać okazjonalnego restartu emulacji. Analiza powinna ponownie przeszukać filesystem, wykorzystać ujawnione webpages i network services oraz zbadać bootloader vulnerabilities. Testy integralności firmware są kluczowe do wykrycia potencjalnych backdoorów.

## Techniki analizy w czasie wykonywania

Analiza w czasie wykonywania polega na interakcji z procesem lub binarium w jego środowisku wykonawczym, przy użyciu narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania breakpointów i identyfikowania podatności poprzez fuzzing i inne techniki.

## Eksploatacja binarna i Proof-of-Concept

Opracowanie PoC dla wykrytych podatności wymaga głębokiego zrozumienia docelowej architektury i programowania w językach niskiego poziomu. Ochrony runtime binariów w systemach embedded są rzadkie, ale gdy występują, mogą być konieczne techniki takie jak Return Oriented Programming (ROP).

## Gotowe systemy operacyjne do analizy firmware

Systemy takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) dostarczają prekonfigurowane środowiska do testów security firmware, wyposażone w niezbędne narzędzia.

## Gotowe OS-y do analizy Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja mająca pomóc w przeprowadzaniu security assessment i penetration testing urządzeń Internet of Things (IoT). Oszczędza czas, dostarczając prekonfigurowane środowisko z załadowanymi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system oparty na Ubuntu 18.04, wstępnie załadowany narzędziami do testów security firmware.

## Ataki downgrade firmware i niezabezpieczone mechanizmy aktualizacji

Nawet gdy vendor implementuje sprawdzanie podpisów kryptograficznych dla obrazów firmware, **ochrona przed version rollback (downgrade) jest często pomijana**. Gdy boot- lub recovery-loader tylko weryfikuje podpis przy użyciu wbudowanego klucza publicznego, ale nie porównuje *wersji* (lub monotonicznego licznika) obrazu będącego flashowanym, atakujący może legalnie zainstalować **starsze, podatne firmware, które nadal ma ważny podpis**, i w ten sposób ponownie wprowadzić załatane wcześniej podatności.

Typowy przebieg ataku:

1. **Obtain an older signed image**
   * Pobierz go z publicznego portalu download vendor’a, CDN lub strony wsparcia.
   * Wydobądź go z aplikacji towarzyszących mobilnych/desktop (np. wewnątrz Android APK pod `assets/firmware/`).
   * Uzyskaj go z repozytoriów third-party, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Upload or serve the image to the device** via any exposed update channel:
   * Web UI, mobile-app API, USB, TFTP, MQTT itp.
   * Wiele konsumenckich urządzeń IoT udostępnia *unauthenticated* HTTP(S) endpoints, które przyjmują Base64-encoded firmware blobs, dekodują je po stronie serwera i wywołują recovery/upgrade.
3. Po downgrade, exploituj podatność, która została załatana w nowszym release (na przykład filter command-injection dodany później).
4. Opcjonalnie wgraj najnowszy obraz z powrotem lub wyłącz updates, aby uniknąć wykrycia po uzyskaniu persistence.

### Przykład: Command Injection po downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (przywróconym do starszej wersji) firmware parametr `md5` jest konkatenowany bezpośrednio do polecenia shell bez sanitizacji, co pozwala na wstrzyknięcie dowolnych poleceń (tutaj — umożliwienie dostępu root opartego na kluczach SSH). Późniejsze wersje firmware wprowadziły podstawowy filtr znaków, ale brak ochrony przed downgrade unieważnia tę poprawkę.

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu dostawców pakuje pełne obrazy firmware wewnątrz ich aplikacji mobilnych towarzyszących urządzeniu, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi‑Fi. Te pakiety są zwykle przechowywane niezaszyfrowane w APK/APEX pod ścieżkami takimi jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra` lub nawet zwykły `unzip` pozwalają pobrać podpisane obrazy bez dotykania fizycznego sprzętu.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista kontrolna oceny logiki aktualizacji

* Czy transport/autentykacja *update endpoint* jest odpowiednio zabezpieczona (TLS + authentication)?
* Czy urządzenie porównuje **version numbers** lub **monotonic anti-rollback counter** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach secure boot chain (e.g. signatures checked by ROM code)?
* Czy userland code wykonuje dodatkowe sanity checks (e.g. allowed partition map, model number)?
* Czy *partial* lub *backup* update flows ponownie używają tej samej logiki walidacji?

> 💡  Jeśli którykolwiek z powyższych elementów brakuje, platforma prawdopodobnie jest podatna na rollback attacks.

## Vulnerable firmware to practice

Aby poćwiczyć odkrywanie podatności w firmware, jako punkt wyjścia użyj następujących projektów vulnerable firmware.

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

## Referencje

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
