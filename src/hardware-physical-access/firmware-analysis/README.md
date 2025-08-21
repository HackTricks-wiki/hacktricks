# Analiza oprogramowania układowego

{{#include ../../banners/hacktricks-training.md}}

## **Wprowadzenie**

### Powiązane zasoby

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

Oprogramowanie układowe to niezbędne oprogramowanie, które umożliwia urządzeniom prawidłowe działanie, zarządzając i ułatwiając komunikację między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy wchodzą w interakcję. Jest przechowywane w pamięci trwałej, co zapewnia, że urządzenie może uzyskać dostęp do istotnych instrukcji od momentu włączenia, co prowadzi do uruchomienia systemu operacyjnego. Badanie i potencjalna modyfikacja oprogramowania układowego to kluczowy krok w identyfikacji luk w zabezpieczeniach.

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy początkowy krok w zrozumieniu budowy urządzenia i technologii, które wykorzystuje. Proces ten obejmuje gromadzenie danych na temat:

- Architektury CPU i systemu operacyjnego, na którym działa
- Szczegółów bootloadera
- Układu sprzętowego i kart katalogowych
- Metryk bazy kodu i lokalizacji źródłowych
- Zewnętrznych bibliotek i typów licencji
- Historii aktualizacji i certyfikatów regulacyjnych
- Diagramów architektonicznych i przepływów
- Oceny bezpieczeństwa i zidentyfikowanych luk

W tym celu narzędzia **inteligencji źródeł otwartych (OSINT)** są nieocenione, podobnie jak analiza wszelkich dostępnych komponentów oprogramowania open-source poprzez ręczne i zautomatyzowane procesy przeglądowe. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują darmową analizę statyczną, która może być wykorzystana do znalezienia potencjalnych problemów.

## **Pozyskiwanie oprogramowania układowego**

Pozyskiwanie oprogramowania układowego można podejść na różne sposoby, z których każdy ma swój poziom złożoności:

- **Bezpośrednio** od źródła (deweloperzy, producenci)
- **Budując** je na podstawie dostarczonych instrukcji
- **Pobierając** z oficjalnych stron wsparcia
- Wykorzystując zapytania **Google dork** do znajdowania hostowanych plików oprogramowania układowego
- Uzyskując dostęp do **chmury** bezpośrednio, z narzędziami takimi jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Ekstrahując** z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Podsłuchując** żądania aktualizacji w komunikacji urządzenia
- Identyfikując i używając **twardo zakodowanych punktów końcowych aktualizacji**
- **Zrzucając** z bootloadera lub sieci
- **Usuwając i odczytując** chip pamięci, gdy wszystko inne zawiedzie, używając odpowiednich narzędzi sprzętowych

## Analiza oprogramowania układowego

Teraz, gdy **masz oprogramowanie układowe**, musisz wyodrębnić informacje na jego temat, aby wiedzieć, jak je traktować. Różne narzędzia, które możesz użyć do tego:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli nie znajdziesz wiele za pomocą tych narzędzi, sprawdź **entropię** obrazu za pomocą `binwalk -E <bin>`, jeśli entropia jest niska, to prawdopodobnie nie jest zaszyfrowany. Jeśli entropia jest wysoka, prawdopodobnie jest zaszyfrowany (lub skompresowany w jakiś sposób).

Ponadto możesz użyć tych narzędzi do wyodrębnienia **plików osadzonych w firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Lub [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), aby zbadać plik.

### Uzyskiwanie systemu plików

Za pomocą wcześniej wspomnianych narzędzi, takich jak `binwalk -ev <bin>`, powinieneś być w stanie **wyodrębnić system plików**.\
Binwalk zazwyczaj wyodrębnia go w **folderze nazwanym zgodnie z typem systemu plików**, który zazwyczaj jest jednym z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie będzie miał magicznego bajtu systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk, aby **znaleźć offset systemu plików i wyciąć skompresowany system plików** z binarnego i **ręcznie wyodrębnić** system plików zgodnie z jego typem, korzystając z poniższych kroków.
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
Alternatywnie, można również uruchomić następujące polecenie.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Dla squashfs (używanego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki będą w katalogu "`squashfs-root`" po tym.

- Pliki archiwum CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z pamięcią NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza Oprogramowania Układowego

Gdy oprogramowanie układowe jest już zdobyte, istotne jest jego rozłożenie na części w celu zrozumienia jego struktury i potencjalnych luk. Proces ten polega na wykorzystaniu różnych narzędzi do analizy i wydobywania cennych danych z obrazu oprogramowania układowego.

### Narzędzia do Wstępnej Analizy

Zestaw poleceń jest dostarczany do wstępnej inspekcji pliku binarnego (nazywanego `<bin>`). Te polecenia pomagają w identyfikacji typów plików, wydobywaniu ciągów, analizie danych binarnych oraz zrozumieniu szczegółów partycji i systemu plików:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić status szyfrowania obrazu, sprawdzana jest **entropia** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, podczas gdy wysoka entropia wskazuje na możliwe szyfrowanie lub kompresję.

Do ekstrakcji **osadzonych plików** zaleca się korzystanie z dokumentacji **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Ekstrakcja systemu plików

Używając `binwalk -ev <bin>`, można zazwyczaj wyodrębnić system plików, często do katalogu nazwanego na cześć typu systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpoznaje typu systemu plików z powodu brakujących bajtów magicznych, konieczna jest ręczna ekstrakcja. Polega to na użyciu `binwalk` do zlokalizowania offsetu systemu plików, a następnie polecenia `dd` do wyodrębnienia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Po tym, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), używane są różne polecenia do ręcznego wyodrębnienia zawartości.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie luk w zabezpieczeniach. Zwraca się uwagę na niebezpieczne demony sieciowe, twardo zakodowane dane uwierzytelniające, punkty końcowe API, funkcjonalności serwera aktualizacji, niekompilowany kod, skrypty uruchamiające oraz skompilowane binaria do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** w celu uzyskania danych uwierzytelniających użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty w poszukiwaniu potencjalnych luk
- Wbudowane binaria do dalszej analizy
- Typowe serwery internetowe urządzeń IoT i binaria

Kilka narzędzi pomaga w odkrywaniu wrażliwych informacji i luk w zabezpieczeniach w systemie plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania wrażliwych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy oprogramowania układowego
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych binariów

Zarówno kod źródłowy, jak i skompilowane binaria znalezione w systemie plików muszą być dokładnie sprawdzone pod kątem luk w zabezpieczeniach. Narzędzia takie jak **checksec.sh** dla binariów Unix i **PESecurity** dla binariów Windows pomagają zidentyfikować niechronione binaria, które mogą być wykorzystane.

## Emulacja oprogramowania układowego do analizy dynamicznej

Proces emulacji oprogramowania układowego umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Podejście to może napotkać trudności związane z zależnościami sprzętowymi lub architektonicznymi, ale przeniesienie systemu plików root lub konkretnych binariów na urządzenie o dopasowanej architekturze i endianness, takie jak Raspberry Pi, lub na wstępnie zbudowaną maszynę wirtualną, może ułatwić dalsze testowanie.

### Emulacja pojedynczych binariów

Aby zbadać pojedyncze programy, kluczowe jest zidentyfikowanie endianness programu i architektury CPU.

#### Przykład z architekturą MIPS

Aby emulować binarium architektury MIPS, można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia emulacyjne:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Dla MIPS (big-endian) używa się `qemu-mips`, a dla binarnych little-endian wybór padnie na `qemu-mipsel`.

#### Emulacja architektury ARM

Dla binariów ARM proces jest podobny, z emulatorem `qemu-arm` wykorzystywanym do emulacji.

### Pełna emulacja systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne, ułatwiają pełną emulację firmware'u, automatyzując proces i wspierając analizę dynamiczną.

## Analiza dynamiczna w praktyce

Na tym etapie używa się rzeczywistego lub emulowanego środowiska urządzenia do analizy. Ważne jest, aby utrzymać dostęp do powłoki systemu operacyjnego i systemu plików. Emulacja może nie idealnie odwzorowywać interakcje sprzętowe, co wymaga okazjonalnych restartów emulacji. Analiza powinna ponownie przeszukać system plików, wykorzystać wystawione strony internetowe i usługi sieciowe oraz zbadać luki w bootloaderze. Testy integralności firmware'u są kluczowe do identyfikacji potencjalnych luk backdoor.

## Techniki analizy w czasie rzeczywistym

Analiza w czasie rzeczywistym polega na interakcji z procesem lub binariami w ich środowisku operacyjnym, przy użyciu narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania punktów przerwania i identyfikacji luk poprzez fuzzing i inne techniki.

## Eksploatacja binarna i dowód koncepcji

Opracowanie PoC dla zidentyfikowanych luk wymaga głębokiego zrozumienia architektury docelowej i programowania w językach niskiego poziomu. Ochrony w czasie rzeczywistym w systemach wbudowanych są rzadkie, ale gdy są obecne, techniki takie jak Return Oriented Programming (ROP) mogą być konieczne.

## Przygotowane systemy operacyjne do analizy firmware'u

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają wstępnie skonfigurowane środowiska do testowania bezpieczeństwa firmware'u, wyposażone w niezbędne narzędzia.

## Przygotowane systemy operacyjne do analizy firmware'u

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja mająca na celu pomoc w przeprowadzaniu oceny bezpieczeństwa i testów penetracyjnych urządzeń Internetu Rzeczy (IoT). Oszczędza dużo czasu, oferując wstępnie skonfigurowane środowisko z wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): System operacyjny do testowania bezpieczeństwa wbudowanego, oparty na Ubuntu 18.04, wstępnie załadowany narzędziami do testowania bezpieczeństwa firmware'u.

## Ataki na obniżenie wersji firmware'u i niebezpieczne mechanizmy aktualizacji

Nawet gdy dostawca wdraża kontrole podpisu kryptograficznego dla obrazów firmware'u, **ochrona przed cofaniem wersji (downgrade) jest często pomijana**. Gdy bootloader lub loader odzyskiwania tylko weryfikuje podpis za pomocą osadzonego klucza publicznego, ale nie porównuje *wersji* (lub monotonicznego licznika) obrazu, który jest wgrywany, atakujący może legalnie zainstalować **starszy, podatny firmware, który nadal ma ważny podpis** i w ten sposób ponownie wprowadzić załatane luki.

Typowy przebieg ataku:

1. **Uzyskaj starszy podpisany obraz**
* Pobierz go z publicznego portalu pobierania dostawcy, CDN lub strony wsparcia.
* Wyodrębnij go z towarzyszących aplikacji mobilnych/desktopowych (np. wewnątrz Android APK w `assets/firmware/`).
* Pobierz go z repozytoriów stron trzecich, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij lub udostępnij obraz urządzeniu** przez dowolny wystawiony kanał aktualizacji:
* Interfejs webowy, API aplikacji mobilnej, USB, TFTP, MQTT itp.
* Wiele konsumenckich urządzeń IoT wystawia *nieautoryzowane* punkty końcowe HTTP(S), które akceptują blob'y firmware'u zakodowane w Base64, dekodują je po stronie serwera i uruchamiają odzyskiwanie/aktualizację.
3. Po obniżeniu wersji wykorzystaj lukę, która została załatana w nowszej wersji (na przykład filtr wstrzykiwania poleceń, który został dodany później).
4. Opcjonalnie wgraj najnowszy obraz z powrotem lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu trwałości.

### Przykład: Wstrzykiwanie poleceń po obniżeniu wersji
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
W podatnym (downgradowanym) firmware, parametr `md5` jest bezpośrednio łączony z poleceniem powłoki bez sanitizacji, co pozwala na wstrzykiwanie dowolnych poleceń (tutaj – włączenie dostępu root opartego na kluczu SSH). Późniejsze wersje firmware wprowadziły podstawowy filtr znaków, ale brak ochrony przed downgrade'em czyni tę poprawkę bezprzedmiotową.

### Ekstrakcja firmware z aplikacji mobilnych

Wielu dostawców pakuje pełne obrazy firmware w swoich towarzyszących aplikacjach mobilnych, aby aplikacja mogła zaktualizować urządzenie przez Bluetooth/Wi-Fi. Te pakiety są zazwyczaj przechowywane w postaci niezaszyfrowanej w APK/APEX pod ścieżkami takimi jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra` lub nawet zwykły `unzip` pozwalają na pobranie podpisanych obrazów bez dotykania fizycznego sprzętu.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista kontrolna oceny logiki aktualizacji

* Czy transport/autoryzacja *punktu aktualizacji* jest odpowiednio chroniona (TLS + autoryzacja)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik przeciwdziałania cofaniu** przed wgraniem?
* Czy obraz jest weryfikowany w ramach bezpiecznego łańcucha rozruchowego (np. podpisy sprawdzane przez kod ROM)?
* Czy kod w przestrzeni użytkownika wykonuje dodatkowe kontrole poprawności (np. dozwolona mapa partycji, numer modelu)?
* Czy *częściowe* lub *kopie zapasowe* przepływy aktualizacji ponownie wykorzystują tę samą logikę walidacji?

> 💡  Jeśli któregokolwiek z powyższych brakuje, platforma prawdopodobnie jest podatna na ataki cofania.

## Podatne oprogramowanie układowe do ćwiczeń

Aby ćwiczyć odkrywanie luk w oprogramowaniu układowym, użyj następujących podatnych projektów oprogramowania układowego jako punktu wyjścia.

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- Projekt Damn Vulnerable Router Firmware
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Odniesienia

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)

## Szkolenie i certyfikacja

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
